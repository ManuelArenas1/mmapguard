# Parte I — Análisis conceptual y preguntas diagnósticas (30%)

> Cada respuesta se fundamenta a nivel de arquitectura del kernel de Linux (estructuras internas, MMU, flujo de eventos) y, cuando aplica, se referencia directamente al código implementado en `kmod/mmapguard.c` y a las pruebas de concepto en `tests/`.

---

## 1. Mapeo virtual y Page Faults: secuencia exacta `mmap()` → primer Page Fault

1. **Espacio de usuario**: el proceso invoca `mmap(addr, len, prot, flags, fd, offset)`. En glibc esto es una envoltura de la syscall `sys_mmap`/`__x64_sys_mmap`.
2. **Entrada a Ring 0**: la CPU ejecuta la instrucción `syscall`, guarda el contexto de usuario y transfiere el control a `entry_SYSCALL_64` → `do_syscall_64` → `sys_mmap` → `ksys_mmap_pgoff()` → `vm_mmap_pgoff()` → `do_mmap()`.
3. **Validaciones y creación del VMA**: `do_mmap()` valida los argumentos (alineación, límites de `mmap_min_addr`, `RLIMIT_AS`), y **antes de tocar ninguna tabla de páginas**, invoca el framework de seguridad: `security_mmap_file(file, prot, flags)`. Este es exactamente el punto de intercepción que usa `mmapguard` (ver pregunta 4). Si el chequeo retorna `0`, se continúa.
4. **Reserva del rango virtual**: el kernel busca un hueco libre en `mm->mmap` (el árbol de VMAs, en kernels modernos un *maple tree*, `mm->mm_mt`) mediante `get_unmapped_area()`, y construye un nuevo `struct vm_area_struct` que describe `[vm_start, vm_end)`, las banderas (`vm_flags`: `VM_READ`, `VM_WRITE`, `VM_EXEC`, `VM_SHARED`...), y el `struct file *vm_file` + `vm_pgoff` si el mapeo está respaldado por archivo.
5. **Instalación en la tabla de páginas (sin contenido aún)**: `do_mmap()` **no** copia datos ni crea las entradas finales de la tabla de páginas (PTE). Solo registra el VMA. Las entradas PTE del rango quedan ausentes (`not present`) — este es el corazón de la paginación por demanda.
6. **Retorno a Ring 3**: la syscall retorna la dirección virtual `addr` al proceso. Hasta este momento, el kernel ha gastado CPU únicamente en contabilidad de VMAs; no se ha tocado una sola página física de datos del archivo.
7. **Primer acceso del proceso**: cuando el proceso ejecuta una instrucción `MOV` (lectura o escritura) sobre una dirección dentro del rango mapeado, la **MMU** traduce la dirección virtual recorriendo las tablas de páginas (`PGD → P4D → PUD → PMD → PTE` en x86_64 de 4/5 niveles). Como la entrada PTE está marcada *not present*, la MMU genera la excepción de hardware **`#PF` (vector 14, Page Fault)**.
8. **Manejo del Page Fault en el kernel**: la CPU transfiere el control a `asm_exc_page_fault` → `exc_page_fault()` → `do_user_addr_fault()` → `handle_mm_fault()` → `__handle_mm_fault()` → `handle_pte_fault()`. El kernel localiza el VMA correspondiente (`find_vma()`), confirma que la dirección cae dentro de un VMA válido y que el tipo de acceso es compatible con `vma->vm_flags` (si no, el proceso recibe `SIGSEGV`).
9. **Resolución del fault para un mapeo de archivo**: como el VMA tiene `vm_file`, el kernel delega en `vma->vm_ops->fault` (para archivos regulares, normalmente `filemap_fault()` del *page cache*). Este busca la página en el *Page Cache* (`address_space->i_pages`, un *xarray*); si no está en caché, dispara I/O de bloque (`->read_folio`) para traerla desde disco, y la deja residente en RAM.
10. **Instalación final de la PTE**: con la página física ya disponible (`struct page`/`struct folio`), el kernel escribe la entrada PTE apuntando al *Page Frame Number* (PFN) correspondiente, con los bits de protección (`R/W`, `U/S`, `NX`) derivados de `vm_page_prot`. La instrucción que falló se reejecuta — esta vez la MMU encuentra la PTE presente y el acceso se resuelve **a velocidad de hardware**, sin volver a entrar a Ring 0.

**Conclusión arquitectónica**: `mmap()` es "barato" en la syscall porque solo crea metadatos (`vm_area_struct`); el costo real de traer datos se paga de forma diferida y granular (4 KB a la vez) en cada Page Fault — este es precisamente el único momento, junto con la syscall inicial, en que el kernel puede tomar decisiones de seguridad sobre el contenido. `mmapguard` interviene en el paso 3 (creación del VMA) porque es la última oportunidad confiable antes de que el acceso se vuelva invisible a nivel de syscall.

---

## 2. `MAP_SHARED` vs `MAP_PRIVATE`: gestión en `vm_area_struct` e implicaciones de seguridad

El `struct vm_area_struct` no almacena un booleano "shared" explícito como tal; la semántica se codifica en **`vma->vm_flags`** mediante el bit **`VM_SHARED`**, derivado del parámetro `flags` de `mmap()` en el momento de `do_mmap()`:

```c
if ((flags & MAP_TYPE) == MAP_SHARED) vm_flags |= VM_SHARED | VM_MAYSHARE;
```

- **`MAP_SHARED`**: todas las referencias al mismo rango de archivo (mismo `(dev, ino, offset)`) comparten las **mismas páginas físicas** a través del *Page Cache* del `address_space` del inodo. Dos procesos distintos que mapeen el mismo archivo con `MAP_SHARED` obtienen VMAs con direcciones virtuales distintas, pero que apuntan al **mismo PFN**. Las escrituras son visibles instantáneamente entre procesos (sin sincronía explícita) y, eventualmente, se reflejan en el archivo en disco (`writeback`, disparado por `msync()`, `fsync()` o el *pdflush*/`kworker` de escritura diferida).
  - **Implicación de seguridad**: una escritura con `PROT_WRITE|MAP_SHARED` modifica el archivo real sin pasar jamás por `write()`/`copy_from_user()` — es indetectable con herramientas basadas en syscalls (`strace`, `LD_PRELOAD`) una vez que el VMA existe. Esta es exactamente la amenaza que `mmapguard` neutraliza (PoC `poc_shared_write.c`).
- **`MAP_PRIVATE`**: el VMA se marca con `VM_MAYWRITE` pero **no** `VM_SHARED`. Las páginas se mapean inicialmente como **solo lectura** compartidas con el *Page Cache* (igual que `MAP_SHARED` para la lectura), pero cualquier escritura dispara **Copy-On-Write (COW)**: el kernel asigna una página física *anónima* nueva, copia el contenido, y re-mapea la PTE del proceso hacia esa copia privada, marcándola `dirty` y quitándole la bandera de solo-lectura que forzaba el COW.
  - **Implicación de seguridad**: el archivo en disco **nunca** se modifica por esta vía (la copia es exclusiva del proceso y se descarta al desmapear), pero el proceso sí puede alterar su **propia vista** de los datos — relevante para integridad de datos en memoria del proceso, no del archivo. Es la base conceptual, mal entendida, detrás de ataques como Dirty COW (pregunta 9).

En `mmapguard`, la clasificación "shared vs private" se obtiene leyendo `vma->vm_flags & VM_SHARED` en el hook de `mprotect` y el bit `MAP_TYPE` de los flags crudos en el hook de `mmap` (ver `mg_evaluate()` en `kmod/mmapguard.c`), que es exactamente el mecanismo que usa el propio kernel.

---

## 3. Mecanismo Copy-On-Write (COW): ciclo de vida y riesgos de escalamiento

**Ciclo de vida de una página bajo COW** (mapeo `MAP_PRIVATE`, `PROT_READ|PROT_WRITE`, archivo abierto en modo lectura o lectura/escritura):

1. **Mapeo inicial**: el VMA se crea con `vm_flags = VM_READ|VM_WRITE|VM_MAYWRITE` (el proceso *puede* escribir eventualmente), pero la PTE real que instala el primer Page Fault de lectura es **de solo lectura a nivel de hardware** (`vma->vm_page_prot` fuerza `_PAGE_RW=0`), aunque `vm_flags` diga `VM_WRITE`. Esta discrepancia intencional entre "permiso lógico" (`vm_flags`) y "permiso físico en la PTE" es el mecanismo que permite que el kernel intercepte la *primera* escritura.
2. **Primera escritura → Page Fault de protección**: cuando el proceso escribe, la MMU detecta que la PTE es de solo lectura y genera `#PF` con el bit de error `WRITE` activo pero la página sí "presente" → esto es un **fault de protección**, no de ausencia, y cae en `handle_pte_fault()` → `do_wp_page()` (*write-protect page*).
3. **Decisión de COW**: `do_wp_page()` verifica el contador de referencias de la página (`page_count`/`folio_ref_count` vía `PageAnonExclusive`/mapcount). Si la página está compartida con el *Page Cache* o con otro proceso, se asigna una página anónima nueva (`alloc_page_vma`), se copia el contenido byte a byte, se actualiza la PTE del proceso para apuntar a la copia con permisos R/W reales, y se decrementa la referencia a la página original.
4. **Página "rota" (unshared)**: a partir de este punto la página es exclusiva del proceso, vive en la lista de páginas anónimas de la `mm_struct` (contabilizada como *swap-backed*), y las escrituras subsecuentes son directas, sin más faults de protección.

**Condiciones de fallo que derivan en escalamiento/corrupción**: el riesgo no está en el COW en sí (que es correcto y está bien probado), sino en **rutas alternativas que modifican la página *antes* de que el COW se complete o la evaden**, en particular:
- Si el kernel permite que un *Get User Pages* con `FOLL_WRITE` forzado (`FOLL_FORCE`, usado por `/proc/pid/mem`, `ptrace`, `process_vm_writev`) escriba sobre la página **compartida original** antes de que `do_wp_page()` la "rompa" (la ruta de GUP tenía su propia lógica de COW, separada de la del fault handler) — esto es exactamente la causa raíz de **Dirty COW / CVE-2016-5195** (ver pregunta 9).
- Si `VM_MAYWRITE` queda activo en un VMA que *no debería* permitir escritura futura (p. ej., un binario ejecutable mapeado `MAP_PRIVATE` de un `fd` de solo lectura), y una ruta de kernel bugueada confía en `vm_flags` sin revalidar `PROT_WRITE`/`mprotect` en cada operación sensible.
- Combinaciones con `PROT_EXEC`: una página rota por COW que **conserva** el bit `NX=0` (ejecutable) puede convertirse en un vector de **inyección de código** si el atacante logra escribir contenido arbitrario en ella antes de que se marque de solo-ejecución — de ahí la política *strict* de `mmapguard`, que también niega `PROT_EXEC` sobre archivos protegidos.

---

## 4. Intercepción en el kernel: LKM con hook en la *System Call Table* vs. LSM (`file_mmap`)

| Criterio | Hook en `sys_call_table` (LKM clásico) | LSM (`security_mmap_file`, hooks `file_mmap`) |
|---|---|---|
| **Viabilidad actual (kernel ≥ 5.7)** | **Prácticamente inviable**: `sys_call_table` ya no se exporta (`EXPORT_SYMBOL`) desde el kernel 5.7+ (hay que resolverla por *kallsyms*/escaneo de memoria, frágil entre versiones). Además, desde el 3.3/CONFIG_ARCH_HAS_SET_MEMORY, la tabla y el segmento de texto del kernel suelen estar mapeados **solo lectura** (`CR0.WP` *pinned*, `set_memory_ro`), por lo que escribirla requiere deshabilitar protecciones de página a mano (`write_cr0`), algo que **rompe SMEP/KPTI** y es tratado como *rootkit behavior* por EDRs y por el propio kernel con `CONFIG_STRICT_KERNEL_RWX`. | **Viable y soportado**: `security_mmap_file()` es una función no estática, exportada, llamada explícitamente por `do_mmap()` en cada `mmap()`. No requiere parchear memoria protegida. |
| **Estabilidad entre versiones** | Baja: el *layout* exacto de la tabla, el *calling convention* (`asmlinkage`), y el número de syscall pueden cambiar. | Alta: la firma de `security_mmap_file(struct file*, unsigned long, unsigned long)` es estable desde hace muchas versiones LTS; es parte de una API pública del subsistema de seguridad. |
| **Cobertura semántica** | Solo ve `sys_mmap` tal cual se invocó; no ve mmaps hechos internamente por el kernel en nombre de un proceso (ej. carga de binarios vía `execve`), ni es trivial correlacionar con el VMA resultante. | Se ejecuta con el `struct file*` ya resuelto y **antes** de que el VMA exista; es el mismo punto donde SELinux/AppArmor/Smack toman decisiones reales — máxima fidelidad semántica. |
| **Permite modificar/denegar** | Sí, en teoría (reemplazando el puntero de función), pero de forma insegura y no soportada. | Sí: devolver `!= 0` desde el hook hace que `do_mmap()` retorne ese error sin crear el VMA. Es el mecanismo **diseñado** para esto. |
| **Limitación real para un LKM (no para un LSM in-tree)** | — | Un **módulo cargable NO puede registrarse como LSM** en kernels modernos: la lista de *security modules* habilitados se fija en tiempo de compilación/arranque (`CONFIG_LSM=...`, parámetro de arranque `lsm=`) via `security_add_hooks()` llamado solo desde código *built-in* marcado `__initdata`. Esto es intencional: evita que un rootkit se "inserte" como LSM dinámicamente. |

**Conclusión y decisión de diseño**: ni "hookear la syscall table" ni "escribir un LSM real" son viables/seguros para un LKM externo en un kernel moderno. La alternativa correcta —y la que usa `mmapguard`— es un **kretprobe** sobre la función del framework LSM (`security_mmap_file`, `security_file_mprotect`). El *kprobe* no parchea memoria permanentemente: usa el framework oficial de *tracing* del kernel (`ftrace`/*breakpoints* dinámicos), que es la vía soportada para instrumentar funciones del kernel en caliente, y permite inspeccionar los argumentos en la entrada y **sustituir el valor de retorno** en el `return-handler`, logrando el mismo efecto que tendría un LSM real (el `do_mmap()` ve un `security_mmap_file() != 0` y aborta con `-EPERM`) sin necesidad de recompilar el kernel ni de registrar un LSM.

---

## 5. Cifrado transparente en memoria para archivos confidenciales mapeados

Para que un archivo cifrado en disco sea legible en claro vía `mmap()` **solo** para procesos autorizados, sin exponer el texto en claro en memoria física a otros procesos no privilegiados, la pila de componentes debe cooperar así:

1. **Descifrado en la frontera disco↔Page Cache, no en la frontera Page Cache↔proceso**: el *Page Cache* almacena **páginas en claro** (es la única forma de que `mmap()` funcione de forma transparente, porque el *Page Cache* es lo que se mapea directamente). El cifrado debe residir en el **driver de bloque o el filesystem** (ej. `fscrypt` para cifrado por-archivo en ext4/F2FS, o `dm-crypt` por debajo del bloque completo), de forma que el descifrado ocurra en el camino `->read_folio()` (al traer la página desde el dispositivo hacia el Page Cache) y el cifrado ocurra en `->writepage()`/`writeback` (al bajar una página sucia de vuelta a disco). El contenido que vive en RAM dentro del Page Cache **ya está en claro**.
2. **El problema real no es "cómo descifrar", sino "cómo evitar que ese Page Cache en claro sea visible a un proceso no autorizado"**: como `MAP_SHARED` comparte el **mismo** `struct page` entre todos los procesos que abren el archivo, **no existe una forma nativa de dar una vista en claro a un proceso y una vista cifrada (o nada) a otro sobre las mismas páginas físicas** — el Page Cache es por-inodo, no por-proceso.
3. **Mecanismos reales para lograr aislamiento**:
   - **Control de acceso en la apertura/mapeo**: negar el `open()` (permisos POSIX/ACL/SELinux) o negar el propio `mmap()` (exactamente el rol de `security_mmap_file`/`mmapguard`) a procesos no autorizados, de forma que únicamente el proceso correcto llegue a tener un VMA sobre ese inodo.
   - **Filesystems cifrados por clave-de-proceso** (ej. `fscrypt` con claves por *keyring* de sesión): el kernel mantiene *page cache* separado cuando las claves de descifrado difieren, de modo que un proceso sin la clave correcta ni siquiera puede completar el `open()` con éxito (obtiene `ENOKEY`), evitando que llegue a existir una página en claro accesible para él.
   - **Enclaves de hardware (SGX/TDX/SEV-SNP)**: el verdadero aislamiento *memoria-a-memoria* frente a otros procesos con el mismo UID/root requiere soporte de hardware que cifre la RAM física fuera del enclave — el kernel por sí solo, con una CPU convencional, no puede impedir que un proceso con acceso directo a `/dev/mem` o con `CAP_SYS_RAWIO`/`ptrace` sobre el proceso autorizado lea esas páginas.
4. **Rol de `mmapguard` en esta cadena**: no implementa cifrado (eso es responsabilidad del filesystem/driver), pero sí es el **punto de control de acceso** descrito en el punto 3: decide *quién* llega a crear el VMA sobre el archivo sensible, lo cual es condición necesaria (aunque no suficiente sin cifrado en disco) para la confidencialidad.

---

## 6. `msync`/`fsync` y consistencia de páginas sucias; evasión si no se inspecciona en el momento de escritura

**Mecanismo de consistencia**: cuando un proceso escribe sobre una página `MAP_SHARED` ya con PTE presente, la **MMU** simplemente setea el bit hardware `DIRTY` en la PTE — esto ocurre sin ninguna intervención del kernel (es automático del hardware x86/ARM). El kernel se entera de que una página está sucia de dos formas:
- **De forma perezosa/periódica**: los *kworkers* de *writeback* (`wb_workfn()`) recorren inodos con páginas sucias (`mapping->i_pages` + `PAGECACHE_TAG_DIRTY`) y las bajan a disco cada cierto intervalo (`dirty_writeback_centisecs`, por defecto 5 s) o cuando se supera un umbral de memoria sucia (`dirty_ratio`/`dirty_background_ratio`).
- **De forma explícita y sincrónica**: `msync(addr, len, MS_SYNC)` (o su análogo a nivel de fd, `fsync()`) fuerza a `filemap_write_and_wait_range()` a recorrer exactamente ese rango, escribir las páginas sucias al dispositivo y esperar la confirmación de I/O antes de retornar.

**El hueco de inspección**: dado que el hardware marca `DIRTY` sin pasar por ninguna función del kernel, **no existe un "hook" nativo que se dispare en cada byte escrito** dentro de una página ya mapeada. Un filtro de seguridad que solo observe `write()`/`pwrite()` (I/O clásica) **nunca verá** estas escrituras. Un atacante que logró obtener un VMA `MAP_SHARED|PROT_WRITE` sobre un archivo puede escribir contenido arbitrario y, si ningún control inspecciona el *contenido* en el momento del `msync`/*writeback* (solo se verificó el **permiso de abrir el mapeo**, no cada escritura posterior), el dato llega a disco sin inspección alguna — exactamente lo que demuestra `poc_shared_write.c`.

**Mitigaciones reales, en orden de intrusividad creciente**:
1. **Negar la creación del VMA de escritura** (enfoque de `mmapguard`): más simple y de costo casi nulo, pero es "todo o nada" — no permite escritura parcial inspeccionada.
2. **`vm_operations_struct->page_mkwrite`**: el kernel sí expone un hook que se dispara en la **primera** transición de una página `MAP_SHARED` de limpia a sucia (usado por filesystems para reservar bloques en disco antes de permitir la escritura, *delayed allocation*). Un driver propio puede usar este hook para auditar/vetar la primera escritura de cada página, pero no ve byte-a-byte el contenido subsecuente dentro de esa misma página ya "abierta" para escritura.
3. **`madvise(MADV_PAGEOUT)`/revocar la PTE tras cada escritura**: forzar artificialmente que cada acceso vuelva a generar un fault (quitando el bit *present* después de cada `page_mkwrite`) permite inspección por página a costa de un overhead altísimo (vuelve cada escritura tan cara como un `write()`, anulando la ventaja de `mmap()`).

---

## 7. Auditoría con eBPF (kprobes/fexit) sin recompilar el kernel

**eBPF** permite cargar programas verificados en una VM dentro del kernel, adjuntos a puntos de instrumentación dinámicos, sin tocar el código fuente ni reiniciar:
- **`kprobe`/`kretprobe` genéricos**: se adjuntan a *cualquier* símbolo del kernel exportado en *kallsyms* (ej. `security_mmap_file`, `do_madvise`, `handle_mm_fault`). El programa eBPF corre en la entrada (o salida, para `kretprobe`) de la función, puede leer argumentos (vía `BPF_CORE_READ` para resistir cambios de *offsets* entre versiones — *CO-RE*), y escribir eventos a un **`BPF_MAP_TYPE_RINGBUF`** que un proceso de usuario (`libbpf`) consume en tiempo real.
- **`fentry`/`fexit`** (BPF trampolines): mecanismo más moderno y de **menor overhead** que los kprobes clásicos (evita el *breakpoint trap* de `int3`/`ftrace`, usando en su lugar un trampolín generado por JIT que llama directamente al programa BPF). `fexit` es particularmente útil porque entrega tanto los argumentos **como el valor de retorno real** de la función, permitiendo decidir auditoría *después* de conocer si el kernel permitió o no la operación.
- **`bpf_lsm` (LSM basado en eBPF)**: desde el kernel 5.7, es posible adjuntar programas eBPF directamente a los *hooks* LSM (incluyendo `mmap_file`) usando `BPF_PROG_TYPE_LSM`, y estos **sí pueden alterar el resultado** (retornar `-EPERM`) de forma soportada — a diferencia de un kprobe convencional, esto es una ruta oficialmente diseñada para ese propósito, aunque requiere `CONFIG_BPF_LSM=y` y que el LSM `bpf` esté habilitado en la lista de LSMs activos del sistema (parámetro `lsm=` en el *cmdline* del kernel), algo que no siempre está disponible fuera de distros recientes configuradas para ello.
- **Patrón típico de auditoría de accesos anómalos sobre `mmap()`**: adjuntar `kprobe`/`fentry` a `security_mmap_file` y `security_file_mprotect` (lectura de argumentos), correlacionar en un mapa eBPF (`BPF_MAP_TYPE_HASH` por `pid`/`inode`) con eventos de `do_madvise` (detectar `MADV_DONTNEED`), y exportar al *ring buffer* cualquier secuencia temporal sospechosa (p. ej., `MADV_DONTNEED` seguido en pocos microsegundos de una escritura vía `/proc/pid/mem`) — exactamente el patrón que la PoC `poc_race_madvise.c` reproduce de forma controlada, y que en este proyecto se detecta/comenta por la vía de kprobes/kretprobes del propio LKM en lugar de eBPF (ver sección de limitaciones en la Parte III sobre por qué se eligió kprobe-LKM sobre eBPF para este entregable).

---

## 8. Evasión de permisos POSIX: `O_RDONLY` + `mmap(PROT_WRITE, MAP_PRIVATE)`

**Sí, el kernel lo permite**, y es un comportamiento documentado, no un bug: `mmap(2)` exige que los permisos de apertura del descriptor sean **compatibles como mínimo** con `PROT_READ` para cualquier mapeo, y con `PROT_WRITE` **solo si** `flags` incluye `MAP_SHARED` (en cuyo caso el kernel exige que el `fd` haya sido abierto con `O_RDWR`, verificado en `do_mmap_pgoff()`/`vma_wants_writenotify()`). Pero si `flags = MAP_PRIVATE`, el kernel permite `PROT_WRITE` incluso con un `fd` abierto `O_RDONLY`, **porque la semántica de `MAP_PRIVATE` garantiza que la escritura jamás se propaga al archivo**: cualquier escritura primero pasa por COW (pregunta 3), produciendo una página anónima privada; el archivo subyacente, al que el proceso solo tiene permiso de lectura, nunca se toca.

El propio código del kernel lo valida explícitamente en `do_mmap()`:
```c
if (flags & MAP_SHARED) {
    if (prot & PROT_WRITE) {
        if (!(file->f_mode & FMODE_WRITE))
            return -EACCES;    /* MAP_SHARED exige fd con permiso real de escritura */
    }
}
/* MAP_PRIVATE con PROT_WRITE sobre fd O_RDONLY: no hay chequeo adicional,
 * porque COW garantiza que nunca se llega a escribir el inodo. */
```

**Riesgos que esto sí introduce** (demostrados en `tests/poc_private_cow.c`):
1. **Alteración temporal de datos "en caliente"**: el proceso puede modificar su copia en memoria de un archivo que el sistema de permisos le dijo que era "solo lectura" para él. Si ese proceso luego **comparte esa memoria** con otro componente (ej. la pasa a un hijo con `fork()`, o la expone via otro `mmap(MAP_SHARED, /* de memoria anónima compartida */)`), puede inducir a otros componentes a confiar en datos alterados sin que el archivo real haya cambiado — un vector de **confusión de integridad**, no de fuga.
2. **Fuga de información indirecta**: no hay fuga de contenido *adicional* al que ya tenía por `PROT_READ` (el proceso ya podía leer todo el archivo); el riesgo real es que un atacante use este patrón como **paso 1** de un ataque de carrera tipo Dirty COW (pregunta 9), combinando esta "escritura permitida sobre la copia" con una forma de redirigir esa escritura hacia la página original *antes* de que el COW termine de separarla.
3. **Mitigación de `mmapguard`**: el modo **strict** niega explícitamente `MAP_PRIVATE + PROT_WRITE` sobre archivos protegidos, precisamente porque aunque el archivo esté seguro en sí mismo, este patrón es el primer paso observable de las PoC de carrera.

---

## 9. Mitigación de ataques de carrera: `madvise(MADV_DONTNEED)` vs escrituras sobre páginas privadas (Dirty COW)

**El ataque histórico (CVE-2016-5195, "Dirty COW", 2007–2016)**: la ruta de *Get User Pages* (`get_user_pages()`, usada por `/proc/pid/mem`, `ptrace(POKETEXT)`, `process_vm_writev`) para escribir con `FOLL_WRITE|FOLL_FORCE` sobre una página de un mapeo `MAP_PRIVATE` de solo lectura (`vma->vm_flags` sin `VM_WRITE` real a nivel PTE) tenía su **propia** lógica de COW, separada de la de `do_wp_page()` (el *fault handler* normal). La carrera:

1. **Hilo A** (`madvise(MADV_DONTNEED)` en bucle): descarta la página privada ya "rota" por COW que el proceso tenía, haciendo que la próxima referencia vuelva a mapearse directamente a la página **original del Page Cache** (de solo lectura, compartida con el archivo en disco).
2. **Hilo B** (escritura vía `/proc/self/mem` con `pwrite`): en la estrecha ventana de tiempo en que la PTE vuelve a apuntar al Page Cache original pero **antes** de que el camino de GUP complete su propio COW, la escritura de `FOLL_FORCE` se aplicaba directamente sobre la página **compartida real**, modificando permanentemente el archivo en disco (incluso uno de solo lectura para el usuario), porque el camino de escritura forzada de GUP no revalidaba atómicamente el estado COW frente al `madvise` concurrente.

**Cómo lo previene el kernel parcheado (desde 4.8.3/4.7.9, commit `19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619`, "mm: remove gup_flags FOLL_WRITE games from __get_user_pages()")**: se introdujo la bandera **`FOLL_COW`**, que obliga a la ruta de GUP a **revalidar explícitamente**, bajo el mismo `page table lock`/`mmap_lock` que usa `do_wp_page()`, que la página a escribir ya pasó por COW y es verdaderamente privada/exclusiva del proceso (`can_follow_write_pte()` verifica `PageAnonExclusive`), en lugar de confiar en el estado de la PTE leído momentos antes. Esto cierra la ventana de carrera: cualquier intento de escribir vía GUP forzado sobre una página que *todavía* es la compartida del Page Cache obliga, en la misma operación atómica, a ejecutar el COW real antes de escribir — nunca se escribe la página original.

**Rol de `mmapguard` frente a esto**: dado que el *fix* ya está en el kernel mainline desde 2016, `tests/poc_race_madvise.c` reproduce fielmente el **patrón** de la carrera (sin ninguna vulnerabilidad real) y, al ejecutarse sobre un kernel moderno, **siempre** reporta `[KERNEL PARCHEADO]` — es decir, verifica que el entorno de ejecución tiene el *fix* de `FOLL_COW` activo. `mmapguard` en modo *strict* añade una capa de **defensa en profundidad**: como niega de entrada `MAP_PRIVATE+PROT_WRITE` sobre archivos protegidos, ni siquiera se llega a crear el VMA que un futuro bug similar podría explotar — es decir, reduce la superficie de ataque independientemente de si existe o no una vulnerabilidad de carrera vigente.

---

## 10. `struct page`, tablas de páginas (PGD/P4D/PUD/PMD/PTE) y bits NX/R-W/U-S en la contención de inyección de código

- **`struct page`** (o `struct folio` en kernels recientes ≥ 5.17, que agrupa páginas compuestas): es el descriptor **por página física** que el kernel usa para rastrear su estado — contador de referencias (`_refcount`), si está mapeada y por cuántas PTEs (`_mapcount`), si pertenece al Page Cache de un inodo o es anónima, si está sucia, bloqueada, reservada, etc. Es la unidad de contabilidad que permite al kernel saber, en cualquier momento, **quién** tiene acceso a una página física dada — condición necesaria para poder razonar sobre aislamiento.
- **Jerarquía de tablas de páginas (x86_64, 4 niveles: PGD→PUD→PMD→PTE, o 5 con P4D en sistemas con más de 48 bits de dirección)**: cada proceso tiene su propio **PGD** (apuntado por el registro `CR3`, cambiado en cada *context switch*), de forma que el mismo rango de direcciones virtuales en dos procesos distintos puede traducir a páginas físicas completamente distintas (o a la misma, si comparten un mapeo). Esta jerarquía es la base del **aislamiento de espacios de direcciones**: un proceso no puede, por diseño de hardware, generar una dirección virtual que resuelva a una página física para la cual no existe una PTE válida en *su propio* árbol de tablas.
- **Bits de protección en la PTE (leídos por la MMU en cada acceso, no por software)**:
  - **R/W** (bit de escritura): si está en `0` (solo lectura) y la CPU intenta escribir, se genera `#PF` de protección — es el mecanismo que habilita COW (pregunta 3) y `page_mkwrite` (pregunta 6).
  - **U/S** (*User/Supervisor*): separa qué páginas son accesibles desde Ring 3 vs. solo desde Ring 0. Combinado con **SMEP** (*Supervisor Mode Execution Prevention*) y **SMAP** (*Supervisor Mode Access Prevention*) a nivel de CPU, impide que, incluso si el kernel fuera engañado para saltar a una dirección controlada por el atacante en espacio de usuario, lo haga con privilegios de Ring 0, o que lea/escriba memoria de usuario sin usar explícitamente `copy_to_user`/`copy_from_user` (que activan temporalmente el permiso).
  - **NX/XD** (*No-eXecute* / *eXecute Disable*, bit 63 de la PTE): si está activo, la CPU genera `#PF` ante cualquier intento de **ejecutar** instrucciones desde esa página, independientemente de los permisos R/W. Es la defensa de hardware central contra inyección de código: una página de datos (heap, stack, una región anónima producto de COW) se mapea típicamente con `NX=1`, de modo que aunque un atacante logre escribir shellcode en ella (vía un buffer overflow, por ejemplo), **no puede hacer que la CPU lo ejecute** directamente ahí — debe recurrir a técnicas más complejas (ROP/JOP reutilizando código ya ejecutable existente, *W^X bypass*).
- **Contención de inyección en el contexto de este proyecto**: una región mapeada con `mmap()` que combine `PROT_WRITE` y `PROT_EXEC` simultáneamente (`W^X` violado) es el escenario de mayor riesgo, porque permite escribir datos arbitrarios y luego ejecutarlos en la misma página sin pasar por `NX`. Por esto, el modo *strict* de `mmapguard` trata `PROT_EXEC` sobre archivos protegidos como motivo de denegación igual que las escrituras: el objetivo es nunca permitir que una página respaldada por un archivo sensible llegue a tener, simultáneamente o en secuencia vía `mprotect`, permisos de escritura y ejecución.
