# Parte II — Diseño de la estrategia con apoyo de Inteligencia Artificial (30%)

## 3.1 Definición del flujo de trabajo asistido por IA

El proyecto se desarrolló con **Claude** (Anthropic) como copiloto de ingeniería a lo largo de tres fases, cada una con un rol distinto y distinto nivel de confianza otorgado a la salida del modelo:

| Fase | Rol de la IA | Nivel de confianza en la salida |
|---|---|---|
| **Exploración arquitectónica** | Explicar estructuras del kernel (`vm_area_struct`, `security_mmap_file`, `kretprobe`), comparar alternativas de intercepción (syscall table vs. LSM vs. kprobe vs. eBPF) y su viabilidad en kernels ≥ 5.7, y leer/sintetizar el repositorio base del curso (`SO2026B/CapaKernel`) para alinear el estilo y las convenciones del proyecto con el material visto en clase. | Alta para conceptos estables y bien documentados (ABI de syscalls, ciclo de vida de un Page Fault); **media-baja** para afirmaciones sobre disponibilidad de símbolos/kprobes específicos en una versión de kernel concreta — estas se verificaron compilando contra los headers reales (ver 3.2). |
| **Generación y verificación de código C de bajo nivel** | Generar el esqueleto del LKM (`kmod/mmapguard.c`): registro de `kretprobe`, manejo RCU de la lista de archivos protegidos, `/proc` con `seq_file`, contadores por-CPU. | Media: todo el código generado se compiló con `-Wall -Werror` contra `linux-headers-6.8.0-71-generic` antes de aceptarlo, y se revisó línea por línea buscando APIs obsoletas (ver tabla de alucinaciones). |
| **Creación de casos de prueba / PoC controladas** | Diseñar las 4 pruebas de concepto de usuario (`tests/poc_*.c`) que *demuestran* cada vector (escritura directa, escalamiento vía `mprotect`, COW privado, patrón de carrera tipo Dirty COW) y el benchmark de overhead. | Alta: son programas de usuario simples, sin privilegios elevados, que solo tocan un archivo de prueba propio (`/tmp/mmapguard-demo/secret.dat`) — no exploits reales contra el sistema. |

## 3.2 Metodología de ingeniería de prompts y verificación crítica

### Tabla de prompts estructurados (contexto · rol · restricción · resultado esperado)

| # | Contexto | Rol asignado a la IA | Restricción explícita | Resultado esperado |
|---|---|---|---|---|
| 1 | Se necesita decidir **dónde** interceptar `mmap()` desde un módulo cargable en un kernel 6.x moderno, sin recompilar el kernel ni usar técnicas no soportadas. | Arquitecto de sistemas operativos / revisor de seguridad de kernel. | No proponer parches a `sys_call_table` ni a `CR0.WP`; la solución debe funcionar como LKM externo cargado con `insmod` en un kernel *stock* de distro (Ubuntu/Debian). | Comparación razonada de alternativas (LSM estático, kprobe/kretprobe, eBPF/bpf_lsm) con la recomendación final y su justificación técnica. |
| 2 | Implementar en C el LKM que usa `kretprobe` sobre `security_mmap_file` y `security_file_mprotect` para auditar y, en modo *enforce*, denegar el mapeo de archivos en una lista protegida identificada por `(dev, ino)`. | Programador de kernel en C, siguiendo el estilo del kernel de Linux (`checkpatch`-friendly). | Debe compilar sin advertencias con `-Wall -Werror` contra `linux-headers` reales; debe soportar x86_64 y arm64 (acceso portable a argumentos vía `pt_regs`); debe usar RCU para la lista protegida (sin bloquear el *hot path* de lectura). | Código completo de `mmapguard.c`, compilable, con manejo de errores en `init`/`exit` (desenrollado correcto si falla el segundo `register_kretprobe`). |
| 3 | Generar 4 programas de usuario que *demuestren* (no exploten el sistema real) los escenarios de las preguntas 1, 4, 8 y 9 de la Parte I, cada uno con un código de salida estandarizado para automatizar la verificación. | Ingeniero de pruebas de seguridad ofensiva controlada (red team educativo). | Cada PoC debe operar **únicamente** sobre un archivo de prueba propio creado por el mismo programa (`/tmp/mmapguard-demo/...`), nunca sobre archivos del sistema; debe poder ejecutarse sin privilegios de root salvo para cargar el módulo. | 4 archivos `.c` + `common.h` con convención de códigos de salida (`0`=bloqueado, `10`=ataque exitoso, `2`=error), compilables con `-Wall -Wextra -Werror`. |
| 4 | Diseñar un script de automatización (`run_tests.sh`) que compile todo, mida una línea base sin el módulo, cargue `mmapguard` en modo *enforce+strict*, repita las pruebas (deben bloquearse) y mida el overhead con y sin protección activa. | Ingeniero de QA/DevOps para kernel. | Debe declarar explícitamente sus prerrequisitos (root, `CAP_SYS_MODULE`, headers del kernel en ejecución) y fallar de forma clara y explicada si el entorno no los cumple (p. ej. un contenedor sandboxeado sin soporte de módulos), en vez de fallar en silencio o con un error críptico. | Script bash idempotente con log persistente en `docs/evidence/`, resumen de PASS/FAIL. |
| 5 | Redactar las respuestas rigurosas de las 10 preguntas diagnósticas de la Parte I, citando estructuras internas correctas (`vm_area_struct`, PTE, COW, GUP) y conectándolas con el código del proyecto. | Profesor/autor técnico de sistemas operativos. | Cada respuesta debe referenciar, cuando aplique, el archivo/función exacta del proyecto donde el concepto se materializa; no se permiten afirmaciones sobre el *fix* de CVEs sin indicar el commit o mecanismo real (`FOLL_COW`). | Documento Markdown estructurado por pregunta, con fragmentos de código ilustrativos cuando ayudan a la claridad. |

### Análisis de alucinaciones técnicas detectadas

Durante la iteración con el modelo se identificaron y **rechazaron explícitamente** las siguientes sugerencias, por ser técnicamente incorrectas, obsoletas o inseguras:

1. **"Deshabilitar temporalmente el bit `CR0.WP` con `write_cr0()` para parchear `sys_call_table` en caliente."** — Técnica documentada en blogs de rootkits de hace más de una década. Es **peligrosamente insegura**: en SMP introduce una carrera entre núcleos (cada CPU tiene su propio `CR0`; deshabilitar WP en uno no afecta a los demás, lo que puede causar una excepción de protección general en otro núcleo justo durante la escritura), y en kernels modernos con `CONFIG_STRICT_KERNEL_RWX`/`DEBUG_RODATA` el segmento de texto está mapeado en páginas realmente separadas del resto, de forma que incluso con `WP=0` algunas rutas de verificación (control-flow integrity, IBT) pueden abortar. **Se descartó por completo** y se optó por `kretprobe`, que usa el framework oficial de *tracing* sin tocar memoria protegida.
2. **"Usar `kallsyms_lookup_name()` para resolver la dirección de `sys_call_table` y escribir directamente el puntero de la syscall deseada."** — `kallsyms_lookup_name` fue **removida de los símbolos exportados a módulos desde el kernel 5.7** (commit `0bd476e6c671`, parte de un endurecimiento deliberado contra rootkits). El modelo inicialmente sugirió esta función como si siguiera disponible para LKMs externos; se verificó que ya no compila contra los headers 6.8 usados en este proyecto (`undefined reference`), confirmando la alucinación. La API de `register_kprobe`/`register_kretprobe` resuelve el símbolo internamente sin necesitar esta función.
3. **`EXPORT_SYMBOL` inexistente/no exportado**: una iteración intermedia sugirió hookear directamente `do_mmap()` (en vez de `security_mmap_file()`) con un kprobe, argumentando que era "más temprano en el flujo". Se verificó que, si bien `do_mmap` existe y es *kprobe-able*, modificar su valor de retorno desde un `kretprobe` **no es equivalente** a lo que hace un LSM: `do_mmap` ya avanzó parte de la contabilidad de memoria (`mm->total_vm`, reservas de `vm_unmapped_area`) antes de completar, por lo que forzar un error tardío ahí puede dejar al `mm_struct` en un estado parcialmente inconsistente en ciertas rutas de error no esperadas por el *caller* original. `security_mmap_file()` es el punto **diseñado explícitamente** para decidir sí/no *antes* de cualquier efecto secundario sobre la memoria del proceso — se corrigió el diseño para usar este hook.
4. **"`remap_pfn_range()` acepta un `prot` adicional de cifrado por página."** — En una fase de explorar cifrado transparente (pregunta 5 de la Parte I), el modelo mencionó inicialmente una API ficticia de "mapeo cifrado transparente" a nivel de `remap_pfn_range`. Esta función no tiene ni ha tenido tal parámetro; el cifrado transparente real se implementa en la capa de filesystem (`fscrypt`) o de bloque (`dm-crypt`), nunca en la llamada de mapeo de páginas. Se corrigió la Parte I (pregunta 5) para reflejar la arquitectura real.
5. **Macro `MAP_SHARED_VALIDATE` tratada como sinónimo exacto de `MAP_SHARED`** en una primera versión del código de clasificación shared/private — se verificó contra `<linux/mman.h>` que `MAP_TYPE` es una máscara de 2 bits que agrupa `MAP_SHARED` (0x01) y `MAP_SHARED_VALIDATE` (0x03) como "compartido" para efectos de nuestra política, pero **no** son bit a bit idénticos; el código final en `mg_evaluate()` compara `(flags & MAP_TYPE) != MAP_PRIVATE` en lugar de `flags & MAP_SHARED`, para cubrir ambos casos correctamente (evitando un *bypass* usando `MAP_SHARED_VALIDATE`).

### Procedimiento de validación manual y compilación

Todo el código generado se validó con el siguiente procedimiento, sin excepciones:

1. **Lectura manual completa** de cada función generada, verificando contra la documentación oficial (`Documentation/` del árbol del kernel y los propios headers) que cada API usada existe con esa firma en el árbol de kernel objetivo.
2. **Compilación real** contra `linux-headers-6.8.0-71-generic` (instalados en el entorno de desarrollo) con `ccflags-y += -Wall -Werror`, exigiendo **cero advertencias** — cualquier *warning* (p. ej. conversión implícita de punteros, variables sin usar, *shadowing*) se trató como error bloqueante y se corrigió antes de aceptar el código. La salida íntegra de esta compilación está documentada en `docs/03-implementacion-resultados.md`.
3. **Compilación de las PoC de usuario** con `-Wall -Wextra -Werror`, mismo criterio de cero advertencias.
4. **Ejecución de línea base** de las PoC sin el módulo cargado, en el entorno de desarrollo (que sí permite `mmap`/`mprotect` de usuario aunque no `insmod`), confirmando que el comportamiento documentado del kernel (ataque exitoso sin protección) es reproducible, no solo teórico.
5. **Documentación honesta de lo que no se pudo ejecutar end-to-end**: el entorno de desarrollo usado para este repositorio es un contenedor sandboxeado sin soporte de carga de módulos de kernel (`insmod` falla con `Function not implemented`, no existe `/proc/modules`). Esto se declaró explícitamente en lugar de simular o fabricar una salida de `insmod`/`dmesg` falsa — ver limitaciones en la Parte III. El script `scripts/run_tests.sh` queda listo para ejecutarse en una VM Linux real (p. ej. la misma VM del laboratorio del curso) con un solo comando.

## 3.3 Estrategia arquitectónica seleccionada

### Diagrama conceptual

```
                         ESPACIO DE USUARIO (Ring 3)
   proceso A  --mmap(PROT_WRITE,MAP_SHARED,fd)-->   [bloqueado/auditado]
   proceso B  --mprotect(vma,+PROT_WRITE)-->        [bloqueado/auditado]
            |                                   |
            v                                   v
   =====================  FRONTERA RING3 -> RING0 (syscall) =====================
            |                                   |
            v                                   v
      do_mmap()                         do_mprotect_pkey()
            |                                   |
            v                                   v
   security_mmap_file(file,prot,flags)   security_file_mprotect(vma,req,prot)
            |  <-- kretprobe: krp_mmap          |  <-- kretprobe: krp_mprot
            |      entry_handler: decide        |      entry_handler: decide
            |      return_handler: fuerza        |      return_handler: fuerza
            |      -EPERM si procede            |      -EPERM si procede
            v                                   v
     (VMA se crea o la syscall falla)   (permisos cambian o la syscall falla)
            |
            v
   ====================== mmapguard.c (LKM, Ring 0) ==============================
   - Lista RCU de archivos protegidos (dev,ino)   <- /proc/mmapguard (add/del/clear)
   - Motor de decisión mg_evaluate(): shared-write | private-write(strict) | exec(strict)
   - Modo: off | audit | enforce                  <- /proc/mmapguard (mode/strict)
   - Contadores por-CPU (vistas/protegidas/denegadas) + log printk (dmesg)
   =================================================================================
```

### Descripción de la arquitectura

`mmapguard` se implementa como **un único LKM** (no un LSM, no eBPF) que coloca **dos `kretprobe`** sobre los puntos de decisión reales que ya usa el framework de seguridad del kernel (`security_mmap_file`, `security_file_mprotect`). En el `entry_handler` se inspeccionan los argumentos (archivo, permisos solicitados, si el mapeo es compartido o privado) contra una lista de archivos protegidos identificados por **`(s_dev, i_ino)`** —no por ruta de texto, para resistir *symlinks*, *bind mounts* y *renames*, que serían un *bypass* trivial de un filtro basado en *strings*—. La decisión (permitir, solo auditar, o denegar) se calcula en `mg_evaluate()` y se comunica al `return_handler` del mismo `kretprobe`, que sobrescribe el valor de retorno de la función interceptada con `-EPERM` cuando corresponde, logrando que `do_mmap()`/`do_mprotect_pkey()` aborten exactamente como lo harían frente a un LSM real que deniegue la operación.

La lista de archivos protegidos se protege con **RCU** (`list_add_tail_rcu`/`list_for_each_entry_rcu`) porque se lee en el *hot path* de **cada** `mmap()`/`mprotect()` del sistema (no solo de los archivos protegidos) y debe tener el menor overhead posible para los procesos no afectados; las modificaciones (`add`/`del`/`clear`, solo para `CAP_SYS_ADMIN`) ocurren con muy baja frecuencia a través de `/proc/mmapguard`, donde sí se usa un *spinlock* para serializar escritores. Las estadísticas se mantienen **por-CPU** (`DEFINE_PER_CPU`) para evitar contención entre núcleos en el camino crítico, y se suman solo al leer `/proc/mmapguard`.

### Matriz de compensaciones (trade-offs): rendimiento vs. seguridad

| Estrategia | Latencia añadida por `mmap()`/`mprotect()` | Profundidad de inspección | Cobertura | Riesgo de inestabilidad del kernel |
|---|---|---|---|---|
| **Sin protección** | 0 | Ninguna | — | Ninguno |
| **`mmapguard` (kretprobe sobre LSM hooks)** — *elegido* | Baja: un *breakpoint*/trampolín de `ftrace` + lectura de una lista RCU pequeña, **solo** en la syscall de creación/cambio de permisos (no en cada Page Fault ni en cada byte escrito). Medido empíricamente en la Parte III. | Decisión binaria por archivo + tipo de mapeo (shared/private) + permisos solicitados. No inspecciona el *contenido* de los datos. | Cubre `mmap()` inicial **y** el *bypass* clásico vía `mprotect()` posterior — ver pregunta 4 de la Parte I y PoC 2. | Bajo: usa framework oficial de *tracing*; `unregister_kretprobe` espera a que terminen *handlers* en vuelo antes de descargar. |
| **`vm_operations_struct->page_mkwrite` en un driver propio** | Se paga en la *primera* escritura de cada página (no en el `mmap()` inicial), potencialmente muchas veces por archivo. | Permite inspeccionar/vetar cada página individualmente al momento de ensuciarse, más granular que una decisión global por archivo. | Solo cubre archivos servidos *por ese driver específico*, no archivos arbitrarios del VFS ya existentes — mucho menos general que interceptar el framework LSM. | Bajo, pero requiere reimplementar el archivo como un dispositivo de caracteres propio en vez de proteger archivos reales del VFS. |
| **eBPF (`bpf_lsm` + `fentry`/`fexit`)** | Muy baja (trampolín JIT, sin *breakpoint trap*); es el mecanismo de menor overhead de los cuatro. | Puede ser igual o más rica que `mmapguard` (acceso a `BPF_CORE_READ`, mapas por-pid). | Igual cobertura potencial que `mmapguard`, de forma "nativa" soportada para alterar el resultado. | Muy bajo (verificador de eBPF garantiza terminación/seguridad de memoria) — pero requiere `CONFIG_BPF_LSM=y` y el LSM `bpf` activo en `lsm=`, no garantizado en todo kernel de distro estándar; además exige mantener *headers* BTF (`vmlinux.h`) sincronizados con el kernel objetivo. |
| **Hook en `sys_call_table` / parche a `CR0.WP`** | Variable, pero irrelevante frente al riesgo. | Puede ver la syscall cruda, pero no el VMA resuelto. | Frágil entre versiones de kernel. | **Alto**: descartado explícitamente (ver análisis de alucinaciones, punto 1). |

**Justificación de la elección final**: `mmapguard` se decidió sobre eBPF por una razón puramente práctica de **portabilidad del entregable**: el curso evalúa el módulo en distintas máquinas/VMs de estudiantes, y `CONFIG_BPF_LSM` no está garantizado ni habilitado por defecto en todas las distros (requiere además pasar `lsm=...,bpf` en el *cmdline* de arranque, algo que un LKM no puede activar retroactivamente). Un LKM con `kretprobe` solo requiere `CONFIG_KPROBES=y` (prácticamente universal en kernels de distro modernos) y compila/carga igual en cualquier máquina con los headers del kernel en ejecución — maximizando que la demostración funcione *tal cual* en el entorno de evaluación. Esta decisión, y su costo en rendimiento frente a la alternativa de eBPF, se documenta y mide en la Parte III.
