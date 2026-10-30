# Parte III — Implementación, presentación y argumentación de la solución (40%)

## 4.1 Entregables de código e implementación

| Entregable exigido | Ubicación en el repositorio |
|---|---|
| Código C modularizado y comentado, compatible con Linux 5.x/6.x | `kmod/mmapguard.c` (LKM, kretprobes), `tests/*.c` (PoC y benchmark) |
| Demostración de intercepción / validación de permisos sobre regiones `mmap()` | `tests/poc_shared_write.c`, `tests/poc_mprotect_upgrade.c`, `tests/poc_private_cow.c` |
| Makefile de compilación limpia (*clean build*) | `kmod/Makefile` (kbuild, `ccflags-y += -Wall -Werror`), `tests/Makefile` (`-Wall -Wextra -Werror`) |
| Scripts que simulen accesos no autorizados / carreras / modificaciones indebidas | `tests/poc_race_madvise.c` (patrón Dirty-COW), `scripts/run_tests.sh` (orquestador end-to-end) |

### Arquitectura del módulo (`kmod/mmapguard.c`)

```
module_init
   │
   ├─ proc_create("mmapguard")              -> interfaz de control (root-only)
   ├─ mg_add(ruta) por cada protect=...      -> protección desde el arranque (module_param_array)
   ├─ register_kretprobe(security_mmap_file) -> krp_mmap  (entry: decide, return: fuerza -EPERM)
   └─ register_kretprobe(security_file_mprotect) -> krp_mprot (idéntico, cubre el bypass vía mprotect)

mg_evaluate(op, file, prot, shared, ...)      <- núcleo de la política, común a ambos ganchos
   │
   ├─ mg_lookup(inode)  [RCU, sin locks]      -> ¿el archivo está en la lista protegida?
   ├─ clasifica: shared-write | private-write(COW, solo si strict) | exec(solo si strict)
   ├─ si mode==enforce y hay motivo           -> devuelve EPERM (contado en stats por-CPU)
   └─ siempre, si hay motivo                  -> pr_warn_ratelimited(...) (auditoría en dmesg)

/proc/mmapguard
   ├─ lectura  (mg_show)  -> modo, strict, contadores agregados, lista de archivos protegidos
   └─ escritura (mg_write) -> "mode X" | "strict 0|1" | "add RUTA" | "del RUTA" | "clear"
```

**Decisiones de implementación clave y su justificación:**

1. **Identificación por `(s_dev, i_ino)`, no por ruta de texto** (`mg_resolve()` vía `kern_path()` + `d_backing_inode()`). Una política basada en comparar *strings* de ruta es trivialmente evadible con *symlinks*, *bind mounts*, o simplemente abriendo el archivo por una ruta alterna (`/proc/self/fd/N`, un hardlink). El inodo y el dispositivo son la identidad real y estable del archivo en el VFS.
2. **RCU para la lista de archivos protegidos**: el `entry_handler` del `kretprobe` se ejecuta en el *hot path* de **cada** `mmap()`/`mprotect()` del sistema completo (no solo de los archivos protegidos), potencialmente con el *page table lock* ya tomado por capas superiores. Usar un *mutex* o incluso un *spinlock* para la lectura habitual introduciría contención entre núcleos en cargas con mucho `mmap()` concurrente (ej. servidores de bases de datos, intérpretes que cargan muchas bibliotecas). RCU permite lectura sin bloqueo (`rcu_read_lock()` es casi gratis) a cambio de que las modificaciones (`add`/`del`/`clear`) usen `list_add_tail_rcu`/`kfree_rcu` y toleren una ventana de gracia antes de liberar memoria — aceptable porque `add`/`del` son operaciones administrativas, no de *hot path*.
3. **Contadores por-CPU (`DEFINE_PER_CPU`)**: evitan una línea de caché compartida incrementada desde todos los núcleos en cada `mmap()`, que sería un cuello de botella de escalabilidad en máquinas multinúcleo.
4. **`kretprobe` en vez de `kprobe` simple**: se necesita el **`entry_handler`** para leer los argumentos originales (antes de que la función interceptada los modifique) y el **`return_handler`** para sobrescribir el valor de retorno (`regs_set_return_value()`) **solo si** el kernel iba a permitir la operación (`regs_return_value(regs) == 0`) — así nunca se "mejora" accidentalmente una denegación que ya venía de otra capa de seguridad (SELinux/AppArmor/permisos POSIX), solo se puede *restringir* más, nunca relajar.
5. **Acceso portátil a argumentos vía `pt_regs`** (`MG_ARG1`/`MG_ARG2`/`MG_ARG3`): como el `kretprobe` intercepta la función en su punto de entrada a nivel de registros de CPU (no hay forma de "tipar" los argumentos como en una llamada C normal sin usar BTF/CO-RE, que es terreno de eBPF), se leen directamente los registros del *calling convention* de la arquitectura (`rdi`/`rsi`/`rdx` en x86_64 System V ABI; `x0`/`x1`/`x2` en arm64 AAPCS64) — documentado y con `#error` explícito si se compila para una arquitectura no soportada.
6. **`-Wall -Werror` obligatorio en el Makefile**: el enunciado exige *clean build*; forzar `-Werror` en el propio `Makefile` del proyecto (no solo confiar en que el desarrollador recuerde pasarlo) garantiza que cualquier regresión futura falle la compilación en vez de colarse como advertencia ignorada.

## 4.2 Argumentación y análisis de resultados

### ¿Por qué la capa de kernel es óptima frente a espacio de usuario?

Una defensa en espacio de usuario (biblioteca interpuesta con `LD_PRELOAD` sobre `mmap()`, o un *wrapper* de la syscall) tiene dos fallas estructurales que la vuelven inútil frente al problema planteado:

1. **Es trivialmente eludible**: `LD_PRELOAD` solo afecta a binarios enlazados dinámicamente que resuelven símbolos vía el *dynamic linker* normal; un binario estático, uno que invoque `syscall(SYS_mmap, ...)` directamente, o uno que simplemente no cargue esa variable de entorno (la mayoría de formas de ejecutar un programa con privilegios elevados, `setuid`, o lanzado por `systemd`/`cron`, **ignoran** `LD_PRELOAD` del entorno del atacante) la evade por completo.
2. **No ve lo que importa**: aunque se pudiera interponer *todas* las invocaciones de la syscall `mmap`, una vez que el VMA existe, **las lecturas y escrituras subsecuentes no vuelven a pasar por ninguna syscall** (ver pregunta 1 de la Parte I) — son instrucciones `MOV` directas resueltas por la MMU. Ninguna defensa de espacio de usuario puede interponerse en una instrucción de CPU que no genera ninguna transición a Ring 0.

La única ventana real de control está en la creación/modificación del VMA, y esa decisión **solo el kernel la puede tomar de forma no evadible**, porque es el kernel quien controla las tablas de páginas que la MMU consulta. De ahí que el enunciado del parcial exija explícitamente una solución en la capa de kernel, y que este proyecto implemente la intercepción en `security_mmap_file`/`security_file_mprotect` — el punto más temprano y más difícil de evadir del flujo completo.

### Medición de impacto (overhead)

**Metodología**: se usa `tests/bench_mmap.c`, que mide con `CLOCK_MONOTONIC` el costo mediano (de 5 corridas) de cuatro operaciones sobre un archivo de 8 MiB en `/tmp`: (a) `mmap()+munmap()` repetido (pasa por `security_mmap_file` en cada iteración), (b) `mprotect()` alternando `R↔R|W` sobre un mapeo ya existente (pasa por `security_file_mprotect`), (c) el costo de un *Page Fault* de lectura en frío sobre páginas recién mapeadas (**no** pasa por ninguno de los dos ganchos instrumentados — sirve de control negativo), y (d) `pread()` de 4 KiB como referencia de E/S clásica. El procedimiento completo (compilar, cargar `mmapguard` en modo *enforce+strict*, repetir el benchmark con el archivo agregado a la lista protegida, descargar el módulo) está automatizado en `scripts/run_tests.sh` y debe ejecutarse en una máquina/VM Linux real con `CAP_SYS_MODULE`.

**Resultado obtenido en este entorno (línea base, SIN `mmapguard` cargado — ver limitaciones más abajo):**

| Operación | Mediana (ns/operación) | ¿Pasa por un gancho instrumentado? |
|---|---:|---|
| `mmap()` + `munmap()` | ≈ 2 150 ns | Sí (`security_mmap_file`) |
| `mprotect()` (ida y vuelta) | ≈ 500 ns | Sí (`security_file_mprotect`) |
| Page Fault de lectura (página fría) | ≈ 205 ns | No (control negativo) |
| `pread()` de 4 KiB | ≈ 270 ns | No (referencia de E/S clásica) |

*(Valores completos de las tres corridas en `docs/evidence/baseline_sandbox_*.log`.)*

**Overhead esperado al activar `mmapguard`** (metodología para cuando se ejecute en una máquina con soporte de módulos, documentado para que el profesor/estudiante lo reproduzca con `scripts/run_tests.sh`): el costo adicional introducido por un `kretprobe` es, en orden de magnitud, el de **un *breakpoint* de depuración** (`int3`/manejo de excepción de depuración) **dos veces** por invocación (entrada y retorno) más la ejecución de `mg_evaluate()` — que, para un archivo **no** protegido, se reduce a un recorrido RCU de una lista corta (`mg_lookup`) y un `goto out` inmediato. La literatura y la documentación del subsistema de *kprobes* del kernel sitúan el costo de un `kretprobe` individual en el orden de **cientos de nanosegundos** por invocación en x86_64 moderno (significativamente más caro que una llamada a función normal, pero órdenes de magnitud más barato que una transición de contexto completa o una operación de E/S). Dado que `security_mmap_file`/`security_file_mprotect` se ejecutan **una vez por llamada a `mmap()`/`mprotect()`**, nunca en el camino de cada byte leído/escrito (ver pregunta 1), el overhead es **constante y acotado** independientemente del tamaño del archivo o del número de accesos posteriores — exactamente el perfil de costo que se buscaba al elegir este punto de intercepción sobre alternativas como `page_mkwrite` (que se paga por página, potencialmente muchas veces por archivo) o una inspección por iteración (que convertiría cada acceso en algo tan caro como un `read()`, destruyendo la ventaja de `mmap()` que motiva el problema).

### Limitaciones y trabajo futuro

1. **Este entorno de desarrollo no permite `insmod`**: el contenedor sandboxeado usado para escribir y compilar este proyecto no tiene soporte de carga de módulos de kernel (no existe `/proc/modules`; `insmod` devuelve `Function not implemented`). Esto se documentó honestamente en vez de fabricar una salida de `dmesg`/dmesg falsa: **se verificó que el módulo compila sin advertencias contra headers de kernel reales (6.8.0-71-generic)** y que la lógica de las PoC es correcta ejecutándolas sin el módulo (línea base, ataques exitosos como se espera). La verificación *end-to-end* con el módulo cargado requiere ejecutar `sudo scripts/run_tests.sh` en una VM Linux real (x86_64 o arm64) con permisos de root — exactamente el entorno de laboratorio del curso.
2. **`kretprobe` vs. `bpf_lsm`**: como se discute en la Parte II, un `kretprobe` sobre funciones internas del kernel es una técnica de *tracing*, no una API de seguridad de primera clase como un LSM real o `bpf_lsm`. Si en el futuro el kernel cambia la firma de `security_mmap_file`/`security_file_mprotect`, o decide marcarlas como *notrace* (poco probable dado su rol central, pero posible), el módulo dejaría de cargar (`register_kretprobe` fallaría de forma explícita y controlada en `mg_init`, no de forma silenciosa) en vez de comprometer la seguridad del sistema.
3. **No hay inspección de contenido**: la política actual es binaria por archivo/tipo de mapeo (permitir/denegar), no inspecciona los *bytes* que se intentarían escribir. Trabajo futuro natural: combinar `mmapguard` con un `page_mkwrite` en un *driver* propio (ver Parte II, matriz de *trade-offs*) para los archivos de máxima sensibilidad, a costa de mayor overhead por página.
4. **Vectores de ataque fuera de alcance**: un proceso con `CAP_SYS_MODULE`/root puede simplemente descargar `mmapguard` (`rmmod`) o cargar su propio módulo que desregistre los `kretprobe` — ninguna defensa puramente software en Ring 0 puede protegerse de un atacante que ya tiene privilegios de Ring 0. Mitigaciones reales a este vector residen en capas inferiores: *Secure Boot* + firma de módulos (`CONFIG_MODULE_SIG_FORCE`), *Lockdown LSM*, o aislamiento por hipervisor/TEE (SEV-SNP, TDX) — fuera del alcance de un LKM, pero mencionado explícitamente como lo pide el enunciado (4.2, "vectores de ataque descubiertos... a nivel de hardware o hipervisor").

## 5. Cómo reproducir todo

```bash
# 1. Clonar y entrar al repo
git clone <URL_DEL_REPO> && cd mmapguard

# 2. Compilar el modulo de kernel (contra el kernel EN EJECUCION, o headers explicitos)
make -C kmod                                    # usa /lib/modules/$(uname -r)/build
# make -C kmod KDIR=/usr/src/linux-headers-X.Y   # para compilar contra otro arbol

# 3. Compilar las pruebas de usuario
make -C tests

# 4. Demostracion completa automatizada (REQUIERE root y un kernel con soporte de modulos)
sudo scripts/run_tests.sh
```
