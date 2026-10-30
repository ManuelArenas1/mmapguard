# MMapGuard

**Control de acceso en la capa de Kernel sobre archivos mapeados con `mmap()`**
Parcial práctico-teórico (25%) — Sistemas Operativos, Universidad EAFIT, 2026-2
Tema: *Seguridad de Archivos mediante Intervención en la Capa del Kernel y Mapeo de Memoria (`mmap`)*

> Trabajo de carácter académico. Referencia base del curso: [`evalenciEAFIT/SO2026B/USOS/CapaKernel`](https://github.com/evalenciEAFIT/SO2026B/tree/main/USOS/CapaKernel).

---

## 1. El problema, en una frase

`mmap()` permite que, tras la llamada inicial, las lecturas/escrituras sobre un archivo ocurran **a velocidad de hardware y sin ninguna syscall posterior** — lo que significa que ningún filtro de seguridad en espacio de usuario (`LD_PRELOAD`, un *wrapper* de `read`/`write`, `strace`) puede ver ni impedir esas escrituras. La única ventana real de control es el instante en que el kernel crea o modifica el VMA (`mmap()`/`mprotect()`). **MMapGuard** se sitúa exactamente ahí.

## 2. Qué hace

Un módulo de kernel cargable (`kmod/mmapguard.c`) que:

1. Mantiene una lista de archivos "protegidos", identificados por **`(dispositivo, inodo)`** — no por ruta de texto, para resistir *symlinks* y *bind mounts*.
2. Intercepta, mediante **`kretprobe`**, las dos funciones del framework de seguridad de Linux (`security_mmap_file`, `security_file_mprotect`) que el kernel llama en **cada** `mmap()` y `mprotect()` del sistema.
3. Si el archivo está protegido y la operación solicita escribir sobre él vía `MAP_SHARED` (o, en modo *strict*, también `MAP_PRIVATE`/`PROT_EXEC`), registra el intento (`dmesg`) y, en modo **enforce**, hace que la syscall falle con `-EPERM` — **sin recompilar el kernel, sin parchear memoria protegida y sin registrar un LSM** (ninguna de las tres es viable para un módulo externo en un kernel moderno; ver justificación completa en `docs/02-estrategia-ia.md`).
4. Expone una interfaz de control simple en `/proc/mmapguard` (solo root).

```
echo "mode enforce"               > /proc/mmapguard
echo "strict 1"                   > /proc/mmapguard
echo "add /ruta/al/archivo.dat"   > /proc/mmapguard
cat /proc/mmapguard
```

## 3. Estructura del repositorio

```
mmapguard/
├── kmod/                    Módulo de kernel (LKM)
│   ├── mmapguard.c          kretprobes + política + /proc/mmapguard
│   └── Makefile             kbuild, -Wall -Werror (clean build exigido)
├── tests/                   Pruebas de concepto en espacio de usuario
│   ├── common.h             utilidades compartidas + convención de códigos de salida
│   ├── poc_shared_write.c   PoC 1: escritura directa MAP_SHARED (pregunta 1)
│   ├── poc_mprotect_upgrade.c  PoC 2: bypass vía mprotect() (pregunta 4)
│   ├── poc_private_cow.c    PoC 3: PROT_WRITE sobre fd O_RDONLY vía COW (pregunta 8)
│   ├── poc_race_madvise.c   PoC 4: patrón de carrera tipo Dirty COW (pregunta 9)
│   ├── bench_mmap.c         benchmark de overhead (mmap/mprotect/page-fault/pread)
│   └── Makefile             -Wall -Wextra -Werror
├── scripts/
│   └── run_tests.sh         orquestador end-to-end (compila, carga, prueba, mide, descarga)
├── docs/
│   ├── 01-respuestas-conceptuales.md    Parte I  — 10 preguntas diagnósticas (30%)
│   ├── 02-estrategia-ia.md              Parte II — estrategia con IA, prompts, alucinaciones (30%)
│   ├── 03-implementacion-resultados.md  Parte III — implementación, overhead, limitaciones (40%)
│   └── evidence/                        logs reales de compilación y ejecución
└── .github/workflows/build.yml          CI: compila el LKM y las PoC en cada push
```

## 4. Arquitectura (resumen visual)

```
 Ring 3                 mmap(PROT_WRITE,MAP_SHARED,fd)   /  mprotect(vma,+PROT_WRITE)
                                     │                               │
 ───────────────── syscall ─────────┼───────────────────────────────┼─────────────────
 Ring 0          do_mmap()          │                 do_mprotect_pkey()
                                     ▼                               ▼
                         security_mmap_file(file,prot,flags)   security_file_mprotect(vma,req,prot)
                                     │  kretprobe: krp_mmap          │  kretprobe: krp_mprot
                                     ▼                               ▼
                         ┌─────────────────────────────────────────────────┐
                         │  mmapguard.c:  mg_evaluate()                    │
                         │  lista RCU (dev,ino) protegidos                 │
                         │  modo: off | audit | enforce   strict: 0/1      │
                         │  -> permite, o fuerza retorno = -EPERM          │
                         │  -> pr_warn_ratelimited (auditoría en dmesg)    │
                         └─────────────────────────────────────────────────┘
```

Detalle completo, justificación de cada decisión y comparación contra las alternativas descartadas (hook en `sys_call_table`, parche a `CR0.WP`, LSM estático, eBPF/`bpf_lsm`) en `docs/02-estrategia-ia.md` y `docs/03-implementacion-resultados.md`.

## 5. Compilar y ejecutar

### Requisitos
- Linux x86_64 o arm64, kernel 5.x/6.x, con `CONFIG_KPROBES=y` (prácticamente universal).
- Headers del kernel en ejecución (`linux-headers-$(uname -r)` en Debian/Ubuntu).
- `gcc`, `make`.
- Para la demostración completa: permisos de **root** (`CAP_SYS_MODULE`) en una máquina/VM real — **no funciona en contenedores sandboxeados sin soporte de módulos de kernel** (Docker sin `--privileged` apropiado, gVisor, CI containers estándar).

### Compilar

```bash
make -C kmod                 # usa /lib/modules/$(uname -r)/build por defecto
make -C tests
```

Ambos se compilan con `-Wall -Werror` (el LKM) y `-Wall -Wextra -Werror` (las PoC): cualquier advertencia rompe la compilación.

### Demostración completa automatizada

```bash
sudo scripts/run_tests.sh
```

Esto compila todo, ejecuta las 4 PoC **sin** el módulo (deberían tener éxito, confirmando la vulnerabilidad del kernel "desnudo"), carga `mmapguard` en modo `enforce strict=1`, protege el archivo de la demo, repite las PoC (deberían ser bloqueadas con `EPERM`), corre el benchmark de overhead con y sin protección, y descarga el módulo mostrando el resumen de auditoría en `dmesg`. Queda un log completo en `docs/evidence/`.

### Ejecutar una PoC individual (sin el módulo, para ver el ataque "crudo")

```bash
mkdir -p /tmp/mmapguard-demo
tests/poc_shared_write /tmp/mmapguard-demo/secret.dat
```

## 6. Resultados

- **Compilación**: verificada limpia (`-Wall -Werror`, cero advertencias) contra `linux-headers-6.8.0-71-generic` — ver `docs/evidence/`.
- **Línea base sin protección**: las 4 PoC demuestran los vectores descritos en la Parte I (escritura directa, bypass vía `mprotect`, escritura permitida sobre copia COW, patrón de carrera tipo Dirty COW ya mitigado por el kernel desde 2016).
- **Overhead**: medido con `bench_mmap`; metodología y números completos (incluida la limitación honesta de no poder cargar el módulo dentro del contenedor de desarrollo usado para este repositorio) en `docs/03-implementacion-resultados.md`.

## 7. Respuestas al parcial

| Parte | Documento |
|---|---|
| I — 10 preguntas diagnósticas (30%) | [`docs/01-respuestas-conceptuales.md`](docs/01-respuestas-conceptuales.md) |
| II — Estrategia con IA (30%) | [`docs/02-estrategia-ia.md`](docs/02-estrategia-ia.md) |
| III — Implementación y resultados (40%) | [`docs/03-implementacion-resultados.md`](docs/03-implementacion-resultados.md) |

## 8. Video explicativo

[`video/mmapguard_demo.mp4`](video/mmapguard_demo.mp4) — recorrido de ~4:43 min por el problema, la arquitectura (kretprobes sobre `security_mmap_file`/`security_file_mprotect`), el código del módulo, las 4 pruebas de concepto, el overhead medido y las limitaciones. Generado de forma reproducible (slides HTML renderizadas con Playwright + narración TTS en español + `ffmpeg`) con los scripts de `video/build.sh` y `video/render.js`.

## 9. Autores

Miguel Montoya, Samuel Alarcón y Manuel Arenas — Sistemas Operativos 2026-2, Universidad EAFIT.
Desarrollado con apoyo de IA (Claude, Anthropic) como se documenta íntegramente en `docs/02-estrategia-ia.md`.

## 10. Licencia

Código publicado bajo licencia MIT (ver `LICENSE`) para fines estrictamente académicos.
