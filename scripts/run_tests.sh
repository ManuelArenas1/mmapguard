#!/usr/bin/env bash
# run_tests.sh - Demostracion end-to-end de mmapguard
#
# Requiere una maquina/VM Linux real (x86_64 o arm64) con:
#   - headers del kernel en ejecucion instalados
#   - permisos de root (CAP_SYS_MODULE) para insmod/rmmod
# NO funciona dentro de contenedores sandboxeados sin modulos de kernel
# (gVisor, la mayoria de CI containers, este mismo entorno de desarrollo).
#
# Que hace:
#   1. Compila kmod/ y tests/
#   2. Corre las 4 PoC SIN el modulo cargado (linea base: el kernel estandar
#      permite estas operaciones salvo que ya este parcheado para Dirty COW)
#   3. Carga mmapguard en modo enforce+strict, repite las PoC (deben bloquearse)
#   4. Corre el benchmark de overhead con y sin el modulo
#   5. Descarga el modulo y muestra el log de auditoria (dmesg)
#
# Salida: docs/evidence/run_<timestamp>.log con todo el detalle.

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/docs/evidence/run_$(date +%Y%m%d_%H%M%S).log"
DEMO=/tmp/mmapguard-demo
PASS=0; FAIL=0

log() { echo "$@" | tee -a "$OUT"; }
section() { log ""; log "=== $* ==="; }

if [[ $EUID -ne 0 ]]; then
	echo "Este script debe ejecutarse como root (sudo $0)." >&2
	exit 1
fi
mkdir -p "$DEMO" "$ROOT/docs/evidence"
: > "$OUT"

section "1. Compilacion"
make -C "$ROOT/kmod" KDIR="${KDIR:-/lib/modules/$(uname -r)/build}" 2>&1 | tee -a "$OUT"
[[ -f "$ROOT/kmod/mmapguard.ko" ]] || { log "FALLO: no se genero mmapguard.ko"; exit 1; }
make -C "$ROOT/tests" 2>&1 | tee -a "$OUT"

run_poc() {   # run_poc <binario> <esperado_sin_proteccion> <esperado_protegido> <bajo_proteccion?>
	local bin="$1" protegido="$2" name
	name=$(basename "$bin")
	log "--- $name ---"
	"$ROOT/tests/$bin" "$DEMO/secret.dat" 2 2>&1 | tee -a "$OUT"
	local rc=$?
	if [[ "$protegido" == "1" ]]; then
		if [[ $rc -eq 0 ]]; then log "[OK] bloqueado por mmapguard"; PASS=$((PASS+1));
		else log "[FALLO] se esperaba bloqueo (rc=$rc)"; FAIL=$((FAIL+1)); fi
	fi
	log "(rc=$rc)"
}

section "2. Linea base SIN mmapguard (el ataque deberia funcionar, salvo Dirty COW ya parcheado)"
for p in poc_shared_write poc_mprotect_upgrade poc_private_cow poc_race_madvise; do
	run_poc "$p" 0
done

section "3. Cargando mmapguard (mode=enforce strict=1) y protegiendo el archivo de la demo"
insmod "$ROOT/kmod/mmapguard.ko" mode=enforce strict=1 || { log "insmod fallo (revisa dmesg / CAP_SYS_MODULE)"; exit 1; }
echo "add $DEMO/secret.dat" > /proc/mmapguard

section "4. Repitiendo las PoC CON mmapguard activo (deben ser bloqueadas)"
for p in poc_shared_write poc_mprotect_upgrade poc_private_cow; do
	run_poc "$p" 1
done
log "(poc_race_madvise no se repite: ya esta mitigado por el parche de Dirty COW del kernel, no por mmapguard)"

section "5. Estado de /proc/mmapguard"
cat /proc/mmapguard | tee -a "$OUT"

section "6. Benchmark de overhead (mmap/mprotect/page-fault/pread)"
log "-- sin mmapguard activo sobre este archivo (no esta en la lista protegida) --"
"$ROOT/tests/bench_mmap" "$DEMO/big.dat" 100000 2>&1 | tee -a "$OUT" || head -c 4M /dev/urandom > "$DEMO/big.dat" && "$ROOT/tests/bench_mmap" "$DEMO/big.dat" 100000 2>&1 | tee -a "$OUT"
log "-- con big.dat agregado a la lista protegida (ruta de codigo con decision real) --"
echo "add $DEMO/big.dat" > /proc/mmapguard
"$ROOT/tests/bench_mmap" "$DEMO/big.dat" 100000 2>&1 | tee -a "$OUT"
echo "del $DEMO/big.dat" > /proc/mmapguard

section "7. Descargando el modulo"
rmmod mmapguard
dmesg | tail -n 40 | tee -a "$OUT"

section "Resumen"
log "pruebas de bloqueo OK: $PASS   fallidas: $FAIL"
log "log completo: $OUT"
exit $FAIL
