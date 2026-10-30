/* PoC 1: modificar un archivo sensible via mmap(MAP_SHARED, PROT_WRITE).
 * Tras mmap() la escritura va directo a la page cache SIN syscall:
 * ni strace ni LD_PRELOAD la veran. Solo se puede frenar al crear el VMA. */
#include "common.h"
int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "/tmp/mmapguard-demo/secret.dat";
	make_secret(path, 0600);
	int fd = open(path, O_RDWR);
	if (fd < 0) { perror("open"); return EXIT_ERROR; }
	char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		printf("[BLOQUEADO] mmap(PROT_WRITE, MAP_SHARED): %s\n", strerror(errno));
		return denied(errno) ? EXIT_BLOCKED : EXIT_ERROR;
	}
	memcpy(p, "HACKEADO!!", 10);          /* sin ninguna syscall */
	msync(p, 4096, MS_SYNC);
	munmap(p, 4096);
	close(fd);
	printf("[ATAQUE EXITOSO] archivo %s: %s\n", path, file_intact(path) ? "intacto" : "MODIFICADO");
	return file_intact(path) ? EXIT_ERROR : EXIT_ATTACK_OK;
}
