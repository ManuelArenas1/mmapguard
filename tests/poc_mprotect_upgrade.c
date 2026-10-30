/* PoC 2: bypass clasico de filtros "solo en mmap": mapear PROT_READ (permitido)
 * y luego subir los permisos con mprotect(PROT_WRITE). El hook de mmap por si
 * solo NO lo ve; por eso mmapguard engancha tambien security_file_mprotect. */
#include "common.h"
int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "/tmp/mmapguard-demo/secret.dat";
	make_secret(path, 0600);
	int fd = open(path, O_RDWR);
	if (fd < 0) { perror("open"); return EXIT_ERROR; }
	char *p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) { printf("[ERROR] mmap R/O fallo: %s\n", strerror(errno)); return EXIT_ERROR; }
	printf("mmap(PROT_READ, MAP_SHARED) OK -> leyendo: \"%.24s\"\n", p);
	if (mprotect(p, 4096, PROT_READ | PROT_WRITE) != 0) {
		printf("[BLOQUEADO] mprotect(+PROT_WRITE): %s\n", strerror(errno));
		return denied(errno) ? EXIT_BLOCKED : EXIT_ERROR;
	}
	memcpy(p, "HACKEADO!!", 10);
	msync(p, 4096, MS_SYNC);
	munmap(p, 4096);
	printf("[ATAQUE EXITOSO] archivo %s\n", file_intact(path) ? "intacto" : "MODIFICADO");
	return file_intact(path) ? EXIT_ERROR : EXIT_ATTACK_OK;
}
