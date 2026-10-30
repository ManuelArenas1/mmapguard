/* PoC 3 (pregunta 8): fd O_RDONLY mapeado con PROT_WRITE + MAP_PRIVATE.
 * El kernel LO PERMITE: MAP_PRIVATE no escribe al archivo, la escritura dispara
 * COW y modifica una copia anonima. Verificamos que el archivo NO cambia, pero
 * el proceso si ve su copia alterada (alteracion temporal / base de Dirty COW).
 * En modo strict de mmapguard este mapeo se deniega. */
#include "common.h"
int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "/tmp/mmapguard-demo/secret.dat";
	make_secret(path, 0444);
	int fd = open(path, O_RDONLY);
	if (fd < 0) { perror("open"); return EXIT_ERROR; }
	char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		printf("[BLOQUEADO] mmap(O_RDONLY, PROT_WRITE, MAP_PRIVATE): %s\n", strerror(errno));
		return denied(errno) ? EXIT_BLOCKED : EXIT_ERROR;
	}
	memcpy(p, "COPIA-PRIVADA", 13);
	printf("[PERMITIDO] vista del proceso: \"%.24s\"\n", p);
	printf("            archivo en disco : %s\n", file_intact(path) ? "intacto (COW funciona)" : "MODIFICADO!");
	munmap(p, 4096);
	return file_intact(path) ? EXIT_ATTACK_OK : EXIT_ERROR;
}
