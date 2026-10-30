/* Utilidades comunes de las PoC.
 * Convencion de codigo de salida (la usa run_tests.sh):
 *   0  = defensa efectiva: la operacion fue DENEGADA (EPERM/EACCES)
 *   10 = el ataque funciono (la operacion fue permitida / el archivo cambio)
 *   2  = error inesperado de la prueba */
#ifndef COMMON_H
#define COMMON_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define EXIT_BLOCKED 0
#define EXIT_ATTACK_OK 10
#define EXIT_ERROR 2

#define SECRET "TOP-SECRET: saldo=1000000"

/* Crea el archivo "sensible" de la demo con contenido conocido. */
static inline void make_secret(const char *path, mode_t mode)
{
	chmod(path, 0600);
	FILE *f = fopen(path, "w");
	if (!f) { perror("fopen"); exit(EXIT_ERROR); }
	fputs(SECRET, f);
	/* rellenamos hasta 1 pagina */
	for (int i = strlen(SECRET); i < 4096; i++) fputc('.', f);
	fclose(f);
	chmod(path, mode);
}

static inline int file_intact(const char *path)
{
	char buf[64] = {0};
	int fd = open(path, O_RDONLY);
	if (fd < 0) return 0;
	ssize_t n = read(fd, buf, sizeof(SECRET) - 1);
	close(fd);
	return n == (ssize_t)(sizeof(SECRET) - 1) && !memcmp(buf, SECRET, sizeof(SECRET) - 1);
}

static inline int denied(int e) { return e == EPERM || e == EACCES; }
#endif
