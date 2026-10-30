/* Benchmark de overhead: mide (ns/op, mediana de 5 corridas)
 *   mmap+munmap  de un archivo (pasa por security_mmap_file)
 *   mprotect     R -> R|W -> R sobre MAP_PRIVATE (pasa por security_file_mprotect)
 *   page-fault   toque de cada pagina de un mapeo frio (MAP_PRIVATE, lectura)
 *   pread        4 KiB, referencia (no usa ninguno de los dos ganchos)
 * Uso: bench_mmap <archivo> [iteraciones]   -> imprime CSV: metrica,ns_por_op */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PAGES 1024
static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1e9+t.tv_nsec; }
static int cmp(const void*a,const void*b){ double x=*(double*)a,y=*(double*)b; return (x>y)-(x<y); }
static double med(double *v,int n){ qsort(v,n,sizeof(double),cmp); return v[n/2]; }

int main(int argc, char **argv)
{
	if (argc < 2) { fprintf(stderr, "uso: %s archivo [iter]\n", argv[0]); return 2; }
	int iters = argc > 2 ? atoi(argv[2]) : 200000;
	long ps = sysconf(_SC_PAGESIZE);
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) { perror("open"); return 2; }
	struct stat st;
	if (fstat(fd, &st) || st.st_size < (off_t)PAGES * ps) {
		fprintf(stderr, "el archivo debe medir >= %ld bytes (usa: head -c 4M /dev/urandom > f)\n", (long)PAGES * ps);
		return 2;
	}
	double r[5];
	volatile char sink = 0; char buf[4096];

	for (int k = 0; k < 5; k++) {              /* mmap + munmap */
		double t = now();
		for (int i = 0; i < iters; i++) {
			void *p = mmap(NULL, ps, PROT_READ, MAP_PRIVATE, fd, 0);
			if (p == MAP_FAILED) { perror("mmap"); return 2; }
			munmap(p, ps);
		}
		r[k] = (now() - t) / iters;
	}
	printf("mmap_munmap_ns,%.1f\n", med(r, 5));

	void *p = mmap(NULL, ps, PROT_READ, MAP_PRIVATE, fd, 0);
	for (int k = 0; k < 5; k++) {              /* mprotect */
		double t = now();
		for (int i = 0; i < iters; i++) {
			mprotect(p, ps, PROT_READ | PROT_WRITE);
			mprotect(p, ps, PROT_READ);
		}
		r[k] = (now() - t) / (2.0 * iters);
	}
	munmap(p, ps);
	printf("mprotect_ns,%.1f\n", med(r, 5));

	for (int k = 0; k < 5; k++) {              /* page faults de lectura */
		int rounds = iters / PAGES > 20 ? 200 : 20, n = 0; double t = now();
		for (int j = 0; j < rounds; j++) {
			char *m = mmap(NULL, PAGES * ps, PROT_READ, MAP_PRIVATE, fd, 0);
			if (m == MAP_FAILED) { perror("mmap"); return 2; }
			for (int i = 0; i < PAGES; i++) { sink += m[i * ps]; n++; }
			munmap(m, PAGES * ps);
		}
		r[k] = (now() - t) / n;
	}
	printf("pagefault_ns,%.1f\n", med(r, 5));

	for (int k = 0; k < 5; k++) {              /* pread de referencia */
		double t = now();
		for (int i = 0; i < iters; i++) { if (pread(fd, buf, sizeof buf, 0) < 0) return 2; sink += buf[0]; }
		r[k] = (now() - t) / iters;
	}
	printf("pread_4k_ns,%.1f\n", med(r, 5));
	return 0;
}
