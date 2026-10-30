# Makefile kbuild para mmapguard.ko
#   make                      -> compila contra el kernel en ejecucion
#   make KDIR=/ruta/headers   -> compila contra otro arbol (p.ej. /usr/src/linux-headers-6.8.0-71-generic)
obj-m += mmapguard.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# -Werror: el parcial exige "clean build" sin advertencias
ccflags-y += -Wall -Werror

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
