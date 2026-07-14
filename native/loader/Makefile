ifeq ($(origin CC),default)
CC = x86_64-w64-mingw32-gcc
endif
CFLAGS ?= -O2 -Wall -Wextra

all: bofbench-loader.exe bofbench-loader-x86.exe

bofbench-loader.exe: loader.c capabilities.generated.h
	$(CC) $(CFLAGS) -o $@ loader.c

bofbench-loader-x86.exe: loader.c capabilities.generated.h
	i686-w64-mingw32-gcc $(CFLAGS) -DBOFBENCH_X86 -o $@ loader.c

clean:
	rm -f bofbench-loader.exe bofbench-loader-x86.exe
