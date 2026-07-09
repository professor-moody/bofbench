ifeq ($(origin CC),default)
CC = x86_64-w64-mingw32-gcc
endif
CFLAGS ?= -O2 -Wall -Wextra

all: bofbench-loader.exe

bofbench-loader.exe: loader.c
	$(CC) $(CFLAGS) -o $@ loader.c

clean:
	rm -f bofbench-loader.exe
