#include "beacon.h"

void go(char *args, int len) {
    volatile unsigned long long spin = (unsigned long long)len;
    (void)args;
    for (;;) {
        spin++;
    }
}
