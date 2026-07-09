#include "beacon.h"

static volatile int zero_count;

void go(char *args, int len) {
    (void)args;
    (void)len;
    BeaconPrintf(CALLBACK_OUTPUT, "bss_reloc: zero=%d", zero_count);
}
