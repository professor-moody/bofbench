#include "beacon.h"

static const char banner[] = "data_reloc";
static const char *labels[] = {"alpha", "beta", "gamma"};
static int global_count = 13;

void go(char *args, int len) {
    (void)args;
    BeaconPrintf(CALLBACK_OUTPUT, "%s: %s %d len=%d", banner, labels[1], global_count, len);
}
