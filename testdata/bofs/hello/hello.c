#include "beacon.h"

void go(char *args, int len) {
    (void)args;
    (void)len;
    BeaconPrintf(CALLBACK_OUTPUT, "hello from native loader fixture");
}
