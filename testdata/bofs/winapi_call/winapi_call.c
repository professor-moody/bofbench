#include <windows.h>
#include "beacon.h"

void go(char *args, int len) {
    (void)args;
    (void)len;
    BeaconPrintf(CALLBACK_OUTPUT, "GetCurrentProcessId=%lu", GetCurrentProcessId());
}
