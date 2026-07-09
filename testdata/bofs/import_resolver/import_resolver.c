#include <windows.h>
#include "beacon.h"

void go(char *args, int len) {
    HMODULE module;
    FARPROC procedure;
    BOOL released;
    (void)args;
    (void)len;

    module = LoadLibraryA("kernel32.dll");
    if (!module) {
        BeaconPrintf(CALLBACK_OUTPUT, "LoadLibraryA failed");
        return;
    }
    procedure = GetProcAddress(module, "GetCurrentProcessId");
    released = FreeLibrary(module);
    if (!procedure || !released) {
        BeaconPrintf(CALLBACK_OUTPUT, "plain import resolution failed");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "plain kernel32 imports resolved");
}
