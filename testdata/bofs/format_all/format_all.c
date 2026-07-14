#include "beacon.h"

void go(char *args, int len) {
    formatp format;
    char *output;
    int output_len = 0;
    (void)args;
    (void)len;

    BeaconFormatAlloc(&format, 128);
    BeaconFormatPrintf(&format, "format_all: %s=%d", "value", 7);
    BeaconFormatAppend(&format, " ready", 6);
    output = BeaconFormatToString(&format, &output_len);
    BeaconOutput(CALLBACK_OUTPUT, output, output_len);
    BeaconFormatReset(&format);
    BeaconFormatInt(&format, 0x01020304);
    output = BeaconFormatToString(&format, &output_len);
    BeaconPrintf(CALLBACK_OUTPUT, "format_all: int_bytes=%d,%d,%d,%d", output[0], output[1], output[2], output[3]);
    BeaconFormatFree(&format);
}
