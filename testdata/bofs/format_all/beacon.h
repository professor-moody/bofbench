#pragma once
#define CALLBACK_OUTPUT 0
typedef struct {
    char *original;
    char *buffer;
    int length;
    int size;
} formatp;
void BeaconOutput(int type, char *data, int len);
void BeaconPrintf(int type, const char *fmt, ...);
void BeaconFormatAlloc(formatp *format, int maxsz);
void BeaconFormatReset(formatp *format);
void BeaconFormatFree(formatp *format);
void BeaconFormatAppend(formatp *format, char *text, int len);
void BeaconFormatPrintf(formatp *format, const char *fmt, ...);
char *BeaconFormatToString(formatp *format, int *size);
void BeaconFormatInt(formatp *format, int value);
