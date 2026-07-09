#pragma once
#define CALLBACK_OUTPUT 0
typedef struct {
    char *buffer;
    int length;
    int offset;
} datap;
void BeaconDataParse(datap *parser, char *buffer, int size);
short BeaconDataShort(datap *parser);
int BeaconDataLength(datap *parser);
char *BeaconDataExtract(datap *parser, int *size);
void BeaconOutput(int type, char *data, int len);
void BeaconPrintf(int type, const char *fmt, ...);
