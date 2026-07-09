#pragma once
#define CALLBACK_OUTPUT 0
typedef struct {
    char *buffer;
    int length;
    int offset;
} datap;
void BeaconDataParse(datap *parser, char *buffer, int size);
int BeaconDataInt(datap *parser);
char *BeaconDataExtract(datap *parser, int *size);
void BeaconPrintf(int type, const char *fmt, ...);
