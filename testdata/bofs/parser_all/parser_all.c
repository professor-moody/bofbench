#include "beacon.h"

void go(char *args, int len) {
    datap parser;
    short code = 0;
    char *blob = 0;
    int blob_len = 0;

    BeaconDataParse(&parser, args, len);
    code = BeaconDataShort(&parser);
    blob = BeaconDataExtract(&parser, &blob_len);

    BeaconPrintf(CALLBACK_OUTPUT, "parser_all: short=%d blob_len=%d remaining=%d", code, blob_len, BeaconDataLength(&parser));
    BeaconOutput(CALLBACK_OUTPUT, blob, blob_len);
}
