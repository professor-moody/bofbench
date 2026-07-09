#include "beacon.h"

void go(char *args, int len) {
    datap parser;
    char *message;
    int message_len = 0;
    int count = 0;

    BeaconDataParse(&parser, args, len);
    message = BeaconDataExtract(&parser, &message_len);
    count = BeaconDataInt(&parser);
    BeaconPrintf(CALLBACK_OUTPUT, "arg_echo: %.*s %d", message_len, message, count);
}
