#include "beacon.h"

typedef int (*math_fn)(int);

static int add_seven(int value) {
    return value + 7;
}

static math_fn selected = add_seven;
static const char fixture_name[] = "callback_ptr";

void go(char *args, int len) {
    (void)args;
    BeaconPrintf(CALLBACK_OUTPUT, "%s: %d", fixture_name, selected(len));
}
