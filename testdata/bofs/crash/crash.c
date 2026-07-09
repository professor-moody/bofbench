#ifdef _MSC_VER
__declspec(noinline)
#endif
void go(char *args, int len) {
    volatile unsigned int *invalid = (volatile unsigned int *)0;
    (void)args;
    (void)len;
    *invalid = 0x424f4642;
}
