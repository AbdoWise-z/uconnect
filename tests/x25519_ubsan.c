/* Compile with C11 + UBSan: regression for issue #59. */
#include "x25519.h"
int main(void) {
    unsigned char scalar[32] = {1}, output[32];
    uconnect_x25519_base(output, scalar);
    return 0;
}
