#include <stdio.h>
#include <string.h>
#include "../src/P434/P434_api.h"
#include "../src/P434/P434_internal.h"

static void printhex(const char* title, const unsigned char* seq, const size_t len) {
    int i = 0;

    printf("%s: ", title);
    for (i = 0; i < len; ++i) {
        printf("%02x", seq[i]);
    }
    printf("\n");
}

int main(void) {
    unsigned char sk[SIDH_SECRETKEYBYTES_A /* 27 */], pk[SIDH_PUBLICKEYBYTES /* 330 */];
    unsigned char guesses[128 /* CHANGE ME, PLACEHOLDER!! */];

    int rc = 0;
    int i = 0;

    /* Begin SIKE key exchange */

    /* 1. Alice */
    for (i = 0; i < SIDH_SECRETKEYBYTES_A; ++i) {
        sk[i] = (i % 0xFF);
    }

    printf("================ ALICE PK ================\n");
    custom_EphemeralKeyGeneration_A_SIDHp434(sk);
    custom_compute_guesses(guesses);
    rc = EphemeralKeyGeneration_A_SIDHp434(sk, pk);

    printf("pk_A:\n");
    printhex("\tphiP", pk + 0*FP2_ENCODED_BYTES, FP2_ENCODED_BYTES);
    printhex("\tphiQ", pk + 1*FP2_ENCODED_BYTES, FP2_ENCODED_BYTES);
    printhex("\tphiR", pk + 2*FP2_ENCODED_BYTES, FP2_ENCODED_BYTES);

    return rc;
}
