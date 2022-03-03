/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "api.h"
#include "P434_internal.h"

/* Radixes in 8 bits */
#define UINT8_RADIX 8
#define UINT8_LOG2RADIX 3

/* SIKEp434 constants */
#define SIKE_BOBSK3_P434_BYTES SECRETKEY_B_BYTES /* ((218 - 1 + 7) / 8) */
#define SIKE_ALICEPK_P434_BYTES 346 /* 2*3*434 bits (R0->x[0], R0->x[1], R->x[0], R->x[1], R2->x[0], R2->x[1]) + 16 bytes (MSG) */
#define SIKE_MP_ADDFAST_BYTES 112 /* 2*56 bytes */
#define INIT_NBITS OBOB_BITS - 1 /* Actually 217 since last bit is zero */

/* Experimental durations, roughly according to (Y-4.08)/0.95 for Y microseconds */
#define SLEEP_DURATION_10US 6
#define SLEEP_DURATION_100US 100
#define SLEEP_DURATION_200US 207
#define SLEEP_DURATION_1MS 1050
#define SLEEP_DURATION_10MS 10543
#define SLEEP_DURATION_100MS 105472
#define SLEEP_DURATION_500MS 527368
#define SLEEP_DURATION_1S 1054744

/* Sleep after each loop iteration in LADDER3PT */
#define SLEEP_LOOP SLEEP_DURATION_1S
/* Sleep duration */
#define SLEEP_MPADDFAST SLEEP_DURATION_1MS

/* Enables sleep (remove macro to disable) */
#define SLEEP_ENABLED

/* Definitions for skipping (resp. taking) first mp_addfast triggers of fp2mul434_mont */
#define TRIGGER_SKIPPED 0
#define TRIGGER_TAKEN 1

/* Number of bits used in LADDER3PT */
static uint8_t nbits = INIT_NBITS;

/* Z = 0x0000ECEEA7BD2EDAE93254545F77410CD801A4FB559FACD4B90FF404FC00000000000000000000000000000000000000000000000000742C */
const digit_t custom_Montgomery_one[NWORDS_FIELD] = {
   0x0000742C, 0x00000000,
   0x00000000, 0x00000000,
   0x00000000, 0x00000000,
   0xFC000000, 0xB90FF404,
   0x559FACD4, 0xD801A4FB, 
   0x5F77410C, 0xE9325454,
   0xA7BD2EDA, 0x0000ECEE
};

/* Z = 0x1 */
const digit_t one[NWORDS_FIELD] = {
    0x00000001, 0x00000000,
    0x00000000, 0x00000000,
    0x00000000, 0x00000000,
    0x00000000, 0x00000000,
    0x00000000, 0x00000000,
    0x00000000, 0x00000000,
    0x00000000, 0x00000000
};

/* Bob's private key involved in LADDER3PT */
uint8_t sk[SIKE_BOBSK3_P434_BYTES] = { 0x00 };

static inline void sleep(volatile uint32_t duration)
{ // Experimental delay function of 1.36*duration + 4.46 microseconds
    while (duration-- != 0);
}

void __attribute__ ((noinline, naked))  custom_mp_addfast(const digit_t* a, const digit_t* b, digit_t* c)
{ // Multiprecision addition, c = a+b.
    /*
     * Add 440-bit values in chunks of 32 bits (and propagate carry).
     *
     * Pattern (repeated 4x):
     *     1) load in r2-r5 the next four values of "a" (hence, 128 bits)
     *     2) load in r6-r9 the next four values of "b" (hence, 128 bits)
     *     3) add (with carry) resp. r2-r5 with r6-r9
     *     4) stores results so far in "c"
     *
     */
    asm(
            /* start */
            "push  {r4-r9,lr}           \n\t"
            "mov r14, r2                \n\t" // (r2 = c) r14 <- c (pointer)

            /* pattern #0 */
            "ldmia r0!, {r2-r5}             \n\t" // (r0 = a) r2, r3, r4, r5 <- a[0:4]
            "ldmia r1!, {r6-r9}             \n\t" // (r1 = b) r6, r7, r8, r9 <- b[0:4] 
            // (a + b): {r2-r5} + {r6-r9}, register by register (with carry)
            "adds r2, r2, r6                \n\t"
            "adcs r3, r3, r7                \n\t"
            "adcs r4, r4, r8                \n\t"
            "adcs r5, r5, r9                \n\t"
            // stores results so far in (memory pointed by) r14 (i.e., c)
            "stmia r14!, {r2-r5}            \n\t"

            /* pattern #1 */
            "ldmia r0!, {r2-r5}             \n\t"
            "ldmia r1!, {r6-r9}             \n\t"

            "adcs r2, r2, r6                \n\t"
            "adcs r3, r3, r7                \n\t"
            "adcs r4, r4, r8                \n\t"
            "adcs r5, r5, r9                \n\t"

            "stmia r14!, {r2-r5}            \n\t"

            /* pattern #2 */
            "ldmia r0!, {r2-r5}             \n\t"
            "ldmia r1!, {r6-r9}             \n\t"

            "adcs r2, r2, r6                \n\t"
            "adcs r3, r3, r7                \n\t"
            "adcs r4, r4, r8                \n\t"
            "adcs r5, r5, r9                \n\t"

            "stmia r14!, {r2-r5}            \n\t"

            /* pattern #3 */
            "ldmia r0!, {r2-r3}             \n\t"
            "ldmia r1!, {r6-r7}             \n\t"

            "adcs r2, r2, r6                \n\t"
            "adcs r3, r3, r7                \n\t"

            "stmia r14!, {r2-r3}            \n\t"

            /* end */
            "pop  {r4-r9,pc}                \n\t"
    :
    :
    :
    );

}

static void fp2_decode(const unsigned char *enc, f2elm_t x)
{ // Parse byte sequence back into GF(p^2) element, and conversion to Montgomery representation
    unsigned int i;

    for (i = 0; i < 2*(MAXBITS_FIELD / 8); i++) ((unsigned char *)x)[i] = 0;
    for (i = 0; i < FP2_ENCODED_BYTES / 2; i++) {
        ((unsigned char*)x)[i] = enc[i];
        ((unsigned char*)x)[i + MAXBITS_FIELD / 8] = enc[i + FP2_ENCODED_BYTES / 2];
    }
    to_fp2mont(x, x);
}


static void swap_points(point_proj_t P, point_proj_t Q, const digit_t option)
{ // Swap points.
  // If option = 0 then P <- P and Q <- Q, else if option = 0xFF...FF then P <- Q and Q <- P
    digit_t temp;
    unsigned int i;

    for (i = 0; i < NWORDS_FIELD; i++) {
        temp = option & (P->X[0][i] ^ Q->X[0][i]);
        P->X[0][i] = temp ^ P->X[0][i];
        Q->X[0][i] = temp ^ Q->X[0][i];
        temp = option & (P->Z[0][i] ^ Q->Z[0][i]);
        P->Z[0][i] = temp ^ P->Z[0][i];
        Q->Z[0][i] = temp ^ Q->Z[0][i];
        temp = option & (P->X[1][i] ^ Q->X[1][i]);
        P->X[1][i] = temp ^ P->X[1][i];
        Q->X[1][i] = temp ^ Q->X[1][i];
        temp = option & (P->Z[1][i] ^ Q->Z[1][i]);
        P->Z[1][i] = temp ^ P->Z[1][i];
        Q->Z[1][i] = temp ^ Q->Z[1][i];
    }
}

void custom_fp2mul434_mont(const f2elm_t a, const f2elm_t b, f2elm_t c, int first_trig)
{ // GF(p^2) multiplication using Montgomery arithmetic, c = a*b in GF(p^2).
  // Inputs: a = a0+a1*i and b = b0+b1*i, where a0, a1, b0, b1 are in [0, 2*p-1]
  // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1]
    felm_t t1, t2;
    dfelm_t tt2;

    if (first_trig == TRIGGER_SKIPPED)
    {
        custom_mp_addfast(a[0], a[1], t1);                  // t1 = a0+a1
    } else {
#ifdef SLEEP_ENABLED
        sleep(SLEEP_MPADDFAST);
#endif /* SLEEP_ENABLED */
        trigger_high();
        custom_mp_addfast(a[0], a[1], t1);                  // t1 = a0+a1
        trigger_low();
#ifdef SLEEP_ENABLED
        sleep(SLEEP_MPADDFAST);
#endif /* SLEEP_ENABLED */
    }
#ifdef SLEEP_ENABLED
    sleep(SLEEP_MPADDFAST);
#endif /* SLEEP_ENABLED */
    trigger_high();
    custom_mp_addfast(b[0], b[1], t2);                      // t2 = b0+b1
    trigger_low();
#ifdef SLEEP_ENABLED
    sleep(SLEEP_MPADDFAST);
#endif /* SLEEP_ENABLED */

    fpmul434_mont(a[0], b[0], c[0]);
    fpmul434_mont(a[1], b[1], tt2);
    fpmul434_mont(t1, t2, c[1]);

    fpsub434(c[1],c[0],c[1]);
    fpsub434(c[1],tt2,c[1]);

    fpsub434(c[0],tt2,c[0]);
}

void custom_fp2sqr434_mont(const f2elm_t a, f2elm_t c)
{ // GF(p^2) squaring using Montgomery arithmetic, c = a^2 in GF(p^2).
  // Inputs: a = a0+a1*i, where a0, a1 are in [0, 2*p-1]
  // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1]
    felm_t t1, t2, t3;

#ifdef SLEEP_ENABLED
    sleep(SLEEP_MPADDFAST);
#endif /* SLEEP_ENABLED */
    trigger_high();
    custom_mp_addfast(a[0], a[1], t1);                  // t1 = a0+a1
    trigger_low();
#ifdef SLEEP_ENABLED
    sleep(SLEEP_MPADDFAST);
#endif /* SLEEP_ENABLED */
    fpsub434(a[0], a[1], t2);                           // t2 = a0-a1
#ifdef SLEEP_ENABLED
    sleep(SLEEP_MPADDFAST);
#endif /* SLEEP_ENABLED */
    trigger_high();
    custom_mp_addfast(a[0], a[0], t3);                  // t3 = 2a0
    trigger_low();
#ifdef SLEEP_ENABLED
    sleep(SLEEP_MPADDFAST);
#endif /* SLEEP_ENABLED */

    fpmul434_mont(t1, t2, c[0]);                        // c0 = (a0+a1)(a0-a1)
    fpmul434_mont(t3, a[1], c[1]);                      // c1 = 2a0*a1
}

void custom_xDBLADD(point_proj_t P, point_proj_t Q, const f2elm_t xPQ, const f2elm_t A24)
{ // Simultaneous doubling and differential addition.
  // Input: projective Montgomery points P=(XP:ZP) and Q=(XQ:ZQ) such that xP=XP/ZP and xQ=XQ/ZQ, affine difference xPQ=x(P-Q) and Montgomery curve constant A24=(A+2)/4.
  // Output: projective Montgomery points P <- 2*P = (X2P:Z2P) such that x(2P)=X2P/Z2P, and Q <- P+Q = (XQP:ZQP) such that = x(Q+P)=XQP/ZQP.
    f2elm_t t0, t1, t2;

    fp2add434(P->X, P->Z, t0);                             //  1. t0 = XP+ZP
    fp2sub434(P->X, P->Z, t1);                             //  2. t1 = XP-ZP
    fp2sqr434_mont(t0, P->X);                              //  3. XP = (XP+ZP)^2
    fp2sub434(Q->X, Q->Z, t2); fp2correction434(t2);       //  4. t2 = XQ-ZQ
    fp2add434(Q->X, Q->Z, Q->X);                           //  5. XQ = XQ+ZQ
    custom_fp2mul434_mont(t0, t2, t0, TRIGGER_SKIPPED);    //  6. t0 = (XP+ZP)*(XQ-ZQ)    (#0)
    fp2sqr434_mont(t1, P->Z);                              //  7. ZP = (XP-ZP)^2
    custom_fp2mul434_mont(t1, Q->X, t1, TRIGGER_SKIPPED);  //  8. t1 = (XP-ZP)*(XQ+ZQ)    (#1)
    fp2sub434(P->X, P->Z, t2);                             //  9. t2 = (XP+ZP)^2-(XP-ZP)^2
    fp2mul434_mont(P->X, P->Z, P->X);                      // 10. XP = (XP+ZP)^2*(XP-ZP)^2
    fp2mul434_mont(t2, A24, Q->X);                         // 11. XQ = A24*[(XP+ZP)^2-(XP-ZP)^2]
    fp2sub434(t0, t1, Q->Z);                               // 12. ZQ = (XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)
    fp2add434(Q->X, P->Z, P->Z);                           // 13. ZP = A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2
    fp2add434(t0, t1, Q->X);                               // 14. XQ = (XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)
    fp2mul434_mont(P->Z, t2, P->Z);                        // 15. ZP = [A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2]*[(XP+ZP)^2-(XP-ZP)^2]
    custom_fp2sqr434_mont(Q->Z, Q->Z);                     // 16. ZQ = [(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2    (#2, #3)
    custom_fp2sqr434_mont(Q->X, Q->X);                     // 17. XQ = [(XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)]^2    (#4, #5)
    custom_fp2mul434_mont(Q->Z, xPQ, Q->Z, TRIGGER_TAKEN); // 18. ZQ = xPQ*[(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2    (#6, #7)
}

uint8_t get_nbits(uint8_t* n)
{ // Sets number of iterations in LADDER3PT
    nbits =  n[0];
    return 0x00;
}

uint8_t get_key(uint8_t* k)
{ // Sets private key involved in LADDER3PT
    for (int i=0; i < SIKE_BOBSK3_P434_BYTES; ++i)
    {
        sk[i] = k[i];
    }
    return 0x00;
}

uint8_t do_mp_addfast(uint8_t* pt)
{ // Performs a single mp_addfast.
    felm_t tmp;

    trigger_high();
    custom_mp_addfast((digit_t*) (pt), (digit_t*) (pt + SIKE_MP_ADDFAST_BYTES/2), tmp);
    trigger_low();

    return 0x00;
}

uint8_t get_pt(uint8_t* pt)
{ // Performs LADDER3PT with following modifications:
  //   1. The trigger GPIO is toggled upon informational mp_addfast.
  //   2. Delays were added
  //      (a) at the end of each loop iteration, and
  //      (b) between triggered mp_addfast
    int i = 0, bit = 0, swap = 0, prevbit = 0;
    point_proj_t R = {0};
    point_proj_t R2 = {0};
    point_proj_t R0 = {0};
    digit_t mask;
    f2elm_t A = {0};
    f2elm_t A24 = {0};

    // Initialize images of Alice's basis
    fp2_decode(pt, R->X); /* 0:110 */
    fp2_decode(pt + FP2_ENCODED_BYTES, R0->X); /* 110:220 */
    fp2_decode(pt + 2*FP2_ENCODED_BYTES, R2->X); /* 220:330 */

    // Initialize constants: A24plus = A+2C, A24minus = A-2C, where C=1
    get_A(R->X, R0->X, R2->X, A);

    fpcopy434((digit_t*)&custom_Montgomery_one, A24[0]);
    fp2add434(A24, A24, A24);
    fp2add434(A, A24, A24);
    fp2div2_434(A24, A24);
    fp2div2_434(A24, A24); 

    fpcopy434((digit_t*)&custom_Montgomery_one, (digit_t*)R2->Z);
    fpcopy434((digit_t*)&custom_Montgomery_one, (digit_t*)R->Z);
    fpcopy434((digit_t*)&custom_Montgomery_one, (digit_t*)R0->Z);
    fpzero434((digit_t*)(R->Z)[1]);
    fpzero434((digit_t*)(R0->Z)[1]);
    fpzero434((digit_t*)(R2->Z)[1]);

    for (i = 0; i < nbits; i++) {
        bit = (sk[i >> UINT8_LOG2RADIX] >> (i & (UINT8_RADIX - 1))) & 1;
        swap = bit ^ prevbit;
        prevbit = bit;
        mask = 0 - (digit_t)swap;

        swap_points(R, R2, mask);
        custom_xDBLADD(R0, R2, R->X, A24);
        custom_fp2mul434_mont(R2->X, R->Z, R2->X, TRIGGER_TAKEN); // (#8, #9)
#ifdef SLEEP_ENABLED
        sleep(SLEEP_LOOP);
#endif /* SLEEP_ENABLED */
    }

    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    /* Prints "SIKE" */
    putch('S');
    putch('I');
    putch('K');
    putch('E');

    simpleserial_init();

    /* Functions programmed to attack SIKEp434 */
    simpleserial_addcmd('k', SIKE_BOBSK3_P434_BYTES, get_key);
    simpleserial_addcmd('p', SIKE_ALICEPK_P434_BYTES, get_pt);
    /* Additional (optional) functions for testing purpose */
    simpleserial_addcmd('q', SIKE_MP_ADDFAST_BYTES, do_mp_addfast);
    simpleserial_addcmd('n', 1, get_nbits);

    while(1)
        simpleserial_get();
}
