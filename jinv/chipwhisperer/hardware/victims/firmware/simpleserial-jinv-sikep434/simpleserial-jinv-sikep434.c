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

/* ChaCha's seed length */
#define SEED_BYTES 16

/* ========================================================================== */
/*                                  GLOBALS                                   */
/* ========================================================================== */

const digit_t custom_Montgomery_one[NWORDS_FIELD] = {
   0x0000742C, 0x00000000,
   0x00000000, 0x00000000,
   0x00000000, 0x00000000,
   0xFC000000, 0xB90FF404,
   0x559FACD4, 0xD801A4FB, 
   0x5F77410C, 0xE9325454,
   0xA7BD2EDA, 0x0000ECEE
};

const unsigned int custom_strat_Bob[MAX_Bob-1] = {
66, 33, 17, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 1,
2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 32, 16, 8, 4, 3, 1, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2,
1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1 };

/* ========================================================================== */
/*                                   CHACHA                                   */
/* ========================================================================== */

/*
chacha-ref.c version 20080118
D. J. Bernstein
Public domain.
*/

#define U8V(v) ((uint8_t) ((v) & 0XFF))
#define U32V(v) ((uint32_t) ((v) & 0xFFFFFFFF))

#define U8TO32_LITTLE(p) \
  (((uint32_t)((p)[0])      ) | \
   ((uint32_t)((p)[1]) <<  8) | \
   ((uint32_t)((p)[2]) << 16) | \
   ((uint32_t)((p)[3]) << 24))

#define ROTL32(v, n) \
    (U32V((v) << (n)) | ((v) >> (32 - (n))))

/* 
 * ECRYPT_ctx is the structure containing the representation of the
 * internal state of your cipher. 
 */

typedef struct
{
  uint32_t input[16]; /* could be compressed */
} ECRYPT_ctx;

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
    x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
    x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
    x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
    x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

static void salsa20_wordtobyte(uint8_t output[64], const uint32_t input[16])
{
    uint32_t x[16];
    int i;

    for (i = 0;i < 16;++i) x[i] = input[i];
    for (i = 8;i > 0;i -= 2) {
        QUARTERROUND( 0, 4, 8,12)
        QUARTERROUND( 1, 5, 9,13)
        QUARTERROUND( 2, 6,10,14)
        QUARTERROUND( 3, 7,11,15)
        QUARTERROUND( 0, 5,10,15)
        QUARTERROUND( 1, 6,11,12)
        QUARTERROUND( 2, 7, 8,13)
        QUARTERROUND( 3, 4, 9,14)
    }
    for (i = 0;i < 16;++i) x[i] = PLUS(x[i],input[i]);
    /*
     * there is absolutely no way of making the following line compile,
     * grow the fuck up and write semantically correct code
    for (i = 0;i < 16;++i) U32TO8_LITTLE(output + 4 * i,x[i]);
     */
    for (i = 0;i < 16;++i)
    {
        output[4*i + 0] = U8V(x[i] >> 0);
        output[4*i + 1] = U8V(x[i] >> 8);
        output[4*i + 2] = U8V(x[i] >> 16);
        output[4*i + 3] = U8V(x[i] >> 24);
    }
}

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void ECRYPT_keysetup(ECRYPT_ctx *x, const uint8_t *k, uint32_t kbits, uint32_t ivbits)
{
    const char *constants;

    x->input[4] = U8TO32_LITTLE(k + 0);
    x->input[5] = U8TO32_LITTLE(k + 4);
    x->input[6] = U8TO32_LITTLE(k + 8);
    x->input[7] = U8TO32_LITTLE(k + 12);
    if (kbits == 256) { /* recommended */
        k += 16;
        constants = sigma;
    } else { /* kbits == 128 */
        constants = tau;
    }
    x->input[8] = U8TO32_LITTLE(k + 0);
    x->input[9] = U8TO32_LITTLE(k + 4);
    x->input[10] = U8TO32_LITTLE(k + 8);
    x->input[11] = U8TO32_LITTLE(k + 12);
    x->input[0] = U8TO32_LITTLE(constants + 0);
    x->input[1] = U8TO32_LITTLE(constants + 4);
    x->input[2] = U8TO32_LITTLE(constants + 8);
    x->input[3] = U8TO32_LITTLE(constants + 12);
}

void ECRYPT_ivsetup(ECRYPT_ctx *x, const uint8_t *iv)
{
    x->input[12] = 0;
    x->input[13] = 0;
    x->input[14] = U8TO32_LITTLE(iv + 0);
    x->input[15] = U8TO32_LITTLE(iv + 4);
}

void ECRYPT_encrypt_bytes(ECRYPT_ctx *x, const uint8_t *m, uint8_t *c, uint32_t bytes)
{
    uint8_t output[64] = { 0x00 };
    int i = 0;

    if (!bytes) return;
    for (;;) {
        salsa20_wordtobyte(output,x->input);
        x->input[12] = PLUSONE(x->input[12]);
        if (!x->input[12]) {
            x->input[13] = PLUSONE(x->input[13]);
            /* stopping at 2^70 bytes per nonce is user's responsibility */
        }
        if (bytes <= 64) {
            for (i = 0;i < bytes;++i) c[i] = m[i] ^ output[i];
            return;
        }
        for (i = 0;i < 64;++i) c[i] = m[i] ^ output[i];
        bytes -= 64;
        c += 64;
        m += 64;
    }
}

void ECRYPT_keystream_bytes(ECRYPT_ctx *x, uint8_t *stream, uint32_t bytes)
{
    uint32_t i;
    for (i = 0; i < bytes; ++i) stream[i] = 0;
    ECRYPT_encrypt_bytes(x, stream, stream, bytes);
}


/* ========================================================================== */
/*                              SIKE PARAMETERS                               */
/* ========================================================================== */

/* ChaCha context */
ECRYPT_ctx chacha_ctx;

/* Bob's private key involved in LADDER3PT */
uint8_t sk[SECRETKEY_B_BYTES] = { 0x00 };


/* ========================================================================== */
/*                             INTERNAL FUNCTIONS                             */
/* ========================================================================== */

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

static void custom_prng_nextbytes(uint8_t* output, const uint32_t bytes)
{ // Draw next random bytes
    ECRYPT_keystream_bytes(&chacha_ctx, output, bytes);
}

static void randomize_coordinates(point_proj_t R, point_proj_t R0, point_proj_t R2)
{ // Implement coordinate randomization
    f2elm_t rand_R  = {0}, rand_R0 = {0}, rand_R2 = {0};
    uint8_t randbytes[3*FP2_ENCODED_BYTES] = {0}; /* 6*110 = 660 */

    /* Draw random bytes */
    custom_prng_nextbytes(randbytes, 3*FP2_ENCODED_BYTES);

    /* Decode random bytes in element of GF(p^2) */
    fp2_decode(randbytes + 0*FP2_ENCODED_BYTES, rand_R);  /*   0:110 */
    fp2_decode(randbytes + 1*FP2_ENCODED_BYTES, rand_R0); /* 110:220 */
    fp2_decode(randbytes + 2*FP2_ENCODED_BYTES, rand_R2); /* 220:330 */

    /* Mask coordinates with randomly drawn elements */
    fp2mul434_mont(R->X, rand_R, R->X);
    fp2mul434_mont(R->Z, rand_R, R->Z);
    fp2mul434_mont(R0->X, rand_R0, R0->X);
    fp2mul434_mont(R0->Z, rand_R0, R0->Z);
    fp2mul434_mont(R2->X, rand_R2, R2->X);
    fp2mul434_mont(R2->Z, rand_R2, R2->Z);
}

static int zerocheck(f2elm_t x)
{
    size_t i = 0;
    int cmp = 0;

    for (i = 0; i < 2*NWORDS_FIELD; ++i) {
        cmp |= (0 != ((digit_t*)x)[i]);
    }

    return (!cmp);
}

static void custom_fpinv_chain_mont(felm_t a)
{// Field inversion using Montgomery arithmetic, a = a^-1*R mod p434
    felm_t t[20], tt;
    unsigned int i, j;

    // Precomputed table
    trigger_high();

    fpsqr434_mont(a, tt);
    fpmul434_mont(tt, tt, t[0]);
    fpmul434_mont(t[0], tt, t[0]);
    fpmul434_mont(a, t[0], t[0]);
    fpmul434_mont(t[0], tt, t[1]);
    fpmul434_mont(t[1], tt, t[1]);
    fpmul434_mont(t[1], tt, t[2]);
    fpmul434_mont(t[2], tt, t[3]);
    fpmul434_mont(t[3], tt, t[4]);
    fpmul434_mont(t[4], tt, t[4]);
    fpmul434_mont(t[4], tt, t[4]);
    for (i = 4; i <= 6; i++) fpmul434_mont(t[i], tt, t[i+1]);
    fpmul434_mont(t[7], tt, t[7]);
    for (i = 7; i <= 8; i++) fpmul434_mont(t[i], tt, t[i+1]);
    fpmul434_mont(t[9], tt, t[9]);
    fpmul434_mont(t[9], tt, t[10]);
    fpmul434_mont(t[10], tt, t[10]);
    for (i = 10; i <= 12; i++) fpmul434_mont(t[i], tt, t[i+1]);
    fpmul434_mont(t[13], tt, t[13]);
    for (i = 13; i <= 17; i++) fpmul434_mont(t[i], tt, t[i+1]);
    fpmul434_mont(t[18], tt, t[18]);
    fpmul434_mont(t[18], tt, t[18]);
    fpmul434_mont(t[18], tt, t[19]);


    fpcopy434(a, tt);
    for(i = 0; i < 7; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[2], tt, tt);
    for(i = 0; i < 10; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[8], tt, tt);
    for(i = 0; i < 8; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[10], tt, tt);
    for(i = 0; i < 8; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[5], tt, tt);
    for(i = 0; i < 4; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[0], tt, tt);
    for(i = 0; i < 6; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[2], tt, tt);
    for(i = 0; i < 9; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[9], tt, tt);
    for(i = 0; i < 7; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[15], tt, tt);
    for(i = 0; i < 4; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[3], tt, tt);
    for(i = 0; i < 9; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[13], tt, tt);
    for(i = 0; i < 5; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[7], tt, tt);
    for(i = 0; i < 5; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[2], tt, tt);
    for(i = 0; i < 9; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[0], tt, tt);
    for(i = 0; i < 9; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[11], tt, tt);
    for(i = 0; i < 12; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[12], tt, tt);
    for(i = 0; i < 8; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[18], tt, tt);
    for(i = 0; i < 3; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[0], tt, tt);
    for(i = 0; i < 8; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[6], tt, tt);
    for(i = 0; i < 4; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[0], tt, tt);
    for(i = 0; i < 7; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[3], tt, tt);
    for(i = 0; i < 11; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[14], tt, tt);
    for(i = 0; i < 5; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[1], tt, tt);
    for(i = 0; i < 9; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[12], tt, tt);
    for(i = 0; i < 5; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[4], tt, tt);
    for(i = 0; i < 9; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[19], tt, tt);
    for(i = 0; i < 6; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[17], tt, tt);
    for(i = 0; i < 10; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[5], tt, tt);
    for(i = 0; i < 7; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[15], tt, tt);
    for(i = 0; i < 6; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[16], tt, tt);
    for(i = 0; i < 6; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[14], tt, tt);
    for(i = 0; i < 7; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[19], tt, tt);
    for(j = 0; j < 34; j++){
        for(i = 0; i < 6; i++)fpsqr434_mont(tt, tt);
        fpmul434_mont(t[19], tt, tt);
    }
    for(i = 0; i < 6; i++)fpsqr434_mont(tt, tt);
    fpmul434_mont(t[18], tt, a);

    trigger_low();
return;
}

static void custom_fp2inv_mont(f2elm_t a)
{// GF(p^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2).

    f2elm_t t1;

    fpsqr434_mont(a[0], t1[0]);                         // t10 = a0^2
    fpsqr434_mont(a[1], t1[1]);                         // t11 = a1^2
    fpadd434(t1[0], t1[1], t1[0]);                      // t10 = a0^2+a1^2
    custom_fpinv_chain_mont(t1[0]);                     // t10 = (a0^2+a1^2)^-1
    fpneg434(a[1]);                                     // a = a0-i*a1
    fpmul434_mont(a[0], t1[0], a[0]);
    fpmul434_mont(a[1], t1[0], a[1]);                   // a = (a0-i*a1)*(a0^2+a1^2)^-1

}

static void custom_j_inv(const f2elm_t A, const f2elm_t C, f2elm_t jinv)
{ // Computes the j-invariant of a Montgomery curve with projective constant.
  // Input: A,C in GF(p^2).
  // Output: j=256*(A^2-3*C^2)^3/(C^4*(A^2-4*C^2)), which is the j-invariant of the Montgomery curve B*y^2=x^3+(A/C)*x^2+x or (equivalently) j-invariant of B'*y^2=C*x^3+A*x^2+C*x.
    f2elm_t t0, t1;

    fp2sqr434_mont(A, jinv);                           // jinv = A^2
    fp2sqr434_mont(C, t1);                             // t1 = C^2
    fp2add434(t1, t1, t0);                             // t0 = t1+t1
    fp2sub434(jinv, t0, t0);                           // t0 = jinv-t0
    fp2sub434(t0, t1, t0);                             // t0 = t0-t1
    fp2sub434(t0, t1, jinv);                           // jinv = t0-t1
    fp2sqr434_mont(t1, t1);                            // t1 = t1^2
    fp2mul434_mont(jinv, t1, jinv);                    // jinv = jinv*t1
    fp2add434(t0, t0, t0);                             // t0 = t0+t0
    fp2add434(t0, t0, t0);                             // t0 = t0+t0
    fp2sqr434_mont(t0, t1);                            // t1 = t0^2
    fp2mul434_mont(t0, t1, t0);                        // t0 = t0*t1
    fp2add434(t0, t0, t0);                             // t0 = t0+t0
    fp2add434(t0, t0, t0);                             // t0 = t0+t0
    if (zerocheck(t0)) {
        putch(0x00);
    } else {
        putch(0xFF);
    }
    custom_fp2inv_mont(jinv);                          // jinv = 1/jinv
    fp2mul434_mont(jinv, t0, jinv);                    // jinv = t0*jinv
}

static void custom_swap_points(point_proj_t P, point_proj_t Q, const digit_t option)
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

static void custom_LADDER3PT(const f2elm_t xP, const f2elm_t xQ, const f2elm_t xPQ, const digit_t* m, const unsigned int AliceOrBob, point_proj_t R, const f2elm_t A)
{
    point_proj_t R0 = {0}, R2 = {0};
    f2elm_t A24 = {0};
    digit_t mask;
    int i, nbits, bit, swap, prevbit = 0;
    
    if (AliceOrBob == ALICE) {
        nbits = OALICE_BITS;
    } else {
        nbits = OBOB_BITS - 1;
    }

    // Initializing constant
    fpcopy434((digit_t*)&custom_Montgomery_one, A24[0]);
    fp2add434(A24, A24, A24);
    fp2add434(A, A24, A24);
    fp2div2_434(A24, A24);
    fp2div2_434(A24, A24);  // A24 = (A+2)/4
    
    // Initializing points
    fp2copy434(xQ, R0->X);
    fpcopy434((digit_t*)&custom_Montgomery_one, (digit_t*)R0->Z);
    fp2copy434(xPQ, R2->X);
    fpcopy434((digit_t*)&custom_Montgomery_one, (digit_t*)R2->Z);
    fp2copy434(xP, R->X);
    fpcopy434((digit_t*)&custom_Montgomery_one, (digit_t*)R->Z);
    fpzero434((digit_t*)(R->Z)[1]);
    // Main loop
    for (i = 0; i < nbits; i++) {
        bit = (m[i >> LOG2RADIX] >> (i & (RADIX-1))) & 1;
        swap = bit ^ prevbit;
        prevbit = bit;
        mask = 0 - (digit_t)swap;

        randomize_coordinates(R, R0, R2); /* modif */

        custom_swap_points(R, R2, mask);
        xDBLADD(R0, R2, R->X, A24);
        fp2mul434_mont(R2->X, R->Z, R2->X);
     
    }

    swap = 0 ^ prevbit;
    mask = 0 - (digit_t)swap;
    custom_swap_points(R, R2, mask);

}

static int custom_EphemeralSecretAgreement_B(const unsigned char* PrivateKeyB, const unsigned char* PublicKeyA)
{ // Bob's ephemeral shared secret computation
  // It computes a j-invariant which constitutes the shared secret using his secret key PrivateKeyB and Alice's public key PublicKeyA
  // Inputs: Bob's PrivateKeyB is an integer in the range [0, 2^Floor(Log(2,oB)) - 1].
  //         Alice's PublicKeyA consists of 3 elements in GF(p^2) encoded by removing leading 0 bytes.
    point_proj_t R, pts[MAX_INT_POINTS_BOB];
    f2elm_t coeff[3], PKB[3], jinv;
    f2elm_t A24plus = {0}, A24minus = {0}, A = {0};
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_BOB], npts = 0, ii = 0;

    // Initialize images of Alice's basis
    fp2_decode(PublicKeyA, PKB[0]);
    fp2_decode(PublicKeyA + FP2_ENCODED_BYTES, PKB[1]);
    fp2_decode(PublicKeyA + 2*FP2_ENCODED_BYTES, PKB[2]);

    // Initialize constants: A24plus = A+2C, A24minus = A-2C, where C=1
    get_A(PKB[0], PKB[1], PKB[2], A);
    fpadd434((digit_t*)&custom_Montgomery_one, (digit_t*)&custom_Montgomery_one, A24minus[0]);
    fp2add434(A, A24minus, A24plus);
    fp2sub434(A, A24minus, A24minus);

    // Retrieve kernel point
    custom_LADDER3PT(PKB[0], PKB[1], PKB[2], (digit_t*)PrivateKeyB, BOB, R, A); /* modif */

    // Traverse tree
    index = 0;
    for (row = 1; row < MAX_Bob; row++) {
        while (index < MAX_Bob-row) {
            fp2copy434(R->X, pts[npts]->X);
            fp2copy434(R->Z, pts[npts]->Z);
            pts_index[npts++] = index;
            m = custom_strat_Bob[ii++];
            xTPLe(R, R, A24minus, A24plus, (int)m);
            index += m;
        }
        get_3_isog(R, A24minus, A24plus, coeff);

        for (i = 0; i < npts; i++) {
            eval_3_isog(pts[i], coeff);
        }

        fp2copy434(pts[npts-1]->X, R->X);
        fp2copy434(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_3_isog(R, A24minus, A24plus, coeff);
    fp2add434(A24plus, A24minus, A);
    fp2add434(A, A, A);
    fp2sub434(A24plus, A24minus, A24plus);
    custom_j_inv(A, A24plus, jinv); /* modif */

    return 0;
}


/* ========================================================================== */
/*                             EXTERNAL FUNCTIONS                             */
/* ========================================================================== */

uint8_t get_seed(uint8_t* s)
{ // Set ChaCha seed (and IV to zero)
    int i = 0;
    uint8_t iv[8] = { 0x00 };

    for (i = 0; i < 8; ++i) {
        iv[i] = 0x00;
    }

    ECRYPT_keysetup(&chacha_ctx, s, 128, 0);
    ECRYPT_ivsetup(&chacha_ctx, iv);

    return 0x00;
}


uint8_t get_key(uint8_t* k)
{ // Set private key involved in LADDER3PT
    for (int i=0; i < SECRETKEY_B_BYTES; ++i)
    {
        sk[i] = k[i];
    }
    return 0x00;
}

uint8_t get_pt(uint8_t* inp)
{
    uint8_t PublicKeyA[CRYPTO_PUBLICKEYBYTES] = { 0x00 }; /* 330 bytes = 3x110 (R0->X, R->X, R2->X) */
    size_t i = 0;

    for (i = 0; i < CRYPTO_PUBLICKEYBYTES; ++i)
    {
        PublicKeyA[i] = inp[i];
    }

    custom_EphemeralSecretAgreement_B(sk, PublicKeyA);

    return 0x00;
}

uint8_t compute_j(uint8_t* pt)
{
    f2elm_t A = {0}, C = {0}, jinv = {0};

    fp2_decode(pt, A);
    fp2_decode(pt + FP2_ENCODED_BYTES, C);

    custom_j_inv(A, C, jinv);

    return 0x00;
}

uint8_t test_trig(uint8_t* x)
{ // Test trigger
    trigger_high();
    while (x[0]-- != 0);
    trigger_low();

    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    /* Prints "SIKE-jinv" */
    putch('S');
    putch('I');
    putch('K');
    putch('E');
    putch('-');
    putch('j');
    putch('i');
    putch('n');
    putch('v');

    simpleserial_init();

    /* Functions programmed to attack SIKEp434 */
    simpleserial_addcmd('s', SEED_BYTES, get_seed);
    simpleserial_addcmd('k', SECRETKEY_B_BYTES, get_key);
    simpleserial_addcmd('p', CRYPTO_PUBLICKEYBYTES, get_pt);
    simpleserial_addcmd('j', 2*FP2_ENCODED_BYTES, compute_j);
    /* Additional (optional) functions for testing purpose */
    simpleserial_addcmd('t', 1, test_trig);

    while(1)
        simpleserial_get();
}
