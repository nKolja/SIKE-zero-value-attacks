/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny key encapsulation (SIKE) protocol
*********************************************************************************************/

#include <string.h>
#include "sha3/fips202.h"

//ADDED FOR TESTING PURPOSES
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <getopt.h>
#include <inttypes.h>

// Exponents of breaking points o
#if (NBITS_FIELD == 434)
    #define EXP_2           9
    #define EXP_3           3
    #define OALICE_TRITS    137
#elif (NBITS_FIELD == 503)
    #define EXP_2           7
    #define EXP_3           4
    #define OALICE_TRITS    159
#elif (NBITS_FIELD == 610)
    #define EXP_2           7
    #define EXP_3           2
    #define OALICE_TRITS    193
#elif (NBITS_FIELD == 751)
    #define EXP_2           8
    #define EXP_3           5
    #define OALICE_TRITS    239
#endif

#define MAX_SECRETKEY_BYTES (sizeof(digit_t) * NWORDS_ORDER)


int baseline_alice_keys(int argc, char* argv[])
{   // Create a pair of Alice public keys, such that:
    // When Bob uses first public key, his output j_inv will always be 0
    // When Bob uses second public key, his output j_inv will be random (and almost always non-zero)

    point_proj_t Q = {0}, P = {0}, QP = {0};
    point_full_proj_t T, S, TS;
    f2elm_t A24plus = {0}, A24minus = {0}, C24 = {0}, A={0}, A24 = {0};
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES] = {0}, rand_curve_sk[SECRETKEY_B_BYTES] = {0};
    int point_Q_exponent = (int)OALICE_BITS - ((int)EXP_2 - 1), point_P_exponent = (int)OALICE_BITS - (int)EXP_2;

    // Generate a random curve
    randombytes(ct + CRYPTO_PUBLICKEYBYTES, MSG_BYTES);
    random_mod_order_B(rand_curve_sk);
    EphemeralKeyGeneration_B(rand_curve_sk, ct);

    // Initialize basis points inside E[2^e2]
    fp2_decode(ct,                          P->X);
    fp2_decode(ct + FP2_ENCODED_BYTES,      Q->X);
    fp2_decode(ct + 2*FP2_ENCODED_BYTES,    QP->X);

    // Set z-coordinate of basis points equal to 1
    fpcopy((digit_t *)&Montgomery_one, (P->Z)[0]);      // zP  = 1           
    fpcopy((digit_t *)&Montgomery_one, (Q->Z)[0]);      // zQ  = 1           
    fpcopy((digit_t *)&Montgomery_one, (QP->Z)[0]);     // zQP = 1           

    // Initialize constants: A24plus = A+2C, A24minus = A-2C, C24 = 4C, where C=1
    get_A(P->X, Q->X, QP->X, A);
    mp_add((digit_t*)&Montgomery_one, (digit_t*)&Montgomery_one, A24minus[0], NWORDS_FIELD);
    fp2add(A, A24minus, A24plus);
    fp2sub(A, A24minus, A24minus);
    fp2sub(A24plus, A24minus, C24);
    fp2div2(A24plus, A24);  
    fp2div2(A24, A24);

    // Compute the triple of malicious public key points by using full coordinates
    complete_full_point(QP, A, T);                  // T  = Q2
    complete_full_point(P, A, S);                   // S  = P2 (or [-1]P2 but this is not important)
    DBL_e(T, A24, point_Q_exponent, T);             // T  = QQ := [2^(oA - (EXP_2 - 1)]Q2 - - - Point of order 2^(EXP_2 - 1) 
    DBL_e(S, A24, point_P_exponent, S);             // S  = -FF := [2^(oA - (EXP_2)]P2 - - - Point of order 2^(EXP_2)
    ADD(T, S, A24, TS);                             // TS = QQ + S = QQ - FF
    fp2neg(S->Y);                                   // S  = FF

    // Reduce to [X:Z] coordinates
    reduce_triple(T, S, TS, Q, P, QP);


    // PUBLIC KEY WHICH ALWAYS GIVES A RANDOM J-INVARIANT
    // At this point we have computed:
    // Q  = point of order 2^(EXP_2 - 1)
    // P  = point of order 2^(EXP_2)
    // QP = Q - P

    // Normalise the X coordinate by dividing with the Z coordinate
    inv_3_way(P->Z, Q->Z, QP->Z);
    fp2mul_mont(P->X, P->Z, P->X);
    fp2mul_mont(Q->X, Q->Z, Q->X);
    fp2mul_mont(QP->X, QP->Z, QP->X); 

    // Format public key
    fp2_encode(P->X, ct);
    fp2_encode(Q->X, ct + FP2_ENCODED_BYTES);
    fp2_encode(QP->X, ct + 2*FP2_ENCODED_BYTES);

    // Write alice_pk to memory
    write_alice_pk("public_keys/alice_baseline_1", ct);



    // PUBLIC KEY WHICH ALWAYS GIVES A [0:0] J-INVARIANT
    // Set Z-coordinate equal to one
    fpcopy((digit_t *)&Montgomery_one, (P->Z)[0]);      
    fpzero((P->Z)[1]);
    fpcopy((digit_t *)&Montgomery_one, (Q->Z)[0]);      
    fpzero((Q->Z)[1]);
    fpcopy((digit_t *)&Montgomery_one, (QP->Z)[0]);      
    fpzero((QP->Z)[1]);

    xDBL(P, P, A24plus, C24);
    xDBL(Q, Q, A24plus, C24);
    xDBL(QP, QP, A24plus, C24);

    // At this point we have computed:
    // Q  = point of order 2^(EXP_2 - 2)
    // P  = point of order 2^(EXP_2 - 1)
    // QP = Q - P

    // Normalise the X coordinate by dividing with the Z coordinate
    inv_3_way(P->Z, Q->Z, QP->Z);
    fp2mul_mont(P->X, P->Z, P->X);
    fp2mul_mont(Q->X, Q->Z, Q->X);
    fp2mul_mont(QP->X, QP->Z, QP->X); 

    // Format public key
    fp2_encode(P->X, ct);
    fp2_encode(Q->X, ct + FP2_ENCODED_BYTES);
    fp2_encode(QP->X, ct + 2*FP2_ENCODED_BYTES);

    // Write alice_pk to memory
    write_alice_pk("public_keys/alice_baseline_1", ct);



    return 0;
}

int baseline_bob_keys(int argc, char* argv[])
{   // Create a pair of Bob public keys, such that:
    // When Alice uses first public key, her output j_inv will always be 0
    // When Alice uses second public key, her output j_inv will be random (and almost always non-zero)

    point_proj_t Q = {0}, P = {0}, QP = {0};
    point_full_proj_t T, S, TS;
    f2elm_t A24plus = {0}, A24minus = {0}, C24 = {0}, A={0}, A24 = {0};
    unsigned char pk[CRYPTO_CIPHERTEXTBYTES] = {0}, rand_curve_sk[SECRETKEY_B_BYTES] = {0};
    int point_Q_exponent = (int)OBOB_EXPON - ((int)EXP_3 - 1), point_P_exponent = (int)OBOB_EXPON - (int)EXP_3;

    // Generate a random curve
    randombytes(pk + CRYPTO_PUBLICKEYBYTES, MSG_BYTES);
    random_mod_order_A(rand_curve_sk);
    EphemeralKeyGeneration_A(rand_curve_sk, pk);

    // Initialize basis points inside E[3^e3]
    fp2_decode(pk,                          P->X);
    fp2_decode(pk + FP2_ENCODED_BYTES,      Q->X);
    fp2_decode(pk + 2*FP2_ENCODED_BYTES,    QP->X);

    // Set z-coordinate of basis points equal to 1
    fpcopy((digit_t *)&Montgomery_one, (P->Z)[0]);      // zP  = 1           
    fpcopy((digit_t *)&Montgomery_one, (Q->Z)[0]);      // zQ  = 1           
    fpcopy((digit_t *)&Montgomery_one, (QP->Z)[0]);     // zQP = 1           

    // Initialize constants: A24plus = A+2C, A24minus = A-2C, C24 = 4C, where C=1
    get_A(P->X, Q->X, QP->X, A);
    mp_add((digit_t*)&Montgomery_one, (digit_t*)&Montgomery_one, A24minus[0], NWORDS_FIELD);
    fp2add(A, A24minus, A24plus);
    fp2sub(A, A24minus, A24minus);
    fp2sub(A24plus, A24minus, C24);
    fp2div2(A24plus, A24);  
    fp2div2(A24, A24);

    // Compute the triple of malicious public key points by using full coordinates
    complete_full_point(Q, A, T);                                                       //  T  = Q3
    complete_full_point(P, A, S);                                                       //  S  = P3 (or [-1]P3 but this is not important)
    SCALARMULT(T, (digit_t *)&(POWERS_OF_3[point_Q_exponent]), OBOB_BITS, A24, T);      //  T  = QQ := [3^(oB - (EXP_3 - 1))]Q3 - - - Point of order 3^(EXP_3 - 1)
    SCALARMULT(S, (digit_t *)&(POWERS_OF_3[point_P_exponent]), OBOB_BITS, A24, S);      //  S  = -FF := [3^(oB - (EXP_3))]P3 - - - - - Point of order 3^(EXP_3)
    ADD(T, S, A24, TS);                                                                 // TS  = QQ - FF
    fp2neg(S->Y);                                                                       //  S  = FF


    // Reduce to [X:Z] coordinates
    reduce_triple(T, S, TS, Q, P, QP);

    // PUBLIC KEY WHICH ALWAYS GIVES A RANDOM J-INVARIANT
    // At this point we have computed:
    // Q  = point of order 3^(EXP_3 - 1)
    // P  = point of order 3^(EXP_3)
    // QP = Q - P

    // Normalise the X coordinates by dividing with the Z coordinates
    inv_3_way(P->Z, Q->Z, QP->Z);
    fp2mul_mont(P->X, P->Z, P->X);
    fp2mul_mont(Q->X, Q->Z, Q->X);
    fp2mul_mont(QP->X, QP->Z, QP->X); 

    // Format first public key
    fp2_encode(P->X, pk);
    fp2_encode(Q->X, pk + FP2_ENCODED_BYTES);
    fp2_encode(QP->X, pk + 2*FP2_ENCODED_BYTES);

    // Write to memory
    write_alice_pk("public_keys/bob_baseline_1", pk);



    // PUBLIC KEY WHICH ALWAYS GIVES A [0:0] J-INVARIANT
    // Set Z-coordinate equal to one
    fpcopy((digit_t *)&Montgomery_one, (P->Z)[0]);      
    fpzero((P->Z)[1]);
    fpcopy((digit_t *)&Montgomery_one, (Q->Z)[0]);      
    fpzero((Q->Z)[1]);
    fpcopy((digit_t *)&Montgomery_one, (QP->Z)[0]);      
    fpzero((QP->Z)[1]);

    xTPL(P, P, A24minus, A24plus);
    xTPL(Q, Q, A24minus, A24plus);
    xTPL(QP, QP, A24minus, A24plus);

    // At this point we have computed:
    // Q  = point of order 3^(EXP_3 - 2)
    // P  = point of order 3^(EXP_3 - 1)
    // QP = Q - P

    // Normalise the X coordinate by dividing with the Z coordinate
    inv_3_way(P->Z, Q->Z, QP->Z);
    fp2mul_mont(P->X, P->Z, P->X);
    fp2mul_mont(Q->X, Q->Z, Q->X);
    fp2mul_mont(QP->X, QP->Z, QP->X); 

    // Format public key
    fp2_encode(P->X, pk);
    fp2_encode(Q->X, pk + FP2_ENCODED_BYTES);
    fp2_encode(QP->X, pk + 2*FP2_ENCODED_BYTES);

    // Write alice_pk to memory
    write_alice_pk("public_keys/bob_baseline_0", pk);

    return 0;
}



int bob_computation(int argc, char* argv[])
{   // Bob's ephemeral shared secret computation
    // It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's public key PublicKeyA
    // Inputs: Bob's PrivateKeyB is an integer in the range [0, 2^Floor(Log(2,oB)) - 1]. 
    //         Alice's PublicKeyA consists of 3 elements in GF(p^2) encoded by removing leading 0 bytes.
    // Output: a shared secret SharedSecretB that consists of one element in GF(p^2) encoded by removing leading 0 bytes.  
    point_proj_t R, pts[MAX_INT_POINTS_BOB];
    f2elm_t coeff[3], PKB[3], jinv;
    f2elm_t A24plus = {0}, A24minus = {0}, A = {0};
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_BOB], npts = 0, ii = 0;
    digit_t SecretKeyB[NWORDS_ORDER] = {0};

    unsigned char PrivateKeyB[SECRETKEY_B_BYTES] = {0}, PublicKeyA[CRYPTO_CIPHERTEXTBYTES], SharedSecretB[FP2_ENCODED_BYTES];    
    long type_of_attack = 0, target_bit = 0, k = strtol(argv[2], NULL, 10);     // k = the first k bits are read from memory.
    if      (argv[1][0] == 'O')
        type_of_attack = 1;
    else if (argv[1][0] == 'T')
        type_of_attack = 2;
    else if (argv[1][0] == 'j')
        type_of_attack = 0;

    if(argc == 5)
        target_bit = strtol(argv[4], NULL, 10);
    // Read public key of Alice
    read_alice_pk("public_keys/alice_pk", PublicKeyA);

    // Create random secret key of Bob
    // Set first k bits equal to input. The rest is random.
    random_mod_order_B(PrivateKeyB);

    // Read known bits of Bob's secret key
    for(int j = 0; j < k; j++)
        if(argv[3][j] == '1')
            PrivateKeyB[j >> 3] |= ( 1 << (j & (8-1)) );
        else
            PrivateKeyB[j >> 3] &= ((unsigned char)(0xFF) - (1 << (j & (8-1))));

    // Initialize images of Alice's basis
    fp2_decode(PublicKeyA,                          PKB[0]);        // P
    fp2_decode(PublicKeyA + FP2_ENCODED_BYTES,      PKB[1]);        // Q
    fp2_decode(PublicKeyA + 2*FP2_ENCODED_BYTES,    PKB[2]);        // QP = Q - P

    // Initialize constants: A24plus = A+2C, A24minus = A-2C, where C=1
    get_A_32(PKB[0], PKB[1], PKB[2], A);
    fpadd((digit_t*)&Montgomery_one, (digit_t*)&Montgomery_one, A24minus[0]);
    fp2add(A, A24minus, A24plus);
    fp2sub(A, A24minus, A24minus);


    // Retrieve kernel point
    decode_to_digits(PrivateKeyB, SecretKeyB, SECRETKEY_B_BYTES, NWORDS_ORDER);
    LADDER3PT_32(PKB[0], PKB[1], PKB[2], SecretKeyB, BOB, R, A, target_bit, type_of_attack);

    // Traverse tree
    index = 0;
    for (row = 1; row < MAX_Bob; row++) {
        while (index < MAX_Bob-row) {
            fp2copy(R->X, pts[npts]->X);
            fp2copy(R->Z, pts[npts]->Z);
            pts_index[npts++] = index;
            m = strat_Bob[ii++];
            xTPLe_32(R, R, A24minus, A24plus, (int)m);
            index += m;
        }
        get_3_isog_32(R, A24minus, A24plus, coeff);

        for(i = 0; i < npts; i++) {
            eval_3_isog_32(pts[i], coeff);
        }

        fp2copy(pts[npts-1]->X, R->X); 
        fp2copy(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_3_isog_32(R, A24minus, A24plus, coeff);
    fp2add(A24plus, A24minus, A);
    fp2add(A, A, A);
    fp2sub(A24plus, A24minus, A24plus);
    j_inv_32(A, A24plus, jinv);
    fp2_encode(jinv, SharedSecretB);    // Format shared secret

    if(type_of_attack == 0)
        printf("%u", 1 - f2elm_is_zero(jinv));     // Print 0 if jinv=0, otherwise print 1;
    return 0;
}

int alice_computation(int argc, char* argv[])
{   // Alice's ephemeral shared secret computation
    // It produces a shared secret key SharedSecretA using her secret key PrivateKeyA and Bob's public key PublicKeyB
    // Inputs: Alice's PrivateKeyA is an integer in the range [0, 2^Floor(Log(2,oA)) - 1]. 
    //         Bob's PublicKeyB consists of 3 elements in GF(p^2) encoded by removing leading 0 bytes.
    // Output: a shared secret SharedSecretA that consists of one element in GF(p^2) encoded by removing leading 0 bytes.  
    point_proj_t R, pts[MAX_INT_POINTS_ALICE];
    f2elm_t coeff[3], PKB[3], jinv;
    f2elm_t A24plus = {0}, C24 = {0}, A = {0};
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_ALICE], npts = 0, ii = 0;
    digit_t SecretKeyA[NWORDS_ORDER] = {0};
    unsigned char PrivateKeyA[SECRETKEY_A_BYTES] = {0}, PublicKeyB[CRYPTO_PUBLICKEYBYTES], SharedSecretA[FP2_ENCODED_BYTES], PrivateKeyA_trits[OALICE_TRITS];
    long type_of_attack = 0, target_bit = 0, k = strtol(argv[2], NULL, 10); // k = the first k trits are read from input. If k = 0 then we provide a random key. Otherwise we just use the k trits.

    if      (argv[1][0] == 'O')
        type_of_attack = 1;
    else if (argv[1][0] == 'T')
        type_of_attack = 2;
    else if (argv[1][0] == 'j')
        type_of_attack = 0;
    if(argc == 5)
        target_bit = strtol(argv[4], NULL, 10);

    // Read public key of Alice
    read_alice_pk("public_keys/bob_pk", PublicKeyB);

    
    if((type_of_attack == 1) || (type_of_attack == 2) || (k == 0))
    {
        random_mod_order_A(PrivateKeyA);  // Create random secret key of Alice
        for(int j = 0; j < k; j++)
            if(argv[3][j] == '1')
                PrivateKeyA[j >> 3] |= ( 1 << (j & (8-1)) );
            else
                PrivateKeyA[j >> 3] &= ((unsigned char)(0xFF) - (1 << (j & (8-1))));
    }
    if(type_of_attack == 0)
        for(int j = 0; j < k; j++)        // Read known trits of Alice's secret key
            PrivateKeyA_trits[j] = argv[3][j];



    // Initialize images of Bob's basis
    fp2_decode(PublicKeyB,                          PKB[0]);        // P
    fp2_decode(PublicKeyB + FP2_ENCODED_BYTES,      PKB[1]);        // Q
    fp2_decode(PublicKeyB + 2*FP2_ENCODED_BYTES,    PKB[2]);        // QP = Q - P

    // Initialize constants: A24plus = A+2C, C24 = 4C, where C=1
    get_A(PKB[0], PKB[1], PKB[2], A);
    fpadd((digit_t*)&Montgomery_one, (digit_t*)&Montgomery_one, C24[0]);
    fp2add(A, C24, A24plus);
    fpadd(C24[0], C24[0], C24[0]);

    // Retrieve kernel point
    if((k == 0) || (type_of_attack == 1) || (type_of_attack == 2))
        decode_to_digits(PrivateKeyA, SecretKeyA, SECRETKEY_A_BYTES, NWORDS_ORDER);
    else if(type_of_attack == 0)      
        decode_trits(PrivateKeyA_trits, SecretKeyA, k, NWORDS_ORDER);

    LADDER3PT_32(PKB[0], PKB[1], PKB[2], SecretKeyA, ALICE, R, A, target_bit, type_of_attack);

#if (OALICE_BITS % 2 == 1)
    point_proj_t S;

    xDBLe(R, S, A24plus, C24, (int)(OALICE_BITS-1));
    get_2_isog_32(S, A24plus, C24);
    eval_2_isog_32(R, S);
#endif

    // Traverse tree
    index = 0;        
    for (row = 1; row < MAX_Alice; row++) {
        while (index < MAX_Alice-row) {
            fp2copy(R->X, pts[npts]->X);
            fp2copy(R->Z, pts[npts]->Z);
            pts_index[npts++] = index;
            m = strat_Alice[ii++];
            xDBLe_32(R, R, A24plus, C24, (int)(2*m));
            index += m;
        }
        get_4_isog_32(R, A24plus, C24, coeff);        

        for(i = 0; i < npts; i++) {
            eval_4_isog_32(pts[i], coeff);
        }

        fp2copy(pts[npts-1]->X, R->X); 
        fp2copy(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_4_isog_32(R, A24plus, C24, coeff); 
    mp2_add(A24plus, A24plus, A24plus);                                                
    fp2sub(A24plus, C24, A24plus); 
    fp2add(A24plus, A24plus, A24plus);                    
    j_inv_32(A24plus, C24, jinv);
    fp2_encode(jinv, SharedSecretA);    // Format shared secret

    if(type_of_attack == 0)
        printf("%u", 1 - f2elm_is_zero(jinv));     // Print 0 if jinv=0, otherwise print 1;

    return 0;
}






int malicious_alice(int argc, char* argv[])
{   // Create a malicious Alice public key used to guess bit k+1 of Bob's secret key assuming we have access to k bits of Bob's secret key
    // We want to force Bob to compute a secret point R such that the order of R is either 2^EXP_2 or 2^(EXP_2-1).
    
    // If Bob's secret point R is of order exactly  2^EXP_E,     then his j_invariant will be random (and non-zero with high probability) (Requres also that [2^(EXP_2-1)]R =/= [0:0:1])
    // If Bob's secret point R is of order dividing 2^(EXP_E-1), then his j_invariant output will be zero

    // Alice's public key consists of a triple Q, P, QP
    // sk_k are the the first k known bits of Bob's secret key
    // We are trying to guess k+1'st bit (indexed with k)
    
    // Q = point of order 2^(k+EXP_2)           // Q is a point of order 2^(k+EXP_2) such that [2^(k + EXP_2 - 1)]Q =/= [0:0:1]
    // P = F - [sk_k]Q                          // F is a point of order 2^(EXP_2-1) such that [2^(EXP_2 - 1 - 1)]F =/= [0:0:1]; also such that F and Q are independent
    // QP = Q - P

    // The output R of LADDER3PT of Bob will be:
    // of order 2^EXP_2      if his k+1'st bit is 0
    // of order 2^(EXP_2-1)  if his k+1'st bit is 1

    // Therefore jinv = 0 if and only if k+1'st bit of Bob = 0.

    point_proj_t Q = {0}, P = {0}, QP = {0};
    point_full_proj_t T, S, TS;
    f2elm_t A24plus = {0}, A24minus = {0}, C24 = {0}, A={0}, A24 = {0};
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES] = {0}, rand_curve_sk[SECRETKEY_B_BYTES] = {0}, PrivateKeyB[SECRETKEY_B_BYTES] = {0};
    long k = strtol(argv[1], NULL, 10);     // k = the index of bit we are trying to guess. There are k known bits, we are guessing k+1'st bit (which is indexed by k since indexing starts with 0)
    int point_Q_exponent = (int)OALICE_BITS - (k + (int)EXP_2), point_P_exponent = (int)OALICE_BITS - ((int)EXP_2 - 1);
    digit_t sk_k[NWORDS_ORDER] = {0};

    // Read known bits of Bob's secret key
    for(int j = 0; j < k; j++)
        if(argv[2][j] == '1')
            PrivateKeyB[j >> 3] |= ( 1 << (j & (8-1)) );

    // Decode bits into a binary secret key string
    decode_to_digits(PrivateKeyB, sk_k, SECRETKEY_B_BYTES, NWORDS_ORDER);

    // Generate a random curve
    randombytes(ct + CRYPTO_PUBLICKEYBYTES, MSG_BYTES);
    random_mod_order_B(rand_curve_sk);
    EphemeralKeyGeneration_B(rand_curve_sk, ct);

    // Initialize basis points inside E[2^e2]
    fp2_decode(ct,                          P->X);
    fp2_decode(ct + FP2_ENCODED_BYTES,      Q->X);
    fp2_decode(ct + 2*FP2_ENCODED_BYTES,    QP->X);

    // Set z-coordinate of basis points equal to 1
    fpcopy((digit_t *)&Montgomery_one, (P->Z)[0]);      // zP  = 1           
    fpcopy((digit_t *)&Montgomery_one, (Q->Z)[0]);      // zQ  = 1           
    fpcopy((digit_t *)&Montgomery_one, (QP->Z)[0]);     // zQP = 1           

    // Initialize constants: A24plus = A+2C, A24minus = A-2C, C24 = 4C, where C=1
    get_A(P->X, Q->X, QP->X, A);
    mp_add((digit_t*)&Montgomery_one, (digit_t*)&Montgomery_one, A24minus[0], NWORDS_FIELD);
    fp2add(A, A24minus, A24plus);
    fp2sub(A, A24minus, A24minus);
    fp2sub(A24plus, A24minus, C24);
    fp2div2(A24plus, A24);  
    fp2div2(A24, A24);

    // Compute the triple of malicious public key points by using full coordinates
    complete_full_point(QP, A, T);                  // T  = Q2
    complete_full_point(P, A, S);                   // S  = P2 (or [-1]P2 but this is not important)
    DBL_e(T, A24, point_Q_exponent, T);             // T  = QQ := [2^(oA - (k + EXP_2)]Q2 - - - Point of order 2^(k + EXP_2) 
    DBL_e(S, A24, point_P_exponent, S);             // S  = FF := [2^(oA - (EXP_2 - 1)]P2 - - - Point of order 2^(EXP_2 - 1)
    SCALARMULT(T, sk_k, k, A24, TS);                // TS = [sk_k]QQ
    fp2neg(TS->Y);                                  // TS = [-sk_k]QQ
    ADD(TS, S, A24, S);                             // S  = FF + [-sk_k]QQ
    fp2neg(S->Y);                                   // S  = -(FF + [-sk_k]QQ)
    ADD(T, S, A24, TS);                             // TS = QQ + S = ([1+sk_k]QQ - FF) = QQ - (FF - [sk_k]QQ)
    fp2neg(S->Y);                                   // S  = FF - [sk_k]QQ

    // Reduce to [X:Z] coordinates
    reduce_triple(T, S, TS, Q, P, QP);

    // At this point we have computed:
    // Q  = point of order 2^(k+EXP_2)
    // P  = F - [sk_k]Q                     // where F is a point of order 2^(EXP_2-1) and independent of Q, both independent with [0:0:1]
    // QP = Q - P

    // Normalise the X coordinate by dividing with the Z coordinate
    inv_3_way(P->Z, Q->Z, QP->Z);
    fp2mul_mont(P->X, P->Z, P->X);
    fp2mul_mont(Q->X, Q->Z, Q->X);
    fp2mul_mont(QP->X, QP->Z, QP->X); 

    // Format public key
    fp2_encode(P->X, ct);
    fp2_encode(Q->X, ct + FP2_ENCODED_BYTES);
    fp2_encode(QP->X, ct + 2*FP2_ENCODED_BYTES);

    // Write alice_pk to memory
    write_alice_pk("public_keys/pk_j", ct);

    return 0;
}

int malicious_bob(int argc, char* argv[])
{   // Create a malicious Bob public key used to guess trit k+1 of Alice's secret key assuming we have access to k trits of Alice's secret key
    // We want to force Alice to compute a secret point R such that the order of R is either 3^EXP_3 or 3^(EXP_3-1).
    // If Alice's secret point R is of order 3^EXP_E,     then her j_invariant will be random (and non-zero with high probability)
    // If Alice's secret point R is of order 3^(EXP_E-1), then her j_invariant will be zero

    // Bob's public key consists of a triple Q, P, QP
    // sk_k are the the first k known trits of Alice's secret key
    // We are trying to guess k+1'st trit (indexed with k)
    
    // Q  = point of order 3^(k+EXP_3)           // [3^k]Q is of order 3^EXP_3  
    // P  = F - [sk_k]Q                          // F a point of order 3^(EXP_3-1), and such that F and Q are independent.
    // QP = Q - P

    // The output R of LADDER3PT of Alice will be:
    // of order 3^EXP_3     if her k+1'st trit is 0
    // of order 3^(EXP_3-1) if her k+1'st trit is 1 or 2

    // Therefore jinv = 0 if and only if k+1'st trit of Alice = 0.


    // In order to differentiate the case when Alice's k+1'st trit is 1 or 2 we create another public key of the form:
    // Q = point of order 3^(k+EXP_3)         // [3^k]Q is of order 3^EXP_3
    // P = F - [sk_k + 3^k]Q                  // F a point of order 3^(EXP_3-1), and such that F and Q are independent.
    // TS = T - S

    // With this input, the output R of LADDER3PT of Alice will be:
    // of order 3^EXP_3     if her k+1'st trit is 1
    // of order 3^(EXP_3-1) if her k+1'st trit is 0 or 2

    // Therefore jinv = 0 if and only if k+1'st trit of Alice = 1.



    point_proj_t Q = {0}, P = {0}, QP = {0}, P2 = {0}, QP2 = {0};
    point_full_proj_t T, S, TS, S2, TS2;
    f2elm_t A24plus = {0}, A24minus = {0}, C24 = {0}, A={0}, A24 = {0};
    unsigned char pk[CRYPTO_CIPHERTEXTBYTES] = {0}, rand_curve_sk[SECRETKEY_B_BYTES] = {0}, PrivateKeyA_trits[OALICE_TRITS] = {0};
    long k = strtol(argv[1], NULL, 10);     // k = the index of trit we are trying to guess. There are k known trits, we are guessing k+1'st trit (which is indexed by k since indexing starts with 0)
    int point_Q_exponent = (int)OBOB_EXPON - (k + (int)EXP_3), point_P_exponent = (int)OBOB_EXPON - ((int)EXP_3 - 1);
    digit_t sk_k_0[NWORDS_ORDER] = {0}, sk_k_1[NWORDS_ORDER] = {0};

    // Read known trits of Alice's secret key
    for(int j = 0; j < k; j++)
        PrivateKeyA_trits[j] = argv[2][j];

    // Decode trits into a binary secret key string
    decode_trits(PrivateKeyA_trits, sk_k_0, k, NWORDS_ORDER);

    // Create second key sk_k_1 of the form sk_k_1 = sk_k_0 + 3^k
    mp_add(sk_k_0, (digit_t *)&(POWERS_OF_3[k]), sk_k_1, NWORDS_ORDER);

    // Generate a random curve
    randombytes(pk + CRYPTO_PUBLICKEYBYTES, MSG_BYTES);
    random_mod_order_A(rand_curve_sk);
    EphemeralKeyGeneration_A(rand_curve_sk, pk);

    // Initialize basis points inside E[3^e3]
    fp2_decode(pk,                          P->X);
    fp2_decode(pk + FP2_ENCODED_BYTES,      Q->X);
    fp2_decode(pk + 2*FP2_ENCODED_BYTES,    QP->X);

    // Set z-coordinate of basis points equal to 1
    fpcopy((digit_t *)&Montgomery_one, (P->Z)[0]);      // zP  = 1           
    fpcopy((digit_t *)&Montgomery_one, (Q->Z)[0]);      // zQ  = 1           
    fpcopy((digit_t *)&Montgomery_one, (QP->Z)[0]);     // zQP = 1           

    // Initialize constants: A24plus = A+2C, A24minus = A-2C, C24 = 4C, where C=1
    get_A(P->X, Q->X, QP->X, A);
    mp_add((digit_t*)&Montgomery_one, (digit_t*)&Montgomery_one, A24minus[0], NWORDS_FIELD);
    fp2add(A, A24minus, A24plus);
    fp2sub(A, A24minus, A24minus);
    fp2sub(A24plus, A24minus, C24);
    fp2div2(A24plus, A24);  
    fp2div2(A24, A24);

    // Compute the triple of malicious public key points by using full coordinates
    complete_full_point(Q, A, T);                                                       //  T  = Q3
    complete_full_point(P, A, S);                                                       //  S  = P3 (or [-1]P3 but this is not important)
    SCALARMULT(T, (digit_t *)&(POWERS_OF_3[point_Q_exponent]), OBOB_BITS, A24, T);      //  T  = QQ := [3^(oB - (k + EXP_3))]Q3 - - - Point of order 3^(k + EXP_3)
    SCALARMULT(S, (digit_t *)&(POWERS_OF_3[point_P_exponent]), OBOB_BITS, A24, S);      //  S  = FF := [3^(oB - (EXP_3 - 1))]P3 - - - Point of order 3^(EXP_3 - 1)
    SCALARMULT(T, sk_k_0, OBOB_BITS, A24, TS);                                          // TS  = [sk_k]QQ
    SCALARMULT(T, sk_k_1, OBOB_BITS, A24, TS2);                                         // TS2 = [sk_k + 3^k]QQ
    fp2neg(TS->Y);                                                                      // TS  = -[sk_k]QQ
    fp2neg(TS2->Y);                                                                     // TS2  = -[sk_k + 3^k]QQ
    ADD(S, TS2, A24, S2);                                                               // S2  = FF - [sk_k + 3^k]QQ
    ADD(S, TS, A24, S);                                                                 //  S  = FF - [sk_k]QQ
    fp2neg(S->Y);                                                                       //  S  = -(FF - [sk_k]QQ)
    fp2neg(S2->Y);                                                                      // S2  = -(FF - [sk_k + 3^k]QQ)
    ADD(T, S, A24, TS);                                                                 // TS  = QQ - (FF - [sk_k]QQ)
    ADD(T, S2, A24, TS2);                                                               // TS2 = QQ - (FF - [sk_k + 3^k]QQ)
    fp2neg(S->Y);                                                                       //  S  = FF - [sk_k]QQ
    fp2neg(S2->Y);                                                                      // S2  = FF - [sk_k + 3^k]QQ


    // Reduce to [X:Z] coordinates
    reduce_triple(T, S, TS, Q, P, QP);
    reduce_triple(T, S2, TS2, Q, P2, QP2);

    // At this point we have computed:
    // Q  = point of order 3^(k+EXP_3)
    // P  = F - [sk_k]Q
    // QP = Q - P

    // and:
    // Q   = point of order 3^(k+EXP_3)
    // P2  = F - [sk_k + 3^k]Q
    // QP2 = Q - P2

    // Normalise the X coordinates by dividing with the Z coordinates
    inv_3_way(P->Z, Q->Z, QP->Z);
    fp2mul_mont(P->X, P->Z, P->X);
    fp2mul_mont(Q->X, Q->Z, Q->X);
    fp2mul_mont(QP->X, QP->Z, QP->X); 

    // Format first public key
    fp2_encode(P->X, pk);
    fp2_encode(Q->X, pk + FP2_ENCODED_BYTES);
    fp2_encode(QP->X, pk + 2*FP2_ENCODED_BYTES);

    // Write to memory
    write_alice_pk("public_keys/pk_j", pk);


    // Normalise the X coordinates by dividing with the Z coordinates
    //Set Q->Z = 1 because Q->X was normalised above.
    fpcopy((digit_t *)&Montgomery_one, (Q->Z)[0]);      
    fpzero((Q->Z)[1]);
    inv_3_way(P2->Z, Q->Z, QP2->Z);
    fp2mul_mont(P2->X, P2->Z, P2->X);
    fp2mul_mont(Q->X, Q->Z, Q->X);
    fp2mul_mont(QP2->X, QP2->Z, QP2->X); 

    // Format second
    fp2_encode(P2->X, pk);
    fp2_encode(Q->X, pk + FP2_ENCODED_BYTES);
    fp2_encode(QP2->X, pk + 2*FP2_ENCODED_BYTES);

    // Write to memory
    write_alice_pk("public_keys/pk_j_1", pk);

    return 0;
}



int malicious_pk_x(int argc, char* argv[])
{   // Create a malicious public key which can be used to attack both Alice and Bob.
    // We assume that we know the first k bits of the computing party (called sk_k where bits are indexed with 0,1,...,k-1)
    // We compute a special key which, depending on the k+1'st bit of the computing parties secret key, 
    // will force them to compute the point T = [0:0:1] = [0:1]
    // We compute the public key to be the following triple: 
    // Q, P, Q-P

    // Then the output at step of index k of the LADDER3PT loop is:
    // [2^(k+1)]Q,  -P + [2^(k+1)-sk_k]Q,   P +         [sk_k]Q     // if sk[k] == 0
    // [2^(k+1)]Q,   P +   [2^k + sk_k]Q,  -P + [2^(k+1)-sk_k]Q     // if sk[k] == 1

    // We compute a public key which forces the second output of xDBLADD to be equal to T=[0:1] depending on sk[k]

    // CASE 0
    // Q  = Random point
    // P  = -T + [2^(k+1) - sk_k]Q
    // QP = Q - P
    // The computing party will compute the point T=[0:1] if and only if sk[k] == 0

    // CASE 1
    // Q  = Random point
    // P  = T - [2^k - sk_k]Q
    // QP = Q - P
    // The computing party will compute the point T=[0:1] if and only if sk[k] == 1



    point_proj_t Q = {0}, P = {0}, QP = {0};
    point_full_proj_t R, S, RS, S2, RS2, T = {0};
    f2elm_t A24plus = {0}, A24minus = {0}, C24 = {0}, A={0}, A24 = {0};
    unsigned char ct0[CRYPTO_CIPHERTEXTBYTES] = {0}, ct1[CRYPTO_CIPHERTEXTBYTES] = {0}, rand_curve_sk[MAX_SECRETKEY_BYTES] = {0}, private_key[MAX_SECRETKEY_BYTES] = {0};
    long k = strtol(argv[1], NULL, 10); // k = the index of bit we are trying to guess. Known bits are k, we are guessing k+1'st bit (indexed by k since indexing starts with 0)
    char public_key_path[200], BITS[k], last_bit = 0;
    digit_t secret_key[NWORDS_ORDER] = {0};


    // Read known bits of the secret key
    for(int j = 0; j < k; j++)
        BITS[j] = argv[2][j];

    for(int i = 0; i < k; i++)
        if(BITS[i] == '1')
            private_key[i >> 3] |= ( 1 << (i & (8-1)) );

    // Set last_bit equal to the last known bit of secret key. It is 0 if k=0 (standard).
    last_bit = ((k > 0) && (BITS[k-1]=='1')) ? 1 : 0;

    decode_to_digits(private_key, secret_key, MAX_SECRETKEY_BYTES, NWORDS_ORDER);

    // Generate a random curve
    randombytes(ct0 + CRYPTO_PUBLICKEYBYTES, MSG_BYTES);
    randombytes(ct1 + CRYPTO_PUBLICKEYBYTES, MSG_BYTES);
    random_mod_order_A(rand_curve_sk);
    EphemeralKeyGeneration_A(rand_curve_sk, ct0);

    // Initialize basis points inside E[3^e3]
    fp2_decode(ct0,    P->X);
    fp2_decode(ct0 + FP2_ENCODED_BYTES,    Q->X);
    fp2_decode(ct0 + 2*FP2_ENCODED_BYTES,    QP->X);

    // Set z-coordinate of basis points equal to 1
    fpcopy((digit_t *)&Montgomery_one, (P->Z)[0]);      // zP  = 1           
    fpcopy((digit_t *)&Montgomery_one, (Q->Z)[0]);      // zQ  = 1           
    fpcopy((digit_t *)&Montgomery_one, (QP->Z)[0]);     // zQP = 1           

    // Initialize constants: A24plus = A+2C, A24minus = A-2C, C24 = 4C, where C=1
    get_A(P->X, Q->X, QP->X, A);
    mp_add((digit_t*)&Montgomery_one, (digit_t*)&Montgomery_one, A24minus[0], NWORDS_FIELD);
    fp2add(A, A24minus, A24plus);
    fp2sub(A, A24minus, A24minus);
    fp2sub(A24plus, A24minus, C24);
    fp2div2(A24plus, A24);  
    fp2div2(A24, A24);

    // Compute Т =[0:0:1] of order 2. Т = {0} at definition. Only need to set Z-coordinate = 1
    fpcopy((digit_t *)&Montgomery_one, (T->Z)[0]);                


    // Compute the triple of malicious public key points by using full coordinates
    complete_full_point(Q, A, R);               // R   = Q3
    DBL_e(R, A24, k, RS);                       // RS  = [2^k]R
    SCALARMULT(R, secret_key, k, A24, S);       // S   = [sk_k]R
    ADD(S, RS, A24, S2);                        // S2  = [2^k + sk_k]R
    fp2neg(S->Y);                               // S   = [-sk_k]R
    ADD(S, RS, A24, S);                         // S   = [2^k - sk_k]R
    ADD(S, RS, A24, S);                         // S   = [2^(k+1) - sk_k]R
    ADD(S, T, A24, S);                          // S   = T + [2^(k+1) - sk_k]R = -T + [2^(k+1) - sk_k]R                 // T = -T
    ADD(S2, T, A24, S2);                        // S2  = T + [2^k + sk_k]R = -T + [2^k + sk_k]R = -(T - [2^k + sk_k]R)  // T = -T
    fp2neg(S->Y);                               // S   = -(-T + [2^(k+1) - sk_k]R)
    ADD(R, S, A24, RS);                         // RS  = R + S
    ADD(R, S2, A24, RS2);                       // RS2 = R + S2
    fp2neg(S->Y);                               // S   = -T + [2^(k+1) - sk_k]R
    fp2neg(S2->Y);                              // S2  =  T - [2^k + sk_k]R

    // At this point:
    
    // R   = a random point of order 3^e3
    // S   = -T + [2^(k+1) - sk_k]R
    // RS  = R - S

    // R   = a random point of order 3^e3
    // S2  = T - [2^k + sk_k]R
    // RS2 = R - S2


    // Format triple with S = -T + [2^(k+1) - sk_k]R
    reduce_triple(R, S, RS, Q, P, QP);

    inv_3_way(P->Z, Q->Z, QP->Z);
    fp2mul_mont(P->X, P->Z, P->X);
    fp2mul_mont(Q->X, Q->Z, Q->X);
    fp2mul_mont(QP->X, QP->Z, QP->X); 

    // Format public key
    fp2_encode(P->X,  ct0 + 0*FP2_ENCODED_BYTES);
    fp2_encode(Q->X,  ct0 + 1*FP2_ENCODED_BYTES);
    fp2_encode(QP->X, ct0 + 2*FP2_ENCODED_BYTES);


    // Format triple with S = T - [2^k + sk_k]R
    reduce_triple(R, S2, RS2, Q, P, QP);

    inv_3_way(P->Z, Q->Z, QP->Z);
    fp2mul_mont(P->X, P->Z, P->X);
    fp2mul_mont(Q->X, Q->Z, Q->X);
    fp2mul_mont(QP->X, QP->Z, QP->X); 

    // Format public key
    fp2_encode(P->X,  ct1 + 0*FP2_ENCODED_BYTES);
    fp2_encode(Q->X,  ct1 + 1*FP2_ENCODED_BYTES);
    fp2_encode(QP->X, ct1 + 2*FP2_ENCODED_BYTES);

    // Write public key to memory
    sprintf(public_key_path, "public_keys/pk_x_0");
    write_alice_pk(public_key_path, ct0);
    sprintf(public_key_path, "public_keys/pk_x_1");
    write_alice_pk(public_key_path, ct1);

    return 0;
}


int malicious_pk_z(int argc, char* argv[])
{   // Create a malicious public key which can be used to attack both Alice and Bob.
    // We assume that we know the first k bits of the computing party (called sk_k where bits are indexed with 0,1,...,k-1)
    // We compute a special key which, depending on the k+1'st bit of the computing parties secret key, 
    // will force them to compute the point O = [0:1:0] = [1:0]
    // We compute the public key to be the following triple: 
    // Q, P, Q-P

    // Then the output at step of index k of the LADDER3PT loop is:
    // [2^(k+1)]Q,  -P + [2^(k+1)-sk_k]Q,   P +         [sk_k]Q     // if sk[k] == 0
    // [2^(k+1)]Q,   P +   [2^k + sk_k]Q,  -P + [2^(k+1)-sk_k]Q     // if sk[k] == 1

    // We compute a public key which forces the second output of xDBLADD to be equal to T=[0:1] depending on sk[k]

    // CASE 0
    // Q  = Random point
    // P  = 2^(k+1) - sk_k]Q
    // QP = Q - P
    // The computing party will compute the point O=[1:0] if and only if sk[k] == 0

    // CASE 1
    // Q  = Random point
    // P  = [2^k - sk_k]Q
    // QP = Q - P
    // The computing party will compute the point O=[1:0] if and only if sk[k] == 1

    point_proj_t Q = {0}, P = {0}, QP = {0};
    point_full_proj_t R, S, RS, S2, RS2;
    f2elm_t A24plus = {0}, A24minus = {0}, C24 = {0}, A={0}, A24 = {0};
    unsigned char ct0[CRYPTO_CIPHERTEXTBYTES] = {0}, ct1[CRYPTO_CIPHERTEXTBYTES] = {0}, rand_curve_sk[MAX_SECRETKEY_BYTES] = {0}, private_key[MAX_SECRETKEY_BYTES] = {0};
    long k = strtol(argv[1], NULL, 10); // k = the index of bit we are trying to guess. Known bits are k, we are guessing k+1'st bit (indexed by k since indexing starts with 0)
    char public_key_path[200], BITS[k], last_bit;
    digit_t secret_key[NWORDS_ORDER] = {0};


    // Read known bits of the secret key
    for(int j = 0; j < k; j++)
        BITS[j] = argv[2][j];

    for(int i = 0; i < k; i++)
        if(BITS[i] == '1')
            private_key[i >> 3] |= ( 1 << (i & (8-1)) );

    // Set last_bit equal to the last known bit of secret key. It is 0 if k=0 (standard).
    last_bit = ((k > 0) && (BITS[k-1]=='1')) ? 1 : 0;

    decode_to_digits(private_key, secret_key, MAX_SECRETKEY_BYTES, NWORDS_ORDER);

    // Generate a random curve
    randombytes(ct0 + CRYPTO_PUBLICKEYBYTES, MSG_BYTES);
    randombytes(ct1 + CRYPTO_PUBLICKEYBYTES, MSG_BYTES);
    random_mod_order_A(rand_curve_sk);
    EphemeralKeyGeneration_A(rand_curve_sk, ct0);

    // Initialize basis points inside E[3^e3]
    fp2_decode(ct0,    P->X);
    fp2_decode(ct0 + FP2_ENCODED_BYTES,    Q->X);
    fp2_decode(ct0 + 2*FP2_ENCODED_BYTES,    QP->X);

    // Set z-coordinate of basis points equal to 1
    fpcopy((digit_t *)&Montgomery_one, (P->Z)[0]);      // zP  = 1           
    fpcopy((digit_t *)&Montgomery_one, (Q->Z)[0]);      // zQ  = 1           
    fpcopy((digit_t *)&Montgomery_one, (QP->Z)[0]);     // zQP = 1           

    // Initialize constants: A24plus = A+2C, A24minus = A-2C, C24 = 4C, where C=1
    get_A(P->X, Q->X, QP->X, A);
    mp_add((digit_t*)&Montgomery_one, (digit_t*)&Montgomery_one, A24minus[0], NWORDS_FIELD);
    fp2add(A, A24minus, A24plus);
    fp2sub(A, A24minus, A24minus);
    fp2sub(A24plus, A24minus, C24);
    fp2div2(A24plus, A24);  
    fp2div2(A24, A24);

    // Compute the triple of malicious public key points by using full coordinates
    complete_full_point(Q, A, R);               // R   = Q3
    DBL_e(R, A24, k, RS);                       // RS  = [2^k]R
    SCALARMULT(R, secret_key, k, A24, S);       // S   = [sk_k]R
    ADD(S, RS, A24, S2);                        // S2  = [2^k + sk_k]R
    fp2neg(S->Y);                               // S   = [-sk_k]R
    ADD(S, RS, A24, S);                         // S   = [2^k - sk_k]R
    ADD(S, RS, A24, S);                         // S   = [2^(k+1) - sk_k]R
    fp2neg(S->Y);                               // S   = -([2^(k+1) - sk_k]R)
    ADD(R, S, A24, RS);                         // RS  = R + S
    ADD(R, S2, A24, RS2);                       // RS2 = R + S2
    fp2neg(S->Y);                               // S   = 2^(k+1) - sk_k]R
    fp2neg(S2->Y);                              // S2  = -[2^k + sk_k]R

    // At this point:
    
    // R   = a random point of order 3^e3
    // S   = [2^(k+1) - sk_k]R
    // RS  = R - S

    // R   = a random point of order 3^e3
    // S2  = -[2^k + sk_k]R
    // RS2 = R - S2


    // Format triple with S = [2^(k+1) - sk_k]R
    reduce_triple(R, S, RS, Q, P, QP);

    inv_3_way(P->Z, Q->Z, QP->Z);
    fp2mul_mont(P->X, P->Z, P->X);
    fp2mul_mont(Q->X, Q->Z, Q->X);
    fp2mul_mont(QP->X, QP->Z, QP->X); 

    // Format public key
    fp2_encode(P->X,  ct0 + 0*FP2_ENCODED_BYTES);
    fp2_encode(Q->X,  ct0 + 1*FP2_ENCODED_BYTES);
    fp2_encode(QP->X, ct0 + 2*FP2_ENCODED_BYTES);


    // Format triple with S = [2^k + sk_k]R
    reduce_triple(R, S2, RS2, Q, P, QP);

    inv_3_way(P->Z, Q->Z, QP->Z);
    fp2mul_mont(P->X, P->Z, P->X);
    fp2mul_mont(Q->X, Q->Z, Q->X);
    fp2mul_mont(QP->X, QP->Z, QP->X); 

    // Format public key
    fp2_encode(P->X,  ct1 + 0*FP2_ENCODED_BYTES);
    fp2_encode(Q->X,  ct1 + 1*FP2_ENCODED_BYTES);
    fp2_encode(QP->X, ct1 + 2*FP2_ENCODED_BYTES);

    // Write public key to memory
    sprintf(public_key_path, "public_keys/pk_z_0");
    write_alice_pk(public_key_path, ct0);
    sprintf(public_key_path, "public_keys/pk_z_1");
    write_alice_pk(public_key_path, ct1);

    return 0;
}



int remove_compile_warnings(int a, int b)
{
    unsigned char key[10] = {0};
    f2elm_t A = {0};
    point_proj_t P = {0}, Q = {0}, R = {0};
    point_full_proj_t T = {0};

    print_secret_key_alice(key);
    print_secret_key_bob(key);
    print_public_key(key);
    print_f2elm(A, "P");
    print_full_point(T, "T");
    print_triple(P, Q, R, "P", "Q", "R");

    return 0;
}
