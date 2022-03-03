/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny key encapsulation (SIKE) protocol
*********************************************************************************************/ 

#include <string.h>
#include "sha3/fips202.h"
#include "random/random.h"

//ADDED FOR TESTING PURPOSES
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <getopt.h>
#include <inttypes.h>


typedef struct { f2elm_t X; f2elm_t Y; f2elm_t Z; } point_full_proj;  // Point representation in full projective XYZ Montgomery coordinates 
typedef point_full_proj point_full_proj_t[1]; 




unsigned char FromHex(char c)
{
    switch(c)
        {
        case '0': return 0;
        case '1': return 1;
        case '2': return 2;
        case '3': return 3;
        case '4': return 4;
        case '5': return 5;
        case '6': return 6;
        case '7': return 7;
        case '8': return 8;
        case '9': return 9;
        case 'a': return 10;
        case 'b': return 11;
        case 'c': return 12;
        case 'd': return 13;
        case 'e': return 14;
        case 'f': return 15;
        }
    // Report a problem here!
    return -1;
}

const char *bit_rep[16] = {
    [ 0] = "0000", [ 1] = "0001", [ 2] = "0010", [ 3] = "0011",
    [ 4] = "0100", [ 5] = "0101", [ 6] = "0110", [ 7] = "0111",
    [ 8] = "1000", [ 9] = "1001", [10] = "1010", [11] = "1011",
    [12] = "1100", [13] = "1101", [14] = "1110", [15] = "1111",
};

static int hamming_weight(uint32_t i)
{
    i = i - ((i >> 1) & 0x55555555);
    i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
    return (int)((((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24);
}




void read_alice_pk(char* alice_pk_path, unsigned char* alice_pk)
{   // Reads Alice's public key from file saved in alice_pk_path into the array pointed to by alice_pk

    FILE *fp = fopen(alice_pk_path, "rb");
    assert((fp != NULL) && "Error opening Alice's public key file");

    assert( fread(alice_pk, CRYPTO_CIPHERTEXTBYTES, 1, fp) != 0 );
    fclose(fp);
}

void read_bob_pk(char* bob_pk_path, unsigned char* bob_pk)
{   // Reads Bob's public key from file saved in bob_pk_path into the array pointed to by bob_pk

    FILE *fp = fopen(bob_pk_path, "rb");
    assert((fp != NULL) && "Error opening Bob's public key file");

    assert( fread(bob_pk, CRYPTO_PUBLICKEYBYTES, 1, fp) != 0 );
    fclose(fp);
}

void write_alice_pk(char *alice_pk_path, unsigned char* alice_pk)
{   // Writes Alice's public key file from the array pointed to by alice_pk into the file saved in alice_pk_path

    FILE *fp = fopen(alice_pk_path, "wb");
    assert((fp != NULL) && "Error opening Alice's public key file");

    fwrite((unsigned char *)alice_pk, CRYPTO_CIPHERTEXTBYTES, 1, fp);
    fclose(fp);
}

void write_bob_pk(char *bob_pk_path, unsigned char* bob_pk)
{   // Writes Bob's public key file from the array pointed to by bob_pk into the file saved in bob_pk_path

    FILE *fp = fopen(bob_pk_path, "wb");
    assert((fp != NULL) && "Error opening Bob's public key file");

    fwrite((unsigned char *)bob_pk, CRYPTO_PUBLICKEYBYTES, 1, fp);
    fclose(fp);
}

void write_alice_sk(char *alice_sk_path, unsigned char* alice_sk)
{   // Writes Alice's secret key file from the array pointed to by alice_sk into the file saved in alice_sk_path

    FILE *fp = fopen(alice_sk_path, "wb");
    assert((fp != NULL) && "Error opening Alice's secret key file");

    fwrite((unsigned char *)alice_sk, CRYPTO_SECRETKEYBYTES, 1, fp);
    fclose(fp);
}

void write_bob_sk(char *bob_sk_path, unsigned char* bob_sk)
{   // Writes Bob's secret key file from the array pointed to by bob_sk into the file saved in bob_sk_path

    FILE *fp = fopen(bob_sk_path, "wb");
    assert((fp != NULL) && "Error opening Bob's secret key file");

    fwrite((unsigned char *)bob_sk, CRYPTO_SECRETKEYBYTES, 1, fp);
    fclose(fp);
}

void write_only_alice_sk(char *alice_sk_path, unsigned char* alice_sk)
{   // Writes only the private key part of Alice's secret key file from 
    // the array pointed to by alice_sk into the file saved in alice_sk_path

    FILE *fp = fopen(alice_sk_path, "wb");
    assert((fp != NULL) && "Error opening Alice's secret key file");

    fwrite((unsigned char *)alice_sk, SECRETKEY_A_BYTES, 1, fp);
    fclose(fp);
}

void write_only_bob_sk(char *bob_sk_path, unsigned char* bob_sk)
{   // Writes only the private key part of Bob's secret key file from 
    // the array pointed to by bob_sk into the file saved in bob_sk_path

    FILE *fp = fopen(bob_sk_path, "wb");
    assert((fp != NULL) && "Error opening Bob's secret key file");

    fwrite((unsigned char *)bob_sk, SECRETKEY_B_BYTES, 1, fp);
    fclose(fp);
}

int create_empty_alice_sk(unsigned char *alice_pk, unsigned char *alice_sk)
{ 
    // SIKE's key generation
    // Outputs: secret key alice_sk (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_A_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
    //          public key alice_pk (CRYPTO_PUBLICKEYBYTES bytes) 

    // Generate lower portion of secret key alice_sk <- s||SK
    randombytes(alice_sk, MSG_BYTES);                        //WRITE RANDOMNESS IN THE BEGGINING
    memset(alice_sk+MSG_BYTES, 0x00, SECRETKEY_A_BYTES);     //WRITE ALL ZEROS -> THIS IS WHAT WE'RE SEARCHING FOR

    // Append public key bob_pk to secret key bob_sk
    memcpy(&alice_sk[MSG_BYTES + SECRETKEY_A_BYTES], alice_pk, CRYPTO_PUBLICKEYBYTES);    //APPEND THE PUBLIC KEY THAT WAS READ FROM FILE

    return 0;
}

int create_empty_bob_sk(unsigned char *bob_pk, unsigned char *bob_sk)
{ 
    // SIKE's key generation
    // Outputs: secret key bob_sk (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
    //          public key bob_pk (CRYPTO_PUBLICKEYBYTES bytes) 

    // Generate lower portion of secret key bob_sk <- s||SK
    randombytes(bob_sk, MSG_BYTES);                        //WRITE RANDOMNESS IN THE BEGGINING
    memset(bob_sk+MSG_BYTES, 0x00, SECRETKEY_B_BYTES);     //WRITE ALL ZEROS -> THIS IS WHAT WE'RE SEARCHING FOR

    // Append public key bob_pk to secret key bob_sk
    memcpy(&bob_sk[MSG_BYTES + SECRETKEY_B_BYTES], bob_pk, CRYPTO_PUBLICKEYBYTES);    //APPEND THE PUBLIC KEY THAT WAS READ FROM FILE

    return 0;
}

void generate_alice_sk_pk(unsigned char* bob_pk, unsigned char* temp, unsigned char* alice_sk, unsigned char* alice_pk, unsigned char* shared_secret, unsigned char* jinvariant, unsigned char* h)
{
    // SIKE's encapsulation
    // Input:   public key          bob_pk          (CRYPTO_PUBLICKEYBYTES bytes)
    // Outputs: shared secret       shared_secret      (CRYPTO_BYTES bytes)
    //          ciphertext message  alice_pk       (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes)

    // Generate alice_sk <- G(temp||bob_pk) mod oA 
    randombytes(temp, MSG_BYTES);                                                       //Generate random bytes
    memcpy(&temp[MSG_BYTES], bob_pk, CRYPTO_PUBLICKEYBYTES);                            //Concatenate random bytes with BOB's public key
    shake256(alice_sk, SECRETKEY_A_BYTES, temp, CRYPTO_PUBLICKEYBYTES+MSG_BYTES);       //Hash the above
    alice_sk[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;                                      //Pad correctly

    // Encrypt
    EphemeralKeyGeneration_A(alice_sk, alice_pk);                                       //Generate Alice's public key
    EphemeralSecretAgreement_A(alice_sk, bob_pk, jinvariant);                           //Generate the common j invariant
    shake256(h, MSG_BYTES, jinvariant, FP2_ENCODED_BYTES);                              //Hash the j invariant
    for (int i = 0; i < MSG_BYTES; i++) 
    {
        alice_pk[i + CRYPTO_PUBLICKEYBYTES] = temp[i] ^ h[i];                           //XOR hashed j inv with the random bytes and write it to the public key
    }

    // Generate shared secret shared_secret <- H(temp||alice_pk)
    memcpy(&temp[MSG_BYTES], alice_pk, CRYPTO_CIPHERTEXTBYTES);                         //Concatenate random bytes with Alice's public key
    shake256(shared_secret, CRYPTO_BYTES, temp, CRYPTO_CIPHERTEXTBYTES+MSG_BYTES);      //Hash to obtain the common shared secret K
}















void read_points(char* path_name, int step, char* type, point_proj_t A, point_proj_t B, point_proj_t C)
{
    sprintf(path_name, "data/%s_%03d", type, step);
    FILE *fp = fopen(path_name, "rb");
    assert((fp != NULL) && "Error reading points file");

    assert(( fread((point_proj_t *)A, sizeof(point_proj_t), 1, fp) != 0 ) && "Error reading points file");
    assert(( fread((point_proj_t *)B, sizeof(point_proj_t), 1, fp) != 0 ) && "Error reading points file");
    assert(( fread((point_proj_t *)C, sizeof(point_proj_t), 1, fp) != 0 ) && "Error reading points file");

    fclose(fp);
}


void read_consts(char* path_name, int step, char* type, f2elm_t A, f2elm_t B)
{
    sprintf(path_name, "data/%s_%03d", type, step);
    FILE *fp = fopen(path_name, "rb");
    assert((fp != NULL) && "Error reading constants file");

    assert(( fread((f2elm_t *)A, sizeof(f2elm_t), 1, fp) != 0 ) && "Error reading constants file");
    assert(( fread((f2elm_t *)B, sizeof(f2elm_t), 1, fp) != 0 ) && "Error reading constants file");

    fclose(fp);
}


void write_points(char* path_name, int step, int guess, char* type, point_proj_t A, point_proj_t B, point_proj_t C)
{
    sprintf(path_name, "data/%s_%03d_%01d", type, step, guess);
    FILE *fp = fopen(path_name, "wb");
    assert((fp != NULL) && "Error writing points file");

    fwrite((point_proj_t *)A, sizeof(point_proj_t), 1, fp);
    fwrite((point_proj_t *)B, sizeof(point_proj_t), 1, fp);
    fwrite((point_proj_t *)C, sizeof(point_proj_t), 1, fp);


    fclose(fp);
}


void write_consts(char* path_name, int step, int guess, char* type, f2elm_t A, f2elm_t B)
{
    sprintf(path_name, "data/%s_%03d_%01d", type, step, guess);
    FILE *fp = fopen(path_name, "wb");
    assert((fp != NULL) && "Error writing constants file");

    fwrite((f2elm_t *)A, sizeof(f2elm_t), 1, fp);
    fwrite((f2elm_t *)B, sizeof(f2elm_t), 1, fp);

    fclose(fp);
}






static void print_secret_key_alice(const unsigned char* key)
{
    printf("\nAlice's private key is 0x");
    for(int i = NBITS_TO_NBYTES(OALICE_BITS) - 1; i >= 0; i--)
            printf("%02x", key[i]);
    printf("\n\n");
}

static void print_secret_key_bob(const unsigned char* key)
{
    printf("\nBob's private key is 0b");
    for(int i = NBITS_TO_NBYTES(OBOB_BITS) - 1; i >= 0; i--)
            printf("%s%s", bit_rep[key[i] >> 4], bit_rep[key[i] & 0x0F]);
    printf("\n\n");
}

static void print_public_key(const unsigned char* key)
{
    int felm_size = FP2_ENCODED_BYTES/2;
    printf("\nReX = 0x");
    for(int i = felm_size - 1; i >= 0; i--)
            printf("%02x", key[i]);
    printf("\nImX = 0x");
    for(int i = felm_size - 1; i >= 0; i--)
            printf("%02x", key[i + felm_size]);
    printf("\nReY = 0x");
    for(int i = felm_size - 1; i >= 0; i--)
            printf("%02x", key[i + 2*felm_size]);
    printf("\nImY = 0x");
    for(int i = felm_size - 1; i >= 0; i--)
            printf("%02x", key[i + 3*felm_size]);
    printf("\nReZ = 0x");
    for(int i = felm_size - 1; i >= 0; i--)
            printf("%02x", key[i + 4*felm_size]);
    printf("\nImZ = 0x");
    for(int i = felm_size - 1; i >= 0; i--)
            printf("%02x", key[i + 5*felm_size]);
    printf("\n\n");
}

static void print_felm(const felm_t a)
{   
    for (int i = sizeof(felm_t) - 1; i >= 0; i--)
        printf("%02x", ((uint8_t *)(a))[i]);
    // printf("\n");
}

static void print_f2elm(const f2elm_t a, char* name)
{
    printf("%s", name);
    printf("\nRe = 0x");
    print_felm(a[0]);
    printf("\nIm = 0x");
    print_felm(a[1]);
    printf("\n\n");
}

static void print_point(const point_proj_t R, char* name)
{
    printf("%s", name);
    printf("\nReX = 0x");
    print_felm((R->X)[0]);
    printf("\nImX = 0x");
    print_felm((R->X)[1]);
    printf("\nReZ = 0x");
    print_felm((R->Z)[0]);
    printf("\nImZ = 0x");
    print_felm((R->Z)[1]);
    printf("\n\n");
}

static void print_full_point(const point_full_proj_t R, char* name)
{
    printf("%s", name);
    printf("\nReX = 0x");
    print_felm((R->X)[0]);
    printf("\nImX = 0x");
    print_felm((R->X)[1]);
    printf("\nReY = 0x");
    print_felm((R->Y)[0]);
    printf("\nImY = 0x");
    print_felm((R->Y)[1]);
    printf("\nReZ = 0x");
    print_felm((R->Z)[0]);
    printf("\nImZ = 0x");
    print_felm((R->Z)[1]);
    printf("\n\n");
}

static void print_triple(const point_proj_t A, const point_proj_t B, const point_proj_t C, char* nameA, char* nameB, char* nameC)
{
    print_point(A, nameA);
    print_point(B, nameB);
    print_point(C, nameC);
}


int f2elm_is_zero(const f2elm_t a)
{   // return 1 if element is equal to zero
    // return 0 if element is not equal to zero
    f2elm_t zero = {0}, b;
    fp2copy(a,b);
    fp2correction(b);
    if((memcmp((unsigned char*)b, (unsigned char*)zero, NBITS_TO_NBYTES(MAXBITS_FIELD*2)) == 0))
        return 1;
    return 0;
}

void point_from_mont(point_proj_t A, point_proj_t B)
{
    from_fp2mont(A->X, B->X);
    from_fp2mont(A->Z, B->Z);
}

void full_point_from_mont(const point_full_proj_t A, point_full_proj_t B)
{
    from_fp2mont(A->X, B->X);
    from_fp2mont(A->Y, B->Y);
    from_fp2mont(A->Z, B->Z);
}

void copy_point(const point_proj_t A, point_proj_t P)
{
    // Copies a point A into P
    fp2copy(A->X, P->X);
    fp2copy(A->Z, P->Z);
}

void copy_full_point(const point_full_proj_t A, point_full_proj_t P)
{
    // Copies a point A into P
    fp2copy(A->X, P->X);
    fp2copy(A->Y, P->Y);
    fp2copy(A->Z, P->Z);
}

void copy_triple(const point_proj_t A, const point_proj_t B, const point_proj_t C, point_proj_t P, point_proj_t Q, point_proj_t R)
{
    // Copies a triple of points A,B,C into P,Q,R
    copy_point(A, P);
    copy_point(B, Q);
    copy_point(C, R);
}

void copy_full_triple(const point_full_proj_t A, const point_full_proj_t B, const point_full_proj_t C, point_full_proj_t P, point_full_proj_t Q, point_full_proj_t R)
{
    // Copies a triple of points A,B,C into P,Q,R
    copy_full_point(A, P);
    copy_full_point(B, Q);
    copy_full_point(C, R);
}

void reduce_point(const point_full_proj_t P, point_proj_t A)
{
    fp2copy(P->X, A->X);
    fp2copy(P->Z, A->Z);
}

void reduce_triple(const point_full_proj_t P, const point_full_proj_t Q, const point_full_proj_t R, point_proj_t A, point_proj_t B, point_proj_t C)
{
    reduce_point(P,A);
    reduce_point(Q,B);
    reduce_point(R,C);
}




void random_felm(felm_t a)
{   // NOT UNIFORM RANDOMNESS ! BE CAREFUL !
    unsigned long long nbytes = NBITS_TO_NBYTES(MAXBITS_FIELD);

    randombytes((unsigned char *)a, nbytes);
    ((unsigned char *)(a))[nbytes - 1] &= 0x00;
    ((unsigned char *)(a))[nbytes - 2] &= 0x03;
    fpcorrection(a);
}

void random_f2elm(f2elm_t a)
{   // NOT UNIFORM RANDOMNESS ! BE CAREFUL !
    random_felm(a[0]);
    random_felm(a[1]);
}



void extract_hamming_weight(const felm_t a, const felm_t b, const felm_t c,  int hamming_weights[3][14])
{
    // Compute hamming weights of each 32bit word of a field element (tot 14)
    // To be more precise the Hamming distance from the previous word in the pipeline register is computed.
    // FROM PREVIOUS PROJECT.
    // MIGHT BE USEFUL. WE'LL SEE...

    uint32_t hwa0, hwa1, hwa2, hwa3, hwb0, hwb1, hwb2, hwb3, hwc0, hwc1, hwc2, hwc3;
    uint32_t backup = 0;



    for(int i = 0; i < 12; i+= 4)
    {
        hwa0 = ((uint32_t *) (a))[i+0];
        hwa1 = ((uint32_t *) (a))[i+1];
        hwa2 = ((uint32_t *) (a))[i+2];
        hwa3 = ((uint32_t *) (a))[i+3];

        hwb0 = ((uint32_t *) (b))[i+0];
        hwb1 = ((uint32_t *) (b))[i+1];
        hwb2 = ((uint32_t *) (b))[i+2];
        hwb3 = ((uint32_t *) (b))[i+3];

        hwc0 = ((uint32_t *) (c))[i+0];
        hwc1 = ((uint32_t *) (c))[i+1];
        hwc2 = ((uint32_t *) (c))[i+2];
        hwc3 = ((uint32_t *) (c))[i+3];


        hamming_weights[0][i+0] = hamming_weight(hwa0^backup);
        hamming_weights[0][i+1] = hamming_weight(hwa1^hwa0);
        hamming_weights[0][i+2] = hamming_weight(hwa2^hwa1);
        hamming_weights[0][i+3] = hamming_weight(hwa3^hwa2);

        hamming_weights[1][i+0] = hamming_weight(hwb0^hwa3);
        hamming_weights[1][i+1] = hamming_weight(hwb1^hwb0);
        hamming_weights[1][i+2] = hamming_weight(hwb2^hwb1);
        hamming_weights[1][i+3] = hamming_weight(hwb3^hwb2);

        hamming_weights[2][i+0] = hamming_weight(hwc0^hwb3);
        hamming_weights[2][i+1] = hamming_weight(hwc1^hwc0);
        hamming_weights[2][i+2] = hamming_weight(hwc2^hwc1);
        hamming_weights[2][i+3] = hamming_weight(hwc3^hwc2);

        backup = hwc3;
    }



    hwa0 = ((uint32_t *) (a))[12];
    hwa1 = ((uint32_t *) (a))[13];

    hwb0 = ((uint32_t *) (b))[12];
    hwb1 = ((uint32_t *) (b))[13];

    hwc0 = ((uint32_t *) (c))[12];
    hwc1 = ((uint32_t *) (c))[13];


    hamming_weights[0][12] = hamming_weight(hwa0^backup);
    hamming_weights[0][13] = hamming_weight(hwa1^hwa0);

    hamming_weights[1][12] = hamming_weight(hwb0^hwa1);
    hamming_weights[1][13] = hamming_weight(hwb1^hwb0);

    hamming_weights[2][12] = hamming_weight(hwc0);
    hamming_weights[2][13] = hamming_weight(hwc1^hwc0);
}











void sqrt_Fp2(const f2elm_t u, f2elm_t y)
{   // Computes square roots of elements in (Fp2)^2 using Hamburg's trick. 
    felm_t t0, t1, t2, t3;
    digit_t *a  = (digit_t*)u[0], *b  = (digit_t*)u[1];
    unsigned int i;

    fpsqr_mont(a, t0);                          // t0 = a^2
    fpsqr_mont(b, t1);                          // t1 = b^2
    fpadd(t0, t1, t0);                          // t0 = t0+t1
    fpcopy(t0, t1);
    for (i = 0; i < OALICE_BITS - 2; i++)       // t = t3^((p+1)/4) = sqrt(t3)
        fpsqr_mont(t1, t1);
    for (i = 0; i < OBOB_EXPON; i++) {
        fpsqr_mont(t1, t2);
        fpmul_mont(t1, t2, t1);
    }  
    fpadd(a, t1, t0);                           // t0 = a+t1
    fpdiv2(t0, t0);                             // t0 = t0/2
    fpcopy(t0, t2);
    fpinv_chain_mont(t2);                       // t2 = t0^((p-3)/4)
    fpmul_mont(t0, t2, t1);                     // t1 = t2*t0
    fpmul_mont(t2, b, t2);                      // t2 = t2*b
    fpdiv2(t2, t2);                             // t2 = t2/2
    fpsqr_mont(t1, t3);                         // t3 = t1^2
    fpcorrection(t0);
    fpcorrection(t3);

    if (memcmp(t0, t3, NBITS_TO_NBYTES(NBITS_FIELD)) == 0) {
        fpcopy(t1, y[0]);
        fpcopy(t2, y[1]);
    } else {
        fpneg(t1);
        fpcopy(t2, y[0]);
        fpcopy(t1, y[1]);
    }
}

int is_sqr_fp2(const f2elm_t a) 
{   // Test if a is square in GF(p^2) and return 1 if true, 0 otherwise
    int i;
    felm_t a0,a1,z,temp, s;
    
    fpsqr_mont(a[0], a0);
    fpsqr_mont(a[1], a1);
    fpadd(a0, a1, z);                       // z = a[0]^2 + a[1]^2   (is a square in Fp iff a is in Fp2)
    
    fpcopy(z, s);
    for (i = 0; i < OALICE_BITS - 2; i++)           
        fpsqr_mont(s, s);
    for (i = 0; i < OBOB_EXPON; i++) {
        fpsqr_mont(s, temp);
        fpmul_mont(s, temp, s);
    }                                       // s = z^((p+1)/4)
    fpsqr_mont(s, temp);                    // temp = z^((p+1)/2) = = z^((p-1)/2 + 1) = legendre(z,p)*z
    fpcorrection(temp);          
    fpcorrection(z);
    if (memcmp((unsigned char*)temp, (unsigned char*)z, NBITS_TO_NBYTES(NBITS_FIELD)) != 0)  // s^2 !=? z
        return 0;
    
    return 1;
}

static void swap_full_points(point_full_proj_t P, point_full_proj_t Q, const digit_t option)
{   // Swap points.
  // If option = 0 then P <- P and Q <- Q, else if option = 0xFF...FF then P <- Q and Q <- P
    digit_t temp;
    unsigned int i;

    for (i = 0; i < NWORDS_FIELD; i++) {
        temp = option & (P->X[0][i] ^ Q->X[0][i]);
        P->X[0][i] = temp ^ P->X[0][i]; 
        Q->X[0][i] = temp ^ Q->X[0][i];  
        temp = option & (P->X[1][i] ^ Q->X[1][i]);
        P->X[1][i] = temp ^ P->X[1][i]; 
        Q->X[1][i] = temp ^ Q->X[1][i];
        temp = option & (P->Y[0][i] ^ Q->Y[0][i]);
        P->Y[0][i] = temp ^ P->Y[0][i]; 
        Q->Y[0][i] = temp ^ Q->Y[0][i];
        temp = option & (P->Y[1][i] ^ Q->Y[1][i]);
        P->Y[1][i] = temp ^ P->Y[1][i]; 
        Q->Y[1][i] = temp ^ Q->Y[1][i]; 
        temp = option & (P->Z[0][i] ^ Q->Z[0][i]);
        P->Z[0][i] = temp ^ P->Z[0][i]; 
        Q->Z[0][i] = temp ^ Q->Z[0][i];
        temp = option & (P->Z[1][i] ^ Q->Z[1][i]);
        P->Z[1][i] = temp ^ P->Z[1][i]; 
        Q->Z[1][i] = temp ^ Q->Z[1][i]; 
    }
}

void complete_full_point(const point_proj_t P, const f2elm_t A, point_full_proj_t R)
{   // Given an [X:Z] representation on a Montgomery curve, compute its affine representation 
    // Output: [XZ:YZ:ZZ]
    f2elm_t t0 = {0}, zero = {0}, one = {0};

    // 
    // xR = xP * zP
    // yR = yP * zP         --> In order to avoid divisions we multiply with zP. A random square root is provided for yR
    // zR = zP * zP



    fpcopy((digit_t*)&Montgomery_one, one[0]);    

    if (f2elm_is_zero(P->Z)) 
    {
        fp2copy(zero, R->X);
        fp2copy(one, R->Y); 
        fp2copy(zero, R->Z);                // R = EM!0;
    }
    else
    {
        fp2mul_mont(P->X, P->Z, R->X);      // xR = xP * zP
        fp2sqr_mont(P->Z, R->Z);            // zR = zP * zP
        fp2mul_mont(A, P->Z, t0);           // t0 = A * zP
        fp2add(t0, P->X, t0);               // t0 = xP + A * zP
        fp2mul_mont(t0, P->X, t0);          // t0 = xP^2 + A * xP * zP
        fp2add(R->Z, t0, t0);               // t0 = xP^2 + A * xP * zP + zP^2
        fp2mul_mont(t0, R->X, t0);          // t0 = xP * zP * (xP^2 + A * xP * zP + zP^2)
        sqrt_Fp2(t0, R->Y);                 // yR = yP * zP = sqrt(xP * zP * (xP^2 + A * xP * zP + zP^2))

        // Uncomment if you wish X and Z coordinates to stay the same
        // fp2copy(P->Z, t0);               // t0 = zP
        // fp2inv_mont(t0);                 // t0 = 1/zP
        // fp2copy(P->X, R->X);             // xR = xP
        // fp2mul_mont(R->Y, t0, R->X);     // yR = yP
        // fp2copy(P->X, R->Z);             // zR = zP

    }
}

void DBL(const point_full_proj_t P, const f2elm_t A24, point_full_proj_t R)
{   // General doubling.
    // Input: projective Montgomery point P=[xP:yP:zP]
    // Output: projective Montgomery point R <- [2]P = [xR:yR:zR]. 

    // General case formula : (Special formulas used for special input points P in the 2-torsion)
    // xR = 2 * yP * zP * (xP^2 - zP^2)^2
    // yR = (xP^2 - zP^2) * ((xP - zP)^4 + 2 * ((A+2)/4) * 4 * xP * zP * (xP^2 + zP^2))
    // zR = 2 * yP * zP * 4 * xP * zP * ((xP - zP)^2 + ((A+2)/4) * 4 * xP * zP)

    f2elm_t t0, t1, t2, t3, t4, zero = {0}, one = {0};
    fpcopy((digit_t*)&Montgomery_one, one[0]);    

    if (f2elm_is_zero(P->Z) || f2elm_is_zero(P->Y))
    {    
        fp2copy(zero, R->X);
        fp2copy(one, R->Y); 
        fp2copy(zero, R->Z);
    }
    else
    {
    fp2sub(P->X, P->Z, t0);             // t0 = xP - zP
    fp2add(P->X, P->Z, t1);             // t1 = xP + zP
    fp2mul_mont(t0, t1, t2);            // t2 = (xP^2 - zP^2)
    fp2sqr_mont(t0, t0);                // t0 = (xP - zP)^2
    fp2sqr_mont(t1, t1);                // t1 = (xP + zP)^2
    fp2mul_mont(P->Y, P->Z, t3);        // t3 = yP * zP
    fp2add(t3, t3, t3);                 // t3 = 2 * yP * zP
    fp2sqr_mont(t2, R->X);              // xR = (xP^2 - zP^2)^2
    fp2mul_mont(R->X, t3, R->X);        // xR = 2 * yP * zP * (xP^2 - zP^2)^2
    fp2sub(t1, t0, t1);                 // t1 = 4 * xP * zP
    fp2mul_mont(t1, t3, t3);            // t3 = 2 * yP * zP * 4 * xP * zP
    fp2div2(t1, t4);                    // t4 = 2 * xP * zP
    fp2add(t0, t4, t4);                 // t5 = (xP^2 + zP^2)
    fp2mul_mont(t1, A24, t1);           // t1 = ((A+2)/4) * 4 * xP * zP
    fp2add(t1, t0, R->Z);               // zR = (xP - zP)^2 + ((A+2)/4) * 4 * xP * zP
    fp2mul_mont(R->Z, t3, R->Z);        // zR = 2 * yP * zP * 4 * xP * zP * ((zP - xP)^2 + ((A+2)/4) * 4 * xP * zP)
    fp2add(t1, t1, t1);                 // t1 = 2 * ((A+2)/4) * 4 * xP * zP
    fp2mul_mont(t1, t4, t1);            // t1 = 2 * ((A+2)/4) * 4 * xP * zP * (xP^2 + zP^2)
    fp2sqr_mont(t0, t0);                // t0 = (xP - zP)^4
    fp2add(t0, t1, t0);                 // t0 = (xP - zP)^4 + 2 * ((A+2)/4) * 4 * xP * zP * (xP^2 + zP^2)
    fp2mul_mont(t0, t2, R->Y);          // yR = (xP^2 - zP^2) * ((xP - zP)^4 + 2 * ((A+2)/4) * 4 * xP * zP * (zP^2 + xP^2))
    }
}

void DBL_e(const point_full_proj_t P, const f2elm_t A24, const int e, point_full_proj_t R)
{   // Computes [2^e][X:Y:Z] on Montgomery curve with constant A via e repeated doublings.
    // Input: projective Montgomery P = [XP:YP:ZP], with Montgomery curve constant A.
    // Output: projective Montgomery R = [XR:YR:ZP] = [2^e]P.
    copy_full_point(P, R);
    for(int i = 0; i < e; i++)
        DBL(R, A24, R);
}

void ADD(const point_full_proj_t P, const point_full_proj_t Q, const f2elm_t A24, point_full_proj_t R)
{   // General addition.
    // Input: projective Montgomery points P=(XP:YP:ZP) and Q=(XQ:YQ:ZQ).
    // Output: projective Montgomery point R <- P+Q = (XQP:YQP:ZQP). 
    
    // General case formula : (Special formulas used for special input points P,Q = [0:1:0], P,Q = [0:0:1] or P=±Q)
    // xR : zP * zQ * (xP * zQ - xQ * zP) * (xP * yQ - xQ * yP)^2
    // yP : - (xP * yQ - xQ * yP) * (zP * zQ * (yP * zQ - yQ * zP) * (xP * yQ - xQ * yP) + xP * xQ * (xP * zQ - xQ * zP)^2)
    // zP : xP * xQ * (xP * zQ - xQ * zP)^3

    f2elm_t t0 = {0}, t1 = {0}, t2 = {0}, t3 = {0}, t4 = {0}, t5 = {0}, t6 = {0}, t7 = {0}, zero = {0};

    fp2mul_mont(P->X, Q->Z, t0);            // t0 = xP * zQ
    fp2mul_mont(Q->X, P->Z, t1);            // t1 = xQ * zP
    fp2sub(t0, t1, t0);                     // t0 = xP * zQ - xQ * zP
    fp2mul_mont(P->Y, Q->Z, t2);            // t2 = yP * zQ
    fp2mul_mont(Q->Y, P->Z, t3);            // t3 = zP * yQ
    fp2sub(t2, t3, t2);                     // t2 = yP * zQ - zP * yQ

    if(f2elm_is_zero(P->Z))                   // P = [0:1:0]
        copy_full_point(Q,R);
    else if(f2elm_is_zero(Q->Z))              // Q = [0:1:0]
        copy_full_point(P,R);
    else if(f2elm_is_zero(t0))                // P = ±Q
            if(f2elm_is_zero(t2))             // P = Q
                DBL(P, A24, R);
            else                            // P = - Q
            {
                fp2copy(zero, R->X);
                fp2copy(zero, R->Y);
                fp2copy(zero, R->Z);
                fpcopy((digit_t *)&Montgomery_one, (R->Y)[0]);
            }
    else if(f2elm_is_zero(P->X))              // P = [0:0:1]
        {
            fp2sqr_mont(Q->X, t3);          // t3 = xQ^2
            fp2mul_mont(Q->Z, Q->X, R->X);  // xR = xQ * zQ
            fp2mul_mont(Q->Z, Q->Y, R->Y);  // yR = yQ * zQ
            fp2neg(R->Y);                   // yR = - yQ * zQ
            fp2copy(t3, R->Z);              // zR = xP^2
        }        
    else if (f2elm_is_zero(Q->X))             // Q = [0:0:1]
        {   
            fp2sqr_mont(P->X, t3);          // t3 = xP^2
            fp2mul_mont(P->Z, P->X, R->X);  // xR = xP * zP
            fp2mul_mont(P->Z, P->Y, R->Y);  // yR = yP * zP
            fp2neg(R->Y);                   // yR = - yP * zP
            fp2copy(t3, R->Z);              // zR = xP^2
        }
    else                                    // GENERAL CASE
    {
        fp2mul_mont(P->X, Q->X, t3);        // t3 = xP * xQ
        fp2sqr_mont(t0, t1);                // t1 = (xP * zQ - xQ * zP)^2
        fp2mul_mont(t1, t3, t1);            // t1 = xP * xQ * (xP * zQ - xQ * zP)^2
        fp2mul_mont(P->X, Q->Y, t4);        // t4 = xP * yQ
        fp2mul_mont(P->Y, Q->X, t5);        // t5 = yP * xQ
        fp2sub(t4, t5, t4);                 // t4 = xP * yQ - yP * xQ
        fp2mul_mont(P->Z, Q->Z, t5);        // t5 = zP * zQ
        fp2mul_mont(t5, t4, t6);            // t6 = zP * zQ * (xP * yQ - yP * xQ)
        fp2mul_mont(t6, t2, t7);            // t7 = zP * zQ * (xP * yQ - yP * xQ) * (yP * zQ - zP * yQ)
        fp2add(t7, t1, t7);                 // t7 = xP * xQ * (xP * zQ - xQ * zP)^2 + zP * zQ * (xP * yQ - yP * xQ) * (yP * zQ - zP * yQ)
        fp2mul_mont(t7, t4, R->Y);          // yR = (xP * yQ - xQ * yP) * (zP * zQ * (yP * zQ - yQ * zP) * (xP * yQ - xQ * yP) + xP * xQ * (xP * zQ - xQ * zP)^2)
        fp2neg(R->Y);                       // yR = - (xP * yQ - xQ * yP) * (zP * zQ * (yP * zQ - yQ * zP) * (xP * yQ - xQ * yP) + xP * xQ * (xP * zQ - xQ * zP)^2)
        fp2mul_mont(t1, t0, R->Z);          // zR = xP * xQ * (xP * zQ - xQ * zP)^3
        fp2mul_mont(t6, t4, t6);            // t6 = zP * zQ * (xP * yQ - yP * xQ)^2
        fp2mul_mont(t6, t0, R->X);          // xR = zP * zQ * (xP * zQ - xQ * zP) * (xP * yQ - yP * xQ)^2
    }
}

void random_full_torsion_point(const f2elm_t A, const f2elm_t A24plus, const f2elm_t A24minus, const f2elm_t C24, const unsigned int AliceOrBob, point_full_proj_t R)
{
    point_proj_t P = {0}, Q = {0};
    f2elm_t t0, one = {0};
    int flag = 1;

    fpcopy((digit_t*)&Montgomery_one, one[0]);

    // Test the order of the point, be sure that it generates the full torsion;
    while(flag)
    {
        fp2copy(one, P->Z);
        // Compute random point, make sure it is on the curve
        while(flag) 
        {
            random_f2elm(P->X);

            // Check that X^3 + A*X^2 + X is a square -> point can be extended to y coordinate
            fp2add(P->X, A, t0);
            fp2mul_mont(t0, P->X, t0);
            fp2add(t0, one, t0);
            fp2mul_mont(t0, P->X, t0);

            if(is_sqr_fp2(t0))
                flag = 0;
        }
            
        
        if(AliceOrBob == ALICE)
        {
            xTPLe(P, P, A24minus, A24plus, OBOB_EXPON);             // REMOVE 3-TORSION
            xDBLe(P, Q, A24plus, C24, (int)(OALICE_BITS) - 1);      // CHECK IF 2-ORDER IS MAXIMAL
        }
        else
        {
            xDBLe(P, P, A24plus, C24, OALICE_BITS);                 // REMOVE 2-TORSION
            xTPLe(P, Q, A24minus, A24plus, (int)(OBOB_EXPON) - 1);  // CHECK IF 3-ORDER IS MAXIMAL
        }
        
        if(f2elm_is_zero(Q->Z))         // Check for maximality done here
            flag = 1;

    }

    complete_full_point(P, A, R);
}

static void SCALARMULT(const point_full_proj_t inP, const digit_t* m, const int nbits, const f2elm_t A24, point_full_proj_t P)
{   // INPUT: [X:Y:Z] coordinates of Q
    // OUT: [X:Y:Z] coordinates of [m]Q

    point_full_proj_t R0 = {0}, R1 = {0};
    digit_t mask;
    int i, bit, swap, prevbit = 0;

    fpcopy((digit_t*)&Montgomery_one, R0->Y[0]);
    copy_full_point(inP, R1);

    // Main loop
    for (i = nbits - 1; i >= 0; i--) {
        bit = (m[i >> LOG2RADIX] >> (i & (RADIX-1))) & 1;
        swap = bit ^ prevbit;
        prevbit = bit;
        mask = 0 - (digit_t)swap;

        swap_full_points(R0, R1, mask);
        ADD(R0, R1, A24, R1);
        DBL(R0, A24, R0);
    }

    swap = 0 ^ prevbit;
    mask = 0 - (digit_t)swap;
    swap_full_points(R0, R1, mask);

    copy_full_point(R0, P);  
}

void recover_y_OS(const point_proj_t Q, const point_proj_t P, const point_full_proj_t PQ, const f2elm_t A, point_full_proj_t QQ)
{   // Okeya-Sakurai y coordinate extraction algorithm
    // INPUT: [X:Y] coordinates of Q and P and [X:Y:Z] coordinates of P - Q = - (Q - P)     (NOT A MONTGOMERY TRIPLE)
    // OUTPUT: [X:Y:Z] coordinates of Q


    f2elm_t t0, t1, t2, t3, t4, zero = {0}, one = {0};
    fpcopy((digit_t *)&Montgomery_one, one[0]);
    
    // QQ->X := 2 * PQ->Z * PQ->Y * Q->Z * P->Z * Q->X;
    // QQ->Y := P->Z * ((PQ->Z * Q->X + PQ->X * Q->Z + 2 * A * PQ->Z * Q->Z) * (PQ->X * Q->X + PQ->Z * Q->Z) - 2 * A * (PQ->Z * Q->Z)^2) - (PQ->Z * Q->X - PQ->X * Q->Z)^2 * P->X ;
    // QQ->Z := 2 * PQ->Z * PQ->Y * Q->Z * P->Z * Q->Z;

    if(f2elm_is_zero(Q->Z))             // Q = [1:0] -> QQ = [0:1:0]
    {
        fp2copy(zero, QQ->X);
        fp2copy(one, QQ->Y);
        fp2copy(zero, QQ->Z);
    }
    else if(f2elm_is_zero(Q->X))        // Q = [0:1] -> QQ = [0:0:1]
    {
        fp2copy(zero, QQ->X);
        fp2copy(zero, QQ->Y);
        fp2copy(one, QQ->Z);
    }
    else if(f2elm_is_zero(P->Z))        // P = [1:0] -> P = [0:1:0] -> Q = -PQ -> QQ = -PQ
    {
        copy_full_point(PQ, QQ);
        fp2neg(QQ->Y);
    }
    else 
    {
        fp2add(PQ->Y, PQ->Y, t0);                   // t0   = 2 * PQ->Y
        fp2mul_mont(t0, Q->Z, t0);                  // t0   = 2 * PQ->Y * Q->Z
        fp2mul_mont(t0, P->Z, t0);                  // t0   = 2 * PQ->Y * Q->Z * P->Z
        fp2mul_mont(t0, Q->Z, QQ->Z);               // Q->Z = 2 * PQ->Y * Q->Z * P->Z * Q->Z
        fp2mul_mont(QQ->Z, PQ->Z, QQ->Z);           // Q->Z = 2 * PQ->Y * PQ->Z * Q->Z * P->Z * Q->X
        fp2mul_mont(t0, Q->X, QQ->X);               // Q->X = 2 * PQ->Y * Q->Z * P->Z * Q->X
        fp2mul_mont(QQ->X, PQ->Z, QQ->X);           // Q->X = 2 * PQ->Y * PQ->Z * Q->Z * P->Z * Q->X
        fp2mul_mont(PQ->Z, Q->Z, t0);               // t0   = PQ->Z * Q->Z  
        fp2add(A, A, t1);                           // t1   = 2 * A
        fp2mul_mont(t0, t1, t1);                    // t1   = 2 * A * PQ->Z * Q->Z  
        fp2mul_mont(PQ->X, Q->Z, t2);               // t2   = PQ->X * Q->Z 
        fp2mul_mont(PQ->Z, Q->X, t3);               // t3   = PQ->Z * Q->X 
        fp2add(t2, t3, t4);                         // t4   = PQ->Z * Q->X + PQ->X * Q->Z
        fp2add(t4, t1, t4);                         // t4   = PQ->Z * Q->X + PQ->X * Q->Z + 2 * A * z * Q->Z
        fp2sub(t3, t2, t3);                         // t1   = PQ->Z * Q->X - PQ->X * Q->Z
        fp2mul_mont(PQ->X, Q->X, t2);               // t2   = PQ->X * Q->X 
        fp2add(t2, t0, t2);                         // t2   = PQ->X * Q->X  +  PQ->Z * Q->Z
        fp2mul_mont(t1, t0, t1);                    // t1   = 2 * A * (PQ->Z * Q->Z)^2 
        fp2mul_mont(t4, t2, t4);                    // t4   = (PQ->Z * Q->X + PQ->X * Q->Z + 2 * A * PQ->Z * Q->Z) * (PQ->X * Q->X + PQ->Z * Q->Z)
        fp2sub(t4, t1, t4);                         // t4   = (PQ->Z * Q->X + PQ->X * Q->Z + 2 * A * PQ->Z * Q->Z) * (PQ->X * Q->X + PQ->Z * Q->Z) - 2 * A * (PQ->Z * Q->Z)^2
        fp2mul_mont(t4, P->Z, t4);                  // t4   = P->Z * ((PQ->Z * Q->X + PQ->X * Q->Z + 2 * A * PQ->Z * Q->Z) * (PQ->X * Q->X + PQ->Z * Q->Z) - 2 * A * (PQ->Z * Q->Z)^2)
        fp2sqr_mont(t3, t3);                        // t3   = (PQ->Z * Q->X - PQ->X * Q->Z)^2
        fp2mul_mont(t3, P->X, t3);                  // t3   = (PQ->Z * Q->X - PQ->X * Q->Z)^2  *  P->X
        fp2sub(t4, t3, QQ->Y);                      // Q->Y = P->Z * ((PQ->Z * Q->X + PQ->X * Q->Z + 2 * A * PQ->Z * Q->Z) * (PQ->X * Q->X + PQ->Z * Q->Z) - 2 * A * (PQ->Z * Q->Z)^2) - (PQ->Z * Q->X - PQ->X * Q->Z)^2 * X2
    }
}

void complete_full_triple(const point_proj_t Q, const point_proj_t P, const point_proj_t QP, const f2elm_t A, const f2elm_t A24, point_full_proj_t QF, point_full_proj_t PF, point_full_proj_t QPF)
{
    point_full_proj_t O = {0}, V = {0};
    fpcopy((digit_t *)&Montgomery_one, (O->Y)[0]);  // O = [0:1:0] identity elemeny
    fpcopy((digit_t *)&Montgomery_one, (V->Z)[0]);  // V = [0:0:1] point of order two; V = -V

         if(f2elm_is_zero(Q->Z))            // Q = [0:1:0] -> Q - P = -P
    {
        copy_full_point(O, QF);
        complete_full_point(P, A, PF);
        copy_full_point(PF, QPF);
        fp2neg(QPF->Y);
    }
    else if(f2elm_is_zero(P->Z))            // P = [0:1:0] -> Q - P = Q
    {
        copy_full_point(O, PF);
        complete_full_point(Q, A, QF);
        copy_full_point(QF, QPF);
    }
    else if(f2elm_is_zero(QP->Z))           // QP = [0:1:0] -> Q = P
    {
        copy_full_point(O, QPF);
        complete_full_point(Q, A, QF);
        copy_full_point(QF, PF);
    }
    else if(f2elm_is_zero(Q->X))            // Q = [0:0:1] -> Q - P = -(P - [0:0:1]) = -P + V
    {
        copy_full_point(V, QF);
        complete_full_point(P, A, PF);
        copy_full_point(PF, QPF);
        fp2neg(QPF->Y);
        ADD(QPF, V, A24, QPF);
    }
    else if(f2elm_is_zero(P->X))            // P = [0:0:1] -> Q - P = Q - V = Q + V
    {
        copy_full_point(V, PF);
        complete_full_point(Q, A, QF);
        ADD(QF, V, A24, QPF);
    }
    else if(f2elm_is_zero(QP->X))           // QP = [0:0:1] -> Q = P + V; P = Q + V
    {
        copy_full_point(V, QPF);
        complete_full_point(Q, A, QF);
        ADD(QF, V, A24, PF);
    }
    else 
    {
        complete_full_point(Q, A, QF);      // QF  = Q
        recover_y_OS(QP, P, QF, A, QPF);    // QPF = -QP
        fp2neg(QPF->Y);                     // QPF = QP
        recover_y_OS(P, Q, QPF, A, PF);     // PF  = P
    }
}











////////////////////////////////////////////// 3 2 - B I T    F U N C T I O N S //////////////////////////////////////////////








// NOT SURE IF 64-BIT VERSIONS OF FPMUL_MONT, FPSQR_MONT, FPSUB, AND FPADD ARE THE SAME AS 32-BIT VERSION, OR IF THEY CAN BE PORTED
// FOR MP_ADDFAST IT SEEMS TO BE TRUE
// FOR NOW ASSUME THAT THE OUTPUT IS ALWAYS THE SAME

// IGNORE FOR NOW
// static void fp2_encode_32(const f2elm_t x, unsigned char *enc)
// {   // Conversion of GF(p^2) element from Montgomery to standard representation, and encoding by removing leading 0 bytes
//     unsigned int i;
//     f2elm_t t;

//     from_fp2mont(x, t);
//     for (i = 0; i < FP2_ENCODED_BYTES / 2; i++) {
//         enc[i] = ((unsigned char*)t)[i];
//         enc[i + FP2_ENCODED_BYTES / 2] = ((unsigned char*)t)[i + MAXBITS_FIELD / 8];
//     }
// }
//
// IGNORE FOR NOW
// static void fp2_decode_32(const unsigned char *enc, f2elm_t x)
// {   // Parse byte sequence back into GF(p^2) element, and conversion to Montgomery representation
//     unsigned int i;

//     for (i = 0; i < 2*(MAXBITS_FIELD / 8); i++) ((unsigned char *)x)[i] = 0;
//     for (i = 0; i < FP2_ENCODED_BYTES / 2; i++) {
//         ((unsigned char*)x)[i] = enc[i];
//         ((unsigned char*)x)[i + MAXBITS_FIELD / 8] = enc[i + FP2_ENCODED_BYTES / 2];
//     }
//     to_fp2mont(x, x);
// }


void fp2sqr_mont_32(const f2elm_t a, f2elm_t c)
{   // GF(p^2) squaring using Montgomery arithmetic, c = a^2 in GF(p^2).
    // Inputs: a = a0+a1*i, where a0, a1 are in [0, 2*p-1] 
    // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1] 
    felm_t t1, t2, t3;
    
    mp_addfast(a[0], a[1], t1);                      // t1 = a0 + a1
    fpsub(a[0], a[1], t2);                           // t2 = a0 - a1 - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    mp_addfast(a[0], a[0], t3);                      // t3 = 2 * a0
    fpmul_mont(t1, t2, c[0]);                        // c0 = (a0 + a1) * (a0 - a1)
    fpmul_mont(t3, a[1], c[1]);                      // c1 = 2 * a0 * a1
}

void fp2mul_mont_32(const f2elm_t a, const f2elm_t b, f2elm_t c)
{   // GF(p^2) multiplication using Montgomery arithmetic, c = a*b in GF(p^2).
    // Inputs: a = a0+a1*i and b = b0+b1*i, where a0, a1, b0, b1 are in [0, 2*p-1] 
    // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1] 

    // This code is changed by me. If you want original, uncomment below.
    felm_t t1, t2;
    dfelm_t tt2; 

    // This is original code. For some unknown reason it has unused variables
    // felm_t t1, t2;
    // dfelm_t tt1, tt2, tt3; 
    // digit_t mask;
    // unsigned int i;
    
    mp_addfast(a[0], a[1], t1);                     // t1  = a0 + a1
    mp_addfast(b[0], b[1], t2);                     // t2  = b0 + b1
    
    fpmul_mont(a[0], b[0], c[0]);                   // c0  = a0 * b0 - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fpmul_mont(a[1], b[1], tt2);                    // tt2 = a1 * b1 - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fpmul_mont(t1, t2, c[1]);                       // c1  = (a0 + a1) * (b0 + b1) - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    
    fpsub(c[1],c[0],c[1]);                          // c1  = a1 * b1 + a0 * b1 + a1 * b0 - - - - - DIFFERENT FROM 64-BIT VERSION
    fpsub(c[1],tt2,c[1]);                           // c1  = a0 * b1 + a1 * b0 - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fpsub(c[0],tt2,c[0]);                           // c0  = a0 * b0 - a1 * b1 - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
}

void fpinv_chain_mont_32(felm_t a)
{   // Field inversion using Montgomery arithmetic, a = a^-1*R mod p
    // DIFFERENT FROM 64-BIT VERSION
    unsigned int i, j;

#if (NBITS_FIELD == 434)
    
    felm_t t[20], tt;
   
    // Precomputed table
    fpsqr_mont(a, tt);
    fpmul_mont(tt, tt, t[0]);
    fpmul_mont(t[0], tt, t[0]);
    fpmul_mont(a, t[0], t[0]);
    fpmul_mont(t[0], tt, t[1]);
    fpmul_mont(t[1], tt, t[1]);
    fpmul_mont(t[1], tt, t[2]);
    fpmul_mont(t[2], tt, t[3]);
    fpmul_mont(t[3], tt, t[4]);
    fpmul_mont(t[4], tt, t[4]);
    fpmul_mont(t[4], tt, t[4]); 
    for (i = 4; i <= 6; i++) fpmul_mont(t[i], tt, t[i+1]);
    fpmul_mont(t[7], tt, t[7]);
    for (i = 7; i <= 8; i++) fpmul_mont(t[i], tt, t[i+1]);
    fpmul_mont(t[9], tt, t[9]);
    fpmul_mont(t[9], tt, t[10]);
    fpmul_mont(t[10], tt, t[10]);
    for (i = 10; i <= 12; i++) fpmul_mont(t[i], tt, t[i+1]);
    fpmul_mont(t[13], tt, t[13]);
    for (i = 13; i <= 17; i++) fpmul_mont(t[i], tt, t[i+1]);
    fpmul_mont(t[18], tt, t[18]);
    fpmul_mont(t[18], tt, t[18]);
    fpmul_mont(t[18], tt, t[19]);


    fpcopy(a, tt);
    for(i = 0; i < 7; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for(i = 0; i < 10; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[8], tt, tt);
    for(i = 0; i < 8; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for(i = 0; i < 8; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for(i = 0; i < 4; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for(i = 0; i < 6; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for(i = 0; i < 9; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[9], tt, tt);
    for(i = 0; i < 7; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[15], tt, tt);
    for(i = 0; i < 4; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for(i = 0; i < 9; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[13], tt, tt);
    for(i = 0; i < 5; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[7], tt, tt);
    for(i = 0; i < 5; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for(i = 0; i < 9; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for(i = 0; i < 9; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for(i = 0; i < 12; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[12], tt, tt);
    for(i = 0; i < 8; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[18], tt, tt);
    for(i = 0; i < 3; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for(i = 0; i < 8; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for(i = 0; i < 4; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for(i = 0; i < 7; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for(i = 0; i < 11; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[14], tt, tt);
    for(i = 0; i < 5; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[1], tt, tt);
    for(i = 0; i < 9; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[12], tt, tt);
    for(i = 0; i < 5; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[4], tt, tt);
    for(i = 0; i < 9; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[19], tt, tt);
    for(i = 0; i < 6; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[17], tt, tt);
    for(i = 0; i < 10; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for(i = 0; i < 7; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[15], tt, tt);
    for(i = 0; i < 6; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[16], tt, tt);
    for(i = 0; i < 6; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[14], tt, tt);
    for(i = 0; i < 7; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[19], tt, tt);
    for(j = 0; j < 34; j++){
        for(i = 0; i < 6; i++)fpsqr_mont(tt, tt);
        fpmul_mont(t[19], tt, tt);
    }
    for(i = 0; i < 6; i++)fpsqr_mont(tt, tt);
    fpmul_mont(t[18], tt, a);
return;

#elif (NBITS_FIELD == 503)
    felm_t t[15], tt;

    // Precomputed table
    fpsqr_mont(a, tt);
    fpmul_mont(a, tt, t[0]);
    for (i = 0; i <= 13; i++) fpmul_mont(t[i], tt, t[i+1]);

    fpcopy(a, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[8], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[9], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[8], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 12; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[12], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[8], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[12], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[14], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[14], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[8], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[4], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[7], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[13], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[1], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (j = 0; j < 49; j++) {
        for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
        fpmul_mont(t[14], tt, tt);
    }
    fpcopy(tt, a);  

#elif (NBITS_FIELD == 610)
    felm_t t[31], tt;

    // Precomputed table
    fpsqr_mont(a, tt);
    fpmul_mont(a, tt, t[0]);
    for (i = 0; i <= 29; i++) fpmul_mont(t[i], tt, t[i+1]);

    fpcopy(a, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[30], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[25], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[28], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[7], tt, tt);
    for (i = 0; i < 11; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[16], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[24], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[28], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[16], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[4], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[20], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[14], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[15], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[15], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[19], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[9], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[27], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[28], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[29], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[1], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[30], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[25], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[28], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[22], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[22], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[7], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[9], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[4], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[20], tt, tt);
    for (i = 0; i < 11; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[26], tt, tt);
    for (i = 0; i < 11; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (j = 0; j < 50; j++) {
        for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
        fpmul_mont(t[30], tt, tt);
    }
    fpcopy(tt, a);    

#elif (NBITS_FIELD == 751)
    felm_t t[27], tt;
    
    // Precomputed table
    fpsqr_mont(a, tt);
    fpmul_mont(a, tt, t[0]);
    fpmul_mont(t[0], tt, t[1]);
    fpmul_mont(t[1], tt, t[2]);
    fpmul_mont(t[2], tt, t[3]); 
    fpmul_mont(t[3], tt, t[3]);
    for (i = 3; i <= 8; i++) fpmul_mont(t[i], tt, t[i+1]);
    fpmul_mont(t[9], tt, t[9]);
    for (i = 9; i <= 20; i++) fpmul_mont(t[i], tt, t[i+1]);
    fpmul_mont(t[21], tt, t[21]); 
    for (i = 21; i <= 24; i++) fpmul_mont(t[i], tt, t[i+1]); 
    fpmul_mont(t[25], tt, t[25]);
    fpmul_mont(t[25], tt, t[26]);

    fpcopy(a, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[20], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[24], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[8], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[23], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 10; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[15], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[13], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[26], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[20], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[14], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[4], tt, tt);
    for (i = 0; i < 10; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[18], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[1], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[22], tt, tt);
    for (i = 0; i < 10; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[24], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[9], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[18], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[17], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 10; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[16], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[7], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[12], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[19], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[22], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[25], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[22], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[18], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[4], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[14], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[13], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[23], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[21], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[23], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[12], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[9], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[13], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[17], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[26], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[8], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[20], tt, tt);
    for (j = 0; j < 61; j++) {
        for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
        fpmul_mont(t[26], tt, tt);
    }
    fpcopy(tt, a);
#endif
}

void fpinv_mont_32(felm_t a)
{   // Field inversion using Montgomery arithmetic, a = a^(-1)*R mod p.
#if (NBITS_FIELD == 434)
    fpinv_chain_mont_32(a); //- - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
#else
    felm_t tt;

    fpcopy(a, tt);
    fpinv_chain_mont_32(tt);
    fpsqr_mont(tt, tt);
    fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, a);
#endif
}

void fp2inv_mont_32(f2elm_t a)
{   // GF(p^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2).   
    f2elm_t t1;

    fpsqr_mont(a[0], t1[0]);                            // t10 = a0^2
    fpsqr_mont(a[1], t1[1]);                            // t11 = a1^2
    fpadd(t1[0], t1[1], t1[0]);                         // t10 = a0^2 + a1^2
    fpinv_mont_32(t1[0]);                               // t10 = (a0^2 + a1^2)^(-1) - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fpneg(a[1]);                                        // a = a0 - i * a1
    fpmul_mont(a[0], t1[0], a[0]);                      //
    fpmul_mont(a[1], t1[0], a[1]);                      // a = (a0 - i * a1) * (a0^2 + a1^2)^(-1)
}


void get_A_32(const f2elm_t xP, const f2elm_t xQ, const f2elm_t xR, f2elm_t A)
{   // Given the x-coordinates of P, Q, and R, returns the value A corresponding to the Montgomery curve E_A: y^2=x^3+A*x^2+x such that R=Q-P on E_A.
    // Input:  the x-coordinates xP, xQ, and xR of the points P, Q and R.
    // Output: the coefficient A corresponding to the curve E_A: y^2=x^3+A*x^2+x.
    f2elm_t t0, t1, one = {0};
    
    fpcopy((digit_t*)&Montgomery_one, one[0]);
    fp2add(xP, xQ, t1);                           // t1 = xP + xQ
    fp2mul_mont_32(xP, xQ, t0);                   // t0 = xP * xQ - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(xR, t1, A);                    // A  = xR * t1 - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t0, A, A);                             // A  = A + t0
    fp2mul_mont_32(t0, xR, t0);                   // t0 = t0 * xR - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(A, one, A);                            // A  = A - 1
    fp2add(t0, t0, t0);                           // t0 = t0 + t0
    fp2add(t1, xR, t1);                           // t1 = t1 + xR
    fp2add(t0, t0, t0);                           // t0 = t0 + t0
    fp2sqr_mont_32(A, A);                         // A  = A^2 - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2inv_mont_32(t0);                           // t0 = 1 / t0  - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(A, t0, A);                     // A  = A * t0  - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(A, t1, A);                             // Afinal = A - t1
}

void xDBL_32(const point_proj_t P, point_proj_t Q, const f2elm_t A24plus, const f2elm_t C24)
{   // Doubling of a Montgomery point in projective coordinates (X:Z).
    // Input: projective Montgomery x-coordinates P = (X1:Z1), where x1=X1/Z1 and Montgomery curve constants A+2C and 4C.
    // Output: projective Montgomery x-coordinates Q = 2*P = (X2:Z2).
    f2elm_t t0, t1;
    
    fp2sub(P->X, P->Z, t0);                         // t0 = X1-Z1 - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(P->X, P->Z, t1);                         // t1 = X1+Z1 - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(t0, t0);                         // t0 = (X1-Z1)^2 - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION 
    fp2sqr_mont_32(t1, t1);                         // t1 = (X1+Z1)^2 - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION 
    fp2mul_mont(C24, t0, Q->Z);                     // Z2 = C24*(X1-Z1)^2 - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION   
    fp2mul_mont(t1, Q->Z, Q->X);                    // X2 = C24*(X1-Z1)^2*(X1+Z1)^2 - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(t1, t0, t1);                             // t1 = (X1+Z1)^2-(X1-Z1)^2 - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION 
    fp2mul_mont(A24plus, t1, t0);                   // t0 = A24plus*[(X1+Z1)^2-(X1-Z1)^2] - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(Q->Z, t0, Q->Z);                         // Z2 = A24plus*[(X1+Z1)^2-(X1-Z1)^2] + C24*(X1-Z1)^2 - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont(Q->Z, t1, Q->Z);                    // Z2 = [A24plus*[(X1+Z1)^2-(X1-Z1)^2] + C24*(X1-Z1)^2]*[(X1+Z1)^2-(X1-Z1)^2] - - - DIFFERENT FROM 64-BIT VERSION
}

void xDBLe_32(const point_proj_t P, point_proj_t Q, const f2elm_t A24plus, const f2elm_t C24, const int e)
{ // Computes [2^e](X:Z) on Montgomery curve with projective constant via e repeated doublings.
  // Input: projective Montgomery x-coordinates P = (XP:ZP), such that xP=XP/ZP and Montgomery curve constants A+2C and 4C.
  // Output: projective Montgomery x-coordinates Q <- (2^e)*P.
    int i;
    
    copy_words((digit_t*)P, (digit_t*)Q, 2*2*NWORDS_FIELD);

    for (i = 0; i < e; i++) {
        xDBL_32(Q, Q, A24plus, C24);
    }
}

#if (OALICE_BITS % 2 == 1)

void get_2_isog_32(const point_proj_t P, f2elm_t A, f2elm_t C)
{ // Computes the corresponding 2-isogeny of a projective Montgomery point (X2:Z2) of order 2.
  // Input:  projective point of order two P = (X2:Z2).
  // Output: the 2-isogenous Montgomery curve with projective coefficients A/C.
    
    fp2sqr_mont_32(P->X, A);                        // A = X2^2 - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(P->Z, C);                        // C = Z2^2 - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(C, A, A);                                // A = Z2^2 - X2^2  - - - - - DIFFERENT FROM 64-BIT VERSION
}


void eval_2_isog_32(point_proj_t P, point_proj_t Q)
{ // Evaluates the isogeny at the point (X:Z) in the domain of the isogeny, given a 2-isogeny phi.
  // Inputs: the projective point P = (X:Z) and the 2-isogeny kernel projetive point Q = (X2:Z2).
  // Output: the projective point P = phi(P) = (X:Z) in the codomain. 
    f2elm_t t0, t1, t2, t3;
    
    fp2add(Q->X, Q->Z, t0);                         // t0 = X2+Z2 - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(Q->X, Q->Z, t1);                         // t1 = X2-Z2 - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(P->X, P->Z, t2);                         // t2 = X+Z - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(P->X, P->Z, t3);                         // t3 = X-Z - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t0, t3, t0);                     // t0 = (X2+Z2)*(X-Z) - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t1, t2, t1);                     // t1 = (X2-Z2)*(X+Z) - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t0, t1, t2);                             // t2 = (X2+Z2)*(X-Z) + (X2-Z2)*(X+Z) - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(t0, t1, t3);                             // t3 = (X2+Z2)*(X-Z) - (X2-Z2)*(X+Z) - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(P->X, t2, P->X);                 // Xfinal - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(P->Z, t3, P->Z);                 // Zfinal - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
}

#endif

void get_4_isog_32(const point_proj_t P, f2elm_t A24plus, f2elm_t C24, f2elm_t* coeff)
{ // Computes the corresponding 4-isogeny of a projective Montgomery point (X4:Z4) of order 4.
  // Input:  projective point of order four P = (X4:Z4).
  // Output: the 4-isogenous Montgomery curve with projective coefficients A+2C/4C and the 3 coefficients 
  //         that are used to evaluate the isogeny at a point in eval_4_isog().
    
    fp2sub(P->X, P->Z, coeff[1]);                   // coeff[1] = X4-Z4 - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(P->X, P->Z, coeff[2]);                   // coeff[2] = X4+Z4 - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(P->Z, coeff[0]);                 // coeff[0] = Z4^2  - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(coeff[0], coeff[0], coeff[0]);           // coeff[0] = 2*Z4^2  - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(coeff[0], C24);                  // C24 = 4*Z4^4 - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(coeff[0], coeff[0], coeff[0]);           // coeff[0] = 4*Z4^2  - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(P->X, A24plus);                  // A24plus = X4^2 - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(A24plus, A24plus, A24plus);              // A24plus = 2*X4^2 - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(A24plus, A24plus);               // A24plus = 4*X4^4 - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
}


void eval_4_isog_32(point_proj_t P, f2elm_t* coeff)
{ // Evaluates the isogeny at the point (X:Z) in the domain of the isogeny, given a 4-isogeny phi defined 
  // by the 3 coefficients in coeff (computed in the function get_4_isog()).
  // Inputs: the coefficients defining the isogeny, and the projective point P = (X:Z).
  // Output: the projective point P = phi(P) = (X:Z) in the codomain. 
    f2elm_t t0, t1;
    
    fp2add(P->X, P->Z, t0);                         // t0 = X+Z - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(P->X, P->Z, t1);                         // t1 = X-Z - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t0, coeff[1], P->X);             // X = (X+Z)*coeff[1] - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t1, coeff[2], P->Z);             // Z = (X-Z)*coeff[2] - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t0, t1, t0);                     // t0 = (X+Z)*(X-Z) - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t0, coeff[0], t0);               // t0 = coeff[0]*(X+Z)*(X-Z)  - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(P->X, P->Z, t1);                         // t1 = (X-Z)*coeff[2] + (X+Z)*coeff[1] - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(P->X, P->Z, P->Z);                       // Z = (X-Z)*coeff[2] - (X+Z)*coeff[1]  - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(t1, t1);                         // t1 = [(X-Z)*coeff[2] + (X+Z)*coeff[1]]^2 - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(P->Z, P->Z);                     // Z = [(X-Z)*coeff[2] - (X+Z)*coeff[1]]^2  - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t1, t0, P->X);                           // X = coeff[0]*(X+Z)*(X-Z) + [(X-Z)*coeff[2] + (X+Z)*coeff[1]]^2 - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(P->Z, t0, t0);                           // t0 = [(X-Z)*coeff[2] - (X+Z)*coeff[1]]^2 - coeff[0]*(X+Z)*(X-Z)  - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(P->X, t1, P->X);                 // Xfinal - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(P->Z, t0, P->Z);                 // Zfinal - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
}




void xTPL_32(const point_proj_t P, point_proj_t Q, const f2elm_t A24minus, const f2elm_t A24plus)              
{ // Tripling of a Montgomery point in projective coordinates (X:Z).
  // Input: projective Montgomery x-coordinates P = (X:Z), where x=X/Z and Montgomery curve constants A24plus = A+2C and A24minus = A-2C.
  // Output: projective Montgomery x-coordinates Q = 3*P = (X3:Z3).
    f2elm_t t0, t1, t2, t3, t4, t5, t6;
                                    
    fp2sub(P->X, P->Z, t0);                         // t0 = X-Z - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(t0, t2);                         // t2 = (X-Z)^2 - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION        
    fp2add(P->X, P->Z, t1);                         // t1 = X+Z - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION 
    fp2sqr_mont_32(t1, t3);                         // t3 = (X+Z)^2 - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t0, t1, t4);                             // t4 = 2*X - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(t1, t0, t0);                             // t0 = 2*Z - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION 
    fp2sqr_mont_32(t4, t1);                         // t1 = 4*X^2 - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(t1, t3, t1);                             // t1 = 4*X^2 - (X+Z)^2 - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION 
    fp2sub(t1, t2, t1);                             // t1 = 4*X^2 - (X+Z)^2 - (X-Z)^2 - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t3, A24plus, t5);                // t5 = A24plus*(X+Z)^2 - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION 
    fp2mul_mont_32(t3, t5, t3);                     // t3 = A24plus*(X+Z)^3 - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(A24minus, t2, t6);               // t6 = A24minus*(X-Z)^2  - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t2, t6, t2);                     // t2 = A24minus*(X-Z)^3  - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(t2, t3, t3);                             // t3 = A24minus*(X-Z)^3 - coeff*(X+Z)^3  - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(t5, t6, t2);                             // t2 = A24plus*(X+Z)^2 - A24minus*(X-Z)^2  - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t1, t2, t1);                     // t1 = [4*X^2 - (X+Z)^2 - (X-Z)^2]*[A24plus*(X+Z)^2 - A24minus*(X-Z)^2]  - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t3, t1, t2);                             // t2 = [4*X^2 - (X+Z)^2 - (X-Z)^2]*[A24plus*(X+Z)^2 - A24minus*(X-Z)^2] + A24minus*(X-Z)^3 - coeff*(X+Z)^3 - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(t2, t2);                         // t2 = t2^2  - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t4, t2, Q->X);                   // X3 = 2*X*t2  - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(t3, t1, t1);                             // t1 = A24minus*(X-Z)^3 - A24plus*(X+Z)^3 - [4*X^2 - (X+Z)^2 - (X-Z)^2]*[A24plus*(X+Z)^2 - A24minus*(X-Z)^2] - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(t1, t1);                         // t1 = t1^2  - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t0, t1, Q->Z);                   // Z3 = 2*Z*t1  - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
}

void xTPLe_32(const point_proj_t P, point_proj_t Q, const f2elm_t A24minus, const f2elm_t A24plus, const int e)
{ // Computes [3^e](X:Z) on Montgomery curve with projective constant via e repeated triplings.
  // Input: projective Montgomery x-coordinates P = (XP:ZP), such that xP=XP/ZP and Montgomery curve constants A24plus = A+2C and A24minus = A-2C.
  // Output: projective Montgomery x-coordinates Q <- (3^e)*P.
    int i;
        
    copy_words((digit_t*)P, (digit_t*)Q, 2*2*NWORDS_FIELD);

    for (i = 0; i < e; i++) {
        xTPL_32(Q, Q, A24minus, A24plus);
    }
}



void get_3_isog_32(const point_proj_t P, f2elm_t A24minus, f2elm_t A24plus, f2elm_t* coeff)
{ // Computes the corresponding 3-isogeny of a projective Montgomery point (X3:Z3) of order 3.
  // Input:  projective point of order three P = (X3:Z3).
  // Output: the 3-isogenous Montgomery curve with projective coefficient A/C. 
    f2elm_t t0, t1, t2, t3, t4;
    
    fp2sub(P->X, P->Z, coeff[0]);                   // coeff0 = X-Z - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(coeff[0], t0);                   // t0 = (X-Z)^2 - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(P->X, P->Z, coeff[1]);                   // coeff1 = X+Z - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(coeff[1], t1);                   // t1 = (X+Z)^2 - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t0, t1, t2);                             // t2 = (X+Z)^2 + (X-Z)^2 - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(coeff[0], coeff[1], t3);                 // t3 = 2*X - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(t3, t3);                         // t3 = 4*X^2 - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(t3, t2, t3);                             // t3 = 4*X^2 - (X+Z)^2 - (X-Z)^2 - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION 
    fp2add(t1, t3, t2);                             // t2 = 4*X^2 - (X-Z)^2 - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION 
    fp2add(t3, t0, t3);                             // t3 = 4*X^2 - (X+Z)^2 - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t0, t3, t4);                             // t4 = 4*X^2 - (X+Z)^2 + (X-Z)^2 - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t4, t4, t4);                             // t4 = 2(4*X^2 - (X+Z)^2 + (X-Z)^2)  - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION 
    fp2add(t1, t4, t4);                             // t4 = 8*X^2 - (X+Z)^2 + 2*(X-Z)^2 - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t2, t4, A24minus);               // A24minus = [4*X^2 - (X-Z)^2]*[8*X^2 - (X+Z)^2 + 2*(X-Z)^2] - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t1, t2, t4);                             // t4 = 4*X^2 + (X+Z)^2 - (X-Z)^2 - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t4, t4, t4);                             // t4 = 2(4*X^2 + (X+Z)^2 - (X-Z)^2)  - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION 
    fp2add(t0, t4, t4);                             // t4 = 8*X^2 + 2*(X+Z)^2 - (X-Z)^2 - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t3, t4, A24plus);                // A24plus = [4*X^2 - (X+Z)^2]*[8*X^2 + 2*(X+Z)^2 - (X-Z)^2]  - - - - - - - - DIFFERENT FROM 64-BIT VERSION
}


void eval_3_isog_32(point_proj_t Q, const f2elm_t* coeff)
{ // Computes the 3-isogeny R=phi(X:Z), given projective point (X3:Z3) of order 3 on a Montgomery curve and 
  // a point P with 2 coefficients in coeff (computed in the function get_3_isog()).
  // Inputs: projective points P = (X3:Z3) and Q = (X:Z).
  // Output: the projective point Q <- phi(Q) = (X3:Z3). 
    f2elm_t t0, t1, t2;

    fp2add(Q->X, Q->Z, t0);                       // t0 = X+Z  - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(Q->X, Q->Z, t1);                       // t1 = X-Z  - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t0, coeff[0], t0);             // t0 = coeff0*(X+Z) - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t1, coeff[1], t1);             // t1 = coeff1*(X-Z) - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t0, t1, t2);                           // t2 = coeff0*(X+Z) + coeff1*(X-Z)  - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(t1, t0, t0);                           // t0 = coeff1*(X-Z) - coeff0*(X+Z)  - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(t2, t2);                       // t2 = [coeff0*(X+Z) + coeff1*(X-Z)]^2  - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(t0, t0);                       // t0 = [coeff1*(X-Z) - coeff0*(X+Z)]^2  - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(Q->X, t2, Q->X);               // X3final = X*[coeff0*(X+Z) + coeff1*(X-Z)]^2 - - - - DIFFERENT FROM 64-BIT VERSION     
    fp2mul_mont_32(Q->Z, t0, Q->Z);               // Z3final = Z*[coeff1*(X-Z) - coeff0*(X+Z)]^2 - - - - DIFFERENT FROM 64-BIT VERSION
}


void inv_3_way_32(f2elm_t z1, f2elm_t z2, f2elm_t z3)
{ // 3-way simultaneous inversion
  // Input:  z1,z2,z3
  // Output: 1/z1,1/z2,1/z3 (override inputs).
    f2elm_t t0, t1, t2, t3;

    fp2mul_mont_32(z1, z2, t0);                     // t0 = z1*z2  - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(z3, t0, t1);                     // t1 = z1*z2*z3 - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2inv_mont_32(t1);                             // t1 = 1/(z1*z2*z3) - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(z3, t1, t2);                     // t2 = 1/(z1*z2)  - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t2, z2, t3);                     // t3 = 1/z1 - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t2, z1, z2);                     // z2 = 1/z2 - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t0, t1, z3);                     // z3 = 1/z3 - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2copy(t3, z1);                                // z1 = 1/z1
}




void xDBLADD_32(point_proj_t P, point_proj_t Q, const f2elm_t xPQ, const f2elm_t A24)
{   // Simultaneous doubling and differential addition.
    // Input: projective Montgomery points P=(XP:ZP) and Q=(XQ:ZQ) such that xP=XP/ZP and xQ=XQ/ZQ, affine difference xPQ=x(P-Q) and Montgomery curve constant A24=(A+2)/4.
    // Output: projective Montgomery points P <- 2*P = (X2P:Z2P) such that x(2P)=X2P/Z2P, and Q <- P+Q = (XQP:ZQP) such that = x(Q+P)=XQP/ZQP. 
    f2elm_t t0, t1, t2;

    fp2add(P->X, P->Z, t0);                         // t0 = XP+ZP - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(P->X, P->Z, t1);                         // t1 = XP-ZP - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(t0, P->X);                       // XP = (XP+ZP)^2 - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(Q->X, Q->Z, t2);                         // t2 = XQ-ZQ - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2correction(t2);                              //  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(Q->X, Q->Z, Q->X);                       // XQ = XQ+ZQ - - - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t0, t2, t0);                     // t0 = (XP+ZP)*(XQ-ZQ) - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(t1, P->Z);                       // ZP = (XP-ZP)^2 - - - - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t1, Q->X, t1);                   // t1 = (XP-ZP)*(XQ+ZQ) - - - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(P->X, P->Z, t2);                         // t2 = (XP+ZP)^2-(XP-ZP)^2 - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(P->X, P->Z, P->X);               // XP = (XP+ZP)^2*(XP-ZP)^2 - - - - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t2, A24, Q->X);                  // XQ = A24*[(XP+ZP)^2-(XP-ZP)^2] - - - - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sub(t0, t1, Q->Z);                           // ZQ = (XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ) - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(Q->X, P->Z, P->Z);                       // ZP = A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2 - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t0, t1, Q->X);                           // XQ = (XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ) - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(P->Z, t2, P->Z);                 // ZP = [A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2]*[(XP+ZP)^2-(XP-ZP)^2] - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(Q->Z, Q->Z);                     // ZQ = [(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2 - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(Q->X, Q->X);                     // XQ = [(XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)]^2 - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(Q->Z, xPQ, Q->Z);                // ZQ = xPQ*[(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2 - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
}


static void LADDER3PT_32(const f2elm_t xP, const f2elm_t xQ, const f2elm_t xPQ, const digit_t* m, const unsigned int AliceOrBob, point_proj_t R, const f2elm_t A, int k, long type_of_attack)
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
    fpcopy((digit_t*)&Montgomery_one, A24[0]);              // A24 = 1
    fp2add(A24, A24, A24);                                  // A24 = 2 - - - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(A, A24, A24);                                    // A24 = A + 2 - - - - - - - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2div2(A24, A24);                                      // A24 = (A + 2)/2
    fp2div2(A24, A24);                                      // A24 = (A + 2)/4

    // Initializing points
    fp2copy(xQ, R0->X);                                     // xR0 = xQ
    fpcopy((digit_t*)&Montgomery_one, (digit_t*)R0->Z);     // R0  = [xQ : 1]
    fp2copy(xPQ, R2->X);                                    // xR2 = xPQ
    fpcopy((digit_t*)&Montgomery_one, (digit_t*)R2->Z);     // R2  = [xPQ : 1]
    fp2copy(xP, R->X);                                      // xR  = xP
    fpcopy((digit_t*)&Montgomery_one, (digit_t*)R->Z);      // R   = [xP : 1 (+ ?*i)]
    fpzero((digit_t*)(R->Z)[1]);                            // R   = [xP : 1 + 0*i]

    // Main loop
    for (i = 0; i < nbits; i++) {
        bit = (m[i >> LOG2RADIX] >> (i & (RADIX-1))) & 1;
        swap = bit ^ prevbit;
        prevbit = bit;
        mask = 0 - (digit_t)swap;
        swap_points(R, R2, mask);
        xDBLADD_32(R0, R2, R->X, A24);                      // R0, R2 = [2] * R0, R0 + R2 - - - - - - DIFFERENT FROM 64-BIT VERSION
        fp2mul_mont_32(R2->X, R->Z, R2->X);                 // Last step of above operation - - - - - DIFFERENT FROM 64-BIT VERSION
        if((type_of_attack == 1) && (i == k))
            printf("%u", 1 - f2elm_is_zero(R2->Z));         // 0 if R2->Z = 0, 1 otherwise
        if((type_of_attack == 2) && (i == k))
            printf("%u", 1 - f2elm_is_zero(R2->X));         // 0 if R2->X = 0, 1 otherwise
    }
    swap = 0 ^ prevbit;
    mask = 0 - (digit_t)swap;
    swap_points(R, R2, mask);
}


void j_inv_32(const f2elm_t A, const f2elm_t C, f2elm_t jinv)
{   // Computes the j-invariant of a Montgomery curve with projective constant.
  // Input: A,C in GF(p^2).
  // Output: j=256*(A^2-3*C^2)^3/(C^4*(A^2-4*C^2)), which is the j-invariant of the Montgomery curve B*y^2=x^3+(A/C)*x^2+x or (equivalently) j-invariant of B'*y^2=C*x^3+A*x^2+C*x.
    f2elm_t t0, t1;
    
    fp2sqr_mont_32(A, jinv);                        // jinv = A^2 - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2sqr_mont_32(C, t1);                          // t1   = C^2 - - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t1, t1, t0);                             // t0   = t1 + t1
    fp2sub(jinv, t0, t0);                           // t0   = jinv - t0
    fp2sub(t0, t1, t0);                             // t0   = t0 - t1
    fp2sub(t0, t1, jinv);                           // jinv = t0 - t1
    fp2sqr_mont_32(t1, t1);                         // t1   = t1^2  - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(jinv, t1, jinv);                 // jinv = jinv * t1 - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t0, t0, t0);                             // t0   = t0 + t0
    fp2add(t0, t0, t0);                             // t0   = t0 + t0
    fp2sqr_mont_32(t0, t1);                         // t1   = t0^2  - - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2mul_mont_32(t0, t1, t0);                     // t0   = t0 * t1 - - - - - DIFFERENT FROM 64-BIT VERSION
    fp2add(t0, t0, t0);                             // t0   = t0 + t0
    fp2add(t0, t0, t0);                             // t0   = t0 + t0
    fp2inv_mont_32(jinv);                           // jinv = 1 / jinv  - - - - DIFFERENT FROM 64-BIT VERSION 
    fp2mul_mont_32(jinv, t0, jinv);                 // jinv = t0 * jinv - - - - DIFFERENT FROM 64-BIT VERSION
}


#define MAX_NUM_TRITS       240
#define MAX_NWORDS_ORDER    6

const digit_t POWERS_OF_3[MAX_NUM_TRITS][MAX_NWORDS_ORDER] = {
{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x0000000000000003, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x0000000000000009, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x000000000000001B, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x0000000000000051, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x00000000000000F3, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x00000000000002D9, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x000000000000088B, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x00000000000019A1, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x0000000000004CE3, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x000000000000E6A9, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x000000000002B3FB, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x0000000000081BF1, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x00000000001853D3, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x000000000048FB79, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x0000000000DAF26B, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x000000000290D741, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x0000000007B285C3, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x0000000017179149, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x000000004546B3DB, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x00000000CFD41B91, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x000000026F7C52B3, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x000000074E74F819, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x00000015EB5EE84B, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x00000041C21CB8E1, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x000000C546562AA3, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x0000024FD3027FE9, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x000006EF79077FBB, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x000014CE6B167F31, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x00003E6B41437D93, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x0000BB41C3CA78B9, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x000231C54B5F6A2B, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x0006954FE21E3E81, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x0013BFEFA65ABB83, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x003B3FCEF3103289, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x00B1BF6CD930979B, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x02153E468B91C6D1, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x063FBAD3A2B55473, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x12BF307AE81FFD59, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x383D9170B85FF80B, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xA8B8B452291FE821, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xFA2A1CF67B5FB863, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xEE7E56E3721F2929, 0x0000000000000005, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xCB7B04AA565D7B7B, 0x0000000000000011, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x62710DFF03187271, 0x0000000000000035, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x275329FD09495753, 0x00000000000000A0, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x75F97DF71BDC05F9, 0x00000000000001E0, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x61EC79E5539411EB, 0x00000000000005A1, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x25C56DAFFABC35C1, 0x00000000000010E4, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x7150490FF034A143, 0x00000000000032AC, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x53F0DB2FD09DE3C9, 0x0000000000009805, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xFBD2918F71D9AB5B, 0x000000000001C80F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xF377B4AE558D0211, 0x000000000005582F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xDA671E0B00A70633, 0x000000000010088F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x8F355A2101F51299, 0x00000000003019AF, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xADA00E6305DF37CB, 0x0000000000904D0E, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x08E02B29119DA761, 0x0000000001B0E72C, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x1AA0817B34D8F623, 0x000000000512B584, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x4FE184719E8AE269, 0x000000000F38208C, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xEFA48D54DBA0A73B, 0x000000002DA861A4, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xCEEDA7FE92E1F5B1, 0x0000000088F924EE, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x6CC8F7FBB8A5E113, 0x000000019AEB6ECC, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x465AE7F329F1A339, 0x00000004D0C24C65, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xD310B7D97DD4E9AB, 0x0000000E7246E52F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x7932278C797EBD01, 0x0000002B56D4AF8F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x6B9676A56C7C3703, 0x00000082047E0EAE, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x42C363F04574A509, 0x000001860D7A2C0B, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xC84A2BD0D05DEF1B, 0x00000492286E8421, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x58DE83727119CD51, 0x00000DB6794B8C65, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x0A9B8A57534D67F3, 0x000029236BE2A530, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x1FD29F05F9E837D9, 0x00007B6A43A7EF90, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x5F77DD11EDB8A78B, 0x0001723ECAF7CEB0, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x1E679735C929F6A1, 0x000456BC60E76C11, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x5B36C5A15B7DE3E3, 0x000D043522B64433, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x11A450E41279ABA9, 0x00270C9F6822CC9A, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x34ECF2AC376D02FB, 0x007525DE386865CE, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x9EC6D804A64708F1, 0x015F719AA939316A, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xDC54880DF2D51AD3, 0x041E54CFFBAB943F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x94FD9829D87F5079, 0x0C5AFE6FF302BCBF, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xBEF8C87D897DF16B, 0x2510FB4FD908363E, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x3CEA59789C79D441, 0x6F32F1EF8B18A2BC, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xB6BF0C69D56D7CC3, 0x4D98D5CEA149E834, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x243D253D80487649, 0xE8CA816BE3DDB89E, 0x0000000000000003, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x6CB76FB880D962DB, 0xBA5F8443AB9929DA, 0x000000000000000B, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x46264F29828C2891, 0x2F1E8CCB02CB7D8F, 0x0000000000000023, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xD272ED7C87A479B3, 0x8D5BA661086278AD, 0x0000000000000069, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x7758C87596ED6D19, 0xA812F32319276A09, 0x000000000000013C, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x660A5960C4C8474B, 0xF838D9694B763E1C, 0x00000000000003B5, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x321F0C224E58D5E1, 0xE8AA8C3BE262BA55, 0x0000000000000B21, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x965D2466EB0A81A3, 0xB9FFA4B3A7282EFF, 0x0000000000002165, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xC3176D34C11F84E9, 0x2DFEEE1AF5788CFE, 0x0000000000006431, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x4946479E435E8EBB, 0x89FCCA50E069A6FC, 0x0000000000012C93, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xDBD2D6DACA1BAC31, 0x9DF65EF2A13CF4F4, 0x00000000000385BA, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x937884905E530493, 0xD9E31CD7E3B6DEDE, 0x00000000000A912F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xBA698DB11AF90DB9, 0x8DA95687AB249C9B, 0x00000000001FB38F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x2F3CA91350EB292B, 0xA8FC0397016DD5D3, 0x00000000005F1AAE, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x8DB5FB39F2C17B81, 0xFAF40AC504498179, 0x00000000011D500B, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xA921F1ADD8447283, 0xF0DC204F0CDC846C, 0x000000000357F023, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xFB65D50988CD5789, 0xD29460ED26958D45, 0x000000000A07D06B, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xF2317F1C9A68069B, 0x77BD22C773C0A7D1, 0x000000001E177143, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xD6947D55CF3813D1, 0x673768565B41F775, 0x000000005A4653CA, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x83BD78016DA83B73, 0x35A6390311C5E661, 0x000000010ED2FB5F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x8B38680448F8B259, 0xA0F2AB093551B324, 0x000000032C78F21D, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xA1A9380CDAEA170B, 0xE2D8011B9FF5196D, 0x00000009856AD658, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xE4FBA82690BE4521, 0xA8880352DFDF4C48, 0x0000001C9040830A, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xAEF2F873B23ACF63, 0xF99809F89F9DE4DA, 0x00000055B0C1891F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x0CD8E95B16B06E29, 0xECC81DE9DED9AE90, 0x0000010112449B5F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x268ABC1144114A7B, 0xC65859BD9C8D0BB0, 0x0000030336CDD21F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x73A03433CC33DF71, 0x53090D38D5A72310, 0x00000909A469765F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x5AE09C9B649B9E53, 0xF91B27AA80F56931, 0x00001B1CED3C631D, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x10A1D5D22DD2DAF9, 0xEB5176FF82E03B94, 0x00005156C7B52959, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x31E58176897890EB, 0xC1F464FE88A0B2BC, 0x0000F404571F7C0D, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x95B084639C69B2C1, 0x45DD2EFB99E21834, 0x0002DC0D055E7429, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xC1118D2AD53D1843, 0xD1978CF2CDA6489D, 0x00089427101B5C7B, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x4334A7807FB748C9, 0x74C6A6D868F2D9D9, 0x0019BC7530521573, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xC99DF6817F25DA5B, 0x5E53F4893AD88D8B, 0x004D355F90F6405A, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x5CD9E3847D718F11, 0x1AFBDD9BB089A8A3, 0x00E7A01EB2E2C10F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x168DAA8D7854AD33, 0x50F398D3119CF9EA, 0x02B6E05C18A8432D, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x43A8FFA868FE0799, 0xF2DACA7934D6EDBE, 0x0824A11449F8C987, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0xCAFAFEF93AFA16CB, 0xD8905F6B9E84C93A, 0x186DE33CDDEA5C97, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x60F0FCEBB0EE4461, 0x89B11E42DB8E5BB0, 0x4949A9B699BF15C7, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x22D2F6C312CACD23, 0x9D135AC892AB1311, 0xDBDCFD23CD3D4156, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
{0x6878E44938606769, 0xD73A1059B8013933, 0x9396F76B67B7C403, 0x0000000000000002, 0x0000000000000000, 0x0000000000000000},
{0x396AACDBA921363B, 0x85AE310D2803AB9A, 0xBAC4E64237274C0B, 0x0000000000000007, 0x0000000000000000, 0x0000000000000000},
{0xAC400692FB63A2B1, 0x910A9327780B02CE, 0x304EB2C6A575E422, 0x0000000000000017, 0x0000000000000000, 0x0000000000000000},
{0x04C013B8F22AE813, 0xB31FB9766821086C, 0x90EC1853F061AC67, 0x0000000000000045, 0x0000000000000000, 0x0000000000000000},
{0x0E403B2AD680B839, 0x195F2C6338631944, 0xB2C448FBD1250537, 0x00000000000000D0, 0x0000000000000000, 0x0000000000000000},
{0x2AC0B180838228AB, 0x4C1D8529A9294BCC, 0x184CDAF3736F0FA5, 0x0000000000000272, 0x0000000000000000, 0x0000000000000000},
{0x804214818A867A01, 0xE4588F7CFB7BE364, 0x48E690DA5A4D2EEF, 0x0000000000000756, 0x0000000000000000, 0x0000000000000000},
{0x80C63D849F936E03, 0xAD09AE76F273AA2D, 0xDAB3B28F0EE78CCF, 0x0000000000001602, 0x0000000000000000, 0x0000000000000000},
{0x8252B88DDEBA4A09, 0x071D0B64D75AFE88, 0x901B17AD2CB6A66F, 0x0000000000004208, 0x0000000000000000, 0x0000000000000000},
{0x86F829A99C2EDE1B, 0x1557222E8610FB99, 0xB05147078623F34D, 0x000000000000C619, 0x0000000000000000, 0x0000000000000000},
{0x94E87CFCD48C9A51, 0x4005668B9232F2CC, 0x10F3D516926BD9E7, 0x000000000002524D, 0x0000000000000000, 0x0000000000000000},
{0xBEB976F67DA5CEF3, 0xC01033A2B698D865, 0x32DB7F43B7438DB5, 0x000000000006F6E7, 0x0000000000000000, 0x0000000000000000},
{0x3C2C64E378F16CD9, 0x40309AE823CA8931, 0x98927DCB25CAA921, 0x000000000014E4B5, 0x0000000000000000, 0x0000000000000000},
{0xB4852EAA6AD4468B, 0xC091D0B86B5F9B93, 0xC9B77961715FFB63, 0x00000000003EAE20, 0x0000000000000000, 0x0000000000000000},
{0x1D8F8BFF407CD3A1, 0x41B57229421ED2BB, 0x5D266C24541FF22B, 0x0000000000BC0A62, 0x0000000000000000, 0x0000000000000000},
{0x58AEA3FDC1767AE3, 0xC520567BC65C7831, 0x1773446CFC5FD681, 0x0000000002341F27, 0x0000000000000000, 0x0000000000000000},
{0x0A0BEBF9446370A9, 0x4F61037353156894, 0x4659CD46F51F8385, 0x00000000069C5D75, 0x0000000000000000, 0x0000000000000000},
{0x1E23C3EBCD2A51FB, 0xEE230A59F94039BC, 0xD30D67D4DF5E8A8F, 0x0000000013D5185F, 0x0000000000000000, 0x0000000000000000},
{0x5A6B4BC3677EF5F1, 0xCA691F0DEBC0AD34, 0x7928377E9E1B9FAF, 0x000000003B7F491F, 0x0000000000000000, 0x0000000000000000},
{0x0F41E34A367CE1D3, 0x5F3B5D29C342079D, 0x6B78A67BDA52DF0F, 0x00000000B27DDB5E, 0x0000000000000000, 0x0000000000000000},
{0x2DC5A9DEA376A579, 0x1DB2177D49C616D7, 0x4269F3738EF89D2E, 0x000000021779921B, 0x0000000000000000, 0x0000000000000000},
{0x8950FD9BEA63F06B, 0x59164677DD524485, 0xC73DDA5AACE9D78A, 0x00000006466CB651, 0x0000000000000000, 0x0000000000000000},
{0x9BF2F8D3BF2BD141, 0x0B42D36797F6CD90, 0x55B98F1006BD869F, 0x00000012D34622F5, 0x0000000000000000, 0x0000000000000000},
{0xD3D8EA7B3D8373C3, 0x21C87A36C7E468B1, 0x012CAD30143893DD, 0x0000003879D268E0, 0x0000000000000000, 0x0000000000000000},
{0x7B8ABF71B88A5B49, 0x65596EA457AD3A15, 0x038607903CA9BB97, 0x000000A96D773AA0, 0x0000000000000000, 0x0000000000000000},
{0x72A03E55299F11DB, 0x300C4BED0707AE40, 0x0A9216B0B5FD32C6, 0x000001FC4865AFE0, 0x0000000000000000, 0x0000000000000000},
{0x57E0BAFF7CDD3591, 0x9024E3C715170AC1, 0x1FB6441221F79852, 0x000005F4D9310FA0, 0x0000000000000000, 0x0000000000000000},
{0x07A230FE7697A0B3, 0xB06EAB553F452044, 0x5F22CC3665E6C8F7, 0x000011DE8B932EE0, 0x0000000000000000, 0x0000000000000000},
{0x16E692FB63C6E219, 0x114C01FFBDCF60CC, 0x1D6864A331B45AE7, 0x0000359BA2B98CA1, 0x0000000000000000, 0x0000000000000000},
{0x44B3B8F22B54A64B, 0x33E405FF396E2264, 0x58392DE9951D10B5, 0x0000A0D2E82CA5E3, 0x0000000000000000, 0x0000000000000000},
{0xCE1B2AD681FDF2E1, 0x9BAC11FDAC4A672C, 0x08AB89BCBF57321F, 0x0001E278B885F1AA, 0x0000000000000000, 0x0000000000000000},
{0x6A51808385F9D8A3, 0xD30435F904DF3586, 0x1A029D363E05965E, 0x0005A76A2991D4FE, 0x0000000000000000, 0x0000000000000000},
{0x3EF4818A91ED89E9, 0x790CA1EB0E9DA093, 0x4E07D7A2BA10C31C, 0x0010F63E7CB57EFA, 0x0000000000000000, 0x0000000000000000},
{0xBCDD849FB5C89DBB, 0x6B25E5C12BD8E1B9, 0xEA1786E82E324955, 0x0032E2BB76207CEE, 0x0000000000000000, 0x0000000000000000},
{0x36988DDF2159D931, 0x4171B143838AA52D, 0xBE4694B88A96DC00, 0x0098A832626176CC, 0x0000000000000000, 0x0000000000000000},
{0xA3C9A99D640D8B93, 0xC45513CA8A9FEF87, 0x3AD3BE299FC49400, 0x01C9F89727246466, 0x0000000000000000, 0x0000000000000000},
{0xEB5CFCD82C28A2B9, 0x4CFF3B5F9FDFCE96, 0xB07B3A7CDF4DBC02, 0x055DE9C5756D2D32, 0x0000000000000000, 0x0000000000000000},
{0xC216F6888479E82B, 0xE6FDB21EDF9F6BC4, 0x1171AF769DE93406, 0x1019BD5060478798, 0x0000000000000000, 0x0000000000000000},
{0x4644E3998D6DB881, 0xB4F9165C9EDE434E, 0x34550E63D9BB9C14, 0x304D37F120D696C8, 0x0000000000000000, 0x0000000000000000},
{0xD2CEAACCA8492983, 0x1EEB4315DC9AC9EA, 0x9CFF2B2B8D32D43E, 0x90E7A7D36283C458, 0x0000000000000000, 0x0000000000000000},
{0x786C0065F8DB7C89, 0x5CC1C94195D05DC0, 0xD6FD8182A7987CBA, 0xB2B6F77A278B4D09, 0x0000000000000001, 0x0000000000000000},
{0x69440131EA92759B, 0x16455BC4C1711941, 0x84F88487F6C9762F, 0x1824E66E76A1E71D, 0x0000000000000005, 0x0000000000000000},
{0x3BCC0395BFB760D1, 0x42D0134E44534BC4, 0x8EE98D97E45C628D, 0x486EB34B63E5B558, 0x000000000000000F, 0x0000000000000000},
{0xB3640AC13F262273, 0xC87039EACCF9E34C, 0xACBCA8C7AD1527A7, 0xD94C19E22BB12009, 0x000000000000002D, 0x0000000000000000},
{0x1A2C2043BD726759, 0x5950ADC066EDA9E6, 0x0635FA57073F76F7, 0x8BE44DA68313601D, 0x0000000000000089, 0x0000000000000000},
{0x4E8460CB3857360B, 0x0BF2094134C8FDB2, 0x12A1EF0515BE64E6, 0xA3ACE8F3893A2057, 0x000000000000019C, 0x0000000000000000},
{0xEB8D2261A905A221, 0x23D61BC39E5AF916, 0x37E5CD0F413B2EB2, 0xEB06BADA9BAE6105, 0x00000000000004D5, 0x0000000000000000},
{0xC2A76724FB10E663, 0x6B82534ADB10EB44, 0xA7B1672DC3B18C16, 0xC114308FD30B230F, 0x0000000000000E81, 0x0000000000000000},
{0x47F6356EF132B329, 0x4286F9E09132C1CE, 0xF71435894B14A443, 0x433C91AF7921692E, 0x0000000000002B85, 0x0000000000000000},
{0xD7E2A04CD398197B, 0xC794EDA1B398456A, 0xE53CA09BE13DECC9, 0xC9B5B50E6B643B8C, 0x000000000000828F, 0x0000000000000000},
{0x87A7E0E67AC84C71, 0x56BEC8E51AC8D040, 0xAFB5E1D3A3B9C65D, 0x5D211F2B422CB2A6, 0x00000000000187AF, 0x0000000000000000},
{0x96F7A2B37058E553, 0x043C5AAF505A70C1, 0x0F21A57AEB2D5318, 0x17635D81C68617F4, 0x000000000004970E, 0x0000000000000000},
{0xC4E6E81A510AAFF9, 0x0CB5100DF10F5244, 0x2D64F070C187F948, 0x462A1885539247DC, 0x00000000000DC52A, 0x0000000000000000},
{0x4EB4B84EF3200FEB, 0x261F3029D32DF6CE, 0x882ED1524497EBD8, 0xD27E498FFAB6D794, 0x0000000000294F7E, 0x0000000000000000},
{0xEC1E28ECD9602FC1, 0x725D907D7989E46A, 0x988C73F6CDC7C388, 0x777ADCAFF02486BD, 0x00000000007BEE7C, 0x0000000000000000},
{0xC45A7AC68C208F43, 0x5718B1786C9DAD40, 0xC9A55BE469574A99, 0x6670960FD06D9438, 0x000000000173CB75, 0x0000000000000000},
{0x4D0F7053A461ADC9, 0x054A146945D907C2, 0x5CF013AD3C05DFCC, 0x3351C22F7148BCAA, 0x00000000045B6260, 0x0000000000000000},
{0xE72E50FAED25095B, 0x0FDE3D3BD18B1746, 0x16D03B07B4119F64, 0x99F5468E53DA35FF, 0x000000000D122720, 0x0000000000000000},
{0xB58AF2F0C76F1C11, 0x2F9AB7B374A145D4, 0x4470B1171C34DE2C, 0xCDDFD3AAFB8EA1FD, 0x0000000027367561, 0x0000000000000000},
{0x20A0D8D2564D5433, 0x8ED0271A5DE3D17E, 0xCD521345549E9A84, 0x699F7B00F2ABE5F7, 0x0000000075A36025, 0x0000000000000000},
{0x61E28A7702E7FC99, 0xAC70754F19AB747A, 0x67F639CFFDDBCF8D, 0x3CDE7102D803B1E7, 0x0000000160EA2070, 0x0000000000000000},
{0x25A79F6508B7F5CB, 0x05515FED4D025D6F, 0x37E2AD6FF9936EA9, 0xB69B5308880B15B6, 0x0000000422BE6150, 0x0000000000000000},
{0x70F6DE2F1A27E161, 0x0FF41FC7E707184D, 0xA7A8084FECBA4BFB, 0x23D1F91998214122, 0x0000000C683B23F2, 0x0000000000000000},
{0x52E49A8D4E77A423, 0x2FDC5F57B51548E8, 0xF6F818EFC62EE3F1, 0x6B75EB4CC863C367, 0x0000002538B16BD6, 0x0000000000000000},
{0xF8ADCFA7EB66EC69, 0x8F951E071F3FDAB8, 0xE4E84ACF528CABD3, 0x4261C1E6592B4A37, 0x0000006FAA144383, 0x0000000000000000},
{0xEA096EF7C234C53B, 0xAEBF5A155DBF902A, 0xAEB8E06DF7A6037A, 0xC72545B30B81DEA7, 0x0000014EFE3CCA89, 0x0000000000000000},
{0xBE1C4CE7469E4FB1, 0x0C3E0E40193EB080, 0x0C2AA149E6F20A70, 0x556FD11922859BF7, 0x000003ECFAB65F9D, 0x0000000000000000},
{0x3A54E6B5D3DAEF13, 0x24BA2AC04BBC1182, 0x247FE3DDB4D61F50, 0x004F734B6790D3E5, 0x00000BC6F0231ED8, 0x0000000000000000},
{0xAEFEB4217B90CD39, 0x6E2E8040E3343486, 0x6D7FAB991E825DF0, 0x00EE59E236B27BAF, 0x00002354D0695C88, 0x0000000000000000},
{0x0CFC1C6472B267AB, 0x4A8B80C2A99C9D94, 0x487F02CB5B8719D1, 0x02CB0DA6A417730E, 0x000069FE713C1598, 0x0000000000000000},
{0x26F4552D58173701, 0xDFA28247FCD5D8BC, 0xD97D086212954D73, 0x086128F3EC46592A, 0x00013DFB53B440C8, 0x0000000000000000},
{0x74DCFF880845A503, 0x9EE786D7F6818A34, 0x8C77192637BFE85B, 0x19237ADBC4D30B80, 0x0003B9F1FB1CC258, 0x0000000000000000},
{0x5E96FE9818D0EF09, 0xDCB69487E3849E9D, 0xA5654B72A73FB912, 0x4B6A70934E792281, 0x000B2DD5F1564708, 0x0000000000000000},
{0x1BC4FBC84A72CD1B, 0x9623BD97AA8DDBD8, 0xF02FE257F5BF2B38, 0xE23F51B9EB6B6784, 0x00218981D402D518, 0x0000000000000000},
{0x534EF358DF586751, 0xC26B38C6FFA99388, 0xD08FA707E13D81A9, 0xA6BDF52DC242368E, 0x00649C857C087F4A, 0x0000000000000000},
{0xF9ECDA0A9E0935F3, 0x4741AA54FEFCBA98, 0x71AEF517A3B884FD, 0xF439DF8946C6A3AC, 0x012DD59074197DDF, 0x0000000000000000},
{0xEDC68E1FDA1BA1D9, 0xD5C4FEFEFCF62FCA, 0x550CDF46EB298EF7, 0xDCAD9E9BD453EB05, 0x038980B15C4C799F, 0x0000000000000000},
{0xC953AA5F8E52E58B, 0x814EFCFCF6E28F60, 0xFF269DD4C17CACE7, 0x9608DBD37CFBC10F, 0x0A9C821414E56CDF, 0x0000000000000000},
{0x5BFAFF1EAAF8B0A1, 0x83ECF6F6E4A7AE22, 0xFD73D97E447606B6, 0xC21A937A76F3432F, 0x1FD5863C3EB0469E, 0x0000000000000000},
{0x13F0FD5C00EA11E3, 0x8BC6E4E4ADF70A67, 0xF85B8C7ACD621423, 0x464FBA6F64D9C98F, 0x5F8092B4BC10D3DC, 0x0000000000000000},
{0x3BD2F81402BE35A9, 0xA354AEAE09E51F35, 0xE912A57068263C6A, 0xD2EF2F4E2E8D5CAF, 0x1E81B81E34327B94, 0x0000000000000001},
{0xB378E83C083AA0FB, 0xE9FE0C0A1DAF5D9F, 0xBB37F0513872B53F, 0x78CD8DEA8BA8160F, 0x5B85285A9C9772BE, 0x0000000000000003},
{0x1A6AB8B418AFE2F1, 0xBDFA241E590E18DF, 0x31A7D0F3A9581FBF, 0x6A68A9BFA2F8422F, 0x128F790FD5C6583B, 0x000000000000000A},
{0x4F402A1C4A0FA8D3, 0x39EE6C5B0B2A4A9D, 0x94F772DAFC085F3F, 0x3F39FD3EE8E8C68D, 0x37AE6B2F815308B2, 0x000000000000001E},
{0xEDC07E54DE2EFA79, 0xADCB4511217EDFD7, 0xBEE65890F4191DBD, 0xBDADF7BCBABA53A8, 0xA70B418E83F91A16, 0x000000000000005A},
{0xC9417AFE9A8CEF6B, 0x0961CF33647C9F87, 0x3CB309B2DC4B5939, 0x3909E736302EFAFA, 0xF521C4AB8BEB4E44, 0x000000000000010F},
{0x5BC470FBCFA6CE41, 0x1C256D9A2D75DE97, 0xB6191D1894E20BAB, 0xAB1DB5A2908CF0EE, 0xDF654E02A3C1EACC, 0x000000000000032F},
{0x134D52F36EF46AC3, 0x547048CE88619BC6, 0x224B5749BEA62301, 0x015920E7B1A6D2CC, 0x9E2FEA07EB45C066, 0x000000000000098F},
{0x39E7F8DA4CDD4049, 0xFD50DA6B9924D352, 0x66E205DD3BF26903, 0x040B62B714F47864, 0xDA8FBE17C1D14132, 0x0000000000001CAE},
{0xADB7EA8EE697C0DB, 0xF7F28F42CB6E79F6, 0x34A61197B3D73B0B, 0x0C2228253EDD692D, 0x8FAF3A474573C396, 0x000000000000560C},
{0x0927BFACB3C74291, 0xE7D7ADC8624B6DE4, 0x9DF234C71B85B123, 0x2466786FBC983B87, 0xAF0DAED5D05B4AC2, 0x0000000000010225},
{0x1B773F061B55C7B3, 0xB787095926E249AC, 0xD9D69E555291136B, 0x6D33694F35C8B296, 0x0D290C817111E046, 0x0000000000030671},
{0x5265BD1252015719, 0x26951C0B74A6DD04, 0x8D83DAFFF7B33A43, 0x479A3BEDA15A17C4, 0x277B25845335A0D3, 0x0000000000091353},
{0xF7313736F604054B, 0x73BF54225DF4970C, 0xA88B90FFE719AEC9, 0xD6CEB3C8E40E474D, 0x7671708CF9A0E279, 0x00000000001B39F9},
{0xE593A5A4E20C0FE1, 0x5B3DFC6719DDC526, 0xF9A2B2FFB54D0C5C, 0x846C1B5AAC2AD5E8, 0x635451A6ECE2A76D, 0x000000000051ADEC},
{0xB0BAF0EEA6242FA3, 0x11B9F5354D994F74, 0xECE818FF1FE72515, 0x8D445210048081BA, 0x29FCF4F4C6A7F648, 0x0000000000F509C5},
{0x1230D2CBF26C8EE9, 0x352DDF9FE8CBEE5E, 0xC6B84AFD5FB56F3F, 0xA7CCF6300D818530, 0x7DF6DEDE53F7E2D9, 0x0000000002DF1D4F},
{0x36927863D745ACBB, 0x9F899EDFBA63CB1A, 0x5428E0F81F204DBD, 0xF766E29028848F92, 0x79E49C9AFBE7A88C, 0x00000000089D57EE},
{0xA3B7692B85D10631, 0xDE9CDC9F2F2B614E, 0xFC7AA2E85D60E938, 0xE634A7B0798DAEB6, 0x6DADD5D0F3B6F9A6, 0x0000000019D807CB},
{0xEB263B8291731293, 0x9BD695DD8D8223EB, 0xF56FE8B91822BBAA, 0xB29DF7116CA90C24, 0x49098172DB24ECF4, 0x000000004D881762},
{0xC172B287B45937B9, 0xD383C198A8866BC3, 0xE04FBA2B486832FF, 0x17D9E53445FB246E, 0xDB1C8458916EC6DE, 0x00000000E8984626},
{0x445817971D0BA72B, 0x7A8B44C9F993434B, 0xA0EF2E81D93898FF, 0x478DAF9CD1F16D4C, 0x91558D09B44C549A, 0x00000002B9C8D274},
{0xCD0846C55722F581, 0x6FA1CE5DECB9C9E1, 0xE2CD8B858BA9CAFE, 0xD6A90ED675D447E5, 0xB400A71D1CE4FDCE, 0x000000082D5A775D},
{0x6718D4500568E083, 0x4EE56B19C62D5DA5, 0xA868A290A2FD60FB, 0x83FB2C83617CD7B1, 0x1C01F55756AEF96C, 0x00000018880F6619},
{0x354A7CF0103AA189, 0xECB0414D528818F0, 0xF939E7B1E8F822F1, 0x8BF1858A24768714, 0x5405E006040CEC45, 0x00000049982E324B},
{0x9FDF76D030AFE49B, 0xC610C3E7F7984AD0, 0xEBADB715BAE868D5, 0xA3D4909E6D63953E, 0xFC11A0120C26C4D0, 0x000000DCC88A96E1},
{0xDF9E6470920FADD1, 0x52324BB7E6C8E071, 0xC309254130B93A81, 0xEB7DB1DB482ABFBC, 0xF434E03624744E71, 0x00000296599FC4A5},
{0x9EDB2D51B62F0973, 0xF696E327B45AA155, 0x491B6FC3922BAF83, 0xC2791591D8803F36, 0xDC9EA0A26D5CEB55, 0x000007C30CDF4DF1},
{0xDC9187F5228D1C59, 0xE3C4A9771D0FE400, 0xDB524F4AB6830E8B, 0x476B40B58980BDA2, 0x95DBE1E74816C201, 0x00001749269DE9D5},
{0x95B497DF67A7550B, 0xAB4DFC65572FAC02, 0x91F6EDE023892BA3, 0xD641C2209C8238E8, 0xC193A5B5D8444603, 0x000045DB73D9BD80},
{0xC11DC79E36F5FF21, 0x01E9F530058F0407, 0xB5E4C9A06A9B82EB, 0x82C54661D586AAB9, 0x44BAF12188CCD20B, 0x0000D1925B8D3882},
{0x435956DAA4E1FD63, 0x05BDDF9010AD0C17, 0x21AE5CE13FD288C1, 0x884FD3258094002D, 0xCE30D3649A667622, 0x000274B712A7A986},
{0xCA0C048FEEA5F829, 0x11399EB032072445, 0x650B16A3BF779A43, 0x98EF797081BC0087, 0x6A927A2DCF336267, 0x00075E2537F6FC94},
{0x5E240DAFCBF1E87B, 0x33ACDC1096156CD1, 0x2F2143EB3E66CEC9, 0xCACE6C5185340196, 0x3FB76E896D9A2736, 0x00161A6FA7E4F5BD},
{0x1A6C290F63D5B971, 0x9B069431C2404674, 0x8D63CBC1BB346C5B, 0x606B44F48F9C04C2, 0xBF264B9C48CE75A4, 0x00424F4EF7AEE137},
{0x4F447B2E2B812C53, 0xD113BC9546C0D35C, 0xA82B6345319D4512, 0x2141CEDDAED40E47, 0x3D72E2D4DA6B60ED, 0x00C6EDECE70CA3A7},
{0xEDCD718A828384F9, 0x733B35BFD4427A14, 0xF88229CF94D7CF38, 0x63C56C990C7C2AD6, 0xB858A87E8F4222C7, 0x0254C9C6B525EAF5},
{0xC968549F878A8EEB, 0x59B1A13F7CC76E3E, 0xE9867D6EBE876DA9, 0x2B5045CB25748084, 0x2909F97BADC66856, 0x06FE5D541F71C0E1}};







inline static void decode_trits(const unsigned char* PrivateKeyA, digit_t* dec, int ntrits, int ndigits)
{   // Decoding bytes to digits 
    // Small endian only
    for(int i = 0; i < ntrits; i++)
    {
        if(PrivateKeyA[i] == '1')
            mp_add((digit_t *)&(POWERS_OF_3[i]), dec, dec, ndigits);
        else if(PrivateKeyA[i] == '2')
        {
            mp_add((digit_t *)&(POWERS_OF_3[i]), dec, dec, ndigits);
            mp_add((digit_t *)&(POWERS_OF_3[i]), dec, dec, ndigits);
        }
    }
}




// TIMING AND BENCHMARKING CODE
// ADDED COUNTERMEASURES
void fp2shl(const f2elm_t a, const int k, f2elm_t c) 
{  // c = (2^k)*a
   fp2copy(a, c);
   for (int j = 0; j < k; j++) {
      fp2add(c, c, c);
   }
}




void xTPL_fast(const point_proj_t P, point_proj_t Q, const f2elm_t A2)
{ // Montgomery curve (E: y^2 = x^3 + A*x^2 + x) x-only tripling at a cost 5M + 6S + 9A = 27p + 61a.
  // Input : projective Montgomery x-coordinates P = (X:Z), where x=X/Z and Montgomery curve constant A/2. 
  // Output: projective Montgomery x-coordinates Q = 3*P = (X3:Z3).
       f2elm_t t1, t2, t3, t4;
       
       fp2sqr_mont(P->X, t1);        // t1 = x^2
       fp2sqr_mont(P->Z, t2);        // t2 = z^2
       fp2add(t1, t2, t3);           // t3 = t1 + t2
       fp2add(P->X, P->Z, t4);       // t4 = x + z
       fp2sqr_mont(t4, t4);          // t4 = t4^2
       fp2sub(t4, t3, t4);           // t4 = t4 - t3
       fp2mul_mont(A2, t4, t4);      // t4 = t4*A2
       fp2add(t3, t4, t4);           // t4 = t4 + t3
       fp2sub(t1, t2, t3);           // t3 = t1 - t2
       fp2sqr_mont(t3, t3);          // t3 = t3^2
       fp2mul_mont(t1, t4, t1);      // t1 = t1*t4
       fp2shl(t1, 2, t1);            // t1 = 4*t1
       fp2sub(t1, t3, t1);           // t1 = t1 - t3
       fp2sqr_mont(t1, t1);          // t1 = t1^2
       fp2mul_mont(t2, t4, t2);      // t2 = t2*t4
       fp2shl(t2, 2, t2);            // t2 = 4*t2
       fp2sub(t2, t3, t2);           // t2 = t2 - t3
       fp2sqr_mont(t2, t2);          // t2 = t2^2
       fp2mul_mont(P->X, t2, Q->X);  // x = x*t2
       fp2mul_mont(P->Z, t1, Q->Z);  // z = z*t1    
}


void xTPLe_fast(point_proj_t P, point_proj_t Q, const f2elm_t A2, int e)
{ // Computes [3^e](X:Z) on Montgomery curve with projective constant via e repeated triplings. e triplings in E costs k*(5M + 6S + 9A)
  // Input: projective Montgomery x-coordinates P = (X:Z), where x=X/Z, Montgomery curve constant A2 = A/2 and the number of triplings e.
  // Output: projective Montgomery x-coordinates Q <- [3^e]P.    
    point_proj_t T;

    copy_words((digit_t*)P, (digit_t*)T, 2*2*NWORDS_FIELD);
    for (int j = 0; j < e; j++) { 
        xTPL_fast(T, T, A2);
    }
    copy_words((digit_t*)T, (digit_t*)Q, 2*2*NWORDS_FIELD);
}


int countermeasure(const f2elm_t xP, const f2elm_t xQ, const f2elm_t A, const f2elm_t A24plus, const f2elm_t A24minus){

    point_proj_t P = {0}, Q = {0};
    f2elm_t A2, tmp1, tmp2;

    // Check the curve is not singular
    if (f2elm_is_zero(A24plus) || f2elm_is_zero(A24minus))
      return 1;

    fp2div2(A, A2);
    fp2copy(xP, P->X);
    fpcopy((digit_t*)&Montgomery_one, (digit_t*)P->Z);
    fp2copy(xQ, Q->X);
    fpcopy((digit_t*)&Montgomery_one, (digit_t*)Q->Z);

    xTPLe_fast(P, P, A2, OBOB_EXPON-1);
    xTPLe_fast(Q, Q, A2, OBOB_EXPON-1);
    if (f2elm_is_zero(P->X) || f2elm_is_zero(Q->X))
      return 1;
    
    fp2mul_mont(P->X, Q->Z, tmp1);
    fp2mul_mont(P->Z, Q->X, tmp2);
    fp2sub(tmp1, tmp2, tmp1);
    if (f2elm_is_zero(tmp1))
      return 1;

    xTPL_fast(P, P, A2);
    xTPL_fast(Q, Q, A2);
    if (!f2elm_is_zero(P->Z) || !f2elm_is_zero(Q->Z))
      return 1;

#if (NBITS_FIELD == 610)
    // Additionally check that 8 | #E
    if (!is_sqr_fp2(A24plus) || !is_sqr_fp2(A24minus))
      return 1;
#endif

    return 0;
}

