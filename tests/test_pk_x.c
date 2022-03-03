/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Computing malicious pk which force computation of V = [0:1]
*********************************************************************************************/ 
#include <stdio.h>
#include <string.h>
#include "test_extras.h"

#if (PRIME_SIZE == 434)
#include "../src/P434/P434_api.h"
#define SCHEME_NAME    "SIKEp434"
#define crypto_kem_keypair            crypto_kem_keypair_SIKEp434
#define crypto_kem_enc                crypto_kem_enc_SIKEp434
#define crypto_kem_dec                crypto_kem_dec_SIKEp434

#elif (PRIME_SIZE == 503)
#include "../src/P503/P503_api.h"
#define SCHEME_NAME    "SIKEp503"
#define crypto_kem_keypair            crypto_kem_keypair_SIKEp503
#define crypto_kem_enc                crypto_kem_enc_SIKEp503
#define crypto_kem_dec                crypto_kem_dec_SIKEp503

#elif (PRIME_SIZE == 610)
#include "../src/P610/P610_api.h"
#define SCHEME_NAME    "SIKEp610"
#define crypto_kem_keypair            crypto_kem_keypair_SIKEp610
#define crypto_kem_enc                crypto_kem_enc_SIKEp610
#define crypto_kem_dec                crypto_kem_dec_SIKEp610

#elif (PRIME_SIZE == 751)
#include "../src/P751/P751_api.h"
#define SCHEME_NAME    "SIKEp751"
#define crypto_kem_keypair            crypto_kem_keypair_SIKEp751
#define crypto_kem_enc                crypto_kem_enc_SIKEp751
#define crypto_kem_dec                crypto_kem_dec_SIKEp751

#endif


// Benchmark and test parameters  
#if defined(OPTIMIZED_GENERIC_IMPLEMENTATION) || (TARGET == TARGET_ARM) 
    #define BENCH_LOOPS        5      // Number of iterations per bench 
    #define TEST_LOOPS         5      // Number of iterations per test
#else
    #define BENCH_LOOPS       100       
    #define TEST_LOOPS        10      
#endif

int main(int argc, char* argv[])
{
    int Status = PASSED;
    
    Status = malicious_pk_x(argc, argv); 
    if (Status != PASSED) {
        printf("\n\n   Error detected! \n\n");
        return FAILED;
    }


    return Status;
}