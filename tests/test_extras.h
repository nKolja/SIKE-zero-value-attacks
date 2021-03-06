/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: utility header file for tests
*********************************************************************************************/  

#ifndef TEST_EXTRAS_H
#define TEST_EXTRAS_H
    
#include "../src/config.h"

#define PASSED    0
#define FAILED    1


#if (TARGET == TARGET_ARM || TARGET == TARGET_ARM64)
    #define print_unit printf("nsec");
#else
    #define print_unit printf("cycles");
#endif

    
// Access system counter for benchmarking
int64_t cpucycles(void);

// Comparing "nword" elements, a=b? : (1) a!=b, (0) a=b
int compare_words(digit_t* a, digit_t* b, unsigned int nwords);

// Generating a pseudo-random field element in [0, p434-1] 
void fprandom434_test(digit_t* a);

// Generating a pseudo-random element in GF(p434^2)
void fp2random434_test(digit_t* a);

// Generating a pseudo-random field element in [0, p503-1] 
void fprandom503_test(digit_t* a);

// Generating a pseudo-random element in GF(p503^2)
void fp2random503_test(digit_t* a);

// Generating a pseudo-random field element in [0, p546-1] 
void fprandom610_test(digit_t* a);

// Generating a pseudo-random element in GF(p546^2)
void fp2random610_test(digit_t* a);

// Generating a pseudo-random field element in [0, p751-1] 
void fprandom751_test(digit_t* a);

// Generating a pseudo-random element in GF(p751^2)
void fp2random751_test(digit_t* a);

// Make baseline Alice pks
int baseline_alice_keys(int argc, char* argv[]);

// Make a malicious Alice pk
int malicious_alice(int argc, char* argv[]);

// Simulate Bob's computation
int bob_computation(int argc, char* argv[]);

// Make baseline Bob pks
int baseline_bob_keys(int argc, char* argv[]);

// Make a malicious Bob pk
int malicious_bob(int argc, char* argv[]);

// Simulate Alice's computation
int alice_computation(int argc, char* argv[]);

// Make pk which forces x coordinate 0
int malicious_pk_x(int argc, char* argv[]);

// Make pk which forces z coordinate 0
int malicious_pk_z(int argc, char* argv[]);


#endif