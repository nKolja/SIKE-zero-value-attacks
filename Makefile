####  Makefile for compilation on Unix-like operative systems  ####

CC=clang
ifeq "$(CC)" "gcc"
    COMPILER=gcc
else ifeq "$(CC)" "clang"
    COMPILER=clang
endif

ARCHITECTURE=_AMD64_
USE_OPT_LEVEL=_FAST_
ifeq "$(ARCH)" "x64"
    ARCHITECTURE=_AMD64_
    USE_OPT_LEVEL=_FAST_
else ifeq "$(ARCH)" "x86"
    ARCHITECTURE=_X86_
    USE_OPT_LEVEL=_GENERIC_
else ifeq "$(ARCH)" "s390x"
    ARCHITECTURE=_S390X_
    USE_OPT_LEVEL=_GENERIC_
else ifeq "$(ARCH)" "ARM"
    ARCHITECTURE=_ARM_
    USE_OPT_LEVEL=_GENERIC_
    ARM_TARGET=YES
else ifeq "$(ARCH)" "ARM64"
    ARCHITECTURE=_ARM64_
    USE_OPT_LEVEL=_FAST_
    ARM_TARGET=YES
else ifeq "$(ARCH)" "M1"
    ARCHITECTURE=_ARM64_
    USE_OPT_LEVEL=_FAST_
endif

ifeq "$(OPT_LEVEL)" "GENERIC"
    USE_OPT_LEVEL=_GENERIC_
endif

ifeq "$(ARM_TARGET)" "YES"
    ARM_SETTING=-lrt
endif

ifeq "$(ARCHITECTURE)" "_AMD64_"
    ifeq "$(USE_OPT_LEVEL)" "_FAST_"
        MULX=-D _MULX_
        ifeq "$(USE_MULX)" "FALSE"
            MULX=
        else
            ADX=-D _ADX_
            ifeq "$(USE_ADX)" "FALSE"
                ADX=
            endif
        endif
    endif
endif

AR=ar rcs
RANLIB=ranlib

ADDITIONAL_SETTINGS=-march=native
ifeq "$(CC)" "clang"
ifeq "$(ARM_TARGET)" "YES"
    ADDITIONAL_SETTINGS=
endif
endif
ifeq "$(ARCHITECTURE)" "_S390X_"
	ADDITIONAL_SETTINGS=-march=z10
endif

ifeq "$(COUNTERMEASURE)" "YES"
    USE_COUNTER=-D COUNTERMEASURE
endif



ifeq "$(EXTRA_CFLAGS)" ""
CFLAGS= -O3     # Optimization option by default
else
CFLAGS= $(EXTRA_CFLAGS)
endif
CFLAGS+= -std=gnu11 -Wall $(ADDITIONAL_SETTINGS) -D $(ARCHITECTURE) -D __NIX__ -D $(USE_OPT_LEVEL) $(MULX) $(ADX) $(USE_COUNTER)
LDFLAGS=-lm -lgmp


OBJS=objs$(PRIME_SIZE)

ifeq "$(USE_OPT_LEVEL)" "_GENERIC_"
    EXTRA_OBJECTS=$(OBJS)/fp_generic.o
else ifeq "$(USE_OPT_LEVEL)" "_FAST_"
ifeq "$(ARCHITECTURE)" "_AMD64_"
    EXTRA_OBJECTS=$(OBJS)/fp_x64.o $(OBJS)/fp_x64_asm.o
else ifeq "$(ARCHITECTURE)" "_ARM64_"
    EXTRA_OBJECTS=$(OBJS)/fp_arm64.o $(OBJS)/fp_arm64_asm.o
endif
endif
OBJECTS=$(OBJS)/P$(PRIME_SIZE).o $(EXTRA_OBJECTS) objs/random.o objs/fips202.o
OBJECTS_COMP=$(OBJS)comp/P$(PRIME_SIZE)_compressed.o $(EXTRA_OBJECTS) objs/random.o objs/fips202.o

all: tests attacks

attacks: lib alice_computation bob_computation malicious_alice malicious_bob malicious_pk_x malicious_pk_z baseline_bob baseline_alice
attack_alice: lib baseline_bob malicious_bob alice_computation
attack_bob: lib baseline_alice malicious_alice bob_computation
attack_x: lib malicious_pk_x
attack_z: lib malicious_pk_z



$(OBJS)/%.o: src/P$(PRIME_SIZE)/%.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $< -o $@

# $(OBJS)comp/%.o: src/P$(PRIME_SIZE)/%.c
# 	@mkdir -p $(@D)
# 	$(CC) -c $(CFLAGS) $< -o $@


ifeq "$(USE_OPT_LEVEL)" "_GENERIC_"		
    $(OBJS)/fp_generic.o: src/P$(PRIME_SIZE)/generic/fp_generic.c
	    $(CC) -c $(CFLAGS) src/P$(PRIME_SIZE)/generic/fp_generic.c -o $(OBJS)/fp_generic.o
else ifeq "$(USE_OPT_LEVEL)" "_FAST_"
ifeq "$(ARCHITECTURE)" "_AMD64_"		
    $(OBJS)/fp_x64.o: src/P$(PRIME_SIZE)/AMD64/fp_x64.c
	    $(CC) -c $(CFLAGS) src/P$(PRIME_SIZE)/AMD64/fp_x64.c -o $(OBJS)/fp_x64.o

    $(OBJS)/fp_x64_asm.o: src/P$(PRIME_SIZE)/AMD64/fp_x64_asm.S
	    $(CC) -c $(CFLAGS) src/P$(PRIME_SIZE)/AMD64/fp_x64_asm.S -o $(OBJS)/fp_x64_asm.o
else ifeq "$(ARCHITECTURE)" "_ARM64_"	
    $(OBJS)/fp_arm64.o: src/P$(PRIME_SIZE)/ARM64/fp_arm64.c
	    $(CC) -c $(CFLAGS) src/P$(PRIME_SIZE)/ARM64/fp_arm64.c -o $(OBJS)/fp_arm64.o

    $(OBJS)/fp_arm64_asm.o: src/P$(PRIME_SIZE)/ARM64/fp_arm64_asm.S
	    $(CC) -c $(CFLAGS) src/P$(PRIME_SIZE)/ARM64/fp_arm64_asm.S -o $(OBJS)/fp_arm64_asm.o
endif
endif

objs/random.o: src/random/random.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) src/random/random.c -o objs/random.o

objs/fips202.o: src/sha3/fips202.c
	$(CC) -c $(CFLAGS) src/sha3/fips202.c -o objs/fips202.o

lib: $(OBJECTS)
	rm -rf lib$(PRIME_SIZE) sike$(PRIME_SIZE) sidh$(PRIME_SIZE)
	mkdir lib$(PRIME_SIZE) sike$(PRIME_SIZE) sidh$(PRIME_SIZE)
	$(AR) lib$(PRIME_SIZE)/libsidh.a $^
	$(RANLIB) lib$(PRIME_SIZE)/libsidh.a

tests: lib
	$(CC) $(CFLAGS) -L./lib$(PRIME_SIZE) tests/test_SIDHp$(PRIME_SIZE).c tests/test_extras.c -lsidh $(LDFLAGS) -o sidh$(PRIME_SIZE)/test_SIDH $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib$(PRIME_SIZE) tests/test_SIKEp$(PRIME_SIZE).c tests/test_extras.c -lsidh $(LDFLAGS) -o sike$(PRIME_SIZE)/test_SIKE $(ARM_SETTING)



# ATTACKING BOB
baseline_alice: lib     # CREATES A BASLINE PAIR OF PUBLIC KEYS USE TO COMPUTE TWO DIFFERENT J-INVARIANTS
	$(CC) $(CFLAGS) -L./lib$(PRIME_SIZE) tests/test_baseline_alice.c tests/test_extras.c -lsidh $(LDFLAGS) -o baseline_alice $(ARM_SETTING)

malicious_alice: lib    # CREATES A MALICIOUS ALICE PUBLIC KEY
	$(CC) $(CFLAGS) -L./lib$(PRIME_SIZE) tests/test_malicious_alice.c tests/test_extras.c -lsidh $(LDFLAGS) -o malicious_alice $(ARM_SETTING)

bob_computation: lib    # SIMULATING BOB'S COMPUTATION ON THE CORTEX M4
	$(CC) $(CFLAGS) -L./lib$(PRIME_SIZE) tests/test_bob.c tests/test_extras.c -lsidh $(LDFLAGS) -o bob_computation $(ARM_SETTING)

# ATTACKING ALICE
baseline_bob: lib     	# CREATES A BASLINE PAIR OF PUBLIC KEYS USE TO COMPUTE TWO DIFFERENT J-INVARIANTS
	$(CC) $(CFLAGS) -L./lib$(PRIME_SIZE) tests/test_baseline_bob.c tests/test_extras.c -lsidh $(LDFLAGS) -o baseline_bob $(ARM_SETTING)

malicious_bob: lib      # CREATES A MALICIOUS BOB PUBLIC KEY
	$(CC) $(CFLAGS) -L./lib$(PRIME_SIZE) tests/test_malicious_bob.c tests/test_extras.c -lsidh $(LDFLAGS) -o malicious_bob $(ARM_SETTING)

alice_computation: lib  # SIMULATING ALICE'S COMPUTATION ON THE CORTEX M4
	$(CC) $(CFLAGS) -L./lib$(PRIME_SIZE) tests/test_alice.c tests/test_extras.c -lsidh $(LDFLAGS) -o alice_computation $(ARM_SETTING)

# ATTACKING THE LADDER3PT
malicious_pk_x: lib  	# CREATES A MALICIOUS PK WHICH FORCES THE COMPUTATION OF [0:1]
	$(CC) $(CFLAGS) -L./lib$(PRIME_SIZE) tests/test_pk_x.c tests/test_extras.c -lsidh $(LDFLAGS) -o malicious_pk_x $(ARM_SETTING)

malicious_pk_z: lib  # CREATES A MALICIOUS PK WHICH FORCES THE COMPUTATION OF [1:0]
	$(CC) $(CFLAGS) -L./lib$(PRIME_SIZE) tests/test_pk_z.c tests/test_extras.c -lsidh $(LDFLAGS) -o malicious_pk_z $(ARM_SETTING)

# # AES
# AES_OBJS=objs/aes.o objs/aes_c.o

# objs/%.o: tests/aes/%.c
# 	@mkdir -p $(@D)
# 	$(CC) -c $(CFLAGS) $< -o $@

check: tests


.PHONY: clean

clean:
	rm -rf *.req objs434* objs503* objs610* objs751* objs lib434* lib503* lib610* lib751*  sidh434* sidh503* sidh610* sidh751* sike434* sike503* sike610* sike751* arith_tests-* bob_computation alice_computation malicious_alice malicious_bob baseline_alice baseline_bob public_keys/* malicious_pk_x malicious_pk_z

