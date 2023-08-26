####  Makefile for compilation on Unix-like operative systems  ####

CC=gcc
ifeq "$(CC)" "gcc"
    COMPILER=gcc
else ifeq "$(CC)" "clang"
    COMPILER=clang
endif

ARCHITECTURE=_AMD64_
ifeq "$(ARCH)" "x64"
    ARCHITECTURE=_AMD64_
else ifeq "$(ARCH)" "x86"
    ARCHITECTURE=_X86_
    USE_OPT_LEVEL=_FAST_GENERIC_
else ifeq "$(ARCH)" "ARM"
    ARCHITECTURE=_ARM_
    USE_OPT_LEVEL=_FAST_GENERIC_
else ifeq "$(ARCH)" "PPC"
    ARCHITECTURE=_PPC_
    USE_OPT_LEVEL=_REFERENCE_
else ifeq "$(ARCH)" "s390x"
    ARCHITECTURE=_S390X_
    USE_OPT_LEVEL=_REFERENCE_
endif

ifeq "$(ARCHITECTURE)" "_AMD64_"
    USE_OPT_LEVEL=_FAST_
endif

ifeq "$(OPT_LEVEL)" "REFERENCE"
    USE_OPT_LEVEL=_REFERENCE_
else ifeq "$(OPT_LEVEL)" "FAST_GENERIC"
    USE_OPT_LEVEL=_FAST_GENERIC_
else ifeq "$(OPT_LEVEL)" "FAST"
    ifeq "$(ARCHITECTURE)" "_AMD64_"
        USE_OPT_LEVEL=_FAST_
    endif
endif

USE_GENERATION_A=_AES128_FOR_A_
ifeq "$(GENERATION_A)" "AES128"
    USE_GENERATION_A=_AES128_FOR_A_
else ifeq "$(GENERATION_A)" "SHAKE128"
    USE_GENERATION_A=_SHAKE128_FOR_A_
endif

ifeq "$(ARCH)" "ARM"
    ARM_SETTING=-lrt
endif

USING_OPENSSL=_USE_OPENSSL_
ifeq "$(USE_OPENSSL)" "FALSE"
    USING_OPENSSL=NO_OPENSSL
endif

OPENSSL_INCLUDE_DIR=/usr/include
OPENSSL_LIB_DIR=/usr/lib

AR=ar rcs
RANLIB=ranlib
LN=ln -s

VALGRIND_CFLAGS=
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
VALGRIND_CFLAGS= -g -O0 -DDO_VALGRIND_CHECK
endif

ifeq "$(EXTRA_CFLAGS)" ""
CFLAGS= -O3 
else
CFLAGS= $(EXTRA_CFLAGS)
endif
CFLAGS+= $(VALGRIND_CFLAGS)
CFLAGS+= -std=gnu11 -Wall -Wextra -DNIX -D $(ARCHITECTURE) -D $(USE_OPT_LEVEL) -D $(USE_GENERATION_A) -D $(USING_OPENSSL)
ifeq "$(CC)" "gcc"
ifneq "$(ARCHITECTURE)" "_PPC_"
ifneq "$(ARCHITECTURE)" "_S390X_"
CFLAGS+= -march=native
endif
endif
endif

ifeq "$(USE_OPENSSL)" "FALSE"
LDFLAGS=-lm
else
CFLAGS+= -I$(OPENSSL_INCLUDE_DIR)
LDFLAGS=-lm -L$(OPENSSL_LIB_DIR) -lssl -lcrypto
endif

ifeq "$(ARCHITECTURE)" "_AMD64_"
ifeq "$(USE_OPT_LEVEL)" "_FAST_"
CFLAGS += -mavx2 -maes -msse2
endif
endif

.PHONY: all check clean prettyprint

all: lib640 lib976 lib1344 tests KATS

objs/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/efrodo640.o: src/efrodo640.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/efrodo976.o: src/efrodo976.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/efrodo1344.o: src/efrodo1344.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

# RAND
objs/random/random.o: ../common/random/random.c ../common/random/random.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/random/random.c -o objs/random/random.o
RAND_OBJS := objs/random/random.o

# KEM_FRODO
KEM_FRODO640_OBJS := $(addprefix objs/, efrodo640.o util.o)
KEM_FRODO640_HEADERS := $(addprefix src/, api_efrodo640.h config.h frodo_macrify.h)
$(KEM_FRODO640_OBJS): $(KEM_FRODO640_HEADERS) $(addprefix src/, ekem.c noise.c util.c)

KEM_FRODO976_OBJS := $(addprefix objs/, efrodo976.o util.o)
KEM_FRODO976_HEADERS := $(addprefix src/, api_efrodo976.h config.h frodo_macrify.h)
$(KEM_FRODO976_OBJS): $(KEM_FRODO976_HEADERS) $(addprefix src/, ekem.c noise.c util.c)

KEM_FRODO1344_OBJS := $(addprefix objs/, efrodo1344.o util.o)
KEM_FRODO1344_HEADERS := $(addprefix src/, api_efrodo1344.h config.h frodo_macrify.h)
$(KEM_FRODO1344_OBJS): $(KEM_FRODO1344_HEADERS) $(addprefix src/, ekem.c noise.c util.c)

# AES
ifeq "$(USE_OPENSSL)" "FALSE" 
ifeq "$(USE_OPT_LEVEL)" "_FAST_"
# AES_NI
objs/aes/aes_ni.o: ../common/aes/aes_ni.c ../common/aes/aes.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/aes/aes_ni.c -o objs/aes/aes_ni.o
AES_OBJS := objs/aes/aes_ni.o
else
objs/aes/aes_c.o: ../common/aes/aes_c.c ../common/aes/aes.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/aes/aes_c.c -o objs/aes/aes_c.o
AES_OBJS := objs/aes/aes_c.o
endif
else
objs/aes/aes_openssl.o: ../common/aes/aes_openssl.c ../common/aes/aes_openssl.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/aes/aes_openssl.c -o objs/aes/aes_openssl.o
AES_OBJS := objs/aes/aes_openssl.o
endif

# SHAKE
objs/sha3/fips202.o: ../common/sha3/fips202.c ../common/sha3/fips202.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/sha3/fips202.c -o objs/sha3/fips202.o
SHAKE_OBJS := objs/sha3/fips202.o

ifeq "$(USE_OPT_LEVEL)" "_FAST_"
ifeq "$(GENERATION_A)" "SHAKE128"
# SHAKEx4
objs/sha3/fips202x4.o: ../common/sha3/fips202x4.c ../common/sha3/fips202x4.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/sha3/fips202x4.c -o objs/sha3/fips202x4.o

objs/sha3/keccak4x/KeccakP-1600-times4-SIMD256.o: ../common/sha3/keccak4x/KeccakP-1600-times4-SIMD256.c ../common/sha3/keccak4x/KeccakP-1600-times4-SnP.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/sha3/keccak4x/KeccakP-1600-times4-SIMD256.c -o objs/sha3/keccak4x/KeccakP-1600-times4-SIMD256.o

SHAKEx4_OBJS := objs/sha3/fips202x4.o objs/sha3/keccak4x/KeccakP-1600-times4-SIMD256.o
endif
endif

lib640: $(KEM_FRODO640_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf efrodo640
	mkdir efrodo640
	$(AR) efrodo640/libefrodo.a $^
	$(RANLIB) efrodo640/libefrodo.a

lib976: $(KEM_FRODO976_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf efrodo976
	mkdir efrodo976
	$(AR) efrodo976/libefrodo.a $^
	$(RANLIB) efrodo976/libefrodo.a

lib1344: $(KEM_FRODO1344_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf efrodo1344
	mkdir efrodo1344
	$(AR) efrodo1344/libefrodo.a $^
	$(RANLIB) efrodo1344/libefrodo.a

tests: lib640 lib976 lib1344 tests/ds_benchmark.h
	$(CC) $(CFLAGS) -L./efrodo640 tests/test_KEM640.c -lefrodo $(LDFLAGS) -o efrodo640/test_KEM $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./efrodo976 tests/test_KEM976.c -lefrodo $(LDFLAGS) -o efrodo976/test_KEM $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./efrodo1344 tests/test_KEM1344.c -lefrodo $(LDFLAGS) -o efrodo1344/test_KEM $(ARM_SETTING)

lib640_for_KATs: $(KEM_FRODO640_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	$(AR) efrodo640/libefrodo_for_testing.a $^
	$(RANLIB) efrodo640/libefrodo_for_testing.a

lib976_for_KATs: $(KEM_FRODO976_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	$(AR) efrodo976/libefrodo_for_testing.a $^
	$(RANLIB) efrodo976/libefrodo_for_testing.a

lib1344_for_KATs: $(KEM_FRODO1344_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	$(AR) efrodo1344/libefrodo_for_testing.a $^
	$(RANLIB) efrodo1344/libefrodo_for_testing.a

KATS: lib640_for_KATs lib976_for_KATs lib1344_for_KATs
ifeq "$(GENERATION_A)" "SHAKE128"
	$(CC) $(CFLAGS) -L./efrodo640 tests/PQCtestKAT_kem640_shake.c tests/rng.c -lefrodo_for_testing $(LDFLAGS) -o efrodo640/PQCtestKAT_kem_shake $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./efrodo976 tests/PQCtestKAT_kem976_shake.c tests/rng.c -lefrodo_for_testing $(LDFLAGS) -o efrodo976/PQCtestKAT_kem_shake $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./efrodo1344 tests/PQCtestKAT_kem1344_shake.c tests/rng.c -lefrodo_for_testing $(LDFLAGS) -o efrodo1344/PQCtestKAT_kem_shake $(ARM_SETTING)
else
	$(CC) $(CFLAGS) -L./efrodo640 tests/PQCtestKAT_kem640.c tests/rng.c -lefrodo_for_testing $(LDFLAGS) -o efrodo640/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./efrodo976 tests/PQCtestKAT_kem976.c tests/rng.c -lefrodo_for_testing $(LDFLAGS) -o efrodo976/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./efrodo1344 tests/PQCtestKAT_kem1344.c tests/rng.c -lefrodo_for_testing $(LDFLAGS) -o efrodo1344/PQCtestKAT_kem $(ARM_SETTING)
endif

check: tests

test640:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 efrodo640/test_KEM
else
	efrodo640/test_KEM
endif

test976:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 efrodo976/test_KEM
else
	efrodo976/test_KEM
endif

test1344:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 efrodo1344/test_KEM
else
	efrodo1344/test_KEM
endif

clean:
	rm -rf objs *.req efrodo640 efrodo976 efrodo1344
	find . -name .DS_Store -type f -delete

prettyprint:
	astyle --style=java --indent=tab --pad-header --pad-oper --align-pointer=name --align-reference=name --suffix=none src/*.h src/*/*.h src/*/*.c
