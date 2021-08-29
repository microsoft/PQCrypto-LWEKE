/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: benchmarking/testing KEM scheme
*********************************************************************************************/

#include "../src/random/random.h"
#include "../src/sha3/fips202.h"

#ifdef DO_VALGRIND_CHECK
#include <valgrind/memcheck.h>
#endif

#if defined(DO_VALGRIND_CHECK) || defined(_PPC_)
#define KEM_TEST_ITERATIONS   1
#else
#define KEM_TEST_ITERATIONS 100
#endif
#define KEM_BENCH_SECONDS     1


static int kem_test(const char *named_parameters, int iterations) 
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ss_encap[CRYPTO_BYTES], ss_decap[CRYPTO_BYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char bytes[4];
    uint32_t* pos = (uint32_t*)bytes;
    uint8_t Fin[CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES];

    #ifdef DO_VALGRIND_CHECK
        if (!RUNNING_ON_VALGRIND) {
            fprintf(stderr, "This test can only usefully be run inside valgrind.\n");
            fprintf(stderr, "valgrind frodo640/test_KEM (or frodo976 or frodo1344)\n");
            exit(1);
        }
    #endif

    printf("\n");
    printf("=============================================================================================================================\n");
    printf("Testing correctness of key encapsulation mechanism (KEM), system %s, tests for %d iterations\n", named_parameters, iterations);
    printf("=============================================================================================================================\n");

    for (int i = 0; i < iterations; i++) {
        crypto_kem_keypair(pk, sk);
        crypto_kem_enc(ct, ss_encap, pk);
        crypto_kem_dec(ss_decap, ct, sk);
#ifdef DO_VALGRIND_CHECK
        VALGRIND_MAKE_MEM_DEFINED(ss_encap, CRYPTO_BYTES);
        VALGRIND_MAKE_MEM_DEFINED(ss_decap, CRYPTO_BYTES);
#endif
        if (memcmp(ss_encap, ss_decap, CRYPTO_BYTES) != 0) {
            printf("\n ERROR -- encapsulation/decapsulation mechanism failed!\n");
	        return false; 
        }

        // Testing decapsulation after changing random bits of a random 16-bit digit of ct
        randombytes(bytes, 4);
        *pos %= CRYPTO_CIPHERTEXTBYTES/2;
        if (*pos == 0) {
            *pos = 1;
        }
        ((uint16_t*)ct)[*pos] ^= *pos;
        crypto_kem_dec(ss_decap, ct, sk);
#ifdef DO_VALGRIND_CHECK
        VALGRIND_MAKE_MEM_DEFINED(ss_decap, CRYPTO_BYTES);
#endif

        // Compute ss = F(ct || s) with modified ct
        memcpy(Fin, ct, CRYPTO_CIPHERTEXTBYTES);
        memcpy(&Fin[CRYPTO_CIPHERTEXTBYTES], sk, CRYPTO_BYTES);
        shake(ss_encap, CRYPTO_BYTES, Fin, CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES);
        
#ifdef DO_VALGRIND_CHECK
        VALGRIND_MAKE_MEM_DEFINED(ss_encap, CRYPTO_BYTES);
#endif
        if (memcmp(ss_encap, ss_decap, CRYPTO_BYTES) != 0) {
            printf("\n ERROR -- changing random bits of the ciphertext should cause a failure!\n");
	        return false;
        }
    }
    printf("Tests PASSED. All session keys matched.\n");
    printf("\n\n");

    return true;
}


static void kem_bench(const int seconds) 
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ss_encap[CRYPTO_BYTES], ss_decap[CRYPTO_BYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];

    TIME_OPERATION_SECONDS({ crypto_kem_keypair(pk, sk); }, "Key generation", seconds);

    crypto_kem_keypair(pk, sk);
    TIME_OPERATION_SECONDS({ crypto_kem_enc(ct, ss_encap, pk); }, "KEM encapsulate", seconds);
    
    crypto_kem_enc(ct, ss_encap, pk);
    TIME_OPERATION_SECONDS({ crypto_kem_dec(ss_decap, ct, sk); }, "KEM decapsulate", seconds);
}


int main(int argc, char **argv) 
{
    int OK = true;

    OK = kem_test(SYSTEM_NAME, KEM_TEST_ITERATIONS);
    if (OK != true) {
        goto exit;
    }

    if ((argc > 1) && (strcmp("nobench", argv[1]) == 0)) {}
    else {
        PRINT_TIMER_HEADER
        kem_bench(KEM_BENCH_SECONDS);
    }

exit:
    return (OK == true) ? EXIT_SUCCESS : EXIT_FAILURE;
}
