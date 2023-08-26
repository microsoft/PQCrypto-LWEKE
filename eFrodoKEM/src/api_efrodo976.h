/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: parameters and API for eFrodoKEM-976
*********************************************************************************************/

#ifndef _API_eFrodo976_H_
#define _API_eFrodo976_H_


#define CRYPTO_SECRETKEYBYTES  31296     // sizeof(s) + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH
#define CRYPTO_PUBLICKEYBYTES  15632     // sizeof(seed_A) + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8
#define CRYPTO_BYTES              24
#define CRYPTO_CIPHERTEXTBYTES 15744     // (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 + (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8

// Algorithm name
#define CRYPTO_ALGNAME "eFrodoKEM-976"


int crypto_kem_keypair_enc_eFrodo976(unsigned char *ct, unsigned char *ss, unsigned char *pk, unsigned char* sk);
int crypto_kem_dec_eFrodo976(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
