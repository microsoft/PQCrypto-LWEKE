/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: parameters and API for eFrodoKEM-1344
*********************************************************************************************/

#ifndef _API_eFrodo1344_H_
#define _API_eFrodo1344_H_


#define CRYPTO_SECRETKEYBYTES  43088     // sizeof(s) + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH
#define CRYPTO_PUBLICKEYBYTES  21520     // sizeof(seed_A) + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8
#define CRYPTO_BYTES              32
#define CRYPTO_CIPHERTEXTBYTES 21632     // (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 + (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8

// Algorithm name
#define CRYPTO_ALGNAME "eFrodoKEM-1344"


int crypto_kem_keypair_enc_eFrodo1344(unsigned char* ct, unsigned char* ss, unsigned char* pk, unsigned char* sk);
int crypto_kem_dec_eFrodo1344(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
