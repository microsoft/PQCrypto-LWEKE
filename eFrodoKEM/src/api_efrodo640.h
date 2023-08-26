/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: parameters and API for eFrodoKEM-640
*********************************************************************************************/

#ifndef _API_eFrodo640_H_
#define _API_eFrodo640_H_


#define CRYPTO_SECRETKEYBYTES  19888     // sizeof(s) + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH
#define CRYPTO_PUBLICKEYBYTES   9616     // sizeof(seed_A) + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8
#define CRYPTO_BYTES              16
#define CRYPTO_CIPHERTEXTBYTES  9720     // (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 + (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8

// Algorithm name
#define CRYPTO_ALGNAME "eFrodoKEM-640"


int crypto_kem_keypair_enc_eFrodo640(unsigned char* ct, unsigned char* ss, unsigned char* pk, unsigned char* sk);
int crypto_kem_dec_eFrodo640(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
