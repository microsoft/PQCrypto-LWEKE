/********************************************************************************************
* Functions for OpenSSL's AES implementation
*********************************************************************************************/

#include "aes_openssl.h"


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


void AES128_free_schedule(EVP_CIPHER_CTX *schedule) {
    EVP_CIPHER_CTX_free(schedule);
}


void AES256_free_schedule(EVP_CIPHER_CTX *schedule) {
    EVP_CIPHER_CTX_free(schedule);
}
