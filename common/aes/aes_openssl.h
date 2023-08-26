/********************************************************************************************
* Header defining the APIs for OpenSSL's AES implementation
*********************************************************************************************/

#ifndef __AES_OPENSSL_H
#define __AES_OPENSSL_H

#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


void handleErrors(void);
void AES128_free_schedule(EVP_CIPHER_CTX *schedule);
void AES256_free_schedule(EVP_CIPHER_CTX *schedule);


#endif
