/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: setting parameters to test eFrodoKEM-640
*********************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "ds_benchmark.h"
#include "../src/api_efrodo640.h"


#define SYSTEM_NAME    "eFrodoKEM-640"

#define crypto_kem_keypair_enc        crypto_kem_keypair_enc_eFrodo640
#define crypto_kem_dec                crypto_kem_dec_eFrodo640
#define shake                         shake128

#include "test_kem.c"
