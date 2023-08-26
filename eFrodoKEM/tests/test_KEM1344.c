/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: setting parameters to test eFrodoKEM-1344
*********************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "ds_benchmark.h"
#include "../src/api_efrodo1344.h"


#define SYSTEM_NAME    "eFrodoKEM-1344"

#define crypto_kem_keypair_enc        crypto_kem_keypair_enc_eFrodo1344
#define crypto_kem_dec                crypto_kem_dec_eFrodo1344
#define shake                         shake256

#include "test_kem.c"
