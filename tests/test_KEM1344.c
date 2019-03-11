/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: setting parameters to test FrodoKEM-1344
*********************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "ds_benchmark.h"
#include "../src/api_frodo1344.h"


#define SYSTEM_NAME    "FrodoKEM-1344"

#define crypto_kem_keypair            crypto_kem_keypair_Frodo1344
#define crypto_kem_enc                crypto_kem_enc_Frodo1344
#define crypto_kem_dec                crypto_kem_dec_Frodo1344

#include "test_kem.c"
