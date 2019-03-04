/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: Key Encapsulation Mechanism (KEM) based on Frodo
*********************************************************************************************/

#include <string.h>
#include "sha3/fips202.h"
#include "random/random.h"


int crypto_kem_keypair(unsigned char* pk, unsigned char* sk)
{ // Frodo-KEM's key generation
  // Outputs: public key pk (               BYTES_SEED_A + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 bytes)
  //          secret key sk (CRYPTO_BYTES + BYTES_SEED_A + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 + 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH bytes)
    uint8_t *pk_seedA = &pk[0];
    uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t *sk_s = &sk[0];
    uint8_t *sk_pk = &sk[CRYPTO_BYTES];
    uint8_t *sk_S = &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES];
    uint8_t *sk_pkh = &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR];
    uint16_t B[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t S[2*PARAMS_N*PARAMS_NBAR] = {0}; // contains secret data
    uint16_t *E = (uint16_t *)&S[PARAMS_N*PARAMS_NBAR]; // contains secret data
    uint8_t randomness[CRYPTO_BYTES + CRYPTO_BYTES + BYTES_SEED_A]; // contains secret data
    uint8_t *randomness_s = &randomness[0]; // contains secret data
    uint8_t *randomness_seedE = &randomness[CRYPTO_BYTES]; // contains secret data
    uint8_t *randomness_z = &randomness[CRYPTO_BYTES + CRYPTO_BYTES];

    uint8_t shake_input_z[4 + BYTES_SEED_A];
    uint8_t shake_input_seedE[4 + CRYPTO_BYTES];
    uint8_t shake_input_pk[4 + CRYPTO_PUBLICKEYBYTES];

    // Generate the secret value s, the seed for S and E, and the seed for the seed for A. Add seed_A to the public key
    randombytes(randomness, CRYPTO_BYTES + CRYPTO_BYTES + BYTES_SEED_A);
    shake_input_z[0] = 0xAA;
    shake_input_z[1] = 0x55;
    shake_input_z[2] = 0x55;
    shake_input_z[3] = 0xAA;
    memcpy(&shake_input_z[4], randomness_z, BYTES_SEED_A);
    shake(pk_seedA, BYTES_SEED_A, shake_input_z, 4 + BYTES_SEED_A);

    // Generate S and E, and compute B = A*S + E. Generate A on-the-fly
    shake_input_seedE[0] = 0x55;
    shake_input_seedE[1] = 0xAA;
    shake_input_seedE[2] = 0x55;
    shake_input_seedE[3] = 0xAA;
    memcpy(&shake_input_seedE[4], randomness_seedE, CRYPTO_BYTES);
    shake((uint8_t*)S, 2*PARAMS_N*PARAMS_NBAR*sizeof(uint16_t), shake_input_seedE, 4 + CRYPTO_BYTES);
    frodo_sample_n(S, PARAMS_N*PARAMS_NBAR);
    frodo_sample_n(E, PARAMS_N*PARAMS_NBAR);
    frodo_mul_add_as_plus_e(B, S, E, pk);

    // Encode the second part of the public key
    frodo_pack(pk_b, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, B, PARAMS_N*PARAMS_NBAR, PARAMS_LOGQ);

    // Add s, pk and S to the secret key
    memcpy(sk_s, randomness_s, CRYPTO_BYTES);
    memcpy(sk_pk, pk, CRYPTO_PUBLICKEYBYTES);
    memcpy(sk_S, S, 2*PARAMS_N*PARAMS_NBAR);

    // Add G_1(pk) to the secret key
    shake_input_pk[0] = 0x99;
    shake_input_pk[1] = 0x66;
    shake_input_pk[2] = 0x99;
    shake_input_pk[3] = 0x66;
    memcpy(&shake_input_pk[4], pk, CRYPTO_PUBLICKEYBYTES);
    shake(sk_pkh, BYTES_PKHASH, shake_input_pk, 4 + CRYPTO_PUBLICKEYBYTES);

    // Cleanup:
    clear_words((void*)S, PARAMS_N*PARAMS_NBAR/2);
    clear_words((void*)E, PARAMS_N*PARAMS_NBAR/2);
    clear_words((void*)randomness, (CRYPTO_BYTES + CRYPTO_BYTES + BYTES_SEED_A)/4);
    return 0;
}


int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{ // Frodo-KEM's key encapsulation
    const uint8_t *pk_seedA = &pk[0];
    const uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t *ct_c1 = &ct[0];
    uint8_t *ct_c2 = &ct[(PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8];
    uint16_t B[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t V[PARAMS_NBAR*PARAMS_NBAR]= {0}; // contains secret data
    uint16_t C[PARAMS_NBAR*PARAMS_NBAR] = {0};
    ALIGN_HEADER(32) uint16_t Bp[PARAMS_N*PARAMS_NBAR] ALIGN_FOOTER(32) = {0};
    ALIGN_HEADER(32) uint16_t Sp[(2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR] ALIGN_FOOTER(32) = {0}; // contains secret data
    uint16_t *Ep = (uint16_t *)&Sp[PARAMS_N*PARAMS_NBAR]; // contains secret data
    uint16_t *Epp = (uint16_t *)&Sp[2*PARAMS_N*PARAMS_NBAR]; // contains secret data
    uint8_t G2input[4 + BYTES_PKHASH + BYTES_MU]; // contains secret data via mu
    uint8_t *pkh = &G2input[4];
    uint8_t *mu = &G2input[4 + BYTES_PKHASH]; // contains secret data
    uint8_t G2output[CRYPTO_BYTES + CRYPTO_BYTES]; // contains secret data
    uint8_t *seedE = &G2output[0]; // contains secret data
    uint8_t *k = &G2output[CRYPTO_BYTES]; // contains secret data
    uint8_t Finput[4 + CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES]; // contains secret data via Finput_k
    uint8_t *Finput_ct = &Finput[4];
    uint8_t *Finput_k = &Finput[4 + CRYPTO_CIPHERTEXTBYTES]; // contains secret data

    uint8_t shake_input_pk[4 + CRYPTO_PUBLICKEYBYTES];
    uint8_t shake_input_seedE[4 + CRYPTO_BYTES];

    // hpk <- G_1(pk), generate random mu, compute (seedE || k) = G_2(pkh || mu)
    shake_input_pk[0] = 0x99;
    shake_input_pk[1] = 0x66;
    shake_input_pk[2] = 0x99;
    shake_input_pk[3] = 0x66;
    memcpy(&shake_input_pk[4], pk, CRYPTO_PUBLICKEYBYTES);
    shake(pkh, BYTES_PKHASH, shake_input_pk, 4 + CRYPTO_PUBLICKEYBYTES);
    randombytes(mu, BYTES_MU);
    G2input[0] = 0xA5;
    G2input[1] = 0x96;
    G2input[2] = 0x5A;
    G2input[3] = 0x69;
    shake(G2output, CRYPTO_BYTES + CRYPTO_BYTES, G2input, 4 + BYTES_PKHASH + BYTES_MU);

    // Generate Sp and Ep, and compute Bp = Sp*A + Ep. Generate A on-the-fly
    shake_input_seedE[0] = 0x66;
    shake_input_seedE[1] = 0x99;
    shake_input_seedE[2] = 0x99;
    shake_input_seedE[3] = 0x66;
    memcpy(&shake_input_seedE[4], seedE, CRYPTO_BYTES);
    shake((uint8_t*)Sp, (2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR*sizeof(uint16_t), shake_input_seedE, 4 + CRYPTO_BYTES);
    frodo_sample_n(Sp, PARAMS_N*PARAMS_NBAR);
    frodo_sample_n(Ep, PARAMS_N*PARAMS_NBAR);
    frodo_mul_add_sa_plus_e(Bp, Sp, Ep, pk_seedA);
    frodo_pack(ct_c1, (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8, Bp, PARAMS_N*PARAMS_NBAR, PARAMS_LOGQ);

    // Generate Epp, and compute V = Sp*B + Epp
    frodo_sample_n(Epp, PARAMS_NBAR*PARAMS_NBAR);
    frodo_unpack(B, PARAMS_N*PARAMS_NBAR, pk_b, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, PARAMS_LOGQ);
    frodo_mul_add_sb_plus_e(V, B, Sp, Epp);

    // Encode mu, and compute C = V + enc(mu) (mode q)
    frodo_key_encode(C, (uint16_t*)mu);
    frodo_add(C, V, C);
    frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);

    // Compute ss = F(ct||KK)
    Finput[0] = 0x00;
    Finput[1] = 0x01;
    Finput[2] = 0x02;
    Finput[3] = 0x03;
    memcpy(Finput_ct, ct, CRYPTO_CIPHERTEXTBYTES);
    memcpy(Finput_k, k, CRYPTO_BYTES);
    shake(ss, CRYPTO_BYTES, Finput, 4 + CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES);

    // Cleanup:
    clear_words((void*)V, PARAMS_NBAR*PARAMS_NBAR/2);
    clear_words((void*)Sp, PARAMS_N*PARAMS_NBAR/2);
    clear_words((void*)Ep, PARAMS_N*PARAMS_NBAR/2);
    clear_words((void*)Epp, PARAMS_NBAR*PARAMS_NBAR/2);
    clear_words((void*)mu, BYTES_MU/4);
    clear_words((void*)G2output, 2*CRYPTO_BYTES/4);
    clear_words((void*)Finput_k, CRYPTO_BYTES/4);
    return 0;
}


int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{ // Frodo-KEM's key decapsulation
    uint16_t B[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t Bp[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t W[PARAMS_NBAR*PARAMS_NBAR] = {0}; // contains secret data
    uint16_t C[PARAMS_NBAR*PARAMS_NBAR] = {0};
    uint16_t CC[PARAMS_NBAR*PARAMS_NBAR] = {0};
    ALIGN_HEADER(32) uint16_t BBp[PARAMS_N*PARAMS_NBAR] ALIGN_FOOTER(32) = {0};
    ALIGN_HEADER(32) uint16_t Sp[(2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR] ALIGN_FOOTER(32) = {0}; // contains secret data
    uint16_t *Ep = (uint16_t *)&Sp[PARAMS_N*PARAMS_NBAR]; // contains secret data
    uint16_t *Epp = (uint16_t *)&Sp[2*PARAMS_N*PARAMS_NBAR]; // contains secret data
    const uint8_t *ct_c1 = &ct[0];
    const uint8_t *ct_c2 = &ct[(PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8];
    const uint8_t *sk_s = &sk[0];
    const uint8_t *sk_pk = &sk[CRYPTO_BYTES];
    const uint16_t *sk_S = (uint16_t *) &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES];
    const uint8_t *sk_pkh = &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR];
    const uint8_t *pk_seedA = &sk_pk[0];
    const uint8_t *pk_b = &sk_pk[BYTES_SEED_A];
    uint8_t G2input[4 + BYTES_PKHASH + BYTES_MU]; // contains secret data via muprime
    uint8_t *pkh = &G2input[4];
    uint8_t *muprime = &G2input[4 + BYTES_PKHASH]; // contains secret data
    uint8_t G2output[CRYPTO_BYTES + CRYPTO_BYTES]; // contains secret data
    uint8_t *seedEprime = &G2output[0]; // contains secret data
    uint8_t *kprime = &G2output[CRYPTO_BYTES]; // contains secret data
    uint8_t Finput[4 + CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES]; // contains secret data via Finput_k
    uint8_t *Finput_ct = &Finput[4];
    uint8_t *Finput_k = &Finput[4 + CRYPTO_CIPHERTEXTBYTES]; // contains secret data
    
    uint8_t shake_input_seedEprime[4 + CRYPTO_BYTES];

    // Compute W = C - Bp*S (mod q), and decode the randomness mu
    frodo_unpack(Bp, PARAMS_N*PARAMS_NBAR, ct_c1, (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8, PARAMS_LOGQ);
    frodo_unpack(C, PARAMS_NBAR*PARAMS_NBAR, ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, PARAMS_LOGQ);
    frodo_mul_bs(W, Bp, sk_S);
    frodo_sub(W, C, W);
    frodo_key_decode((uint16_t*)muprime, W);

    // Generate (seedE' || k') = G_2(pkh || mu')
    memcpy(pkh, sk_pkh, BYTES_PKHASH);
    G2input[0] = 0xA5;
    G2input[1] = 0x96;
    G2input[2] = 0x5A;
    G2input[3] = 0x69;
    shake(G2output, CRYPTO_BYTES + CRYPTO_BYTES, G2input, 4 + BYTES_PKHASH + BYTES_MU);

    // Generate Sp and Ep, and compute BBp = Sp*A + Ep. Generate A on-the-fly
    shake_input_seedEprime[0] = 0x66;
    shake_input_seedEprime[1] = 0x99;
    shake_input_seedEprime[2] = 0x99;
    shake_input_seedEprime[3] = 0x66;
    memcpy(&shake_input_seedEprime[4], seedEprime, CRYPTO_BYTES);
    shake((uint8_t*)Sp, (2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR*sizeof(uint16_t), shake_input_seedEprime, 4 + CRYPTO_BYTES);
    frodo_sample_n(Sp, PARAMS_N*PARAMS_NBAR);
    frodo_sample_n(Ep, PARAMS_N*PARAMS_NBAR);
    frodo_mul_add_sa_plus_e(BBp, Sp, Ep, pk_seedA);

    // Generate Epp, and compute W = Sp*B + Epp
    frodo_sample_n(Epp, PARAMS_NBAR*PARAMS_NBAR);
    frodo_unpack(B, PARAMS_N*PARAMS_NBAR, pk_b, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, PARAMS_LOGQ);
    frodo_mul_add_sb_plus_e(W, B, Sp, Epp);

    // Encode mu, and compute CC = W + enc(mu') (mode q)
    frodo_key_encode(CC, (uint16_t*)muprime);
    frodo_add(CC, W, CC);

    // Prepare input to F
    memcpy(Finput_ct, ct, CRYPTO_CIPHERTEXTBYTES);

    // Reducing BBp modulo q
    for (int i = 0; i < PARAMS_N*PARAMS_NBAR; i++) BBp[i] = BBp[i] & ((1 << PARAMS_LOGQ)-1);

    // Is (Bp == BBp & C == CC) = true
    Finput[0] = 0x00;
    Finput[1] = 0x01;
    Finput[2] = 0x02;
    Finput[3] = 0x03;
    if (memcmp(Bp, BBp, 2*PARAMS_N*PARAMS_NBAR) == 0 && memcmp(C, CC, 2*PARAMS_NBAR*PARAMS_NBAR) == 0) {
        // Load k' to do ss = F(ct || k')
        memcpy(Finput_k, kprime, CRYPTO_BYTES);
    } else {
        // Load s to do ss = F(ct || s)
        memcpy(Finput_k, sk_s, CRYPTO_BYTES);
    }
    shake(ss, CRYPTO_BYTES, Finput, 4 + CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES);

    // Cleanup:
    clear_words((void*)W, PARAMS_NBAR*PARAMS_NBAR/2);
    clear_words((void*)Sp, PARAMS_N*PARAMS_NBAR/2);
    clear_words((void*)Ep, PARAMS_N*PARAMS_NBAR/2);
    clear_words((void*)Epp, PARAMS_NBAR*PARAMS_NBAR/2);
    clear_words((void*)muprime, BYTES_MU/4);
    clear_words((void*)G2output, 2*CRYPTO_BYTES/4);
    clear_words((void*)Finput_k, CRYPTO_BYTES/4);
    return 0;
}
