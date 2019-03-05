/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: Key Encapsulation Mechanism (KEM) based on Frodo
*********************************************************************************************/

#include <string.h>
#include "sha3/fips202.h"
#include "random/random.h"


int crypto_kem_keypair(unsigned char* pk, unsigned char* sk)
{ // FrodoKEM's key generation
  // Outputs: public key pk (               BYTES_SEED_A + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 bytes)
  //          secret key sk (CRYPTO_BYTES + BYTES_SEED_A + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 + 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH bytes)
    uint8_t *pk_seedA = &pk[0];
    uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t *sk_s = &sk[0];
    uint8_t *sk_pk = &sk[CRYPTO_BYTES];
    uint8_t *sk_S = &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES];
    uint8_t *sk_pkh = &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR];
    uint16_t B[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t S[2*PARAMS_N*PARAMS_NBAR] = {0};               // contains secret data
    uint16_t *E = (uint16_t *)&S[PARAMS_N*PARAMS_NBAR];     // contains secret data
    uint8_t randomness[2*CRYPTO_BYTES + BYTES_SEED_A];      // contains secret data via randomness_s and randomness_seedE
    uint8_t *randomness_s = &randomness[0];                 // contains secret data
    uint8_t *randomness_seedE = &randomness[CRYPTO_BYTES];  // contains secret data
    uint8_t *randomness_z = &randomness[2*CRYPTO_BYTES];

    // Generate the secret value s, the seed for S and E, and the seed for the seed for A. Add seed_A to the public key
    randombytes(randomness, 2*CRYPTO_BYTES + BYTES_SEED_A);
    cshake(pk_seedA, BYTES_SEED_A, 0, randomness_z, (unsigned long long)(BYTES_SEED_A));

    // Generate S and E, and compute B = A*S + E. Generate A on-the-fly
    cshake((uint8_t*)S, 2*PARAMS_N*PARAMS_NBAR*sizeof(uint16_t), 1, randomness_seedE, (unsigned long long)(CRYPTO_BYTES));
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
    cshake(sk_pkh, BYTES_PKHASH, 1, pk, CRYPTO_PUBLICKEYBYTES);

    // Cleanup:
    clear_words((void*)S, PARAMS_N*PARAMS_NBAR/2);
    clear_words((void*)E, PARAMS_N*PARAMS_NBAR/2);
    clear_words((void*)randomness, CRYPTO_BYTES/2);
    return 0;
}


int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{ // FrodoKEM's key encapsulation
    const uint8_t *pk_seedA = &pk[0];
    const uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t *ct_c1 = &ct[0];
    uint8_t *ct_c2 = &ct[(PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8];
    uint16_t B[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t V[PARAMS_NBAR*PARAMS_NBAR]= {0};                 // contains secret data
    uint16_t C[PARAMS_NBAR*PARAMS_NBAR] = {0};
    ALIGN_HEADER(32) uint16_t Bp[PARAMS_N*PARAMS_NBAR] ALIGN_FOOTER(32) = {0};
    ALIGN_HEADER(32) uint16_t Sp[(2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR] ALIGN_FOOTER(32) = {0};  // contains secret data
    uint16_t *Ep = (uint16_t *)&Sp[PARAMS_N*PARAMS_NBAR];     // contains secret data
    uint16_t *Epp = (uint16_t *)&Sp[2*PARAMS_N*PARAMS_NBAR];  // contains secret data
    uint8_t G2in[BYTES_PKHASH + BYTES_MU];                    // contains secret data via mu
    uint8_t *pkh = &G2in[0];
    uint8_t *mu = &G2in[BYTES_PKHASH];                        // contains secret data
    uint8_t G2out[2*CRYPTO_BYTES];                            // contains secret data
    uint8_t *seedE = &G2out[0];                               // contains secret data
    uint8_t *k = &G2out[CRYPTO_BYTES];                        // contains secret data
    uint8_t Fin[CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES];       // contains secret data via Fin_k
    uint8_t *Fin_ct = &Fin[0];
    uint8_t *Fin_k = &Fin[CRYPTO_CIPHERTEXTBYTES];            // contains secret data

    // pkh <- G_1(pk), generate random mu, compute (seedE || k) = G_2(pkh || mu)
    cshake(pkh, BYTES_PKHASH, 1, pk, CRYPTO_PUBLICKEYBYTES);
    randombytes(mu, BYTES_MU);
    cshake(G2out, 2*CRYPTO_BYTES, 2, G2in, (unsigned long long)(BYTES_PKHASH + BYTES_MU));

    // Generate Sp and Ep, and compute Bp = Sp*A + Ep. Generate A on-the-fly
    cshake((uint8_t*)Sp, (2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR*sizeof(uint16_t), 3, seedE, (unsigned long long)(CRYPTO_BYTES));
    frodo_sample_n(Sp, PARAMS_N*PARAMS_NBAR);
    frodo_sample_n(Ep, PARAMS_N*PARAMS_NBAR);
    frodo_mul_add_sa_plus_e(Bp, Sp, Ep, pk_seedA);
    frodo_pack(ct_c1, (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8, Bp, PARAMS_N*PARAMS_NBAR, PARAMS_LOGQ);

    // Generate Epp, and compute V = Sp*B + Epp
    frodo_sample_n(Epp, PARAMS_NBAR*PARAMS_NBAR);
    frodo_unpack(B, PARAMS_N*PARAMS_NBAR, pk_b, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, PARAMS_LOGQ);
    frodo_mul_add_sb_plus_e(V, B, Sp, Epp);

    // Encode mu, and compute C = V + enc(mu) (mod q)
    frodo_key_encode(C, (uint16_t*)mu);
    frodo_add(C, V, C);
    frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);

    // Compute ss = F(ct||KK)
    memcpy(Fin_ct, ct, CRYPTO_CIPHERTEXTBYTES);
    memcpy(Fin_k, k, CRYPTO_BYTES);
    cshake(ss, CRYPTO_BYTES, 4, Fin, (unsigned long long)(CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES));

    // Cleanup:
    clear_words((void*)V, PARAMS_NBAR*PARAMS_NBAR/2);
    clear_words((void*)Sp, PARAMS_N*PARAMS_NBAR/2);
    clear_words((void*)Ep, PARAMS_N*PARAMS_NBAR/2);
    clear_words((void*)Epp, PARAMS_NBAR*PARAMS_NBAR/2);
    clear_words((void*)mu, BYTES_MU/4);
    clear_words((void*)G2out, CRYPTO_BYTES/2);
    clear_words((void*)Fin_k, CRYPTO_BYTES/4);
    return 0;
}


int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{ // FrodoKEM's key decapsulation
    uint16_t B[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t Bp[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t W[PARAMS_NBAR*PARAMS_NBAR] = {0};                // contains secret data
    uint16_t C[PARAMS_NBAR*PARAMS_NBAR] = {0};
    uint16_t CC[PARAMS_NBAR*PARAMS_NBAR] = {0};
    ALIGN_HEADER(32) uint16_t BBp[PARAMS_N*PARAMS_NBAR] ALIGN_FOOTER(32) = {0};
    ALIGN_HEADER(32) uint16_t Sp[(2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR] ALIGN_FOOTER(32) = {0};  // contains secret data
    uint16_t *Ep = (uint16_t *)&Sp[PARAMS_N*PARAMS_NBAR];     // contains secret data
    uint16_t *Epp = (uint16_t *)&Sp[2*PARAMS_N*PARAMS_NBAR];  // contains secret data
    const uint8_t *ct_c1 = &ct[0];
    const uint8_t *ct_c2 = &ct[(PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8];
    const uint8_t *sk_s = &sk[0];
    const uint8_t *sk_pk = &sk[CRYPTO_BYTES];
    const uint16_t *sk_S = (uint16_t *) &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES];
    const uint8_t *sk_pkh = &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR];
    const uint8_t *pk_seedA = &sk_pk[0];
    const uint8_t *pk_b = &sk_pk[BYTES_SEED_A];
    uint8_t G2in[BYTES_PKHASH + BYTES_MU];                   // contains secret data via muprime
    uint8_t *pkh = &G2in[0];
    uint8_t *muprime = &G2in[BYTES_PKHASH];                  // contains secret data
    uint8_t G2out[2*CRYPTO_BYTES];                           // contains secret data
    uint8_t *seedEprime = &G2out[0];                         // contains secret data
    uint8_t *kprime = &G2out[CRYPTO_BYTES];                  // contains secret data
    uint8_t Fin[CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES];      // contains secret data via Finput_k
    uint8_t *Fin_ct = &Fin[0];
    uint8_t *Fin_k = &Fin[CRYPTO_CIPHERTEXTBYTES];           // contains secret data

    // Compute W = C - Bp*S (mod q), and decode the randomness mu
    frodo_unpack(Bp, PARAMS_N*PARAMS_NBAR, ct_c1, (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8, PARAMS_LOGQ);
    frodo_unpack(C, PARAMS_NBAR*PARAMS_NBAR, ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, PARAMS_LOGQ);
    frodo_mul_bs(W, Bp, sk_S);
    frodo_sub(W, C, W);
    frodo_key_decode((uint16_t*)muprime, W);

    // Generate (seedE' || k') = G_2(pkh || mu')
    memcpy(pkh, sk_pkh, BYTES_PKHASH);
    cshake(G2out, 2*CRYPTO_BYTES, 2, G2in, (unsigned long long)(BYTES_PKHASH + BYTES_MU));

    // Generate Sp and Ep, and compute BBp = Sp*A + Ep. Generate A on-the-fly
    cshake((uint8_t*)Sp, (2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR*sizeof(uint16_t), 3, seedEprime, (unsigned long long)(CRYPTO_BYTES));
    frodo_sample_n(Sp, PARAMS_N*PARAMS_NBAR);
    frodo_sample_n(Ep, PARAMS_N*PARAMS_NBAR);
    frodo_mul_add_sa_plus_e(BBp, Sp, Ep, pk_seedA);

    // Generate Epp, and compute W = Sp*B + Epp
    frodo_sample_n(Epp, PARAMS_NBAR*PARAMS_NBAR);
    frodo_unpack(B, PARAMS_N*PARAMS_NBAR, pk_b, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, PARAMS_LOGQ);
    frodo_mul_add_sb_plus_e(W, B, Sp, Epp);

    // Encode mu, and compute CC = W + enc(mu') (mod q)
    frodo_key_encode(CC, (uint16_t*)muprime);
    frodo_add(CC, W, CC);

    // Prepare input to F
    memcpy(Fin_ct, ct, CRYPTO_CIPHERTEXTBYTES);

    // Reducing BBp modulo q
    for (int i = 0; i < PARAMS_N*PARAMS_NBAR; i++) BBp[i] = BBp[i] & ((1 << PARAMS_LOGQ)-1);

    // Is (Bp == BBp & C == CC) = true
    if (memcmp(Bp, BBp, 2*PARAMS_N*PARAMS_NBAR) == 0 && memcmp(C, CC, 2*PARAMS_NBAR*PARAMS_NBAR) == 0) {
        // Load k' to do ss = F(ct || k')
        memcpy(Fin_k, kprime, CRYPTO_BYTES);
    } else {
        // Load s to do ss = F(ct || s)
        memcpy(Fin_k, sk_s, CRYPTO_BYTES);
    }
    cshake(ss, CRYPTO_BYTES, 4, Fin, (unsigned long long)(CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES));

    // Cleanup:
    clear_words((void*)W, PARAMS_NBAR*PARAMS_NBAR/2);
    clear_words((void*)Sp, PARAMS_N*PARAMS_NBAR/2);
    clear_words((void*)Ep, PARAMS_N*PARAMS_NBAR/2);
    clear_words((void*)Epp, PARAMS_NBAR*PARAMS_NBAR/2);
    clear_words((void*)muprime, BYTES_MU/4);
    clear_words((void*)G2out, CRYPTO_BYTES/2);
    clear_words((void*)Fin_k, CRYPTO_BYTES/4);
    return 0;
}
