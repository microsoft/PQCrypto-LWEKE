#ifndef FIPS202X4_H
#define FIPS202X4_H

#include <immintrin.h>

void shake128_absorb4x(__m256i *s, const unsigned char *in0, const unsigned char *in1, const unsigned char *in2, const unsigned char *in3, unsigned long long inlen);

void shake128_squeezeblocks4x(unsigned char *output0, unsigned char *output1, unsigned char *output2, unsigned char *output3, unsigned long long outlen, __m256i *s);

/* N is assumed to be empty; S is assumed to have at most 2 characters */
void shake128_4x(unsigned char *output0, unsigned char *output1, unsigned char *output2, unsigned char *output3, unsigned long long outlen, 
                        const unsigned char *in0, const unsigned char *in1, const unsigned char *in2, const unsigned char *in3, unsigned long long inlen);

#endif
