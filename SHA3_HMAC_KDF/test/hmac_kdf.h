/*
 * hmac_drbg.h
 *
 *  Created on: 2018. 6. 12.
 *      Author: kyu
 */

#ifndef TEST_HMAC_KDF_H_
#define TEST_HMAC_KDF_H_

#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char BitSequence;

/**
 *
 * @param [in] alg_type {1: ctr, 2: fb, 3: dp}
 * @param [in] rate
 * @param [in] capacity
 * @param [in] delimitedSuffix
 * @param [in] password, pass_len (input from txt)
 * @param [in] salt, salt_leng (input from txt)
 * @parma [in] IterationCount (input from txt)
 * @parma [in] Klen (input from txt)
 * @parma [in] loopCount (input from txt)
 * @param [out] outf file 출력
 *
 */
void kdf_sha3_hmac_dp(const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *Kl, unsigned int Kl_len, BitSequence *Label, const unsigned int Label_len, BitSequence *Context, unsigned int Context_len, unsigned int L_len, unsigned int h_len, const unsigned int r, FILE *outf);
void kdf_sha3_hmac_fb(const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *Kl, unsigned int Kl_len, BitSequence *Label, const unsigned int Label_len, BitSequence *Context, unsigned int Context_len, unsigned int L_len, unsigned int h_len, const unsigned int r, FILE *outf);
void kdf_sha3_hmac_ctr(const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *Kl, unsigned int Kl_len, BitSequence *Label, const unsigned int Label_len, BitSequence *Context, unsigned int Context_len, unsigned int L_len, unsigned int h_len, const unsigned int r, FILE *outf);

/**
 *
 * @param [in] alg_type {1: ctr, 2: fb, 3: dp}, alg_type에 맞게 함수 호출
 *
 */
void kdf_sha3_hmac(const unsigned int alg_type, const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *Kl, unsigned int Kl_len, BitSequence *Lable, const unsigned int Label_len, BitSequence *Context, unsigned int Context_len, unsigned int L_len, unsigned int h_len, const unsigned int r, FILE *outf);


#ifdef __cplusplus
}
#endif

#endif /* TEST_HMAC_KDF_H_ */
