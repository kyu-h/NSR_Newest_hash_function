/*
 * hmac_drbg.h
 *
 *  Created on: 2018. 6. 12.
 *      Author: kyu
 */

#ifndef TEST_HMAC_PBKDF_H_
#define TEST_HMAC_PBKDF_H_

#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char BitSequence;

/**
 *
 * @param [in] rate
 * @param [in] capacity
 * @param [in] delimitedSuffix
 * @param [in] password, pass_len (input from txt)
 * @param [in] salt, salt_leng (input from txt)
 * @parma [in] IterationCount (input from txt)
 * @parma [in] Klen (input from txt)
 * @parma [in] loopCount (input from txt)
 * @param [out] outf file Ãâ·Â
 *
 */
void pbkdf_sha3_hmac(const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *password, unsigned int pass_len, BitSequence *salt, const unsigned int salt_leng, unsigned int IterationCount, unsigned int Klen, unsigned int loopCount, FILE *outf);


#ifdef __cplusplus
}
#endif

#endif /* TEST_HMAC_PBKDF_H_ */
