/*
 * hmac_drbg.h
 *
 *  Created on: 2018. 6. 12.
 *      Author: kyu
 */

#ifndef TEST_HMAC_DRBG_H_
#define TEST_HMAC_DRBG_H_

#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STATE_MAX_SIZE_256 55
#define STATE_MAX_SIZE_512 111

typedef unsigned char BitSequence;

struct DRBG_HMAC_Administrative {
	int drbgtype;
	int refreshperiod;
	bool predicttolerance;
	bool usingperstring;
	bool usingaddinput;
};


/**
 * DRBG 계산을 위한 내부 상태 구조체
 */
struct DRBG_SHA3_HMAC_Context {
	//union LSH_Context drbg_ctx;
	struct DRBG_HMAC_Administrative setting;
	BitSequence working_state_V256[STATE_MAX_SIZE_256];
	BitSequence working_state_C256[STATE_MAX_SIZE_256];
	BitSequence working_state_V512[STATE_MAX_SIZE_512];
	BitSequence working_state_C512[STATE_MAX_SIZE_512];
	int reseed_counter;

	unsigned int capacity;
	unsigned char delimitedSuffix;
};

/**
 * HMAC drbg V + 0x00 + intput data(entropy, nonce, perString)
 *
 * @param [in] input 최초 호출지로부터 값 저장하는 장소
 * @param [in] V
 * @param [in] entropy 엔트로피
 * @param [in] nonce 논스
 * @param [in] per_string 개별화 문자열
 *
 */
void drbg_ent_non_pers(struct DRBG_SHA3_HMAC_Context *ctx, BitSequence *input, BitSequence *V, int V_size, const BitSequence *entropy, int ent_size, const BitSequence *nonce, int non_size, const BitSequence *per_string, int per_size);

/**
 * HMAC 출력 함수
 *
 * @param [in] digest_size
 * @param [in] digest
 *
 */
void drbg_sha3_hmac_print(unsigned int digest_size, unsigned char *digest);



/**
 * DRBG HMAC 내부출력함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] V 엔트로피
 * @param [in] Key 논스
 *
 */
void drbg_sha3_inner_output(struct DRBG_SHA3_HMAC_Context *ctx, BitSequence *V, BitSequence *Key, const BitSequence *add_input, int add_size, FILE *outf, int num);

/**
 * DRBG HMAC 내부초기화함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] V 엔트로피
 * @param [in] Key 논스
 * @param [in] add input 추가입력
 *
 */
void drbg_sha3_inner_reset(struct DRBG_SHA3_HMAC_Context *ctx, BitSequence *V, BitSequence *Key, const BitSequence *add_input, int add_size, FILE *outf);

/**
 * DRBG 초기화 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] algtype LSH 알고리즘 명세
 * @param [in] entropy 엔트로피
 * @param [in] nonce 논스
 * @param [in] per_string 개별화 문자열
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
void drbg_sha3_hmac_init(struct DRBG_SHA3_HMAC_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *nonce, int non_size, const BitSequence *per_string, int per_size, const BitSequence *add_input, int add_size, FILE *outf);


/**
 * init, update, final 과정을 한번에 수행하여 HMAC을 계산한다.
 *
 * @param [in] algtype LSH 알고리즘 명세
 * @param [in] key 키
 * @param [in] keybytelen 키 길이 (바이트 단위)
 * @param [in] data 데이터
 * @param [in] databytelen 데이터 길이 (바이트 단위)
 * @param [out] digest HMAC 출력 버퍼
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
void drbg_sha3_hmac_digest(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, BitSequence (*entropy)[65], int ent_size, BitSequence *nonce, int non_size, BitSequence *per_string, int per_size, BitSequence (*add_input)[65], int add_size, int output_bits, int cycle, BitSequence *drbg, FILE *outf);


#ifdef __cplusplus
}
#endif

#endif /* TEST_HMAC_DRBG_H_ */
