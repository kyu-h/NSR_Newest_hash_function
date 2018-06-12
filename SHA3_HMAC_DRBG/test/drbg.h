/*
 * drbg.h
 *
 *  Created on: 2018. 6. 7.
 *      Author: kyu
 */

#ifndef SRC_STANDALONE_DRBG_H_
#define SRC_STANDALONE_DRBG_H_

#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STATE_MAX_SIZE_256 55
#define STATE_MAX_SIZE_512 111

typedef unsigned char BitSequence;

/**
 * DRBG 설정 정보
 * drbgtype 난수발생기, 기반암호 알고리즘
 * refreshperiod 상태 갱신주기
 * predicttolerance 예측내성 활성화 여부
 * usingperstring 개별화 문자열 사용 여부
 * usingaddinput 추가 입력 사용 여부
 */
struct DRBG_Administrative {
	int drbgtype;
	int refreshperiod;
	bool predicttolerance;
	bool usingperstring;
	bool usingaddinput;
};


/**
 * DRBG 계산을 위한 내부 상태 구조체
 */
struct DRBG_SHA3_Context {
	//union LSH_Context drbg_ctx;
	struct DRBG_Administrative setting;
	BitSequence working_state_V256[STATE_MAX_SIZE_256];
	BitSequence working_state_C256[STATE_MAX_SIZE_256];
	BitSequence working_state_V512[STATE_MAX_SIZE_512];
	BitSequence working_state_C512[STATE_MAX_SIZE_512];
	int reseed_counter;

	unsigned int capacity;
	unsigned char delimitedSuffix;
};


void drbg_sha3_digest(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, BitSequence (*entropy)[65], int ent_size, BitSequence *nonce, int non_size, BitSequence *per_string, int per_size, BitSequence (*add_input)[65], int add_size, int output_bits, int cycle, BitSequence *drbg, FILE *outf);

/**
 * DRBG 유도 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] algtype LSH 알고리즘 명세
 * @param [in] data 임의 길이 데이터
 * @param [out] seed 시드
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
void drbg_derivation_func(struct DRBG_SHA3_Context *ctx, const BitSequence *data, int data_size, BitSequence *output);


void drbg_sha3_inner_output_gen(struct DRBG_SHA3_Context *ctx, BitSequence *input, BitSequence *output, int output_bits, FILE *outf);


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
void drbg_sha3_init(struct DRBG_SHA3_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *nonce, int non_size, const BitSequence *per_string, int per_size, FILE *outf);


/**
 * DRBG 갱신 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] add_input 추가 입력
 * @param [in] state 작동상태
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
void drbg_sha3_reseed(struct DRBG_SHA3_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *add_input, int add_size, FILE *outf);


/**
 * DRBG 출력 생성 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] add_input 추가 입력
 * @param [in] state 작동상태
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
void drbg_sha3_output_gen(struct DRBG_SHA3_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *add_input, int add_size, int output_bits, int cycle, BitSequence *drbg, FILE *outf, int counter);


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
void drbg_sha3_digest(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, BitSequence (*entropy)[65], int ent_size, BitSequence *nonce, int non_size, BitSequence *per_string, int per_size, BitSequence (*add_input)[65], int add_size, int output_bits, int cycle, BitSequence *drbg, FILE *outf);


#ifdef __cplusplus
}
#endif


#endif /* SRC_STANDALONE_DRBG_H_ */
