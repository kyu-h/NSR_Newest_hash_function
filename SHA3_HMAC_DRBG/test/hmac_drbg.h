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
 * DRBG ����� ���� ���� ���� ����ü
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
 * @param [in] input ���� ȣ�����κ��� �� �����ϴ� ���
 * @param [in] V
 * @param [in] entropy ��Ʈ����
 * @param [in] nonce ��
 * @param [in] per_string ����ȭ ���ڿ�
 *
 */
void drbg_ent_non_pers(struct DRBG_SHA3_HMAC_Context *ctx, BitSequence *input, BitSequence *V, int V_size, const BitSequence *entropy, int ent_size, const BitSequence *nonce, int non_size, const BitSequence *per_string, int per_size);

/**
 * HMAC ��� �Լ�
 *
 * @param [in] digest_size
 * @param [in] digest
 *
 */
void drbg_sha3_hmac_print(unsigned int digest_size, unsigned char *digest);



/**
 * DRBG HMAC ��������Լ�
 *
 * @param [in] ctx DRBG ���� ���� ����ü
 * @param [in] V ��Ʈ����
 * @param [in] Key ��
 *
 */
void drbg_sha3_inner_output(struct DRBG_SHA3_HMAC_Context *ctx, BitSequence *V, BitSequence *Key, const BitSequence *add_input, int add_size, FILE *outf, int num);

/**
 * DRBG HMAC �����ʱ�ȭ�Լ�
 *
 * @param [in] ctx DRBG ���� ���� ����ü
 * @param [in] V ��Ʈ����
 * @param [in] Key ��
 * @param [in] add input �߰��Է�
 *
 */
void drbg_sha3_inner_reset(struct DRBG_SHA3_HMAC_Context *ctx, BitSequence *V, BitSequence *Key, const BitSequence *add_input, int add_size, FILE *outf);

/**
 * DRBG �ʱ�ȭ �Լ�
 *
 * @param [in] ctx DRBG ���� ���� ����ü
 * @param [in] algtype LSH �˰��� ��
 * @param [in] entropy ��Ʈ����
 * @param [in] nonce ��
 * @param [in] per_string ����ȭ ���ڿ�
 *
 * @return LSH_SUCCESS ���� ���� �ʱ�ȭ ����
 */
void drbg_sha3_hmac_init(struct DRBG_SHA3_HMAC_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *nonce, int non_size, const BitSequence *per_string, int per_size, const BitSequence *add_input, int add_size, FILE *outf);


/**
 * init, update, final ������ �ѹ��� �����Ͽ� HMAC�� ����Ѵ�.
 *
 * @param [in] algtype LSH �˰��� ��
 * @param [in] key Ű
 * @param [in] keybytelen Ű ���� (����Ʈ ����)
 * @param [in] data ������
 * @param [in] databytelen ������ ���� (����Ʈ ����)
 * @param [out] digest HMAC ��� ����
 *
 * @return LSH_SUCCESS ���� ���� �ʱ�ȭ ����
 */
void drbg_sha3_hmac_digest(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, BitSequence (*entropy)[65], int ent_size, BitSequence *nonce, int non_size, BitSequence *per_string, int per_size, BitSequence (*add_input)[65], int add_size, int output_bits, int cycle, BitSequence *drbg, FILE *outf);


#ifdef __cplusplus
}
#endif

#endif /* TEST_HMAC_DRBG_H_ */
