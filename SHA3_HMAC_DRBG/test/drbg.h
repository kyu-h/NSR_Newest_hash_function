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
 * DRBG ���� ����
 * drbgtype �����߻���, ��ݾ�ȣ �˰���
 * refreshperiod ���� �����ֱ�
 * predicttolerance �������� Ȱ��ȭ ����
 * usingperstring ����ȭ ���ڿ� ��� ����
 * usingaddinput �߰� �Է� ��� ����
 */
struct DRBG_Administrative {
	int drbgtype;
	int refreshperiod;
	bool predicttolerance;
	bool usingperstring;
	bool usingaddinput;
};


/**
 * DRBG ����� ���� ���� ���� ����ü
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
 * DRBG ���� �Լ�
 *
 * @param [in] ctx DRBG ���� ���� ����ü
 * @param [in] algtype LSH �˰��� ��
 * @param [in] data ���� ���� ������
 * @param [out] seed �õ�
 *
 * @return LSH_SUCCESS ���� ���� �ʱ�ȭ ����
 */
void drbg_derivation_func(struct DRBG_SHA3_Context *ctx, const BitSequence *data, int data_size, BitSequence *output);


void drbg_sha3_inner_output_gen(struct DRBG_SHA3_Context *ctx, BitSequence *input, BitSequence *output, int output_bits, FILE *outf);


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
void drbg_sha3_init(struct DRBG_SHA3_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *nonce, int non_size, const BitSequence *per_string, int per_size, FILE *outf);


/**
 * DRBG ���� �Լ�
 *
 * @param [in] ctx DRBG ���� ���� ����ü
 * @param [in] add_input �߰� �Է�
 * @param [in] state �۵�����
 *
 * @return LSH_SUCCESS ���� ���� �ʱ�ȭ ����
 */
void drbg_sha3_reseed(struct DRBG_SHA3_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *add_input, int add_size, FILE *outf);


/**
 * DRBG ��� ���� �Լ�
 *
 * @param [in] ctx DRBG ���� ���� ����ü
 * @param [in] add_input �߰� �Է�
 * @param [in] state �۵�����
 *
 * @return LSH_SUCCESS ���� ���� �ʱ�ȭ ����
 */
void drbg_sha3_output_gen(struct DRBG_SHA3_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *add_input, int add_size, int output_bits, int cycle, BitSequence *drbg, FILE *outf, int counter);


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
void drbg_sha3_digest(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, BitSequence (*entropy)[65], int ent_size, BitSequence *nonce, int non_size, BitSequence *per_string, int per_size, BitSequence (*add_input)[65], int add_size, int output_bits, int cycle, BitSequence *drbg, FILE *outf);


#ifdef __cplusplus
}
#endif


#endif /* SRC_STANDALONE_DRBG_H_ */
