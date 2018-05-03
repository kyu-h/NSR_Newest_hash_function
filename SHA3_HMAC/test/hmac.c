/*
 * HMAC-SHA-224/256/384/512 implementation
 * Last update: 06/15/2005
 * Issue date:  06/15/2005
 *
 * Copyright (C) 2005 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "hmac.h"
#include "KeccakHash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { KAT_SUCCESS = 0, KAT_FILE_OPEN_ERROR = 1, KAT_HEADER_ERROR = 2, KAT_DATA_ERROR = 3, KAT_HASH_ERROR = 4 } STATUS_CODES;


/* HMAC-SHA-224 functions */

int hmac_sha3_init(struct HMAC_SHA3 *ctx, int algtype, BitSequence *key, int keybytelen, unsigned int rate, unsigned capacity, BitSequence *data, int databytelen, BitSequence *mac, unsigned char delimitedSuffix)
{
	int result;

	char ipad[256];
	char tempKey[64];

	unsigned int i;
	unsigned int blockbytelen = 256;

	const unsigned int databitlen = databytelen * 8;

	if (ctx == NULL){
		return KAT_DATA_ERROR;
	}

	if (keybytelen > blockbytelen){
		result = Keccak_HashInitialize(&ctx->hash_ctx, rate, capacity, algtype, delimitedSuffix);
		if (result != KAT_SUCCESS){
			return result;
		}

		result = Keccak_HashUpdate(&ctx->hash_ctx, data, databitlen);
		if (result != KAT_SUCCESS){
			return result;
		}

		result = Keccak_HashFinal(&ctx->hash_ctx, tempKey);
		if (result != KAT_SUCCESS){
			return result;
		}

		key = tempKey;
		keybytelen = algtype / 8;
	}

	for (i = 0; i < keybytelen; i++){
		ipad[i] = key[i] ^ 0x36;
		ctx->opad[i] = key[i] ^ 0x5c;
	}

	for (; i < blockbytelen; i++){
		ipad[i] = 0x36;
		ctx->opad[i] = 0x5c;
	}

	result = Keccak_HashInitialize(&ctx->hash_ctx, rate, capacity, algtype, delimitedSuffix);
	if (result != KAT_SUCCESS){
		return result;
	}

	result = Keccak_HashUpdate(&ctx->hash_ctx, data, databitlen);
	if (result != KAT_SUCCESS){
		return result;
	}

	memset(ipad, 0, blockbytelen);

	return KAT_SUCCESS;
}

int hmac_sha3_update(struct HMAC_SHA3 *ctx, const BitSequence *data, unsigned int databytelen)
{
	unsigned int databitlen = databytelen * 8;
	if (ctx == NULL || data == NULL){
			return KAT_DATA_ERROR;
	}

	return Keccak_HashUpdate(&ctx->hash_ctx, data, databitlen);
}

int hmac_sha3_final(struct HMAC_SHA3 *ctx, BitSequence *mac, int algtype, BitSequence *data, unsigned int databytelen, unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix)
{
	int result;
	unsigned int blockbytelen = 256;
	unsigned int databitlen = databytelen * 8;

	if (ctx == NULL || mac == NULL){
		return KAT_DATA_ERROR;
	}
	result = Keccak_HashFinal(&ctx->hash_ctx, mac);
	if (result != KAT_SUCCESS){
		return result;
	}

	result = Keccak_HashInitialize(&ctx->hash_ctx, rate, capacity, algtype, delimitedSuffix);
	if (result != KAT_SUCCESS){
		return result;
	}

	result = Keccak_HashUpdate(&ctx->hash_ctx, ctx->opad, databitlen);
	memset(ctx->opad, 0, blockbytelen);
	if (result != KAT_SUCCESS){
		return result;
	}

	result = Keccak_HashUpdate(&ctx->hash_ctx, mac, databitlen);
	if (result != KAT_SUCCESS){
		return result;
	}

	return Keccak_HashFinal(&ctx->hash_ctx, mac);
}

int hmac_digest(int algtype, unsigned int rate, unsigned int capacity, BitSequence *key, int keybytelen, BitSequence *data, int databytelen, BitSequence *mac) {
	struct HMAC_SHA3 ctx;
	int result;
	unsigned char delimitedSuffix = 0x06;

	result = hmac_sha3_init(&ctx, algtype, key, keybytelen, rate, capacity, data, databytelen, mac, delimitedSuffix);
	if (result != KAT_SUCCESS){
		return result;
	}

	result = hmac_sha3_update(&ctx, data, databytelen);
	if (result != KAT_SUCCESS){
		return result;
	}

	return hmac_sha3_final(&ctx, mac, algtype, data, databytelen, rate, capacity, delimitedSuffix);
}

void hash_out(FILE *fp_out, int counter, int keylen, unsigned int digest_size, BitSequence *Keystring, unsigned char *digest){
    fprintf(fp_out, "COUNT = %d\n", counter);
    fprintf(fp_out, "Klen = %d\n", keylen);
    fprintf(fp_out, "Tlen = %d\n", digest_size);
    fprintf(fp_out, "Key = %s\n", Keystring);

    fprintf(fp_out, "Msg = ");
    for(int i = 0 ; i < digest_size ; i++)
    	fprintf(fp_out, "%02x", digest[i]);
    fprintf(fp_out, "\n\n");

    /*if (strcmp(vector, output)) { //����� ����� �������� Ȯ�ο� test vector
        fprintf(stderr, "Test failed.\n");
        exit(1);
    }*/
}
