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
#include "hmac_Keccak.h"
#include "KeccakHash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { KAT_SUCCESS = 0, KAT_FILE_OPEN_ERROR = 1, KAT_HEADER_ERROR = 2, KAT_DATA_ERROR = 3, KAT_HASH_ERROR = 4 } STATUS_CODES;


/* HMAC-SHA-224 functions */

void hmac_sha224_init(HMAC_SHA3 *ctx, const unsigned char *key, unsigned int key_size,
		unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix,
		const BitSequence *data, BitLength databitlen,
		BitSequence *hashval){
    unsigned int fill;
    unsigned int num;
    BitSequence ipad[256];

    printf("*****hmac_sha224_init*****\n");
    printf("key: %c\n", key);

    const unsigned char *key_used;
    unsigned char key_temp[SHA224_DIGEST_SIZE];
    int i;

    printf("SHA224_BLOCK_SIZE: %d\n", SHA224_BLOCK_SIZE);

    if (key_size == SHA224_BLOCK_SIZE) {
        key_used = key;
        num = SHA224_BLOCK_SIZE;

    } else {
        if (key_size > SHA224_BLOCK_SIZE){
            num = SHA224_DIGEST_SIZE;


            //Keccak_HashInitialize(&ctx->hash_ctx, rate, capacity, hashbitlen, delimitedSuffix);
            if (Keccak_HashInitialize(&ctx->hash_ctx, rate, capacity, hashbitlen, delimitedSuffix) != SUCCESS) {
				printf("Keccak[r=%d, c=%d] is not supported.\n", rate, capacity);
				//return KAT_HASH_ERROR;
			}
            Keccak_HashUpdate(&ctx->hash_ctx, data, databitlen);
			Keccak_HashFinal(&ctx->hash_ctx, hashval);

            key_used = key_temp;
        } else { /* key_size < SHA224_BLOCK_SIZE */
        	//printf("test");
        	 printf("key_size < SHA224_BLOCK_SIZE ");
            key_used = key;
            num = key_size;
        }
        fill = SHA224_BLOCK_SIZE - num;

        memset(ipad + num, 0x36, fill);
        memset(ctx->opad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ipad[i] = key_used[i] ^ 0x36;
        ctx->opad[i] = key_used[i] ^ 0x5c;
    }

    Keccak_HashInitialize(&ctx->ctx_inside, rate, capacity, hashbitlen, delimitedSuffix);
    Keccak_HashUpdate(&ctx->ctx_inside, ipad, SHA224_BLOCK_SIZE);

    Keccak_HashInitialize(&ctx->ctx_outside, rate, capacity, hashbitlen, delimitedSuffix);
	Keccak_HashUpdate(&ctx->ctx_outside, ipad, SHA224_BLOCK_SIZE);


/*
    sha224_init(&ctx->ctx_inside);
    sha224_update(&ctx->ctx_inside, ctx->block_ipad, SHA224_BLOCK_SIZE);


    sha224_init(&ctx->ctx_outside);
    sha224_update(&ctx->ctx_outside, ctx->block_opad, SHA224_BLOCK_SIZE);
*/

    /* for hmac_reinit */
    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside, sizeof(sha224_ctx));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside, sizeof(sha224_ctx));
}

void hmac_sha224_reinit(hmac_sha224_ctx *ctx){
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit, sizeof(sha224_ctx));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit, sizeof(sha224_ctx));
}

void hmac_sha224_update(HMAC_SHA3 *ctx, const unsigned char *message, unsigned int message_len,
		const BitSequence *data, BitLength databitlen){
//    sha224_update(&ctx->ctx_inside, message, message_len);
	printf("hmac_sha224_update start \n");
	Keccak_HashUpdate(&ctx->ctx_inside, message, message_len);
}

void hmac_sha224_final(HMAC_SHA3 *ctx, unsigned char *mac, unsigned int mac_size,
		const BitSequence *data, BitLength databitlen, BitSequence *hashval){
    unsigned char digest_inside[SHA224_DIGEST_SIZE];
    unsigned char mac_temp[SHA224_DIGEST_SIZE];

    printf("final start \n");

/*
    sha224_final(&ctx->ctx_inside, digest_inside);
    sha224_update(&ctx->ctx_outside, digest_inside, SHA224_DIGEST_SIZE);
    sha224_final(&ctx->ctx_outside, mac_temp);
*/
    Keccak_HashFinal(&ctx->ctx_inside, digest_inside);
    Keccak_HashUpdate(&ctx->ctx_outside, digest_inside, SHA224_DIGEST_SIZE);
    Keccak_HashFinal(&ctx->ctx_outside, mac_temp);

    printf("*************mac: %02x\n", mac_temp);

    memcpy(mac, mac_temp, mac_size);
}

void hmac_sha224(const unsigned char *key, unsigned int key_size, const unsigned char *message, unsigned int message_len, unsigned char *mac, unsigned int mac_size,
		unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix,
		const BitSequence *data, BitLength databitlen,
		BitSequence *hashval){

	HMAC_SHA3 ctx;

    //printf("hmac_sha224 key: %c\n", key);
    hmac_sha224_init(&ctx, key, key_size, rate, capacity, hashbitlen, delimitedSuffix, data, databitlen, hashval);
    printf("init finished \n");
    //hmac_sha224_update(&ctx, message, message_len, data, databitlen);
    printf("update finished \n");

    //hmac_sha224_final(&ctx, mac, mac_size, data, databitlen, hashval);
    printf("final finished \n");

}

/* HMAC-SHA-256 functions */

void hmac_sha256_init(hmac_sha256_ctx *ctx, const unsigned char *key, unsigned int key_size){
    unsigned int fill;
    unsigned int num;

    const unsigned char *key_used;
    unsigned char key_temp[SHA256_DIGEST_SIZE];
    int i;

    if (key_size == SHA256_BLOCK_SIZE) {
        key_used = key;
        num = SHA256_BLOCK_SIZE;
    } else {
        if (key_size > SHA256_BLOCK_SIZE){
            num = SHA256_DIGEST_SIZE;
//            sha256(key, key_size, key_temp);
            key_used = key_temp;
        } else { /* key_size > SHA256_BLOCK_SIZE */
            key_used = key;
            num = key_size;
        }
        fill = SHA256_BLOCK_SIZE - num;

        memset(ctx->block_ipad + num, 0x36, fill);
        memset(ctx->block_opad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->block_ipad[i] = key_used[i] ^ 0x36;
        ctx->block_opad[i] = key_used[i] ^ 0x5c;
    }

/*
    sha256_init(&ctx->ctx_inside);
    sha256_update(&ctx->ctx_inside, ctx->block_ipad, SHA256_BLOCK_SIZE);

    sha256_init(&ctx->ctx_outside);
    sha256_update(&ctx->ctx_outside, ctx->block_opad, SHA256_BLOCK_SIZE);
*/

    /* for hmac_reinit */
    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside, sizeof(sha256_ctx));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside, sizeof(sha256_ctx));
}

void hmac_sha256_reinit(hmac_sha256_ctx *ctx){
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit, sizeof(sha256_ctx));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit, sizeof(sha256_ctx));
}

void hmac_sha256_update(hmac_sha256_ctx *ctx, const unsigned char *message, unsigned int message_len){
//    sha256_update(&ctx->ctx_inside, message, message_len);
}

void hmac_sha256_final(hmac_sha256_ctx *ctx, unsigned char *mac, unsigned int mac_size){
    unsigned char digest_inside[SHA256_DIGEST_SIZE];
    unsigned char mac_temp[SHA256_DIGEST_SIZE];

/*
    sha256_final(&ctx->ctx_inside, digest_inside);
    sha256_update(&ctx->ctx_outside, digest_inside, SHA256_DIGEST_SIZE);
    sha256_final(&ctx->ctx_outside, mac_temp);
*/
    memcpy(mac, mac_temp, mac_size);
}

void hmac_sha256(const unsigned char *key, unsigned int key_size, const unsigned char *message, unsigned int message_len, unsigned char *mac, unsigned mac_size){
    hmac_sha256_ctx ctx;

    hmac_sha256_init(&ctx, key, key_size);
    hmac_sha256_update(&ctx, message, message_len);
    hmac_sha256_final(&ctx, mac, mac_size);
}

/* HMAC-SHA-384 functions */

void hmac_sha384_init(hmac_sha384_ctx *ctx, const unsigned char *key, unsigned int key_size){
    unsigned int fill;
    unsigned int num;

    const unsigned char *key_used;
    unsigned char key_temp[SHA384_DIGEST_SIZE];
    int i;

    if (key_size == SHA384_BLOCK_SIZE) {
        key_used = key;
        num = SHA384_BLOCK_SIZE;
    } else {
        if (key_size > SHA384_BLOCK_SIZE){
            num = SHA384_DIGEST_SIZE;
//            sha384(key, key_size, key_temp);
            key_used = key_temp;
        } else { /* key_size > SHA384_BLOCK_SIZE */
            key_used = key;
            num = key_size;
        }
        fill = SHA384_BLOCK_SIZE - num;

        memset(ctx->block_ipad + num, 0x36, fill);
        memset(ctx->block_opad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->block_ipad[i] = key_used[i] ^ 0x36;
        ctx->block_opad[i] = key_used[i] ^ 0x5c;
    }

/*
    sha384_init(&ctx->ctx_inside);
    sha384_update(&ctx->ctx_inside, ctx->block_ipad, SHA384_BLOCK_SIZE);

    sha384_init(&ctx->ctx_outside);
    sha384_update(&ctx->ctx_outside, ctx->block_opad, SHA384_BLOCK_SIZE);
*/

    /* for hmac_reinit */
    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside, sizeof(sha384_ctx));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside, sizeof(sha384_ctx));
}

void hmac_sha384_reinit(hmac_sha384_ctx *ctx){
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit, sizeof(sha384_ctx));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit, sizeof(sha384_ctx));
}

void hmac_sha384_update(hmac_sha384_ctx *ctx, const unsigned char *message, unsigned int message_len){
    //sha384_update(&ctx->ctx_inside, message, message_len);
}

void hmac_sha384_final(hmac_sha384_ctx *ctx, unsigned char *mac, unsigned int mac_size){
    unsigned char digest_inside[SHA384_DIGEST_SIZE];
    unsigned char mac_temp[SHA384_DIGEST_SIZE];

    /*sha384_final(&ctx->ctx_inside, digest_inside);
    sha384_update(&ctx->ctx_outside, digest_inside, SHA384_DIGEST_SIZE);
    sha384_final(&ctx->ctx_outside, mac_temp);*/
    memcpy(mac, mac_temp, mac_size);
}

void hmac_sha384(const unsigned char *key, unsigned int key_size, const unsigned char *message, unsigned int message_len, unsigned char *mac, unsigned mac_size){
    hmac_sha384_ctx ctx;

    hmac_sha384_init(&ctx, key, key_size);
    hmac_sha384_update(&ctx, message, message_len);
    hmac_sha384_final(&ctx, mac, mac_size);
}

/* HMAC-SHA-512 functions */

void hmac_sha512_init(hmac_sha512_ctx *ctx, const unsigned char *key, unsigned int key_size){
    unsigned int fill;
    unsigned int num;

    const unsigned char *key_used;
    unsigned char key_temp[SHA512_DIGEST_SIZE];
    int i;

    if (key_size == SHA512_BLOCK_SIZE) {
        key_used = key;
        num = SHA512_BLOCK_SIZE;
    } else {
        if (key_size > SHA512_BLOCK_SIZE){
            num = SHA512_DIGEST_SIZE;
            //sha512(key, key_size, key_temp);
            key_used = key_temp;
        } else { /* key_size > SHA512_BLOCK_SIZE */
            key_used = key;
            num = key_size;
        }
        fill = SHA512_BLOCK_SIZE - num;

        memset(ctx->block_ipad + num, 0x36, fill);
        memset(ctx->block_opad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->block_ipad[i] = key_used[i] ^ 0x36;
        ctx->block_opad[i] = key_used[i] ^ 0x5c;
    }

    /*sha512_init(&ctx->ctx_inside);
    sha512_update(&ctx->ctx_inside, ctx->block_ipad, SHA512_BLOCK_SIZE);

    sha512_init(&ctx->ctx_outside);
    sha512_update(&ctx->ctx_outside, ctx->block_opad,
                  SHA512_BLOCK_SIZE);*/

    /* for hmac_reinit */
    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside,
           sizeof(sha512_ctx));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside,
           sizeof(sha512_ctx));
}

void hmac_sha512_reinit(hmac_sha512_ctx *ctx){
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit,
           sizeof(sha512_ctx));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit,
           sizeof(sha512_ctx));
}

void hmac_sha512_update(hmac_sha512_ctx *ctx, const unsigned char *message, unsigned int message_len){
    //sha512_update(&ctx->ctx_inside, message, message_len);
}

void hmac_sha512_final(hmac_sha512_ctx *ctx, unsigned char *mac, unsigned int mac_size){
    unsigned char digest_inside[SHA512_DIGEST_SIZE];
    unsigned char mac_temp[SHA512_DIGEST_SIZE];

    /*sha512_final(&ctx->ctx_inside, digest_inside);
    sha512_update(&ctx->ctx_outside, digest_inside, SHA512_DIGEST_SIZE);
    sha512_final(&ctx->ctx_outside, mac_temp);*/
    memcpy(mac, mac_temp, mac_size);
}

void hmac_sha512(const unsigned char *key, unsigned int key_size, const unsigned char *message, unsigned int message_len, unsigned char *mac, unsigned mac_size){
    hmac_sha512_ctx ctx;

    hmac_sha512_init(&ctx, key, key_size);
    hmac_sha512_update(&ctx, message, message_len);
    hmac_sha512_final(&ctx, mac, mac_size);

}

void test(const char *vector, unsigned char *digest, unsigned int digest_size){
    char output[2 * SHA512_DIGEST_SIZE + 1];
    int i;

    output[2 * digest_size] = '\0';

    for (i = 0; i < (int) digest_size ; i++) {
       sprintf(output + 2*i, "%02x", digest[i]);
    }

    printf("H: %s\n", output);
    /*if (strcmp(vector, output)) { //출력이 제대로 나오는지 확인용 test vector
        fprintf(stderr, "Test failed.\n");
        exit(1);
    }*/
}
