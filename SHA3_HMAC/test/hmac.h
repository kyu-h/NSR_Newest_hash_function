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

#ifndef HMAC_SHA2_H
#define HMAC_SHA2_H

#include <stdio.h>
#include "KeccakHash.h"

#define HMAC_SHA224	0
#define HMAC_SHA256	1
#define HMAC_SHA384	2
#define HMAC_SHA512	3

#define HMAC_MODE	HMAC_SHA256

#ifdef __cplusplus
extern "C" {
#endif

struct HMAC_SHA3 {
	Keccak_HashInstance hash_ctx;
	BitSequence opad[256];
};


/******************/
int hmac_sha3_init(struct HMAC_SHA3 *ctx, int algtype, BitSequence *key, int keybytelen, unsigned int rate, unsigned capacity, BitSequence *data, int databytelen, BitSequence *mac, unsigned char delimitedSuffix);
int hmac_sha3_update(struct HMAC_SHA3 *ctx, const BitSequence *data, unsigned int databytelen);
int hmac_sha3_final(struct HMAC_SHA3 *ctx, BitSequence *mac, int algtype, BitSequence *data, unsigned int databytelen, unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix);
int hmac_digest(int algtype, unsigned int rate, unsigned int capacity, BitSequence *key, int keybytelen, BitSequence *data, int databytelen, BitSequence *mac);
/******************/

void hash_out(FILE *fp_out, int counter, int keylen, unsigned int digest_size, BitSequence *Keystring, unsigned char *digest);

#ifdef __cplusplusa
}
#endif

#endif /* !HMAC_SHA2_H */
