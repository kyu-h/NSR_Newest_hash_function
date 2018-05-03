/*
 Copyright (c) 2008, Lawrence E. Bassham, National Institute of Standards and Technology (NIST),
 for the original version (available at http://csrc.nist.gov/groups/ST/hash/sha-3/documents/KAT1.zip)
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the NIST nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
Contributions were made by the Keccak Team, namely, Guido Bertoni, Joan Daemen,
MichaÃ«l Peeters, Gilles Van Assche and Ronny Van Keer,
hereby denoted as "the implementer".
For more information, feedback or questions, please refer to our website:
https://keccak.team/
To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the contributed source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "KeccakHash.h"

#define MAX_MARKER_LEN      4096
#define SUBMITTER_INFO_LEN  128

typedef enum { KAT_SUCCESS = 0, KAT_FILE_OPEN_ERROR = 1, KAT_HEADER_ERROR = 2, KAT_DATA_ERROR = 3, KAT_HASH_ERROR = 4 } STATUS_CODES;

#define ExcludeExtremelyLong

#define SqueezingOutputLength 4096

STATUS_CODES    genShortMsgHash(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, unsigned int hashbitlen, unsigned int squeezedOutputLength, const char *inputFileName, const char *outputFileName, const char *description);
int     FindMarker(FILE *infile, const char *marker);
int     ReadHex(FILE *infile, BitSequence *A, int Length, char *str);
void    fprintBstr(FILE *fp, char *S, BitSequence *A, int L);
//void convertShortMsgToPureLSB(void);

STATUS_CODES
genKAT_main(void)
{
	FILE *fp_in, *fp_out;
	char strTemp[2048];
	char pStr[128], *pAlg;
	int hashbits[4] = {224, 256, 384, 512};
	char inputFileAddress[256], outputFileAddress[256];

	for(int i=0; i<4; i++){
		sprintf(inputFileAddress, "(180430)_HMAC_Vector/RefereceValues_req/HMAC_SHA3-%d.txt", hashbits[i]);
		sprintf(outputFileAddress, "(180430)_HMAC_Vector/RefereceValues_req/HMAC_SHA3-%d_rsp.txt", hashbits[i]);

		fp_in = fopen(inputFileAddress, "r");
		fp_out = fopen(outputFileAddress, "w");

		if (fp_in == NULL ) {
			printf("Couldn't open <%s.txt> for read\n", inputFileAddress);
			return KAT_FILE_OPEN_ERROR;
		}

		fgets(pStr, sizeof(pStr), fp_in);
		pAlg = strstr(pStr, "HMAC");
		pAlg[strlen(pAlg) - 1] = '\0';

		if(!strcmp(pAlg, "HMAC_SHA3-224")){
			genHmac(fp_in, fp_out, 224);
		}else if(!strcmp(pAlg, "HMAC_SHA3-256")){
			genHmac(fp_in, fp_out, 256);
		}else if(!strcmp(pAlg, "HMAC_SHA3-384")){
			genHmac(fp_in, fp_out, 384);
		}else if(!strcmp(pAlg, "HMAC_SHA3-512")){
			genHmac(fp_in, fp_out, 512);
		}else {
			printf("Error!\n");
		}
		fclose(fp_in);
		fclose(fp_out);
	}

    return KAT_SUCCESS;
}

void
genHmac(FILE *fp_in, FILE *fp_out, int hashbits)
{
	int nKeySetCount=0;
	int nMessageCount=0;
	char str;
	BitSequence Msgstring[1000001] = {0, };
	BitSequence Keystring[10][2024];
	int keylen=0;
	int msglen=0;
	int i, o;

	const int SHA3_224_TAGS[5] = {14, 16, 20, 24, 28};
	const int SHA3_256_TAGS[3] = {16, 24, 32};
	const int SHA3_384_TAGS[4] = {24, 32, 40, 48};
	const int SHA3_512_TAGS[5] = {32, 40, 48, 56, 64};
	int *SHA3_TAG, taglen;

	int rate, capacity;

	BitSequence mac[65];
	int counter = 0;

	printf("********************* file %d ******************* \n", hashbits);

	FindMarker(fp_in, "Key_Set");
	fscanf(fp_in, " %c %d\n", &str, &nKeySetCount);

	for(int index = 0 ; index < nKeySetCount ; index++)
	{
		fgets(Keystring[index], MAX_MARKER_LEN, fp_in);
		Keystring[index][strlen(Keystring[index]) - 1] = '\0'; // remove LF character
	}

	if(hashbits == 224)
	{
		taglen = 5;
		SHA3_TAG = SHA3_224_TAGS;
	}
	else if(hashbits == 256)
	{
		taglen = 3;
		SHA3_TAG = SHA3_256_TAGS;
	}
	else if(hashbits == 384)
	{
		taglen = 4;
		SHA3_TAG = SHA3_384_TAGS;
	}
	else if(hashbits == 512)
	{
		taglen = 5;
		SHA3_TAG = SHA3_512_TAGS;
	}

	fprintf(fp_out, "Algo_ID = HMAC_SHA3-%d\n\n", hashbits);

	for(int keyindex=0; keyindex<nKeySetCount; keyindex++)
	{
		keylen = strlen(Keystring[keyindex]);
		rewind(fp_in);
		for(int i = 0 ; i < nKeySetCount + 2 ; i++)
			fgets(Msgstring, MAX_MARKER_LEN, fp_in);	// skip 2 lines

		FindMarker(fp_in, "Message");
		fscanf(fp_in, " %c %d\n", &str, &nMessageCount);

		for(int tagindex = 0 ; tagindex < taglen ; tagindex++)
		{
			if(tagindex)
			{
				rewind(fp_in);
				for(int i = 0 ; i < nKeySetCount + 3 ; i++)
					fgets(Msgstring, MAX_MARKER_LEN, fp_in);	// skip 2 lines
			}
			for(int msgindex = 0 ; msgindex < nMessageCount ; msgindex++)
			{
				fgets(Msgstring, MAX_MARKER_LEN, fp_in);
				for(i = 0, o = 0 ; i < strlen(Msgstring) ; i++)
				{	// remove " character
					if(Msgstring[i] != '\"')
						Msgstring[o++] = Msgstring[i];
				}
				if ((strlen(Msgstring) == 3) && (Msgstring[strlen(Msgstring)-1] == '\"')){
					Msgstring[o] = '\0';
				}else {
					Msgstring[o-1] = '\0';   // add NULL character at the end of String
				}

				msglen = strlen(Msgstring);

				if(msglen == 1 && Msgstring[0] == 'a') // use only "a" million
				{
					for(int data_index = 0 ; data_index < 1000000 ; data_index++)
						Msgstring[data_index] = 'a';
					Msgstring[1000000] = '\0';
					msglen = strlen(Msgstring);
				}

				//////////////HMACINPUT///////////////
				if(hashbits == 224) {
					rate = 1152;
					capacity = 448;
					hmac_digest(hashbits, rate, capacity, Keystring[keyindex], keylen, Msgstring, msglen, mac);
				}
				else if(hashbits == 256) {
					rate = 1088;
					capacity = 512;
					hmac_digest(hashbits, rate, capacity, Keystring[keyindex], keylen, Msgstring, msglen, mac);
				}
				else if(hashbits == 384) {
					rate = 832;
					capacity = 768;
					hmac_digest(hashbits, rate, capacity, Keystring[keyindex], keylen, Msgstring, msglen, mac);
				}
				else if(hashbits == 512) {
					rate = 576;
					capacity = 1024;
					hmac_digest(hashbits, rate, capacity, Keystring[keyindex], keylen, Msgstring, msglen, mac);
				}
				hash_out(fp_out, counter++, keylen, SHA3_TAG[tagindex], Keystring[keyindex], mac);
			}
		}
	}
}

/*  */
/* ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.) */
/*  */
int
FindMarker(FILE *infile, const char *marker)
{
    char    line[MAX_MARKER_LEN];
    int     i, len;

    len = (int)strlen(marker);
    if ( len > MAX_MARKER_LEN-1 )
        len = MAX_MARKER_LEN-1;

    for ( i=0; i<len; i++ )
        if ( (line[i] = fgetc(infile)) == EOF )
            return 0;
    line[len] = '\0';

    while ( 1 ) {
        if ( !strncmp(line, marker, len) )
            return 1;

        for ( i=0; i<len-1; i++ )
            line[i] = line[i+1];
        if ( (line[len-1] = fgetc(infile)) == EOF )
            return 0;
        line[len] = '\0';
    }

    /* shouldn't get here */
    return 0;
}
