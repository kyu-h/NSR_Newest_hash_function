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

STATUS_CODES
genKAT_main(void){
	FILE *fp_in_ReferenceValues, *fp_in_TestVectors_req, *fp_out_TestVectors_req, *fp_out_ReferenceValues;
	char strTemp[2048];
	char pStr_ReferenceValues[128], *pAlg_ReferenceValues, pStr_TestVectors_req[128], *pAlg_TestVectors_req ;
	int hashbits[4] = {224, 256, 384, 512};
	char inputFileAddress_ReferenceValues[256], inputFileAddress_TestVectors_req[256], outputFileAddress_TestVectors_req[256], outputFileAddress_ReferenceValues[256];

	for(int i=0; i<4; i++){
		printf("%d, %d: ", i, hashbits[i]);

		sprintf(inputFileAddress_TestVectors_req, "(180430)_HMAC_Vector/TestVectors_req/HMAC_SHA3-%d.txt", hashbits[i]);
		sprintf(outputFileAddress_TestVectors_req, "(180430)_HMAC_Vector/TestVectors_req/HMAC_SHA3-%d_rsp.txt", hashbits[i]);

		/*sprintf(inputFileAddress_ReferenceValues, "(180430)_HMAC_Vector/RefereceValues_req/HMAC_SHA3-%d.txt", hashbits[i]);
		sprintf(outputFileAddress_ReferenceValues, "(180430)_HMAC_Vector/RefereceValues_req/HMAC_SHA3-%d_rsp.txt", hashbits[i]);*/

		fp_in_TestVectors_req = fopen(inputFileAddress_TestVectors_req, "r");
		fp_out_TestVectors_req = fopen(outputFileAddress_TestVectors_req, "w");

		/*fp_in_ReferenceValues = fopen(inputFileAddress_ReferenceValues, "r");
		fp_out_ReferenceValues = fopen(outputFileAddress_ReferenceValues, "w");*/

		/*if (fp_in_ReferenceValues == NULL ) {
			printf("Couldn't open <%s.txt> for read\n", inputFileAddress_ReferenceValues);
			return KAT_FILE_OPEN_ERROR;
		}*/

		if (fp_in_TestVectors_req == NULL ) {
			printf("Couldn't open <%s.txt> for read\n", inputFileAddress_ReferenceValues);
			return KAT_FILE_OPEN_ERROR;
		}

		/*fgets(pStr_ReferenceValues, sizeof(pStr_ReferenceValues), fp_in_ReferenceValues);
		pAlg_ReferenceValues = strstr(pStr_ReferenceValues, "HMAC");
		pAlg_ReferenceValues[strlen(pAlg_ReferenceValues) - 1] = '\0';*/

		fgets(pStr_TestVectors_req, sizeof(pStr_TestVectors_req), fp_in_TestVectors_req);
		pAlg_TestVectors_req = strstr(pStr_TestVectors_req, "HMAC");
		pAlg_TestVectors_req[strlen(pAlg_TestVectors_req) - 1] = '\0';

		if((!strcmp(pAlg_ReferenceValues, "HMAC_SHA3-224"))||(!strcmp(pAlg_TestVectors_req, "HMAC_SHA3-224"))){
			//genHmac_ReferenceValues(fp_in_ReferenceValues, fp_out_ReferenceValues, 224);
			genHmac_TestVectors(fp_in_TestVectors_req, fp_out_TestVectors_req, 224);
		}else if((!strcmp(pAlg_ReferenceValues, "HMAC_SHA3-256")) || (!strcmp(pAlg_TestVectors_req, "HMAC_SHA3-256"))){
			//genHmac_ReferenceValues(fp_in_ReferenceValues, fp_out_ReferenceValues, 256);
			genHmac_TestVectors(fp_in_TestVectors_req, fp_out_TestVectors_req, 256);
		}else if((!strcmp(pAlg_ReferenceValues, "HMAC_SHA3-384")) || (!strcmp(pAlg_TestVectors_req, "HMAC_SHA3-384"))){
			//genHmac_ReferenceValues(fp_in_ReferenceValues, fp_out_ReferenceValues, 384);
			genHmac_TestVectors(fp_in_TestVectors_req, fp_out_TestVectors_req, 384);
		}else if((!strcmp(pAlg_ReferenceValues, "HMAC_SHA3-512")) || (!strcmp(pAlg_TestVectors_req, "HMAC_SHA3-512"))){
			//genHmac_ReferenceValues(fp_in_ReferenceValues, fp_out_ReferenceValues, 512);
			genHmac_TestVectors(fp_in_TestVectors_req, fp_out_TestVectors_req, 512);
		}else {
			printf("Error!\n");
		}

		fclose(fp_in_TestVectors_req);
		//fclose(fp_in_ReferenceValues);
		fclose(fp_out_TestVectors_req);
		//fclose(fp_out_ReferenceValues);
	}

    return KAT_SUCCESS;
}

void genHmac_ReferenceValues(FILE *fp_in, FILE *fp_out_ReferenceValues, int hashbits){
	int nKeySetCount=0;
	int nMessageCount=0;
	char str;
	BitSequence Msgstring[1000001] = {0, };
	BitSequence Keystring[10][2024];
	BitSequence Key_values[1024];
	int keylen=0;
	int msglen=0;
	int i, o;

	const int SHA3_224 = 28;
	const int SHA3_256 = 32;
	const int SHA3_384 = 48;
	const int SHA3_512 = 64;

	int *SHA3_Len;

	int rate, capacity;

	BitSequence mac[65];
	int counter = 0;

	printf("********************* file %d ******************* \n", hashbits);

	fprintf(fp_out_ReferenceValues, "Algo_ID = HMAC_SHA3-%d\n\n", hashbits);

	FindMarker(fp_in, "Key_Set");
	fscanf(fp_in, " %c %d\n", &str, &nKeySetCount);

	for(int index = 0 ; index < nKeySetCount ; index++){
		fgets(Keystring[index], MAX_MARKER_LEN, fp_in);
		Keystring[index][strlen(Keystring[index]) - 1] = '\0'; // remove LF character
	}

	for(int keyindex=0; keyindex<nKeySetCount; keyindex++){
		keylen = strlen(Keystring[keyindex]);

		rewind(fp_in);
		for(int i = 0 ; i < nKeySetCount + 2 ; i++)
			fgets(Msgstring, MAX_MARKER_LEN, fp_in);	// skip 2 lines

		for(int r = 0, w = 0 ; r < keylen ; r += 2){
		   BitSequence temp_arr[3] = {Keystring[keyindex][r], Keystring[keyindex][r+1], '\0'};
		   Key_values[w++] = strtol(temp_arr, NULL, 16);
		}

        fprintf(fp_out_ReferenceValues, "Key = ");
        for(int kvindex = 0 ; kvindex < keylen / 2 ; kvindex++)
           fprintf(fp_out_ReferenceValues, "%02x", Key_values[kvindex]);
        fprintf(fp_out_ReferenceValues, "\n");

		FindMarker(fp_in, "Message");
		fscanf(fp_in, " %c %d\n", &str, &nMessageCount);

		//fprintf(fp_out_ReferenceValues, "\nKey = %s\n", Keystring[keyindex]);

		for(int msgindex = 0 ; msgindex < nMessageCount ; msgindex++){
			fgets(Msgstring, MAX_MARKER_LEN, fp_in);
			for(i = 0, o = 0 ; i < strlen(Msgstring) ; i++){	// remove " character
				if(Msgstring[i] != '\"')
					Msgstring[o++] = Msgstring[i];
			}

			if ((strlen(Msgstring) == 3) && (Msgstring[strlen(Msgstring)-1] == '\"')){
				Msgstring[o] = '\0';
			}else {
				Msgstring[o-1] = '\0';   // add NULL character at the end of String
			}

			msglen = strlen(Msgstring);

			if(msglen == 1 && Msgstring[0] == 'a'){ // use only "a" million
				for(int data_index = 0 ; data_index < 1000000 ; data_index++)
					Msgstring[data_index] = 'a';
				Msgstring[1000000] = '\0';
				msglen = strlen(Msgstring);
			}

			//////////////HMACINPUT///////////////
			if(hashbits == 224) {
				rate = 1152;
				capacity = 448;

				/*for(int i=0; i<keylen/2; i++){
					printf("%02x", Key_values[i]);
				}printf("\n")*/

				hmac_digest(hashbits, rate, capacity, Key_values, keylen / 2, Msgstring, msglen, mac);
				hash_out_ReferenceValues(fp_out_ReferenceValues, SHA3_224, mac);
			}else if(hashbits == 256) {
				rate = 1088;
				capacity = 512;
				hmac_digest(hashbits, rate, capacity, Key_values, keylen / 2, Msgstring, msglen, mac);
				hash_out_ReferenceValues(fp_out_ReferenceValues, SHA3_256, mac);
			}else if(hashbits == 384) {
				rate = 832;
				capacity = 768;
				hmac_digest(hashbits, rate, capacity, Key_values, keylen / 2, Msgstring, msglen, mac);
				hash_out_ReferenceValues(fp_out_ReferenceValues, SHA3_384, mac);
			}else if(hashbits == 512) {
				rate = 576;
				capacity = 1024;
				hmac_digest(hashbits, rate, capacity, Key_values, keylen / 2, Msgstring, msglen, mac);
				hash_out_ReferenceValues(fp_out_ReferenceValues, SHA3_512, mac);
			}else {
				printf("Error!");
			}
		}
		fprintf(fp_out_ReferenceValues, "\n");
	}
}


void genHmac_TestVectors(FILE *fp_in, FILE *fp_out_TestVectors, int hashbits){
	int kLen = 0;
	int Tlen = 0;
	char str;
	int count = 0;
	int rate = 1152;
	int capacity = 448;
	int keylen, msglen = 0;
	BitSequence Keystring[2024], Key_values[1024];
	BitSequence Msgstring[2024], Msg_values[1024];
	BitSequence mac[65];

	printf("********************* file %d ******************* \n", hashbits);
	fprintf(fp_out_TestVectors, "Algo_ID = HMAC_SHA3-%d\n\n", hashbits);

	while(!feof(fp_in)) {

		fprintf(fp_out_TestVectors, "COUNT = %d\n", count);
		FindMarker(fp_in, "Klen");
		fscanf(fp_in, " %c %d\n", &str, &kLen);
		fprintf(fp_out_TestVectors, "Klen = %d\n", kLen);

		FindMarker(fp_in, "Tlen");
		fscanf(fp_in, " %c %d\n", &str, &Tlen);
		fprintf(fp_out_TestVectors, "Tlen = %d\n", Tlen);

		FindMarker(fp_in, "Key");
		fscanf(fp_in, " %c %s\n", &str, &Keystring);
		keylen = strlen(Keystring);

		for(int r = 0, w = 0 ; r < keylen ; r += 2){
		   BitSequence temp_arr[3] = {Keystring[r], Keystring[r+1], '\0'};
		   Key_values[w++] = strtol(temp_arr, NULL, 16);
		}

		fprintf(fp_out_TestVectors, "Key = ");
		for(int kvindex = 0 ; kvindex < keylen / 2 ; kvindex++)
		   fprintf(fp_out_TestVectors, "%02x", Key_values[kvindex]);
		fprintf(fp_out_TestVectors, "\n");

		FindMarker(fp_in, "Msg");
		fscanf(fp_in, " %c %s\n", &str, &Msgstring);

		msglen = strlen(Msgstring);

		for(int r = 0, w = 0 ; r < msglen ; r += 2){
		   BitSequence temp_arr[3] = {Msgstring[r], Msgstring[r+1], '\0'};
		   Msg_values[w++] = strtol(temp_arr, NULL, 16);
		}

		fprintf(fp_out_TestVectors, "Msg = ");
		for(int kvindex = 0 ; kvindex < msglen / 2 ; kvindex++)
		   fprintf(fp_out_TestVectors, "%02x", Msg_values[kvindex]);
		fprintf(fp_out_TestVectors, "\n");

		if(hashbits == 224) {
			rate = 1152;
			capacity = 448;
		}
		else if(hashbits == 256) {
			rate = 1088;
			capacity = 512;
		}
		else if(hashbits == 384) {
			rate = 832;
			capacity = 768;
		}
		else if(hashbits == 512) {
			rate = 576;
			capacity = 1024;
		}
		hmac_digest(hashbits, rate, capacity, Key_values, keylen / 2, Msg_values, msglen / 2, mac);
		hash_out_TestVectors(fp_out_TestVectors, Tlen, mac);

		count++;
	}
}

/*  */
/* ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.) */
/*  */
int FindMarker(FILE *infile, const char *marker)
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
