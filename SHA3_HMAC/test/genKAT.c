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
Michaël Peeters, Gilles Van Assche and Ronny Van Keer,
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
#ifndef KeccakP1600_excluded
    /* The following instances are from the FIPS 202 standard. */
    /* http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf */
    /*  */
    /* Note: "SakuraSequential" translates into "input followed by 11", */
    /* see https://keccak.team/files/Sakura.pdf for more details. */
    /*  */

	FILE *fp_in;
	char strTemp[255];
	char *pStr;
	char *HashName[6] = {"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256"};
	char inputFileAddress[256], outputFileAddress[256];

	for(int i=0; i<6; i++){
		sprintf(inputFileAddress, "Hash_testvectors/%s.txt", HashName[i]);
		sprintf(outputFileAddress, "Hash_testvectors/%s_rsp.txt", HashName[i]);

		if ( (fp_in = fopen(inputFileAddress, "r")) == NULL ) {
			printf("Couldn't open <ShortMsgKAT.txt> for read\n");
			return KAT_FILE_OPEN_ERROR;
		}

		pStr = fgets(strTemp, sizeof(strTemp), fp_in);
		printf("%s", pStr);

		if(!strcmp(pStr, "Algo_ID = SHA3-224\n")){
			genShortMsgHash(1152, 448, 0x06, 224, 0,inputFileAddress,outputFileAddress,"Algo_ID = SHA3-224");
		}else if(!strcmp(pStr, "Algo_ID = SHA3-256\n")){
			genShortMsgHash(1088, 512, 0x06, 256, 0,inputFileAddress,outputFileAddress,"Algo_ID = SHA3-256");
		}else if(!strcmp(pStr, "Algo_ID = SHA3-384\n")){
			genShortMsgHash(832, 768, 0x06, 384, 0,inputFileAddress,outputFileAddress,"Algo_ID = SHA3-384");
		}else if(!strcmp(pStr, "Algo_ID = SHA3-512\n")){
			genShortMsgHash(576, 1024, 0x06, 512, 0,inputFileAddress,outputFileAddress,"Algo_ID = SHA3-512");
		}else if(!strcmp(pStr, "Algo_ID = SHAKE128\n")){
			genShortMsgHash(1344, 256, 0x1F, 0, 4096,inputFileAddress,outputFileAddress,"Algo_ID = SHAKE128");
		}else if(!strcmp(pStr, "Algo_ID = SHAKE256\n")){
			genShortMsgHash(1088, 512, 0x1F, 0, 4096,inputFileAddress,outputFileAddress,"Algo_ID = SHAKE256");
		}else {
			printf("Error!\n");
		}
	}

	fclose(fp_in);

#endif
    return KAT_SUCCESS;
}

/*void convertShortMsgToPureLSB(void)
{
    int         msglen, msgbytelen;
    BitSequence Msg[256];
    FILE        *fp_in, *fp_out;

    if ( (fp_in = fopen("ShortMsgKAT.txt", "r")) == NULL ) {
        printf("Couldn't open <ShortMsgKAT.txt> for read\n");
        return;
    }

    if ( (fp_out = fopen("ShortMsgKAT-PureLSB.txt", "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", "ShortMsgKAT-PureLSB.txt");
        return;
    }

    do {
        if ( FindMarker(fp_in, "Len = ") )
            fscanf(fp_in, "%d", &msglen);
        else {
            break;
        }
        msgbytelen = (msglen+7)/8;

        if ( !ReadHex(fp_in, Msg, msgbytelen, "Msg = ") ) {
            printf("ERROR: unable to read 'Msg' from <ShortMsgKAT.txt>\n");
            return;
        }
         Align the last byte on the least significant bit
        if ((msglen % 8) != 0)
            Msg[msgbytelen-1] = Msg[msgbytelen-1] >> (8-(msglen%8));

        fprintf(fp_out, "\nLen = %d\n", msglen);
        fprintBstr(fp_out, "Msg = ", Msg, msgbytelen);
        fprintf(fp_out, "MD = ??\n");
    } while (1);

    fclose(fp_in);
    fclose(fp_out);
}*/

STATUS_CODES
genShortMsgHash(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, unsigned int hashbitlen, unsigned int squeezedOutputLength, const char *inputFileName, const char *outputFileName, const char *description)
{
    int         msglen, msgbytelen;
    BitSequence Msg[256];
    BitSequence Squeezed[SqueezingOutputLength/8];
    Keccak_HashInstance   hash;
    FILE        *fp_in, *fp_out;
    unsigned char string[1000001] = {0, };
	char strDec[255];
	char str;
	int nCount=0;

    if ((squeezedOutputLength > SqueezingOutputLength) || (hashbitlen > SqueezingOutputLength)) {
        printf("Requested output length too long.\n");
        return KAT_HASH_ERROR;
    }

    if ( (fp_in = fopen(inputFileName, "r")) == NULL ) {
        printf("Couldn't open <ShortMsgKAT.txt> for read\n");
        return KAT_FILE_OPEN_ERROR;
    }

    if ( (fp_out = fopen(outputFileName, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", outputFileName);
        return KAT_FILE_OPEN_ERROR;
    }
    fprintf(fp_out, "%s\n", description);

    if(FindMarker(fp_in, "Message")){
		printf("Started ShortMsgKAT for <%s>\n", inputFileName);
	}
	fscanf(fp_in, " %c %d\n", &str, &nCount);

	for(int x=0; x<nCount; x++){
		int i, o;

		fgets(string, MAX_MARKER_LEN, fp_in);

		for(i = 0, o = 0 ; i < strlen(string) ; i++){   // remove " character
			if(string[i] != '\"'){
				string[o] = string[i];
				o++;
			}
		}

		if ((strlen(string) == 3) && (string[strlen(string)-1] == '\"')){
			string[o] = '\0';
		}else {
			string[o-1] = '\0';   // add NULL character at the end of String
		}

		msglen = strlen(string);

		if(strlen(string) == 1 && string[0] == 'a'){ // use only "a" million

			for(int temp = 0 ; temp < 1000000 ; temp++){
				string[temp] = 'a';
			}
			string[1000000] = '\0';
			msglen = strlen(string);
		}

		//fprintf(fp_out, "Len = %d\n", msglen * 8);
		//fprintf(fp_out, "string = %s\n", string);

		//printf("string : %s\n", string);

		if (Keccak_HashInitialize(&hash, rate, capacity, hashbitlen, delimitedSuffix) != SUCCESS) {
			printf("Keccak[r=%d, c=%d] is not supported.\n", rate, capacity);
			return KAT_HASH_ERROR;
		}

		Keccak_HashUpdate(&hash, string, msglen * 8);
		Keccak_HashFinal(&hash, Squeezed);

		if (hashbitlen > 0)
			fprintBstr(fp_out, "", Squeezed, hashbitlen/8);
		if (squeezedOutputLength > 0) {
			Keccak_HashSqueeze(&hash, Squeezed, squeezedOutputLength);
			fprintBstr(fp_out, "", Squeezed, squeezedOutputLength/8);
		}

	}

    printf("finished ShortMsgKAT for <%s>\n", inputFileName);

    fclose(fp_in);
    fclose(fp_out);

    return KAT_SUCCESS;
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

/*  */
/* ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.) */
/*  */
int
ReadHex(FILE *infile, BitSequence *A, int Length, char *str)
{
    int         i, ch, started;
    BitSequence ich = '\0';

    if ( Length == 0 ) {
        A[0] = 0x00;
        return 1;
    }
    memset(A, 0x00, Length);
    started = 0;
    if ( FindMarker(infile, str) )
        while ( (ch = fgetc(infile)) != EOF ) {
            if ( !isxdigit(ch) ) {
                if ( !started ) {
                    if ( ch == '\n' )
                        break;
                    else
                        continue;
                }
                else
                    break;
            }
            started = 1;
            if ( (ch >= '0') && (ch <= '9') )
                ich = ch - '0';
            else if ( (ch >= 'A') && (ch <= 'F') )
                ich = ch - 'A' + 10;
            else if ( (ch >= 'a') && (ch <= 'f') )
                ich = ch - 'a' + 10;

            for ( i=0; i<Length-1; i++ )
                A[i] = (A[i] << 4) | (A[i+1] >> 4);
            A[Length-1] = (A[Length-1] << 4) | ich;
        }
    else
        return 0;

    return 1;
}

void
fprintBstr(FILE *fp, char *S, BitSequence *A, int L)
{
    int     i;

    fprintf(fp, "%s", S);

    for ( i=0; i<L; i++ )
        fprintf(fp, "%02x", A[i]);

    if ( L == 0 )
        fprintf(fp, "00");

    fprintf(fp, "\n");
}
