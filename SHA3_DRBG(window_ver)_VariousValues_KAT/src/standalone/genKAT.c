#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "FileOut_struct.h"

void Keccak(int rate, int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen);

typedef unsigned char BitSequence;
typedef size_t BitLength;
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2 } HashReturn;

#define MAX_MARKER_LEN      4096
#define SUBMITTER_INFO_LEN  128

typedef enum { KAT_SUCCESS = 0, KAT_FILE_OPEN_ERROR = 1, KAT_HEADER_ERROR = 2, KAT_DATA_ERROR = 3, KAT_HASH_ERROR = 4 } STATUS_CODES;

#define ExcludeExtremelyLong

#define SqueezingOutputLength 4096

STATUS_CODES    genShortMsgHash(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, unsigned int hashbitlen, unsigned int squeezedOutputLength, const char *inputFileName, const char *outputFileName, const char *description);
int     FindMarker(FILE *infile, const char *marker);
void    fprintBstr(FILE *fp, char *S, BitSequence *A, int L);
void convertShortMsgToPureLSB(void);

STATUS_CODES
genKAT_main(void)
{
    /* The following instances are from the FIPS 202 standard. */
    /* http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf */
    /*  */
    /* Note: "SakuraSequential" translates into "input followed by 11", */
    /* see https://keccak.team/files/Sakura.pdf for more details. */
    /*  */

	FILE *fp_in;
	char strTemp[255];
	char *pStr;
	//char *HashName[4] = {"Hash_DRBG_SHA3-224", "Hash_DRBG_SHA3-256", "Hash_DRBG_SHA3-384", "Hash_DRBG_SHA3-512"};

	char *HashName[1] = {"1.HASH_DRBG(SHA224(-)(PR))_KAT"};
	//char *HashName[1] = {"2.HASH_DRBG(SHA256(-)(no PR))_KAT"};

	char inputFileAddress[256], outputFileAddress[256];

	//for(int i=0; i<4; i++){
		sprintf(inputFileAddress, "HASH_DRBG_KAT/%s.txt", HashName[0]);
		sprintf(outputFileAddress, "HASH_DRBG_KAT/%s_rsp.txt", HashName[0]);

		if ( (fp_in = fopen(inputFileAddress, "r")) == NULL ) {
			printf("Couldn't open <%s> for read\n", inputFileAddress);
			return KAT_FILE_OPEN_ERROR;
		}

		pStr = fgets(strTemp, sizeof(strTemp), fp_in);
		printf("%s", pStr);

		if(!strcmp(pStr, "[SHA-224]\n")){
			genShortMsgHash(1152, 448, 0x06, 224, 0,inputFileAddress,outputFileAddress,"Alg_ID = Hash_DRBG_SHA3-224");
		}else if(!strcmp(pStr, "[SHA-256]\n")){
			genShortMsgHash(1088, 512, 0x06, 256, 0,inputFileAddress,outputFileAddress,"Alg_ID = Hash_DRBG_SHA3-256");
		}else if(!strcmp(pStr, "[SHA-384]\n")){
			genShortMsgHash(832, 768, 0x06, 384, 0,inputFileAddress,outputFileAddress,"Alg_ID = Hash_DRBG_SHA3-384");
		}else if(!strcmp(pStr, "[SHA-512]\n")){
			genShortMsgHash(576, 1024, 0x06, 512, 0,inputFileAddress,outputFileAddress,"Alg_ID = Hash_DRBG_SHA3-512");
		}else {
			printf("Error!\n");
		}
	//}

	fclose(fp_in);
    return KAT_SUCCESS;
}

STATUS_CODES
genShortMsgHash(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, unsigned int hashbitlen, unsigned int squeezedOutputLength, const char *inputFileName, const char *outputFileName, const char *description)
{
    FILE *fp_in, *fp_out;
    char str;
    BitSequence predict[5];
    BitSequence entropy[3][65], nonce[65], perString[65], addinput[2][65];
    int r, w, a, b, c, d, e, f = 0;
    int num = 0;

    if ((squeezedOutputLength > SqueezingOutputLength) || (hashbitlen > SqueezingOutputLength)) {
		printf("Requested output length too long.\n");
		return KAT_HASH_ERROR;
	}

	if ( (fp_in = fopen(inputFileName, "r")) == NULL ) {
		printf("Couldn't open <ShortMsgKAT.txt> for read\n");
		return KAT_FILE_OPEN_ERROR;
	}

	fp_out = fopen(outputFileName, "w");


	BitSequence drbg[64];

	int ent_size = 0; //현재 여기서는 bit 단위로 받고있지만 우리는 byte 단위로 쓰기 때문에 사용할 때는 /8 해야함
	int non_size = 0;
	int per_size = 0;
	int add_size = 0;
	int count = 0;

	int output_bits = 512;
	int cycle = 1;

	if(rate == 1152){
		output_bits = 448;
	}else if(rate == 1088){
		output_bits = 512;
	}else if(rate == 832){
		output_bits = 768;
	}else{
		output_bits = 1024;
	}

	fprintf(fp_out, "%s\n", description);

	while(!feof(fp_in)){
		num = 0; //for under while

		for(int i=0; i<5; i++){
			predict[i] = '\0';
		}

		FindMarker(fp_in, "PredictionResistance");
		fscanf(fp_in, " %c %s", &str, &predict);
		fprintf(fp_out, "PredictionResistance = ");

		if(predict[0] == 'F'){
			for(int i=0; i<5; i++){
				fprintf(fp_out, "%c", predict[i]);
			}
		}else {
			for(int i=0; i<4; i++){
				fprintf(fp_out, "%c", predict[i]);
			}
		}
		fprintf(fp_out, "\n");

		FindMarker(fp_in, "EntropyInputLen");
		fscanf(fp_in, " %c %d", &str, &ent_size);
		fprintf(fp_out, "EntropyInputLen = %d\n", ent_size);

		FindMarker(fp_in, "NonceLen");
		fscanf(fp_in, " %c %d", &str, &non_size);
		fprintf(fp_out, "NonceLen = %d\n", non_size);

		FindMarker(fp_in, "PersonalizationStringLen");
		fscanf(fp_in, " %c %d", &str, &per_size);
		fprintf(fp_out, "PersonalizationStringLen = %d\n", per_size);

		FindMarker(fp_in, "AdditionalInputLen");
		fscanf(fp_in, " %c %d", &str, &add_size);
		fprintf(fp_out, "AdditionalInputLen = %d\n\n", add_size);
		printf("add size : %d\n", add_size);

		while(!(num == 15)) {
			for(int i=0; i<65; i++){
				perString[i] = '\0';
				addinput[0][i] = '\0';
				addinput[1][i] = '\0';
				entropy[0][i] = '\0';
				entropy[1][i] = '\0';
				entropy[2][i] = '\0';
				nonce[i] = '\0';
			}
			count = 0;

			FindMarker(fp_in, "COUNT");
			fscanf(fp_in, " %c %d", &str, &count);

			num = count;

			FindMarker(fp_in, "EntropyInput");
			fscanf(fp_in, " %c %s", &str, &entropy[0]);

			FindMarker(fp_in, "Nonce");
			fscanf(fp_in, " %c %s", &str, &nonce);

			if(per_size == 0){
				printf("per_size = 0\n");
				for(int i=0; i<65; i++){
					perString[i] = '\0';
				}
			}else {
				FindMarker(fp_in, "PersonalizationString");
				fscanf(fp_in, " %c %s", &str, &perString);
			}

			if(add_size == 0){
				for(int i=0; i<65; i++){
					addinput[0][i] = '\0';
				}
			}else{
				FindMarker(fp_in, "AdditionalInput");
				fscanf(fp_in, " %c %s", &str, &addinput[0]);
			}

			if(predict[0] == 'T'){
				FindMarker(fp_in, "EntropyInputPR");
			}else{
				FindMarker(fp_in, "EntropyInputReseed");
			}
			fscanf(fp_in, " %c %s", &str, &entropy[1]);

			if(add_size == 0){
				for(int i=0; i<65; i++){
					addinput[1][i] = '\0';
				}
			}else{
				if(predict[0] == 'T'){
					FindMarker(fp_in, "AdditionalInput");
				}else{
					FindMarker(fp_in, "AdditionalInputReseed");
				}
				fscanf(fp_in, " %c %s", &str, &addinput[1]);
			}

			if(predict[0] == 'T'){
				FindMarker(fp_in, "EntropyInputPR");
				fscanf(fp_in, " %c %s", &str, &entropy[2]);
			}else {
				if(add_size == 0){
					for(int i=0; i<65; i++){
						entropy[2][i] = '\0';
					}
				}else{
					FindMarker(fp_in, "AdditionalInput");
					fscanf(fp_in, " %c %s", &str, &entropy[2]);
				}
			}

			fprintf(fp_out, "COUNT = %d\n", count);
			fprintf(fp_out, "EntropyInput = %s\n", entropy[0]);
			fprintf(fp_out, "Nonce = %s\n", nonce);
			fprintf(fp_out, "PersonalizationString = %s\n", perString);
			fprintf(fp_out, "AdditionalInput = %s\n", addinput[0]);
			if(predict[0] == 'T'){
				fprintf(fp_out, "EntropyInputPR = %s\n", entropy[1]);
				fprintf(fp_out, "AdditionalInput = %s\n", addinput[1]);
				fprintf(fp_out, "EntropyInputPR = %s\n", entropy[2]);
			}else {
				fprintf(fp_out, "EntropyInputReseed = %s\n", entropy[1]);
				fprintf(fp_out, "AdditionalInputReseed = %s\n", addinput[1]);
				fprintf(fp_out, "AdditionalInput = %s\n", entropy[2]);
			}

			for(r = 0, w =0, a = 0, b=0, c=0, d=0, e=0; r < 64 ; r += 2){
				unsigned char temp_arr[3] = {entropy[0][r], entropy[0][r+1], '\0'};
				entropy[0][w++] = strtol(temp_arr, NULL, 16);

				unsigned char temp_arr01[3] = {entropy[1][r], entropy[1][r+1], '\0'};
				entropy[1][a++] = strtol(temp_arr01, NULL, 16);

				unsigned char temp_arr02[3] = {entropy[2][r], entropy[2][r+1], '\0'};
				entropy[2][b++] = strtol(temp_arr02, NULL, 16);

				unsigned char temp_arr03[3] = {perString[r], perString[r+1], '\0'};
				perString[c++] = strtol(temp_arr03, NULL, 16);

				unsigned char temp_arr04[3] = {addinput[0][r], addinput[0][r+1], '\0'};
				addinput[0][d++] = strtol(temp_arr04, NULL, 16);

				unsigned char temp_arr05[3] = {addinput[1][r], addinput[1][r+1], '\0'};
				addinput[1][e++] = strtol(temp_arr05, NULL, 16);

			} //2 string to hex

			for(r=0, f=0; f<64; r+=2){
				unsigned char tmp_arr[3] = {nonce[r], nonce[r+1], '\0'};
				nonce[f++] = strtol(tmp_arr, NULL, 16);
			}

			drbg_sha3_digest(predict, rate, capacity, delimitedSuffix, entropy, ent_size / 8, nonce, non_size / 8, perString, per_size / 8, addinput, add_size / 8, output_bits, cycle, drbg, fp_out);

			num++;
		}
	}
    fclose(fp_in);
    fclose(fp_out);

    return KAT_SUCCESS;
}

/*  */
/* ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.) */
/*  */
int FindMarker(FILE *infile, const char *marker){
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

void fprintBstr(FILE *fp, char *S, BitSequence *A, int L){
    int     i;

    fprintf(fp, "%s", S);

    for ( i=0; i<L; i++ )
        fprintf(fp, "%02x", A[i]); //write small

    if ( L == 0 )
        fprintf(fp, "00");

    fprintf(fp, "\n");
}
