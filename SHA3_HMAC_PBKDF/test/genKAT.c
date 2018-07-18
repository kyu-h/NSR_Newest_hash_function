#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

void Keccak(int rate, int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen);

typedef unsigned char BitSequence;
typedef size_t BitLength;
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2 } HashReturn;

#define MAX_MARKER_LEN      4096
#define SUBMITTER_INFO_LEN  128

typedef enum { KAT_SUCCESS = 0, KAT_FILE_OPEN_ERROR = 1, KAT_HEADER_ERROR = 2, KAT_DATA_ERROR = 3, KAT_HASH_ERROR = 4 } STATUS_CODES;

#define ExcludeExtremelyLong

#define SqueezingOutputLength 4096

STATUS_CODES    genShortMsgHash_PBKDF(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, unsigned int hashbitlen, unsigned int squeezedOutputLength, const char *inputFileName, const char *outputFileName, const char *description);
STATUS_CODES    genShortMsgHash_testVector_PBKDF(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, unsigned int hashbitlen, unsigned int squeezedOutputLength, const char *inputFileName, const char *outputFileName, const char *description);
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
	char *HashName[4] = {"PBKDF_SHA3-224", "PBKDF_SHA3-256", "PBKDF_SHA3-384", "PBKDF_SHA3-512"};
	//char *HashName[1] = {"PBKDF_SHA3-256"};
	char inputFileAddress[256], outputFileAddress[256];

	for(int i=0; i<4; i++){
		/*sprintf(inputFileAddress, "PBKDF/%s.txt", HashName[i]);
		sprintf(outputFileAddress, "PBKDF/%s_rsp.txt", HashName[i]);*/

		sprintf(inputFileAddress, "PBKDF_testvectors/%s.txt", HashName[i]);
		sprintf(outputFileAddress, "PBKDF_testvectors/%s_rsp.txt", HashName[i]);

		if ( (fp_in = fopen(inputFileAddress, "r")) == NULL ) {
			printf("Couldn't open <%s> for read\n", inputFileAddress);
			return KAT_FILE_OPEN_ERROR;
		}

		pStr = fgets(strTemp, sizeof(strTemp), fp_in);
		printf("%s", pStr);

		if(!strcmp(pStr, "Algo_ID = PBKDF_SHA3-224\n")){
			//genShortMsgHash_PBKDF(1152, 448, 0x06, 224, 0,inputFileAddress,outputFileAddress,"Alg_ID = PBKDF_SHA3-224");
			//genShortMsgHash_testVector_PBKDF(1152, 448, 0x06, 224, 0,inputFileAddress,outputFileAddress,"Algo_ID = PBKDF_SHA3-224");
		}else if(!strcmp(pStr, "Algo_ID = PBKDF_SHA3-256\n")){
			//genShortMsgHash_PBKDF(1088, 512, 0x06, 256, 0,inputFileAddress,outputFileAddress,"Alg_ID = PBKDF_SHA3-256");
			genShortMsgHash_testVector_PBKDF(1088, 512, 0x06, 256, 0,inputFileAddress,outputFileAddress,"Algo_ID = PBKDF_SHA3-256");
		}else if(!strcmp(pStr, "Algo_ID = PBKDF_SHA3-384\n")){
			//genShortMsgHash_PBKDF(832, 768, 0x06, 384, 0,inputFileAddress,outputFileAddress,"Alg_ID = PBKDF_SHA3-384");
			genShortMsgHash_testVector_PBKDF(832, 768, 0x06, 384, 0,inputFileAddress,outputFileAddress,"Algo_ID = PBKDF_SHA3-384");
		}else if(!strcmp(pStr, "Algo_ID = PBKDF_SHA3-512\n")){
			//genShortMsgHash_PBKDF(576, 1024, 0x06, 512, 0,inputFileAddress,outputFileAddress,"Alg_ID = PBKDF_SHA3-512");
			genShortMsgHash_testVector_PBKDF(576, 1024, 0x06, 512, 0,inputFileAddress,outputFileAddress,"Algo_ID = PBKDF_SHA3-512");
		}else {
			printf("Error!\n");
		}
	}

	fclose(fp_in);
    return KAT_SUCCESS;
}

STATUS_CODES
genShortMsgHash_testVector_PBKDF(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, unsigned int hashbitlen, unsigned int squeezedOutputLength, const char *inputFileName, const char *outputFileName, const char *description)
{
    FILE *fp_in, *fp_out;
    char str;
    BitSequence password[128];
    BitSequence salt[128];
    unsigned int IterationCount = 0;
    unsigned int Klen = 0;
    unsigned int loopCount = 0;
    unsigned int salt_len = 0;
    unsigned int pass_len = 0;

    int r, w = 0;
    int i = 0;

    if ((squeezedOutputLength > SqueezingOutputLength) || (hashbitlen > SqueezingOutputLength)) {
		printf("Requested output length too long.\n");
		return KAT_HASH_ERROR;
	}

	if ( (fp_in = fopen(inputFileName, "r")) == NULL ) {
		printf("Couldn't open <ShortMsgKAT.txt> for read\n");
		return KAT_FILE_OPEN_ERROR;
	}
	fp_out = fopen(outputFileName, "w");

	fprintf(fp_out, "%s\n", description);

	FindMarker(fp_in, "IterationCount");
	fscanf(fp_in, " %c %d", &str, &IterationCount);
	fprintf(fp_out, "IterationCount = %d", IterationCount);
	fprintf(fp_out, "\n\n");

	while(!(loopCount == 79)) {
		FindMarker(fp_in, "COUNT");
		fscanf(fp_in, " %c %d", &str, &loopCount);
		fprintf(fp_out, "COUNT = %d", loopCount);
		fprintf(fp_out, "\n");

		FindMarker(fp_in, "Password = ");
		fprintf(fp_out, "Password = ");
		fgets(password, 40, fp_in);
		fprintf(fp_out, "%s", password);

		pass_len = strlen(password) - 1;
		i=0;

		FindMarker(fp_in, "Salt");
		fscanf(fp_in, " %c %s", &str, &salt);
		fprintf(fp_out, "Salt = ");
		while(!(salt[i] == '\0')){
			fprintf(fp_out, "%c", salt[i++]);
		}fprintf(fp_out, "\n");

		FindMarker(fp_in, "KLen");
		fscanf(fp_in, " %c %d", &str, &Klen);
		fprintf(fp_out, "KLen = %d", Klen);
		fprintf(fp_out, "\n");

		for(r = 0; r < i ; r += 2){
			unsigned char temp_arr[3] = {salt[r], salt[r+1], '\0'};
			salt[w++] = strtol(temp_arr, NULL, 16);
		} //2 string to hex

		salt_len = i/2;

		/*printf("passlen: %d\n", pass_len);

		for(int z=0; z<pass_len; z++){
			printf("%02x", password[z]);
		}printf("\n");*/

		pbkdf_testvector_sha3_hmac(rate, capacity, delimitedSuffix, password, pass_len, salt, salt_len, IterationCount, Klen, loopCount, fp_out);
		//loopCount++;

		/*for(int i=0; i<128; i++){
			password[i] = '\0';
			salt[i] = '\0';
		}*/
	}

    fclose(fp_in);
    fclose(fp_out);
    return KAT_SUCCESS;
}

STATUS_CODES
genShortMsgHash_PBKDF(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, unsigned int hashbitlen, unsigned int squeezedOutputLength, const char *inputFileName, const char *outputFileName, const char *description)
{
    FILE *fp_in, *fp_out;
    char str;
    BitSequence password[128];
    BitSequence salt[128];
    unsigned int IterationCount = 0;
    unsigned int Klen = 0;
    unsigned int loopCount = 0;
    unsigned int salt_len = 0;
    unsigned int pass_len = 0;

    int r, w = 0;
    int i = 0;

    if ((squeezedOutputLength > SqueezingOutputLength) || (hashbitlen > SqueezingOutputLength)) {
		printf("Requested output length too long.\n");
		return KAT_HASH_ERROR;
	}

	if ( (fp_in = fopen(inputFileName, "r")) == NULL ) {
		printf("Couldn't open <ShortMsgKAT.txt> for read\n");
		return KAT_FILE_OPEN_ERROR;
	}

	fp_out = fopen(outputFileName, "w");

	fprintf(fp_out, "%s\n\n", description);

	FindMarker(fp_in, "Password");
	fscanf(fp_in, " %c %s", &str, &password);
	fprintf(fp_out, "Password = ");
	while(!(password[i] == '\0')){
		fprintf(fp_out, "%c", password[i++]);
	}fprintf(fp_out, "\n");

	pass_len = i;
	i=0;

	FindMarker(fp_in, "Salt");
	fscanf(fp_in, " %c %s", &str, &salt);
	fprintf(fp_out, "Salt = ");
	while(!(salt[i] == '\0')){
		fprintf(fp_out, "%c", salt[i++]);
	}fprintf(fp_out, "\n");

	FindMarker(fp_in, "IterationCount");
	fscanf(fp_in, " %c %d", &str, &IterationCount);
	fprintf(fp_out, "IterationCount = %d", IterationCount);
	fprintf(fp_out, "\n");

	FindMarker(fp_in, "kLen");
	fscanf(fp_in, " %c %d", &str, &Klen);
	fprintf(fp_out, "kLen = %d", Klen);
	fprintf(fp_out, "\n");

	FindMarker(fp_in, "loopCount");
	fscanf(fp_in, " %c %d", &str, &loopCount);
	fprintf(fp_out, "loopCount = %d", loopCount);
	fprintf(fp_out, "\n\n");


	for(r = 0; r < i ; r += 2){
		unsigned char temp_arr[3] = {salt[r], salt[r+1], '\0'};
		salt[w++] = strtol(temp_arr, NULL, 16);
	} //2 string to hex

	salt_len = i/2;

	pbkdf_sha3_hmac(rate, capacity, delimitedSuffix, password, pass_len, salt, salt_len, IterationCount, Klen, loopCount, fp_out);

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
