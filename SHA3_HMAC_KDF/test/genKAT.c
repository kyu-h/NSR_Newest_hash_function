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
	char *HashName[4] = {"HMAC_KDF_CTRmode_SHA3-224", "HMAC_KDF_CTRmode_SHA3-256", "HMAC_KDF_CTRmode_SHA3-384", "HMAC_KDF_CTRmode_SHA3-512"};
	//char *HashName[4] = {"HMAC_KDF_FBmode_SHA3-224", "HMAC_KDF_FBmode_SHA3-256", "HMAC_KDF_FBmode_SHA3-384", "HMAC_KDF_FBmode_SHA3-512"};
	//char *HashName[4] = {"HMAC_KDF_DPmode_SHA3-224", "HMAC_KDF_DPmode_SHA3-256", "HMAC_KDF_DPmode_SHA3-384", "HMAC_KDF_DPmode_SHA3-512"};

	char inputFileAddress[256], outputFileAddress[256];
	int alg_type = 0;

	for(int i=0; i<4; i++){
		sprintf(inputFileAddress, "PBKDF/%s.txt", HashName[i]);
		sprintf(outputFileAddress, "PBKDF/%s_rsp.txt", HashName[i]);

		if ( (fp_in = fopen(inputFileAddress, "r")) == NULL ) {
			printf("Couldn't open <%s> for read\n", inputFileAddress);
			return KAT_FILE_OPEN_ERROR;
		}

		pStr = fgets(strTemp, sizeof(strTemp), fp_in);
		printf("%s", pStr);

		if(pStr == "HMAC_KDF_CTRmode_SHA3-224" || pStr == "HMAC_KDF_CTRmode_SHA3-256" || pStr == "HMAC_KDF_CTRmode_SHA3-384" || pStr == "HMAC_KDF_CTRmode_SHA3-512"){
			alg_type = 1;
		}else if(pStr == "HMAC_KDF_FBmode_SHA3-224" || pStr == "HMAC_KDF_FBmode_SHA3-256" || pStr == "HMAC_KDF_FBmode_SHA3-384" || pStr == "HMAC_KDF_FBmode_SHA3-512"){
			alg_type = 2;
		}else if(pStr == "HMAC_KDF_DPmode_SHA3-224" || pStr == "HMAC_KDF_DPmode_SHA3-256" || pStr == "HMAC_KDF_DPmode_SHA3-384" || pStr == "HMAC_KDF_DPmode_SHA3-512"){
			alg_type = 3;
		}else {
			printf("alg type error \n");
		}

		if((!strcmp(pStr, "Algo_ID = HMAC_KDF_CTRmode_SHA3-224\n")) || (!strcmp(pStr, "Algo_ID = HMAC_KDF_FBmode_SHA3-224\n")) || (!strcmp(pStr, "Algo_ID = HMAC_KDF_CTRmode_SHA3-224\n"))){
			genShortMsgHash_PBKDF(alg_type, 1152, 448, 0x06, 224, 0,inputFileAddress,outputFileAddress, pStr);
		}else if((!strcmp(pStr, "Algo_ID = HMAC_KDF_CTRmode_SHA3-256\n")) || (!strcmp(pStr, "Algo_ID = HMAC_KDF_FBmode_SHA3-256\n")) || (!strcmp(pStr, "Algo_ID = HMAC_KDF_CTRmode_SHA3-256\n"))){
			genShortMsgHash_PBKDF(alg_type, 1088, 512, 0x06, 256, 0,inputFileAddress,outputFileAddress, pStr);
		}else if((!strcmp(pStr, "Algo_ID = HMAC_KDF_CTRmode_SHA3-384\n")) || (!strcmp(pStr, "Algo_ID = HMAC_KDF_FBmode_SHA3-384\n")) || (!strcmp(pStr, "Algo_ID = HMAC_KDF_CTRmode_SHA3-384\n"))){
			genShortMsgHash_PBKDF(alg_type, 832, 768, 0x06, 384, 0,inputFileAddress,outputFileAddress, pStr);
		}else if((!strcmp(pStr, "Algo_ID = HMAC_KDF_CTRmode_SHA3-512\n")) || (!strcmp(pStr, "Algo_ID = HMAC_KDF_FBmode_SHA3-512\n")) || (!strcmp(pStr, "Algo_ID = HMAC_KDF_CTRmode_SHA3-512\n"))){
			genShortMsgHash_PBKDF(alg_type, 576, 1024, 0x06, 512, 0,inputFileAddress,outputFileAddress, pStr);
		}else {
			printf("error !!");
		}
	}

	fclose(fp_in);
    return KAT_SUCCESS;
}

STATUS_CODES
genShortMsgHash_PBKDF(unsigned int alg_type, unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, unsigned int hashbitlen, unsigned int squeezedOutputLength, const char *inputFileName, const char *outputFileName, const char *description)
{
    FILE *fp_in, *fp_out;
    unsigned int r = 0;
    char str;
    BitSequence Kl[128];
    BitSequence Label[128];
    BitSequence Context[128];
    BitSequence L[2];
    BitSequence h[2];
    int i = 0;
    int Kl_len, Label_len, Context_len = 0;
    int a,b,c,d,e = 0;

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

	FindMarker(fp_in, "r");
	fscanf(fp_in, " %c %s", &str, &r);
	fprintf(fp_out, "r = %d\n", r);

	FindMarker(fp_in, "Kl");
	fscanf(fp_in, " %c %s", &str, &Kl);
	fprintf(fp_out, "Kl = ");
	while(!(Kl[i] == '\0')){
		fprintf(fp_out, "%c", Kl[i++]);
	}fprintf(fp_out, "\n");
	Kl_len = i;
	i=0;

	FindMarker(fp_in, "Label");
	fscanf(fp_in, " %c %s", &str, &Label);
	fprintf(fp_out, "Label = ");
	while(!(Label[i] == '\0')){
		fprintf(fp_out, "%c", Label[i++]);
	}fprintf(fp_out, "\n");
	Label_len = i;
	i=0

	FindMarker(fp_in, "Context");
	fscanf(fp_in, " %c %s", &str, &Context);
	fprintf(fp_out, "Label = ");
	while(!(Context[i] == '\0')){
		fprintf(fp_out, "%c", Context[i++]);
	}fprintf(fp_out, "\n");
	Context_len = i;
	i=0;

	FindMarker(fp_in, "L");
	fscanf(fp_in, " %c %s", &str, &L);
	fprintf(fp_out, "Label = ");
	while(!(L[i] == '\0')){
		fprintf(fp_out, "%c", L[i++]);
	}fprintf(fp_out, "\n");
	fprintf(fp_out, "\n");

	FindMarker(fp_in, "h");
	fscanf(fp_in, " %c %s", &str, &h);
	fprintf(fp_out, "h = ");
	while(!(h[i] == '\0')){
		fprintf(fp_out, "%c", h[i++]);
	}fprintf(fp_out, "\n");
	fprintf(fp_out, "\n\n");


	for(int j = 0; j < Kl_len ; j += 2){
		unsigned char temp_arr[3] = {Kl[j], Kl[j+1], '\0'};
		Kl[a++] = strtol(temp_arr, NULL, 16);
	} //2 string to hex

	for(int j = 0; j < Label_len ; j += 2){
		unsigned char temp_arr01[3] = {Label[j], Label[j+1], '\0'};
		Label[b++] = strtol(temp_arr01, NULL, 16);
	} //2 string to hex

	for(int j = 0; j < Context_len ; j += 2){
		unsigned char temp_arr01[3] = {Context[j], Context[j+1], '\0'};
		Context[c++] = strtol(temp_arr01, NULL, 16);
	} //2 string to hex

	for(int j = 0; j < 2 ; j += 2){
		unsigned char temp_arr01[3] = {L[j], L[j+1], '\0'};
		L[d++] = strtol(temp_arr01, NULL, 16);
	} //2 string to hex

	for(int j = 0; j < 2 ; j += 2){
		unsigned char temp_arr01[3] = {L[j], L[j+1], '\0'};
		h[e++] = strtol(temp_arr01, NULL, 16);
	} //2 string to hex

	pbkdf_sha3_hmac(alg_type, rate, capacity, delimitedSuffix, Kl, Kl_len, Label, Label_len, Context, Context_len, L, h, r, fp_out);

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
