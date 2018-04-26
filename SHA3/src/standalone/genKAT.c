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
    return KAT_SUCCESS;
}

STATUS_CODES
genShortMsgHash(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, unsigned int hashbitlen, unsigned int squeezedOutputLength, const char *inputFileName, const char *outputFileName, const char *description)
{
    int         msglen, msgbytelen;
    BitSequence Msg[256];
    BitSequence Squeezed[SqueezingOutputLength/8];
    FILE *fp_in, *fp_out;
    char string[1000001] = {0, };
    char strDec[255];
    char str;
    int nCount=0;
    /*char *HashName[6] = {"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256"};
    char fileAddress[256];

    for(int i=0; i<6; i++){
    	sprintf(fileAddress, "Hash_testvectors/%s.txt", HashName[i]);
		printf("%s\n", fileAddress);
    }*/

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

	if(FindMarker(fp_in, "Message")){
		printf("Started ShortMsgKAT for <%s>\n", inputFileName);
	}
	fscanf(fp_in, " %c %d\n", &str, &nCount);
	//printf("count : %d\n", nCount);

	//while(!feof(fp_in))
    for(int x=0; x<nCount; x++){
    	int i, o;

    	fgets(string, MAX_MARKER_LEN, fp_in);

    	//printf("1string %d: %s\n", strlen(string), string);

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
    	printf("string : %s\n", string);

    	if(strlen(string) == 1 && string[0] == 'a'){ // use only "a" million

    		for(int temp = 0 ; temp < 1000000 ; temp++){
    			string[temp] = 'a';
    		}
    		string[1000000] = '\0';
    		msglen = strlen(string);
    	}

		//fprintf(fp_out, "\nLen = %d\n", msglen * 8);
		//fprintBstr(fp_out, "Msg = ", string, msglen);

		if (hashbitlen > 0) {
			Keccak(rate, capacity, string, msglen, delimitedSuffix, Squeezed, hashbitlen/8);
			fprintBstr(fp_out, "", Squeezed, hashbitlen/8);
		}
		else {
			Keccak(rate, capacity, string, msglen, delimitedSuffix, Squeezed, squeezedOutputLength/8);
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
        fprintf(fp, "%02X", A[i]);

    if ( L == 0 )
        fprintf(fp, "00");

    fprintf(fp, "\n");
}
