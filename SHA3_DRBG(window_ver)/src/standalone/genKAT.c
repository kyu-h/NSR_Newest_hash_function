#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

void Keccak(int rate, int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen);
void V_DerivedFunction(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen);

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
			genShortMsgHash(1344, 256, 0x1F, 128, 4096,inputFileAddress,outputFileAddress,"Algo_ID = SHAKE128");
		}else if(!strcmp(pStr, "Algo_ID = SHAKE256\n")){
			genShortMsgHash(1088, 512, 0x1F, 512, 4096,inputFileAddress,outputFileAddress,"Algo_ID = SHAKE256");
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

    int r,w = 0;
    unsigned char Key_values01[10000];

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

    	for(r = 0, w = 0 ; r < strlen(string) ; r += 2){
			unsigned char temp_arr[3] = {string[r], string[r+1], '\0'};
			Key_values01[w++] = strtol(temp_arr, NULL, 16);
		} //2 string to hex

    	V_DerivedFunction(rate, capacity, string, msglen, delimitedSuffix, Squeezed, hashbitlen);

		if (hashbitlen > 0) {
			Keccak(rate, capacity, Key_values01, w, delimitedSuffix, Squeezed, hashbitlen/8);
			fprintBstr(fp_out, "", Squeezed, hashbitlen/8);
		}
		else {
			Keccak(rate, capacity, Key_values01, w, delimitedSuffix, Squeezed, squeezedOutputLength/8);
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
        fprintf(fp, "%02x", A[i]); //write small

    if ( L == 0 )
        fprintf(fp, "00");

    fprintf(fp, "\n");
}

void operation_add(unsigned char *arr, int ary_size, unsigned int num){
   unsigned int current;
   unsigned int carry = 0;
   int index = 1;

   current = arr[ary_size - index];
   current += num;
   carry = (current >> 8);
   arr[ary_size - index] = (unsigned char) current;

    while(carry){
    	index++;
    	current = arr[ary_size - index];
    	current += carry;
    	carry = (current >> 8);
    	arr[ary_size - index] = (unsigned char) current;
    }
}

void Output_Generation_Func(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen, unsigned char *V, unsigned int Vlen, unsigned char *C, unsigned int Clen){
	unsigned int reseed = 0;
	BitSequence buff[10] = "02";
	BitSequence buff01[10] = "03";
	BitSequence First_before_SHA3[10000];
	BitSequence First_after_SHA3[outputByteLen/8];
	BitSequence Second_before_SHA3[10000];
	BitSequence Second_after_SHA3[outputByteLen/8];
	BitSequence Final_V[10000];
	BitSequence *inputdata = "18711A6A00A18B3A2FA62A2B4F85CBDAC46F837AC92368DF250DE14C";

	BitSequence Squeezed[SqueezingOutputLength/8];
	int r, w, length = 0;
	int j = Vlen;
	printf("************Output_Generation_Function start************\n");

	//*********************buff**************************//
	for(r = 0, w = 0 ; r < strlen(buff) ; r += 2){
		unsigned char temp_arr[3] = {buff[r], buff[r+1], '\0'};
		First_before_SHA3[w++] = strtol(temp_arr, NULL, 16);
	} //2 string to hex

	for(r = 0, w; r < Vlen; r++){ //inputByteLen를 v에 대한 길이로 변경
		First_before_SHA3[w++] = V[r];
	} //2 string to hex

	length = strlen(inputdata);
	for(r = 0, w; r < length; r += 2){
		unsigned char temp_arr[3] = {inputdata[r], inputdata[r+1], '\0'};
		First_before_SHA3[w++] = strtol(temp_arr, NULL, 16);
	} //2 string to hex
	//*********************buff**************************//

	printf("First before SHA3 data: ");
	for(int i=0; i<w; i++){
		printf("%02x", First_before_SHA3[i]);
	}
	printf("\n");

	Keccak(rate, capacity, First_before_SHA3, w, delimitedSuffix, Squeezed, outputByteLen/8); //have to check output, input length
	for (int i=0; i<outputByteLen/8; i++){
		First_after_SHA3[i] = Squeezed[i];
		//printf("%02x", SHA3_values02[i]); //write small
	}

	printf("First after SHA3 data: ");
	for(int i=0; i<outputByteLen/8; i++){
		printf("%02x", First_after_SHA3[i]);
	}
	printf("\n");

	/*for(int i=outputByteLen/8; i>=0; i--){
		Final_V[Vlen--] = V[Vlen--] + First_after_SHA3[i];
	}*/ //have to check carry












	//*********************buff01**************************//
	for(r = 0, w = 0 ; r < strlen(buff01) ; r += 2){
		unsigned char temp_arr[3] = {buff01[r], buff01[r+1], '\0'};
		Second_before_SHA3[w++] = strtol(temp_arr, NULL, 16);
	} //2 string to hex

	for(r = 0, w; r < j; r++){ //inputByteLen를 First_after_SHA3에 대한 길이로 변경
		Second_before_SHA3[w++] = Final_V[r];
	} //2 string to hex
	//*********************buff01**************************//

	Keccak(rate, capacity, Second_before_SHA3, j, delimitedSuffix, Squeezed, outputByteLen/8); //have to check output, input length
	for (int i=0; i<outputByteLen/8; i++){
		Second_after_SHA3[i] = Squeezed[i];
		//printf("%02x", SHA3_values02[i]); //write small
	}










	//Final_V = Second_after_SHA3 + C + First_after_SHA3 + reseed; // have to change using array
	reseed += 0x01; //have to check

	//Inner_Output_Generation_Function(rate, capacity, First_after_SHA3, w, delimitedSuffix, Squeezed, outputByteLen/8); //have to check output, input length
}

void Inner_Output_Generation_Function(unsigned int rate, unsigned int capacity, unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen){
	int length = inputByteLen - 1;
	int BlockSize = (inputByteLen) / 2;

	BitSequence mod01_before_sha3[BlockSize];
	BitSequence mod02_before_sha3[BlockSize];
	BitSequence SHA3_mod01[outputByteLen];
	BitSequence SHA3_mod02[outputByteLen];
	BitSequence SHA3_mod03[outputByteLen];
	BitSequence Final_SHA3_after_mod[outputByteLen * 3];
	int num= 0;
	int j=0;

	BitSequence Squeezed[SqueezingOutputLength/8];

	printf("************Inner_Output_Generation_Function start************\n");


	/*printf("Output Generation Function: ");
	for(int i=0; i<length; i++){
		printf("%02X", input[i]);
	}
	printf("\n");*/

	operation_add(input, length, 0x01);

	/*for(int i=0; i<length; i++){
		printf("%02X", input[i]);
	}
	printf("\n");

	printf("mod01_before_sha3: ");*/
	j=BlockSize;
	for(int i=length; i>=length-BlockSize-1; i--){
		mod01_before_sha3[j--] = input[i];
	}
	/*for(int i=0; i<BlockSize; i++){
		printf("%02X", mod01_before_sha3[i]);
	}
	printf("\n");*/

	operation_add(input, length, 0x01);
	//input[length-1] += 0x01;

	//printf("mod02_before_sha3: ");
	j=BlockSize;
	for(int i=length; i>=length-BlockSize-1; i--){
		mod02_before_sha3[j--] = input[i];
	}
	/*for(int i=0; i<BlockSize; i++){
		printf("%02X", mod02_before_sha3[i]);
	}
	printf("\n");*/

	//printf("SHA3_mod01: ");
	Keccak(rate, capacity, mod01_before_sha3, BlockSize, delimitedSuffix, Squeezed, outputByteLen);
	for (int i=0; i<outputByteLen; i++){
		SHA3_mod01[i] = Squeezed[i];
		Final_SHA3_after_mod[num++] = SHA3_mod01[i];
		//printf("%02x", SHA3_mod01[i]); //write small
	}
	//printf("\n");

	//printf("SHA3_mod02: ");
	Keccak(rate, capacity, mod02_before_sha3, BlockSize, delimitedSuffix, Squeezed, outputByteLen);
	for (int i=0; i<outputByteLen; i++){
		SHA3_mod02[i] = Squeezed[i];
		SHA3_mod03[i] = Squeezed[i];
		Final_SHA3_after_mod[num++] = SHA3_mod02[i];
		//printf("%02x", SHA3_mod02[i]); //write small
	}
	//printf("\n");

	//printf("SHA3_mod03: ");
	for (int i=0; i<outputByteLen; i++){
		Final_SHA3_after_mod[num++] = SHA3_mod03[i];
		//printf("%02x", SHA3_mod03[i]); //write small
	}
	//printf("\n");

	printf("Final_SHA3_after_mod: ");
	for (int i=0; i<outputByteLen * 3; i++){
		printf("%02x", Final_SHA3_after_mod[i]); //write small
	}
	printf("\n");

}

void C_DerivedFunction(unsigned int rate, unsigned int capacity, unsigned char input[110], unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen) {
	BitSequence buff[2] = "00";
	BitSequence buff_01[10] = "01000001B8";
	BitSequence buff_02[10] = "02000001B8";
	BitSequence V[inputByteLen];
	BitSequence Key_values01[10000];
	BitSequence Key_values02[10000];
	BitSequence SHA3_values01[10000];
	BitSequence SHA3_values02[10000];
	BitSequence Add_Key[30000];
	BitSequence Input_data[10000];
	BitSequence Final_Key[110];
	BitSequence Squeezed[SqueezingOutputLength/8];

	int r, w, j = 0;

	for(int i=0; i<inputByteLen-1; i++){
		V[i] = input[i];
	}

	printf("************C_DerivedFunction start************\n");

	//*********************buff**************************//
	for(r = 0, w = 0 ; r < strlen(buff) ; r += 2){
		unsigned char temp_arr[3] = {buff[r], buff[r+1], '\0'};
		Input_data[w++] = strtol(temp_arr, NULL, 16);
	} //2 string to hex

	for(r = 0, w; r < inputByteLen-1 ; r++){
		Input_data[w++] = input[r];
	} //2 string to hex
	//*********************buff**************************//

	/*printf("\nInput data: ");
	for(int i=0; i< w; i++){
		printf("%02X", Input_data[i]);
	}
	printf("\n");*/

	//*********************buff01**************************//
	for(r = 0, w = 0 ; r < strlen(buff_01) ; r += 2){
		unsigned char temp_arr[3] = {buff_01[r], buff_01[r+1], '\0'};
		Key_values01[w++] = strtol(temp_arr, NULL, 16);
	} //2 string to hex

	for(r = 0, w; r < inputByteLen ; r++){
		Key_values01[w++] = Input_data[r];
	} //2 string to hex
	//*********************buff01**************************//

	//*********************buff02**************************//
	for(r = 0, w = 0 ; r < strlen(buff_02) ; r += 2){
		unsigned char temp_arr[3] = {buff_02[r], buff_02[r+1], '\0'};
		Key_values02[w++] = strtol(temp_arr, NULL, 16);
	} //2 string to hex

	for(r = 0, w; r < inputByteLen ; r++){
		Key_values02[w++] = Input_data[r];
	} //2 string to hex
	//*********************buff02**************************//

	/*printf("Key_values01: ");
	for(int i=0; i< w; i++){
		printf("%02X", Key_values01[i]);
	}
	printf("\n");

	printf("Key_values02: ");
	for(int i=0; i< w; i++){
		printf("%02X", Key_values02[i]);
	}
	printf("\n");*/

	Keccak(rate, capacity, Key_values01, w, delimitedSuffix, Squeezed, outputByteLen/8);

	for (int i=0; i<outputByteLen/8; i++){
		SHA3_values01[i] = Squeezed[i];
		//printf("%02x", SHA3_values01[i]); //write small
	}
	//printf("\n");

	Keccak(rate, capacity, Key_values02, w, delimitedSuffix, Squeezed, outputByteLen/8);

	for (int i=0; i<outputByteLen/8; i++){
		SHA3_values02[i] = Squeezed[i];
		//printf("%02x", SHA3_values02[i]); //write small
	}
	//printf("\n");

	for(int i=0; i< outputByteLen/8; i++){
		Add_Key[i] = SHA3_values01[i];
	}

	j = outputByteLen/8;
	for(int i=0; i< outputByteLen/8; i++){
		Add_Key[j++] = SHA3_values02[i];
	}

	/*printf("Add Key: ");
	for(int i=0; i< j; i++){
		printf("%02x", Add_Key[i]);
	}
	printf("\n");

	printf("j: %d\n", j);*/

	printf("C Final Key: ");
	for(int i=0; i<j-1; i++){ //55맞는지 확인 필요
		Final_Key[i] = Add_Key[i];
		printf("%02X", Final_Key[i]);
	}
	printf("\n");

    //Inner_Output_Generation_Function(rate, capacity, Final_Key, j, delimitedSuffix, Squeezed, outputByteLen/8);
	Output_Generation_Func(rate, capacity, delimitedSuffix, Squeezed, outputByteLen, V, inputByteLen-1, Final_Key, j-1);
}

void V_DerivedFunction(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen) {
	BitSequence buff_01[100] = "01000001B8";
	BitSequence buff_02[100] = "02000001B8";
	BitSequence Key_values01[10000];
	BitSequence Key_values02[10000];
	BitSequence SHA3_values01[10000];
	BitSequence SHA3_values02[10000];
	BitSequence Add_Key[30000];
	BitSequence Final_Key[110];
    BitSequence Squeezed[SqueezingOutputLength/8];
    int r, w, j = 0;

    printf("************V_DerivedFunction start************\n");

    printf("string: %s\n", input);

    //*********************buff01**************************//
    for(r = 0, w = 0 ; r < strlen(buff_01) ; r += 2){
        unsigned char temp_arr[3] = {buff_01[r], buff_01[r+1], '\0'};
        Key_values01[w++] = strtol(temp_arr, NULL, 16);
    } //2 string to hex

    for(r = 0, w; r < strlen(input) ; r += 2){
        unsigned char temp_arr[3] = {input[r], input[r+1], '\0'};
        Key_values01[w++] = strtol(temp_arr, NULL, 16);
    } //2 string to hex
    //*********************buff01**************************//

    //*********************buff02**************************//
    for(r = 0, w = 0 ; r < strlen(buff_02) ; r += 2){
        unsigned char temp_arr[3] = {buff_02[r], buff_02[r+1], '\0'};
        Key_values02[w++] = strtol(temp_arr, NULL, 16);
    } //2 string to hex

    for(r = 0, w; r < strlen(input) ; r += 2){
        unsigned char temp_arr[3] = {input[r], input[r+1], '\0'};
        Key_values02[w++] = strtol(temp_arr, NULL, 16);
    } //2 string to hex
    //*********************buff02**************************//

    /*printf("Key_values01: ");
    for(int i=0; i< w; i++){
        printf("%02X", Key_values01[i]);
    }
    printf("\n");*/

    //printf("Key_values02: ");
    j = w;
    /*for(int i=0; i< w; i++){
        printf("%02X", Key_values02[i]);
    }
    printf("\n");*/ //just for test

    Keccak(rate, capacity, Key_values01, w, delimitedSuffix, Squeezed, outputByteLen/8);

	for (int i=0; i<outputByteLen/8; i++){
		SHA3_values01[i] = Squeezed[i];
		//printf("%02x", SHA3_values01[i]); //write small
	}
	//printf("\n");

	Keccak(rate, capacity, Key_values02, w, delimitedSuffix, Squeezed, outputByteLen/8);

	for (int i=0; i<outputByteLen/8; i++){
		SHA3_values02[i] = Squeezed[i];
		//printf("%02x", SHA3_values02[i]); //write small
	}
	//printf("\n");

	for(int i=0; i< outputByteLen/8; i++){
		Add_Key[i] = SHA3_values01[i];
	}

	j = outputByteLen/8;
	for(int i=0; i< outputByteLen/8; i++){
		Add_Key[j++] = SHA3_values02[i];
	}

    //printf("Add Key: ");
    for(int i=0; i< j; i++){
        //printf("%02x", Add_Key[i]);
    }
    //printf("\n");

    //printf("j: %d\n", j);

    printf("V Final Key: ");
    for(int i=0; i<j-1; i++){ //55맞는지 확인 필요
        Final_Key[i] = Add_Key[i];
        printf("%02X", Final_Key[i]);
    }
    printf("\n");

    C_DerivedFunction(rate, capacity, Final_Key, j, delimitedSuffix, Squeezed, outputByteLen);
    Inner_Output_Generation_Function(rate, capacity, Final_Key, j, delimitedSuffix, Squeezed, outputByteLen/8);
}

void ResetFunction(unsigned char *entropy, unsigned char *nonce, unsigned char *perString){
	int num = 0;
	int length = 0;
	BitSequence input_data[1000];

	length = strlen(entropy);
	for(int i=0; i<length; i++){
		input_data[num++] = entropy[i];
	}

	length = strlen(nonce);
	for(int i=0; i<length; i++){
		input_data[num++] = nonce[i];
	}

	length = strlen(perString);
	for(int i=0; i<length; i++){
		input_data[num++] = perString[i];
	}

	//DerivedFunction(input_data);

}
