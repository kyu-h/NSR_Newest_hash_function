#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdbool.h>

#include "hmac_kdf.h"

#define CTR_MODE 1
#define FB_MODE 2
#define DP_MODE 3

#define MAX_READ_LEN 1024

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


		/*sprintf(inputFileAddress, "PBKDF/%s.txt", HashName[i]);
		sprintf(outputFileAddress, "PBKDF/%s_rsp.txt", HashName[i]);*/

		/*sprintf(inputFileAddress, "PBKDF_testvectors/PBKDF_SHA3-224.txt");
		sprintf(outputFileAddress, "PBKDF_testvectors/PBKDF_SHA3-224_rsp.txt");

		if ( (fp_in = fopen(inputFileAddress, "r")) == NULL ) {
			printf("Couldn't open <%s> for read\n", inputFileAddress);
			return KAT_FILE_OPEN_ERROR;
		}

		pStr = fgets(strTemp, sizeof(strTemp), fp_in);
		printf("%s", pStr);*/

		/*if(!strcmp(pStr, "Algo_ID = PBKDF_SHA3-224\n")){
			genShortMsgHash_testVector_PBKDF(1152, 448, 0x06, 224, 0,inputFileAddress,outputFileAddress,"Algo_ID = PBKDF_SHA3-224");
		}else if(!strcmp(pStr, "Algo_ID = PBKDF_SHA3-256\n")){
			genShortMsgHash_testVector_PBKDF(1088, 512, 0x06, 256, 0,inputFileAddress,outputFileAddress,"Algo_ID = PBKDF_SHA3-256");
		}else {
			printf("Error!\n");
		}*/

		genShortMsgHash_HMAC_KDF_CTR();
		//genShortMsgHash_HMAC_KDF_DP();
		//genShortMsgHash_HMAC_KDF_FB();

		//testvector_HMAC_KDF_CTR();
		//testvector_HMAC_KDF_DP();
		//testvector_HMAC_KDF_FB();

	//fclose(fp_in);
    return KAT_SUCCESS;
}

/********** hmac pbkdf **********/

void genShortMsgHash_HMAC_KDF_CTR()
{
	FILE *fp_in, *fp_out;
	int output_std[4] = {224, 256, 384, 512};
	unsigned int rate, capacity;
	const unsigned char delimitedSuffix = 6;
	char inputFileAddress[256], outputFileAddress[256];
	unsigned char read_line[256];

	int r, len, hash_len;

	BitSequence ki[256], label[512], context[512], iv[256];
	int ki_size, label_size, context_size, iv_size;

	int std, old_r = -1; //temp

	int read, write;

	BitSequence *str_to_int;

	for(std = 0 ; std < 4 ; std++)
	{
		sprintf(inputFileAddress, "HMAC_KDF_CTR_test/HMAC_KDF_CTRmode_SHA3-%d.txt", output_std[std]);
		sprintf(outputFileAddress, "HMAC_KDF_CTR_test/HMAC_KDF_CTRmode_SHA3-%d_rsp.txt", output_std[std]);

		fp_in = fopen(inputFileAddress, "r");
		if(fp_in  == NULL)
		{
			printf("file open error \n");
			return;
		}
		else
			printf("%s file opened \n", inputFileAddress);

		fp_out = fopen(outputFileAddress, "w");

		if(std == 0)
		{
			rate = 1152;
			capacity = 448;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_CTRmode_SHA3-224\n\n");
		}
		else if(std == 1)
		{
			rate = 1088;
			capacity = 512;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_CTRmode_SHA3-256\n\n");
		}
		else if(std == 2)
		{
			rate = 832;
			capacity = 768;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_CTRmode_SHA3-384\n\n");
		}
		else if(std == 3)
		{
			rate = 576;
			capacity = 1024;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_CTRmode_SHA3-512\n\n");
		}

		fgets(read_line, MAX_READ_LEN, fp_in);	// skip line
		fgets(read_line, MAX_READ_LEN, fp_in);	// skip line

		while(!feof(fp_in))
		{
			fgets(read_line, MAX_READ_LEN, fp_in);	// read r
			str_to_int = &read_line[4];
			r = atoi(str_to_int);

			fgets(read_line, MAX_READ_LEN, fp_in);	// read ki
			ki_size = 0;
			for(read = 5, write = 0 ; read < strlen(read_line) - 1; read += 2)
			{
				BitSequence temp_arr[3] = {read_line[read], read_line[read + 1], '\0'};
				ki[write++] = strtol(temp_arr, NULL, 16);
				ki_size++;
			}

			/*fgets(read_line, MAX_READ_LEN, fp_in);	// read iv
			iv_size = 0;
			for(read = 5, write = 0 ; read < strlen(read_line) - 1 ; read += 2)
			{
				BitSequence temp_arr[3] = {read_line[read], read_line[read + 1], '\0'};
				iv[write++] = strtol(temp_arr, NULL, 16);
				iv_size++;
			}*/

			fgets(read_line, MAX_READ_LEN, fp_in);	// read label
			label_size = 0;
			for(read = 8, write = 0 ; read < strlen(read_line) - 1 ; read += 2)
			{
				BitSequence temp_arr[3] = {read_line[read], read_line[read + 1], '\0'};
				label[write++] = strtol(temp_arr, NULL, 16);
				label_size++;
			}

			fgets(read_line, MAX_READ_LEN, fp_in);	// read context
			context_size = 0;
			for(read = 10, write = 0 ; read < strlen(read_line) - 1 ; read += 2)
			{
				BitSequence temp_arr[3] = {read_line[read], read_line[read + 1], '\0'};
				context[write++] = strtol(temp_arr, NULL, 16);
				context_size++;
			}

			fgets(read_line, MAX_READ_LEN, fp_in);	// read len
			str_to_int = &read_line[4];
			len = strtol(str_to_int, NULL, 16);

			fgets(read_line, MAX_READ_LEN, fp_in);	// read hash len
			str_to_int = &read_line[4];
			hash_len = strtol(str_to_int, NULL, 16);

			hmac_kdf_digest(CTR_MODE, rate, capacity, ki, ki_size, iv, iv_size, label, label_size, context, context_size, r, len, hash_len, fp_out);

			fgets(read_line, MAX_READ_LEN, fp_in);	// skip line
		}

		fclose(fp_in);
		fclose(fp_out);
	}
}
void testvector_HMAC_KDF_CTR()
{
	FILE *fp_in, *fp_out;
	int output_std[4] = {224, 256, 384, 512};
	unsigned int rate, capacity;
	const unsigned char delimitedSuffix = 6;
	char inputFileAddress[256], outputFileAddress[256];
	unsigned char read_line[256];

	int r, count, len, hash_len;
	char read[4096];
	BitSequence ki[256], label[512], context[512];
	int ki_size, label_size, context_size;
	int label_byte, context_byte;

	int std, old_r = -1; //temp

	for(std = 0 ; std < 4 ; std++)
	{
		sprintf(inputFileAddress, "HMAC_KDF_test/testvector/HMAC_KDF_CTR_test/HMAC_KDF_CTRmode_SHA3-%d.txt", output_std[std]);
		sprintf(outputFileAddress, "HMAC_KDF_test/testvector/HMAC_KDF_CTR_test/HMAC_KDF_CTRmode_SHA3-%d_rsp.txt", output_std[std]);

		fp_in = fopen(inputFileAddress, "r");
		if(fp_in  == NULL)
		{
			printf("file open error \n");
			return;
		}
		else
			printf("%s file opened \n", inputFileAddress);

		fp_out = fopen(outputFileAddress, "w");

		if(std == 0)
		{
			rate = 1152;
			capacity = 448;
			hash_len = 224;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_CTRmode_SHA3-224\n\n");
		}
		else if(std == 1)
		{
			rate = 1088;
			capacity = 512;
			hash_len = 256;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_CTRmode_SHA3-256\n\n");
		}
		else if(std == 2)
		{
			rate = 832;
			capacity = 768;
			hash_len = 384;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_CTRmode_SHA3-384\n\n");
		}
		else if(std == 3)
		{
			rate = 576;
			capacity = 1024;
			hash_len = 512;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_CTRmode_SHA3-512\n\n");
		}

		count = 40;

		while(!feof(fp_in))
		{
			if(count > 39)
			{
				count = 0;
				FindMarker(fp_in, "RLEN ");
				fscanf(fp_in, "%*c %d", &r);	// read r
				fprintf(fp_out, "RLEN = %d\n\n", r);
			}

			fprintf(fp_out, "COUNT = %d\n", count++);

			FindMarker(fp_in, "L ");
			fscanf(fp_in, "%*c %d", &len);
			fprintf(fp_out, "L = %d\n", len);

			FindMarker(fp_in, "KI ");
			fscanf(fp_in, "%*c %s", read);
			fprintf(fp_out, "KI = %s\n", read);
			ki_size = 0;
			for(int i = 0, w = 0 ; i < strlen(read) ; i += 2)
			{
				BitSequence temp_arr[3] = {read[i], read[i + 1], '\0'};
				ki[w++] = strtol(temp_arr, NULL, 16);
				ki_size++;
			}

			FindMarker(fp_in, "LabelLen ");
			fscanf(fp_in, "%*c %d", &label_size);
			fprintf(fp_out, "LabelLen = %d\n", label_size);
			label_byte = label_size / 8;

			FindMarker(fp_in, "Label ");
			fscanf(fp_in, "%*c %s", read);
			fprintf(fp_out, "Label = %s\n", read);
			for(int i = 0, w = 0 ; i < strlen(read) ; i += 2)
			{
				BitSequence temp_arr[3] = {read[i], read[i + 1], '\0'};
				label[w++] = strtol(temp_arr, NULL, 16);
			}

			FindMarker(fp_in, "ContextLen ");
			fscanf(fp_in, "%*c %d", &context_size);
			fprintf(fp_out, "ContextLen = %d\n", context_size);
			context_byte = context_size / 8;

			FindMarker(fp_in, "Context ");
			fscanf(fp_in, "%*c %s", read);
			fprintf(fp_out, "Context = %s\n", read);
			for(int i = 0, w = 0 ; i < strlen(read) ; i += 2)
			{
				BitSequence temp_arr[3] = {read[i], read[i + 1], '\0'};
				context[w++] = strtol(temp_arr, NULL, 16);
			}

			hmac_kdf_digest(CTR_MODE, rate, capacity, ki, ki_size, NULL, 0, label, label_byte, context, context_byte, r, len, hash_len, fp_out, true);
		}

		fclose(fp_in);
		fclose(fp_out);
	}
}
void genShortMsgHash_HMAC_KDF_DP()
{
	FILE *fp_in, *fp_out;
	int output_std[4] = {224, 256, 384, 512};
	unsigned int rate, capacity;
	const unsigned char delimitedSuffix = 6;
	char inputFileAddress[256], outputFileAddress[256];
	unsigned char read_line[256];

	int r, len, hash_len;

	BitSequence ki[256], label[512], context[512], iv[256];
	int ki_size, label_size, context_size, iv_size;

	int std, old_r = -1; //temp

	int read, write;

	BitSequence *str_to_int;


	for(std = 0 ; std < 4 ; std++)
	{
		sprintf(inputFileAddress, "HMAC_KDF_DP_test/HMAC_KDF_DPmode_SHA3-%d.txt", output_std[std]);
		sprintf(outputFileAddress, "HMAC_KDF_DP_test/HMAC_KDF_DPmode_SHA3-%d_rsp.txt", output_std[std]);

		fp_in = fopen(inputFileAddress, "r");
		if(fp_in  == NULL)
		{
			printf("file open error \n");
			return;
		}
		else
			printf("%s file opened \n", inputFileAddress);

		fp_out = fopen(outputFileAddress, "w");

		if(std == 0)
		{
			rate = 1152;
			capacity = 448;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_DPmode_SHA3-224\n\n");
		}
		else if(std == 1)
		{
			rate = 1088;
			capacity = 512;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_DPmode_SHA3-256\n\n");
		}
		else if(std == 2)
		{
			rate = 832;
			capacity = 768;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_DPmode_SHA3-384\n\n");
		}
		else if(std == 3)
		{
			rate = 576;
			capacity = 1024;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_CTRmode_SHA3-512\n\n");
		}

		fgets(read_line, MAX_READ_LEN, fp_in);	// skip line
		fgets(read_line, MAX_READ_LEN, fp_in);	// skip line

		while(!feof(fp_in))
		{
			fgets(read_line, MAX_READ_LEN, fp_in);	// read r
			str_to_int = &read_line[4];
			r = atoi(str_to_int);

			fgets(read_line, MAX_READ_LEN, fp_in);	// read ki
			ki_size = 0;
			for(read = 5, write = 0 ; read < strlen(read_line) - 1; read += 2)
			{
				BitSequence temp_arr[3] = {read_line[read], read_line[read + 1], '\0'};
				ki[write++] = strtol(temp_arr, NULL, 16);
				ki_size++;
			}

			/*fgets(read_line, MAX_READ_LEN, fp_in);	// read iv
			iv_size = 0;
			for(read = 5, write = 0 ; read < strlen(read_line) - 1 ; read += 2)
			{
				BitSequence temp_arr[3] = {read_line[read], read_line[read + 1], '\0'};
				iv[write++] = strtol(temp_arr, NULL, 16);
				iv_size++;
			}*/

			fgets(read_line, MAX_READ_LEN, fp_in);	// read label
			label_size = 0;
			for(read = 8, write = 0 ; read < strlen(read_line) - 1 ; read += 2)
			{
				BitSequence temp_arr[3] = {read_line[read], read_line[read + 1], '\0'};
				label[write++] = strtol(temp_arr, NULL, 16);
				label_size++;
			}

			fgets(read_line, MAX_READ_LEN, fp_in);	// read context
			context_size = 0;
			for(read = 10, write = 0 ; read < strlen(read_line) - 1 ; read += 2)
			{
				BitSequence temp_arr[3] = {read_line[read], read_line[read + 1], '\0'};
				context[write++] = strtol(temp_arr, NULL, 16);
				context_size++;
			}

			fgets(read_line, MAX_READ_LEN, fp_in);	// read len
			str_to_int = &read_line[4];
			len = strtol(str_to_int, NULL, 16);

			fgets(read_line, MAX_READ_LEN, fp_in);	// read hash len
			str_to_int = &read_line[4];
			hash_len = strtol(str_to_int, NULL, 16);

			hmac_kdf_digest(DP_MODE, rate, capacity, ki, ki_size, iv, iv_size, label, label_size, context, context_size, r, len, hash_len, fp_out);

			fgets(read_line, MAX_READ_LEN, fp_in);	// skip line
		}

		fclose(fp_in);
		fclose(fp_out);
	}
}

void testvector_HMAC_KDF_DP()
{
	FILE *fp_in, *fp_out;
	int output_std[4] = {224, 256, 384, 512};
	unsigned int rate, capacity;
	const unsigned char delimitedSuffix = 6;
	char inputFileAddress[256], outputFileAddress[256];
	unsigned char read_line[256];

	int r, count, len, hash_len;
	char read[4096];
	BitSequence ki[256], label[512], context[512];
	int ki_size, label_size, context_size;
	int label_byte, context_byte;

	int std, old_r = -1; //temp

	for(std = 0 ; std < 4 ; std++)
	{
		sprintf(inputFileAddress, "HMAC_KDF_test/testvector/HMAC_KDF_DP_test/HMAC_KDF_DPmode_SHA3-%d.txt", output_std[std]);
		sprintf(outputFileAddress, "HMAC_KDF_test/testvector/HMAC_KDF_DP_test/HMAC_KDF_DPmode_SHA3-%d_rsp.txt", output_std[std]);

		fp_in = fopen(inputFileAddress, "r");
		if(fp_in  == NULL)
		{
			printf("file open error \n");
			return;
		}
		else
			printf("%s file opened \n", inputFileAddress);

		fp_out = fopen(outputFileAddress, "w");

		if(std == 0)
		{
			rate = 1152;
			capacity = 448;
			hash_len = 224;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_DPmode_SHA3-224\n\n");
		}
		else if(std == 1)
		{
			rate = 1088;
			capacity = 512;
			hash_len = 256;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_DPmode_SHA3-256\n\n");
		}
		else if(std == 2)
		{
			rate = 832;
			capacity = 768;
			hash_len = 384;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_DPmode_SHA3-384\n\n");
		}
		else if(std == 3)
		{
			rate = 576;
			capacity = 1024;
			hash_len = 512;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_DPmode_SHA3-512\n\n");
		}

		count = 40;

		while(!feof(fp_in))
		{
			if(count > 39)
			{
				count = 0;
				FindMarker(fp_in, "RLEN ");
				fscanf(fp_in, "%*c %d", &r);	// read r
				fprintf(fp_out, "RLEN = %d\n\n", r);
			}

			fprintf(fp_out, "COUNT = %d\n", count++);

			FindMarker(fp_in, "L ");
			fscanf(fp_in, "%*c %d", &len);
			fprintf(fp_out, "L = %d\n", len);

			FindMarker(fp_in, "KI ");
			fscanf(fp_in, "%*c %s", read);
			fprintf(fp_out, "KI = %s\n", read);
			ki_size = 0;
			for(int i = 0, w = 0 ; i < strlen(read) ; i += 2)
			{
				BitSequence temp_arr[3] = {read[i], read[i + 1], '\0'};
				ki[w++] = strtol(temp_arr, NULL, 16);
				ki_size++;
			}

			FindMarker(fp_in, "LabelLen ");
			fscanf(fp_in, "%*c %d", &label_size);
			fprintf(fp_out, "LabelLen = %d\n", label_size);
			label_byte = label_size / 8;

			FindMarker(fp_in, "Label ");
			fscanf(fp_in, "%*c %s", read);
			fprintf(fp_out, "Label = %s\n", read);
			for(int i = 0, w = 0 ; i < strlen(read) ; i += 2)
			{
				BitSequence temp_arr[3] = {read[i], read[i + 1], '\0'};
				label[w++] = strtol(temp_arr, NULL, 16);
			}

			FindMarker(fp_in, "ContextLen ");
			fscanf(fp_in, "%*c %d", &context_size);
			fprintf(fp_out, "ContextLen = %d\n", context_size);
			context_byte = context_size / 8;

			FindMarker(fp_in, "Context ");
			fscanf(fp_in, "%*c %s", read);
			fprintf(fp_out, "Context = %s\n", read);
			for(int i = 0, w = 0 ; i < strlen(read) ; i += 2)
			{
				BitSequence temp_arr[3] = {read[i], read[i + 1], '\0'};
				context[w++] = strtol(temp_arr, NULL, 16);
			}

			hmac_kdf_digest(DP_MODE, rate, capacity, ki, ki_size, NULL, 0, label, label_byte, context, context_byte, r, len, hash_len, fp_out, true);
		}

		fclose(fp_in);
		fclose(fp_out);
	}
}

void genShortMsgHash_HMAC_KDF_FB()
{
	FILE *fp_in, *fp_out;
	int output_std[4] = {224, 256, 384, 512};
	unsigned int rate, capacity;
	const unsigned char delimitedSuffix = 6;
	char inputFileAddress[256], outputFileAddress[256];
	unsigned char read_line[MAX_READ_LEN];

	int r, len, hash_len;
	BitSequence ki[256], iv[256], label[512], context[512];
	int ki_size, iv_size, label_size, context_size;

	int std;

	int read, write;

	BitSequence *str_to_int;

	for(std = 0 ; std < 4 ; std++)
	{
		sprintf(inputFileAddress, "HMAC_KDF_FB_test/HMAC_KDF_FBmode_SHA3-%d.txt", output_std[std]);
		sprintf(outputFileAddress, "HMAC_KDF_FB_test/HMAC_KDF_FBmode_SHA3-%d_rsp.txt", output_std[std]);

		fp_in = fopen(inputFileAddress, "r");
		if(fp_in  == NULL)
		{
			printf("file open error \n");
			return;
		}
		else
			printf("%s file opened \n", inputFileAddress);

		fp_out = fopen(outputFileAddress, "w");

		if(std == 0)
		{
			rate = 1152;
			capacity = 448;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_FBmode_SHA3-224\n\n");
		}
		else if(std == 1)
		{
			rate = 1088;
			capacity = 512;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_FBmode_SHA3-256\n\n");
		}
		else if(std == 2)
		{
			rate = 832;
			capacity = 768;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_FBmode_SHA3-384\n\n");
		}
		else if(std == 3)
		{
			rate = 576;
			capacity = 1024;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_FBmode_SHA3-512\n\n");
		}

		fgets(read_line, MAX_READ_LEN, fp_in);	// skip line
		fgets(read_line, MAX_READ_LEN, fp_in);	// skip line

		while(!feof(fp_in))
		{
			fgets(read_line, MAX_READ_LEN, fp_in);	// read r
			str_to_int = &read_line[4];
			r = atoi(str_to_int);

			fgets(read_line, MAX_READ_LEN, fp_in);	// read ki
			ki_size = 0;
			for(read = 5, write = 0 ; read < strlen(read_line) - 1; read += 2)
			{
				BitSequence temp_arr[3] = {read_line[read], read_line[read + 1], '\0'};
				ki[write++] = strtol(temp_arr, NULL, 16);
				ki_size++;
			}

			fgets(read_line, MAX_READ_LEN, fp_in);	// read iv
			iv_size = 0;
			for(read = 5, write = 0 ; read < strlen(read_line) - 1 ; read += 2)
			{
				BitSequence temp_arr[3] = {read_line[read], read_line[read + 1], '\0'};
				iv[write++] = strtol(temp_arr, NULL, 16);
				iv_size++;
			}

			fgets(read_line, MAX_READ_LEN, fp_in);	// read label
			label_size = 0;
			for(read = 8, write = 0 ; read < strlen(read_line) - 1 ; read += 2)
			{
				BitSequence temp_arr[3] = {read_line[read], read_line[read + 1], '\0'};
				label[write++] = strtol(temp_arr, NULL, 16);
				label_size++;
			}

			fgets(read_line, MAX_READ_LEN, fp_in);	// read context
			context_size = 0;
			for(read = 10, write = 0 ; read < strlen(read_line) - 1 ; read += 2)
			{
				BitSequence temp_arr[3] = {read_line[read], read_line[read + 1], '\0'};
				context[write++] = strtol(temp_arr, NULL, 16);
				context_size++;
			}

			fgets(read_line, MAX_READ_LEN, fp_in);	// read len
			str_to_int = &read_line[4];
			len = strtol(str_to_int, NULL, 16);

			fgets(read_line, MAX_READ_LEN, fp_in);	// read hash len
			str_to_int = &read_line[4];
			hash_len = strtol(str_to_int, NULL, 16);

			hmac_kdf_digest(FB_MODE, rate, capacity, ki, ki_size, iv, iv_size, label, label_size, context, context_size, r, len, hash_len, fp_out);

			fgets(read_line, MAX_READ_LEN, fp_in);	// skip line
		}

		fclose(fp_in);
		fclose(fp_out);
	}
}

void testvector_HMAC_KDF_FB()
{
	FILE *fp_in, *fp_out;
	int output_std[4] = {224, 256, 384, 512};
	unsigned int rate, capacity;
	const unsigned char delimitedSuffix = 6;
	char inputFileAddress[256], outputFileAddress[256];
	unsigned char read_line[256];

	int r, count, len, hash_len;
	char read[4096];
	BitSequence ki[256], iv[256], label[512], context[512];
	int ki_size, iv_size, label_size, context_size;
	int iv_byte, label_byte, context_byte;

	int std, old_r = -1; //temp

	for(std = 0 ; std < 4 ; std++)
	{
		sprintf(inputFileAddress, "HMAC_KDF_test/testvector/HMAC_KDF_FB_test/HMAC_KDF_FBmode_SHA3-%d.txt", output_std[std]);
		sprintf(outputFileAddress, "HMAC_KDF_test/testvector/HMAC_KDF_FB_test/HMAC_KDF_FBmode_SHA3-%d_rsp.txt", output_std[std]);

		fp_in = fopen(inputFileAddress, "r");
		if(fp_in  == NULL)
		{
			printf("file open error \n");
			return;
		}
		else
			printf("%s file opened \n", inputFileAddress);

		fp_out = fopen(outputFileAddress, "w");

		if(std == 0)
		{
			rate = 1152;
			capacity = 448;
			hash_len = 224;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_FBmode_SHA3-224\n\n");
		}
		else if(std == 1)
		{
			rate = 1088;
			capacity = 512;
			hash_len = 256;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_FBmode_SHA3-256\n\n");
		}
		else if(std == 2)
		{
			rate = 832;
			capacity = 768;
			hash_len = 384;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_FBmode_SHA3-384\n\n");
		}
		else if(std == 3)
		{
			rate = 576;
			capacity = 1024;
			hash_len = 512;
			fprintf(fp_out, "Algo_ID = HMAC_KDF_FBmode_SHA3-512\n\n");
		}

		count = 40;

		while(!feof(fp_in))
		{
			if(count > 39)
			{
				count = 0;
				FindMarker(fp_in, "RLEN ");
				fscanf(fp_in, "%*c %d", &r);	// read r
				fprintf(fp_out, "RLEN = %d\n\n", r);
			}

			fprintf(fp_out, "COUNT = %d\n", count++);

			FindMarker(fp_in, "L ");
			fscanf(fp_in, "%*c %d", &len);
			fprintf(fp_out, "L = %d\n", len);

			FindMarker(fp_in, "KI ");
			fscanf(fp_in, "%*c %s", read);
			fprintf(fp_out, "KI = %s\n", read);
			ki_size = 0;
			for(int i = 0, w = 0 ; i < strlen(read) ; i += 2)
			{
				BitSequence temp_arr[3] = {read[i], read[i + 1], '\0'};
				ki[w++] = strtol(temp_arr, NULL, 16);
				ki_size++;
			}

			FindMarker(fp_in, "IVLen ");
			fscanf(fp_in, "%*c %d", &iv_size);
			fprintf(fp_out, "IVLen = %d\n", iv_size);
			iv_byte = iv_size / 8;

			if(iv_size)
			{
				FindMarker(fp_in, "IV ");
				fscanf(fp_in, "%*c %s", read);
				fprintf(fp_out, "IV = %s\n", read);
				for(int i = 0, w = 0 ; i < strlen(read) ; i += 2)
				{
					BitSequence temp_arr[3] = {read[i], read[i + 1], '\0'};
					iv[w++] = strtol(temp_arr, NULL, 16);
				}
			}
			else
			{
				fprintf(fp_out, "IV = \n");
				fgets(NULL, 0, fp_in);
			}

			FindMarker(fp_in, "LabelLen ");
			fscanf(fp_in, "%*c %d", &label_size);
			fprintf(fp_out, "LabelLen = %d\n", label_size);
			label_byte = label_size / 8;

			FindMarker(fp_in, "Label ");
			fscanf(fp_in, "%*c %s", read);
			fprintf(fp_out, "Label = %s\n", read);
			for(int i = 0, w = 0 ; i < strlen(read) ; i += 2)
			{
				BitSequence temp_arr[3] = {read[i], read[i + 1], '\0'};
				label[w++] = strtol(temp_arr, NULL, 16);
			}

			FindMarker(fp_in, "ContextLen ");
			fscanf(fp_in, "%*c %d", &context_size);
			fprintf(fp_out, "ContextLen = %d\n", context_size);
			context_byte = context_size / 8;

			FindMarker(fp_in, "Context ");
			fscanf(fp_in, "%*c %s", read);
			fprintf(fp_out, "Context = %s\n", read);
			for(int i = 0, w = 0 ; i < strlen(read) ; i += 2)
			{
				BitSequence temp_arr[3] = {read[i], read[i + 1], '\0'};
				context[w++] = strtol(temp_arr, NULL, 16);
			}

			hmac_kdf_digest(FB_MODE, rate, capacity, ki, ki_size, iv, iv_byte, label, label_byte, context, context_byte, r, len, hash_len, fp_out, true);
		}

		fclose(fp_in);
		fclose(fp_out);
	}
}
/********** hmac pbkdf end **********/

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

		for(r = 0, w=0; r < i ; r += 2){
			unsigned char temp_arr[3] = {salt[r], salt[r+1], '\0'};
			salt[w++] = strtol(temp_arr, NULL, 16);
		} //2 string to hex

		FindMarker(fp_in, "KLen");
		fscanf(fp_in, " %c %d", &str, &Klen);
		fprintf(fp_out, "KLen = %d", Klen);
		fprintf(fp_out, "\n");

		salt_len = i/2;

		/*printf("salt: ");
		for(int z=0; z<salt_len; z++){
			printf("%02x", salt[z]);
		}printf("\n");*/

		pbkdf_testvector_sha3_hmac(rate, capacity, delimitedSuffix, password, pass_len, salt, salt_len, IterationCount, Klen, loopCount, fp_out);

		memset(password, 0, 128);
		memset(salt, 0, 128);
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
