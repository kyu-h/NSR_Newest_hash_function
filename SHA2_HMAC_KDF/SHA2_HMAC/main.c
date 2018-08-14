#include "hmac_sha2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CTR_MODE 1
#define FB_MODE 2
#define DP_MODE 3

#define MAX_READ_LEN 1024

typedef unsigned char BitSequence;

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

			//hmac_kdf_digest(FB_MODE, rate, capacity, ki, ki_size, iv, iv_size, label, label_size, context, context_size, r, len, hash_len, fp_out);

			fgets(read_line, MAX_READ_LEN, fp_in);	// skip line
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

			//hmac_kdf_digest(DP_MODE, rate, capacity, ki, ki_size, iv, iv_size, label, label_size, context, context_size, r, len, hash_len, fp_out);

			fgets(read_line, MAX_READ_LEN, fp_in);	// skip line
		}

		fclose(fp_in);
		fclose(fp_out);
	}
}

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

			//hmac_kdf_digest(CTR_MODE, rate, capacity, ki, ki_size, iv, iv_size, label, label_size, context, context_size, r, len, hash_len, fp_out);

			fgets(read_line, MAX_READ_LEN, fp_in);	// skip line
		}

		fclose(fp_in);
		fclose(fp_out);
	}
}

int main(void){
/*	unsigned int mac_224_size, mac_256_size, mac_384_size, mac_512_size;
	unsigned char Keystring[1024], Msgstring[1024];
	int i;

	mac_224_size = 224 / 8;
	mac_256_size = 256 / 8;
	mac_384_size = 384 / 8;
	mac_512_size = 512 / 8;

	int keylen = 0, msglen = 0;
	int mode;

	unsigned char *keys[] = {
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	};

    static char *messages[] ={
        "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
        "what do ya want for nothing?"
    };

    mode = 3;				// 0: 224 , 1: 256, 2: 384, 3: 512

    unsigned char mac[SHA512_DIGEST_SIZE];

	for(int r = 0, w = 0 ; r < strlen(keys[0]); r += 2){
	   unsigned char temp_arr[3] = {keys[0][r], keys[0][r+1], '\0'};
	   Keystring[w++] = strtol(temp_arr, NULL, 16);
	   keylen++;
	}
	//keylen /= 2;

	for(int r = 0, w = 0 ; r < strlen(messages[0]); r += 2){
	   unsigned char temp_arr[3] = {messages[0][r], messages[0][r+1], '\0'};
	   Msgstring[w++] = strtol(temp_arr, NULL, 16);
	   msglen++;
	}
	//msglen /= 2;

	for(int i=0; i<keylen; i++){
		printf("%02x", Keystring[i]);
	}printf("\n");

	for(int i=0; i<msglen; i++){
		printf("%02x", Msgstring[i]);
	}printf("\n");

	if(mode == 0)
	{
		hmac_sha224(Keystring, keylen, Msgstring, msglen, mac, mac_224_size);
		test(mac, mac_224_size);
	}
	else if(mode == 1)
	{
		hmac_sha256(Keystring, keylen, Msgstring, msglen, mac, mac_256_size);
		test(mac, mac_256_size);
	}
	else if(mode == 2)
	{
		hmac_sha384(Keystring, keylen, Msgstring, msglen, mac, mac_384_size);
		test(mac, mac_384_size);
	}
	else if(mode == 3)
	{
		hmac_sha512(Keystring, keylen, Msgstring, msglen, mac, mac_512_size);
		test(mac, mac_512_size);
	}*/


	genShortMsgHash_HMAC_KDF_CTR();
	//genShortMsgHash_HMAC_KDF_DP();
	//genShortMsgHash_HMAC_KDF_FB();

    return 0;
}
