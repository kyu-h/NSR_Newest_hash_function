#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include "hmac_sha2.h"
#include "sha2.h"

#define CTR_MODE 1
#define FB_MODE 2
#define DP_MODE 3

typedef unsigned char BitSequence;

unsigned int mac_224_size = 224/8, mac_256_size = 256/8, mac_384_size = 384/8, mac_512_size = 512/8;

unsigned char mac[SHA512_DIGEST_SIZE];

void drbg_sha3_hmac_print(unsigned int digest_size, BitSequence *digest){
	for(int i = 0 ; i < digest_size ; i++)
		printf("%02x", digest[i]);

	printf("\n");
}

void pbkdf_sha3_hmac(const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *password, unsigned int pass_len, BitSequence *salt, const unsigned int salt_leng, unsigned int IterationCount, unsigned int Klen, unsigned int loopCount, FILE *outf){
	unsigned int hlen, length = 0;
	int r, c;
	int num = 0;
	int j = 0;
	int w= 0;
	BitSequence T[capacity / 16];
	BitSequence U[capacity / 16];
	BitSequence MK[(capacity / 16) * 2];
	BitSequence salt_inti[salt_leng + 4];
	BitSequence tmp[0];

	printf("%d, %d\n", capacity, rate);

	if(rate == 1152){
		hlen = 224;
	}else if(rate == 1088){
		hlen = 256;
	}else if(rate == 832){
		hlen = 384;
	}else {
		hlen = 512;
	}

	if(Klen > ((pow(2,32) - 1) * hlen)){
		printf("Error !\n");
	}

	length = ceil(Klen / hlen);

	//printf("%d\n", length);
	r = Klen - (length - 1) * hlen;

	for(int i=1; i<length + 1; i++){
		printf("Output start %d \n", i);
		for(int ii=0; ii<capacity/16; ii++){
			T[ii] = '\0';
		}

		for(int k=0; k<salt_leng; k++){
			salt_inti[w++] = salt[k];
		}

		salt_inti[w++] = 0x00;
		salt_inti[w++] = 0x00;
		salt_inti[w++] = 0x00;
		if(i == 1){
			salt_inti[w] = 0x01;
		}else if(i == 2){
			salt_inti[w] = 0x02;
		}else if(i == 3){
			salt_inti[w] = 0x03;
		}

		fprintf(outf, "U0 = ");
		for(int b =0; b<salt_leng + 4; b++){
			fprintf(outf, "%02x", salt_inti[b]);
		}fprintf(outf, "\n\n");

		/*for(int q=0; q<pass_len; q++){
			printf("%02x", password[q]);
		}printf("\n");*/

		for(j=1; j<IterationCount+1; j++){
			if(j == 1){
				//hmac_digest(capacity / 2, rate, capacity, password, pass_len, salt_inti, salt_leng + 4, U);
				drbg_sha3_hmac_print(capacity / 16, U);
			}else {
				//hmac_digest(capacity / 2, rate, capacity, password, pass_len, U, capacity / 16, U);
				//drbg_sha3_hmac_print(capacity / 16, U);
			}

			if(j == 1 || j == 2 || j ==3 || j == IterationCount-2 || j == IterationCount-1 || j == IterationCount){
				fprintf(outf, "U%i = ", j);
				for(int b =0; b<capacity / 16; b++){
					fprintf(outf, "%02x", U[b]);
				}fprintf(outf, "\n");
			}

			for(int k=0; k<capacity / 16; k++){
				T[k] = T[k] ^ U[k];
			}

			if(j == 1 || j == 2 || j ==3 ||  j == IterationCount-2 || j == IterationCount-1 || j == IterationCount){
				fprintf(outf, "T%d = ", i);
				for(int b =0; b<capacity / 16; b++){
					fprintf(outf, "%02x", T[b]);
				}fprintf(outf, "\n\n");
			}

		}
		w = 0;
		if(j == IterationCount+1){
			for(int b =0; b<capacity / 16; b++){
				MK[num++] = T[b];
				printf("%02x", T[b]);
			}printf("\n");
		}
	}
	fprintf(outf, "MK = ");
	for(int m=0; m<num; m++){
		fprintf(outf, "%02x", MK[m]);
	}
}

void pbkdf_gen(int capacity, int rate, int hash_len, BitSequence *U, int size_u, BitSequence *T, int t_index, BitSequence *password, int pass_size, int iteration_count, FILE *fp)
{	int index = t_index;

	for(int i = 0 ; i < iteration_count ; i++)
	{
		if(!i){
			//hmac_digest(capacity / 2, rate, capacity, password, pass_size, U, size_u, U);
		}else{
			//hmac_digest(capacity / 2, rate, capacity, password, pass_size, U, hash_len, U);
		}

		for(int j = 0 ; j < hash_len ; j++)
			T[index++] ^=  U[j];
		index = t_index;
	}
}

void pbkdf_testvector_sha3_rev(const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *password, unsigned int pass_len, BitSequence *salt, const unsigned int salt_leng, unsigned int IterationCount, unsigned int Klen, unsigned int loopCount, FILE *outf)
{
	unsigned int hlen;

	BitSequence U[128] = {'\0', };
	BitSequence *T;

	int hash_byte, key_byte;

	double len;
	int r, w;
	int size_u, size_t;

	if(rate == 1152){
		hlen = 224;
	}else if(rate == 1088){
		hlen = 256;
	}else if(rate == 832){
		hlen = 384;
	}else {
		hlen = 512;
	}

	hash_byte = hlen / 8;
	key_byte = Klen / 8;

	len = ceil((double) key_byte / (double) hash_byte);

	size_t = hash_byte * len;

	T = (BitSequence*) malloc(sizeof(BitSequence) * size_t);

	for(int i = 0 ; i < size_t ; i++)
		T[i] = '\0';

	for(int i = 0 ; i < len ; i++)
	{
		int t_index = size_t / len * i;

		for(r = 0, w = 0 ; r < salt_leng ; r++)
			U[w++] = salt[r];
		U[w++] = 0;
		U[w++] = 0;
		U[w++] = 0;
		U[w] = i + 1;
		size_u = salt_leng + 4;

		pbkdf_gen(capacity, rate, hash_byte, U, size_u, T, t_index, password, pass_len, IterationCount, outf);
	}

	fprintf(outf, "MK = ");
	for(int i = 0 ; i < key_byte ; i++)
		fprintf(outf, "%02x", T[i]);
	fprintf(outf, "\n\n");

	free(T);
}

void pbkdf_testvector_sha3_hmac(const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *password, unsigned int pass_len, BitSequence *salt, const unsigned int salt_leng, unsigned int IterationCount, unsigned int Klen, unsigned int loopCount, FILE *outf){
	unsigned int hlen, length = 0;
	int r, c;
	int num = 0;
	int j = 0;
	int w= 0;
	BitSequence T[capacity / 16];
	BitSequence U[capacity / 16];
	BitSequence MK[(capacity / 16) * 8];
	BitSequence salt_inti[salt_leng + 4];
	BitSequence tmp[0];

	//printf("%d, %d\n", capacity, rate);

	for(int i = 0 ; i < (capacity / 16) * 8 ; i++)
		MK[i] = '\0';

	if(rate == 1152){
		hlen = 224;
	}else if(rate == 1088){
		hlen = 256;
	}else if(rate == 832){
		hlen = 384;
	}else {
		hlen = 512;
	}

	int temp = hlen / 8;

	if(Klen > ((pow(2,32) - 1) * hlen)){
		printf("Error !\n");
	}

	length = ceil(Klen / hlen);
	r = Klen - (length - 1) * hlen;

	for(int i=1; i<length+2; i++){
		//printf("Output start %d \n", i);
		for(int ii=0; ii<capacity/16; ii++){
			T[ii] = '\0';
		}

		for(int k=0; k<salt_leng; k++){
			salt_inti[w++] = salt[k];
		}

		salt_inti[w++] = 0x00;
		salt_inti[w++] = 0x00;
		salt_inti[w++] = 0x00;

		salt_inti[w] = i;

		/*printf("U0 = ");
		for(int b =0; b<salt_leng + 4; b++){
			printf("%02x", salt_inti[b]);
		}printf("\n");*/

		for(j=1; j<IterationCount+1; j++){
			if(j == 1){
				//hmac_digest(capacity / 2, rate, capacity, password, pass_len, salt_inti, salt_leng + 4, U);
				//drbg_sha3_hmac_print(capacity / 16, U);
			}else {
				//hmac_digest(capacity / 2, rate, capacity, password, pass_len, U, capacity / 16, U);
				//drbg_sha3_hmac_print(capacity / 16, U);
			}

			/*if(j == 1 || j == 2 || j ==3 || j == IterationCount-2 || j == IterationCount-1 || j == IterationCount){
				printf("U%i = ", j);
				for(int b =0; b<capacity / 16; b++){
					printf("%02x", U[b]);
				}printf("\n");
			}*/

			for(int k=0; k< temp; k++){
				T[k] = T[k] ^ U[k];
			}
		}

		w = 0;
		if(j == IterationCount+1){
			/*if(Klen == 2048 && i > 7)
			{
				if(i > 7 && Klen == 2048)
				{
					printf("current len: %d \n", i);
					for(int k = 0 ; k < temp ; k++)
						printf("%02x", T[k]);
					printf("\n");
				}
			}*/
			/*for(int k=0; k<capacity / 16; k++){
				printf("%02x", T[k]);
			}printf("\n");*/

			for(int b =0; b< temp; b++){
				MK[num++] = T[b];
			}//printf("\n");
			printf("\n");
		}
	}

	fprintf(outf, "MK = ");
	for(int m=0; m<Klen / 8; m++){
		fprintf(outf, "%02x", MK[m]);
	}fprintf(outf, "\n\n");

	for(int i=0; i<(capacity / 16) * 8; i++){
		MK[i] = '\0';
	}
}



/********** hmac pbkdf **********/

void hmac_kdf_ctr_digest(int loop_count, int byte_r, BitSequence *Ki, int Ki_len, BitSequence *label, int label_len, BitSequence *context, int ct_len, unsigned int len, unsigned int hash_len, BitSequence *output, FILE *fp, bool tv)
{
	BitSequence *input;
	BitSequence *k_temp;

	int input_size;
	int temp_index = 0;
	int result_index = 0;
	int len_to_hex = len * 8;

	input_size = byte_r + label_len + ct_len + 3;	// 3 = 0x00(1) || [L]2(2)

	input = (BitSequence*) malloc(sizeof(BitSequence) * input_size);
	k_temp = (BitSequence*) malloc(sizeof(BitSequence) * hash_len);
	for(int i = 0 ; i < input_size ; i++)
		input[i] = '\0';	// initializing input

	temp_index = byte_r;
	for(int i = 0 ; i < label_len ; i++)
		input[temp_index++] = label[i];	// || label
	input[temp_index++] = 0;			// || 0x00
	for(int i = 0 ; i < ct_len ; i++)
		input[temp_index++] = context[i];//|| context
	input[temp_index + 1] = len_to_hex % 256;
	len_to_hex /= 256;
	input[temp_index] = len_to_hex % 256;	// || [L]2

	for(int i = 0 ; i < loop_count ; i++)
	{
		if(byte_r)							// || [i]2
		{
			for(temp_index = 0 ; temp_index < byte_r - 1; temp_index++)
				input[temp_index] = 0;
			input[temp_index] = i + 1;
		}

		printf("input %d size data: ", input_size);
		for(int j = 0 ; j < input_size ; j++)
			printf("%02x", input[j]);
		printf("\n");

		//hmac_digest(capacity / 2, rate, capacity, Ki, Ki_len, input, input_size, k_temp);

		hmac_sha224(Ki, Ki_len, input, input_size, mac, mac_224_size);
		test(mac, mac_224_size);

		printf("output data number %d: ", i + 1);
		for(int j = 0 ; j < hash_len ; j++)
			printf("%02x", k_temp[j]);
		printf("\n");

		if(!tv)
		{
			fprintf(fp, "Input = ");
			for(int k = 0 ; k < input_size ; k++)
				fprintf(fp, "%02x", input[k]);
			fprintf(fp, "\n");
			fprintf(fp, "Result = ");
			for(int k = 0 ; k < hash_len ; k++)
				fprintf(fp, "%02x", k_temp[k]);
			fprintf(fp, "\n\n");
		}

		for(int j = 0 ; j < hash_len ; j++)
		{
			if(result_index == len)
				break;
			output[result_index++] = k_temp[j];
		}
	}

	printf("final output: ");
	for(int i = 0 ; i < len ; i++)
		printf("%02x", output[i]);
	printf("\n");

	free(input);
	free(k_temp);
}

void hmac_kdf_fb_digest(int loop_count, int byte_r, BitSequence *Ki, int Ki_len, BitSequence *iv, int iv_len, BitSequence *label, int label_len, BitSequence *context, int ct_len, unsigned int len, unsigned int hash_len, BitSequence *output, FILE *fp, bool tv)
{
	BitSequence *input;
	BitSequence *iv_zero_input;
	BitSequence *k_temp;

	int input_size;
	int iv_zero_input_size;
	int temp_index = 0;
	int result_index = 0;
	int len_to_hex = len * 8;

	input_size = byte_r + hash_len + label_len + ct_len + 3;	// 3 = 0x00(1) || [L]2(2)

	input = (BitSequence*) malloc(sizeof(BitSequence) * input_size);
	k_temp = (BitSequence*) malloc(sizeof(BitSequence) * hash_len);
	for(int i = 0 ; i < input_size ; i++)
		input[i] = '\0';	// initializing input
	if(iv_len)				// initailizing key
	{
		for(int i = 0 ; i < hash_len ; i++)
			k_temp[i] = iv[i];
	}
	else
	{
		for(int i = 0 ; i < hash_len ; i++)
			k_temp[i] = '\0';
		iv_zero_input_size = byte_r + label_len + ct_len + 3;
		iv_zero_input = (BitSequence*) malloc(sizeof(BitSequence) * iv_zero_input_size);
	}

	temp_index = hash_len;				// skip k-size array
	if(byte_r)							// skip array when r != 0
		temp_index += byte_r;
	for(int i = 0 ; i < label_len ; i++)
		input[temp_index++] = label[i];	// || label
	input[temp_index++] = 0;			// || 0x00
	for(int i = 0 ; i < ct_len ; i++)
		input[temp_index++] = context[i];//|| context
	input[temp_index + 1] = len_to_hex % 256;
	len_to_hex /= 256;
	input[temp_index] = len_to_hex % 256;	// || [L]2

	if(!iv_len)
	{
		temp_index = hash_len;
		for(int i = 0 ; i < iv_zero_input_size ; i++)
			iv_zero_input[i] = input[temp_index++];
	}

	for(int i = 0 ; i < loop_count ; i++)
	{
		temp_index = 0;
		for(int j = 0 ; j < hash_len ; j++)
			input[temp_index++] = k_temp[j];	// feedback Ki
		if(byte_r)								// || [i]2
		{
			int flag = byte_r - 1;
			temp_index = hash_len;
			while(flag--)
				input[temp_index++] = 0;
			input[temp_index] = i + 1;
		}

		if(!i && !iv_len)
		{
			if(byte_r)
			{
				int flag = byte_r - 1;
				temp_index = 0;
				while(flag--)
					iv_zero_input[temp_index++] = 0;
				iv_zero_input[temp_index] = i + 1;
			}

			printf("input %d size data: ", iv_zero_input_size);
			for(int j = 0 ; j < iv_zero_input_size ; j++)
				printf("%02x", iv_zero_input[j]);
			printf("\n");

			//hmac_digest(capacity / 2, rate, capacity, Ki, Ki_len, iv_zero_input, iv_zero_input_size, k_temp);

			hmac_sha224(Ki, Ki_len, iv_zero_input, iv_zero_input_size, mac, mac_224_size);
			//test(mac, mac_224_size);
		}
		else
		{
			printf("input %d size data: ", input_size);
			for(int j = 0 ; j < input_size ; j++)
				printf("%02x", input[j]);
			printf("\n");

			//hmac_digest(capacity / 2, rate, capacity, Ki, Ki_len, input, input_size, k_temp);

			hmac_sha224(Ki, Ki_len, input, input_size, mac, mac_224_size);
			//test(mac, mac_224_size);
		}

		printf("output data number %d: ", i + 1);
		for(int j = 0 ; j < hash_len ; j++)
			printf("%02x", k_temp[j]);
		printf("\n");

		if(!tv)
		{
			fprintf(fp, "Input = ");
			for(int k = 0 ; k < input_size ; k++)
				fprintf(fp, "%02x", input[k]);
			fprintf(fp, "\n");
			fprintf(fp, "Result = ");
			for(int k = 0 ; k < hash_len ; k++)
				fprintf(fp, "%02x", k_temp[k]);
			fprintf(fp, "\n\n");
		}

		for(int j = 0 ; j < hash_len ; j++)
		{
			if(result_index == len)
				break;
			output[result_index++] = k_temp[j];
		}
	}

	printf("final output: ");
	for(int i = 0 ; i < len ; i++)
		printf("%02x", output[i]);
	printf("\n");

	free(input);
	free(k_temp);
}

void hmac_kdf_dp_digest(int loop_count, int byte_r, BitSequence *Ki, int Ki_len, BitSequence *label, int label_len, BitSequence *context, int ct_len, unsigned int len, unsigned int hash_len, BitSequence *output, FILE *fp, bool tv)
{
	BitSequence *input;
	BitSequence *k_temp;
	BitSequence *k_saved;
	BitSequence *a_temp;
	BitSequence *a_iv;

	int input_size;
	int a_size;
	int temp_index = 0;
	int a_index = 0;
	int result_index = 0;
	int len_to_hex = len * 8;

	a_size = label_len + ct_len + 3;		// 3 = 0x00(1) || [L]2(2)
	input_size = byte_r + hash_len + label_len + ct_len + 3;	// 3 = 0x00(1) || [L]2(2)

	input = (BitSequence*) malloc(sizeof(BitSequence) * input_size);
	k_temp = (BitSequence*) malloc(sizeof(BitSequence) * hash_len);
	k_saved = (BitSequence*) malloc(sizeof(BitSequence) * hash_len * loop_count);
	a_temp = (BitSequence*) malloc(sizeof(BitSequence) * hash_len);
	a_iv = (BitSequence*) malloc(sizeof(BitSequence) * a_size);
	for(int i = 0 ; i < input_size ; i++)
		input[i] = '\0';	// initializing input

	temp_index = hash_len;				// skip a-size array
	if(byte_r)							// skip array when r != 0
		temp_index += byte_r;
	for(int i = 0 ; i < label_len ; i++)
	{
		a_iv[a_index++] = label[i];
		input[temp_index++] = label[i];	// || label
	}
	a_iv[a_index++] = 0;
	input[temp_index++] = 0;			// || 0x00
	for(int i = 0 ; i < ct_len ; i++)
	{
		a_iv[a_index++] = context[i];
		input[temp_index++] = context[i];//|| context
	}
	a_iv[a_index + 1] = len_to_hex % 256;
	input[temp_index + 1] = len_to_hex % 256;
	len_to_hex /= 256;
	a_iv[a_index] = len_to_hex % 256;
	input[temp_index] = len_to_hex % 256;	// || [L]2

	for(int i = 0 ; i < loop_count ; i++)
	{
		if(!i)
		{
			printf("input %d size A(iv) data: ", a_size);
			for(int j = 0 ; j < a_size ; j++)
				printf("%02x", a_iv[j]);
			printf("\n");

			if(!tv)
			{
				fprintf(fp, "Input1 = ");
				for(int k = 0 ; k < a_size ; k++)
					fprintf(fp, "%02x", a_iv[k]);
				fprintf(fp, "\n");
			}

			//hmac_digest(capacity / 2, rate, capacity, Ki, Ki_len, a_iv, a_size, a_temp);
		}
		else
		{
			printf("input %d size A data: ", hash_len);
			for(int j = 0 ; j < hash_len ; j++)
				printf("%02x", a_temp[j]);
			printf("\n");

			if(!tv)
			{
				fprintf(fp, "Input1 = ");
				for(int k = 0 ; k < hash_len ; k++)
					fprintf(fp, "%02x", a_temp[k]);
				fprintf(fp, "\n");
			}

			//hmac_digest(capacity / 2, rate, capacity, Ki, Ki_len, a_temp, hash_len, a_temp);
		}

		printf("output A data number %d: ", i + 1);
		for(int j = 0 ; j < hash_len ; j++)
			printf("%02x", a_temp[j]);
		printf("\n");

		if(!tv)
		{
			fprintf(fp, "A(%d) = ", i + 1);
			for(int k = 0 ; k < hash_len ; k++)
				fprintf(fp, "%02x", a_temp[k]);
			fprintf(fp, "\n");
		}

		temp_index = 0;
		for(int j = 0 ; j < hash_len ; j++)
			input[temp_index++] = a_temp[j];
		if(byte_r)
		{
			int flag = byte_r - 1;
			temp_index = hash_len;
			while(flag--)
				input[temp_index++] = 0;
			input[temp_index] = i + 1;
		}

		printf("input %d size data: ", input_size);
		for(int j = 0 ; j < input_size ; j++)
			printf("%02x", input[j]);
		printf("\n");

		//hmac_digest(capacity / 2, rate, capacity, Ki, Ki_len, input, input_size, k_temp);

		for(int j = 0, k = hash_len * i ; j < hash_len ; j++)
			k_saved[k++] = k_temp[j];

		printf("output data number %d: ", i + 1);
		for(int j = 0 ; j < hash_len ; j++)
			printf("%02x", k_temp[j]);
		printf("\n");

		if(!tv)
		{
			fprintf(fp, "Input2 = ");
			for(int k = 0 ; k < input_size ; k++)
				fprintf(fp, "%02x", input[k]);
			fprintf(fp, "\n");
			fprintf(fp, "K(%d) = ", i + 1);
			for(int k = 0 ; k < hash_len ; k++)
				fprintf(fp, "%02x", k_temp[k]);
			fprintf(fp, "\n");
			fprintf(fp, "Result = ");
			for(int k = 0 ; k < hash_len * (i + 1) ; k++)
				fprintf(fp, "%02x", k_saved[k]);
			fprintf(fp, "\n\n");
		}
	}

	for(int j = 0 ; j < len ; j++)
		output[result_index++] = k_saved[j];

	printf("final output: ");
	for(int i = 0 ; i < len ; i++)
		printf("%02x", output[i]);
	printf("\n");

	free(input);
	free(a_iv);
	free(a_temp);
	free(k_temp);
	free(k_saved);
}

void hmac_kdf_digest(int mode, BitSequence *Ki, int Ki_len, BitSequence *iv, int iv_len, BitSequence *label, int label_len, BitSequence *context, int context_len, unsigned int r, unsigned int len, unsigned int hash_len, FILE *fp, bool tv)
{
	BitSequence *k_output;
	double n;

	int byte_r = r / 8;
	int len_byte = len / 8;
	int hash_byte = hash_len / 8;

	n = ceil((double)len_byte / (double) hash_byte);

	k_output = (BitSequence*) malloc(sizeof(BitSequence) * len_byte);
	for(int i = 0 ; i < len_byte ; i++)
		k_output[i] = '\0';		// initializing k_output

	if(!tv)
		fprintf(fp, "n = %d\n\n", (int) n);

	if(mode == CTR_MODE)
		hmac_kdf_ctr_digest((int) n, byte_r, Ki, Ki_len, label, label_len, context, context_len, len_byte, hash_byte, k_output, fp, tv);
	else if(mode == FB_MODE)
		hmac_kdf_fb_digest((int) n, byte_r, Ki, Ki_len, iv, iv_len, label, label_len, context, context_len, len_byte, hash_byte, k_output, fp, tv);
	else if(mode == DP_MODE)
		hmac_kdf_dp_digest((int) n, byte_r, Ki, Ki_len, label, label_len, context, context_len, len_byte, hash_byte, k_output, fp, tv);
	else
		printf("unknown mode \n");

	fprintf(fp, "K0 = ");
	for(int i = 0 ; i < len_byte ; i++)
		fprintf(fp, "%02x", k_output[i]);
	fprintf(fp, "\n\n");

	free(k_output);
}
