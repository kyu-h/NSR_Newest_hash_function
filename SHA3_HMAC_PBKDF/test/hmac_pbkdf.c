#include "hmac_pbkdf.h"

#include <string.h>

typedef unsigned char BitSequence;

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
				hmac_digest(capacity / 2, rate, capacity, password, pass_len, salt_inti, salt_leng + 4, U);
				drbg_sha3_hmac_print(capacity / 16, U);
			}else {
				hmac_digest(capacity / 2, rate, capacity, password, pass_len, U, capacity / 16, U);
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
			hmac_digest(capacity / 2, rate, capacity, password, pass_size, U, size_u, U);

			for(int z=0; z<size_u; z++){
				printf("%02x", U[z]);
			}printf("\n");
		}else{
			hmac_digest(capacity / 2, rate, capacity, password, pass_size, U, hash_len, U);
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

		for(int z=0; z<w+1; z++){
			printf("%02x", U[z]);
		}printf("\n");

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
				hmac_digest(capacity / 2, rate, capacity, password, pass_len, salt_inti, salt_leng + 4, U);
				//drbg_sha3_hmac_print(capacity / 16, U);
			}else {
				hmac_digest(capacity / 2, rate, capacity, password, pass_len, U, capacity / 16, U);
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
