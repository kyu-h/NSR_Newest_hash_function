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
		if(i == 1){
			salt_inti[w] = 0x01;
		}else if(i == 2){
			salt_inti[w] = 0x02;
		}else if(i == 3){
			salt_inti[w] = 0x03;
		}else if(i == 3){
			salt_inti[w] = 0x03;
		}else if(i == 4){
			salt_inti[w] = 0x04;
		}else if(i == 5){
			salt_inti[w] = 0x05;
		}else if(i == 6){
			salt_inti[w] = 0x06;
		}else if(i == 7){
			salt_inti[w] = 0x07;
		}else if(i == 8){
			salt_inti[w] = 0x08;
		}else if(i == 9){
			salt_inti[w] = 0x09;
		}else if(i == 10){
			salt_inti[w] = 0x10;
		}else {
			printf("i is over 10\n");
		}

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

			for(int k=0; k<capacity / 16; k++){
				T[k] = T[k] ^ U[k];
			}
		}
		w = 0;
		if(j == IterationCount+1){
			/*for(int k=0; k<capacity / 16; k++){
				printf("%02x", T[k]);
			}printf("\n");*/

			for(int b =0; b<capacity / 16; b++){
				MK[num++] = T[b];
			}//printf("\n");
		}
	}
	fprintf(outf, "MK = ");
	for(int m=0; m<num; m++){
		fprintf(outf, "%02x", MK[m]);
	}fprintf(outf, "\n\n");

	for(int i=0; i<(capacity / 16) * 8; i++){
		MK[i] = '\0';
	}
}
