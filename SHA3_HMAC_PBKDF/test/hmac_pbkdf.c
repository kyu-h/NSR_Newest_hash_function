#include "hmac_pbkdf.h"

#include <string.h>

typedef unsigned char BitSequence;

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
			salt_inti[w] = 0x10;
		}else if(i == 3){
			salt_inti[w] = 0x11;
		}

		fprintf(outf, "U0 = ");
		for(int b =0; b<salt_leng + 4; b++){
			fprintf(outf, "%02x", salt_inti[b]);
		}fprintf(outf, "\n\n");

		for(j=1; j<IterationCount+1; j++){
			if(j == 1){
				hmac_digest(capacity / 2, rate, capacity, password, pass_len, salt_inti, salt_leng + 4, U);
				//drbg_sha3_hmac_print(capacity / 16, U);
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
