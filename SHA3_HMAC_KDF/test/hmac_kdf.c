#include "hmac_kdf.h"

#include <string.h>

typedef unsigned char BitSequence;

void kdf_sha3_hmac_dp(const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *Kl, unsigned int Kl_len, BitSequence *Label, const unsigned int Label_len, BitSequence *Context, unsigned int Context_len, BitSequence *L, BitSequence *h, const unsigned int r, FILE *outf){
	unsigned int n = 0;
	BitSequence input_data[128];
	BitSequence inner_input_data[128];

	BitSequence result[128] = {'\0', }; //고쳐야함
	BitSequence A[128];
	BitSequence IV[128];
	int w,q = 0;
	int num = 0;
	int A_len = 0;

	n = ceil(L/h);

	if(n > (pow(2, 32) - 1)){
		printf("error !\n");
	}

	for(int j=0; j<Label_len; j++){
		A[w++] = Label[j];
		IV[q++] = Label[j];
	}
	A[w++] = 0x00;
	IV[q++] = 0x00;

	for(int j=0; j<Context_len; j++){
		A[w++] = Context[j];
		IV[q++] = Context[j];
	}

	for(int j=0; j<2; j++){
		A[w++] = L[j];
		IV[q++] = L[j];
	}

	A_len = w;
	w = 0;

	for(int i=1; i<n; i++){

		hmac_digest(capacity / 2, rate, capacity, Kl, Kl_len, A, A_len, A);

		inner_input_data[w++] = i;
		for(int j=0; j<A_len; j++){
			inner_input_data[w++] = input_data[j];
		}

		hmac_digest(capacity / 2, rate, capacity, Kl, Kl_len, inner_input_data, w, Kl);
		//drbg_sha3_hmac_print(capacity / 16, U);

		for(int i=0; i<strlen(L); i++){ //strlenL 고쳐야함
			 result[num++] = Kl[i];
		 }
	}
	 w=0;

}

void kdf_sha3_hmac_fb(const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *Kl, unsigned int Kl_len, BitSequence *Label, const unsigned int Label_len, BitSequence *Context, unsigned int Context_len, BitSequence *L, BitSequence *h, const unsigned int r, FILE *outf){
	unsigned int n = 0;
	BitSequence input_data[128];
	BitSequence result[128] = {'\0', }; //고쳐야함
	int w = 0;
	int num = 0;

	n = ceil(L/h);

	if(n > (pow(2, 32) - 1)){
		printf("error !\n");
	}

	for(int i=1; i<n; i++){
		input_data[w++] = i;

		for(int j=0; j<Label_len; j++){
			input_data[w++] = Label[j];
		}
		input_data[w++] = 0x00;

		for(int j=0; j<Context_len; j++){
			input_data[w++] = Context[j];
		}

		for(int j=0; j<2; j++){
			input_data[w++] = L[j];
		}
		hmac_digest(capacity / 2, rate, capacity, Kl, Kl_len, input_data, w, Kl);
		//drbg_sha3_hmac_print(capacity / 16, U);

		for(int i=0; i<strlen(L); i++){ //strlenL 고쳐야함
			 result[num++] = Kl[i];
		 }
	}
	 w=0;

}

void kdf_sha3_hmac_ctr(const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *Kl, unsigned int Kl_len, BitSequence *Label, const unsigned int Label_len, BitSequence *Context, unsigned int Context_len, BitSequence *L, BitSequence *h, const unsigned int r, FILE *outf){
	unsigned int n = 0;
	BitSequence input_data[128];
	BitSequence result[128] = {'\0', }; //고쳐야함
	int w = 0;
	int num = 0;

	n = ceil(L/h);

	if(n > (pow(2, r) - 1)){
		printf("error !\n");
	}

	for(int i=1; i<n; i++){
		input_data[w++] = i;

		for(int j=0; j<Label_len; j++){
			input_data[w++] = Label[j];
		}
		input_data[w++] = 0x00;

		for(int j=0; j<Context_len; j++){
			input_data[w++] = Context[j];
		}

		for(int j=0; j<2; j++){
			input_data[w++] = L[j];
		}
		hmac_digest(capacity / 2, rate, capacity, Kl, Kl_len, input_data, w, Kl);
		//drbg_sha3_hmac_print(capacity / 16, U);

		for(int i=0; i<strlen(L); i++){ //strlenL 고쳐야함
			 result[num++] = Kl[i];
		 }
	}
	 w=0;

}

void kdf_sha3_hmac(const unsigned int alg_type, const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *Kl, unsigned int Kl_len, BitSequence *Label, const unsigned int Label_len, BitSequence *Context, unsigned int Context_len, BitSequence *L, BitSequence *h, const unsigned int r, FILE *outf){

	if(alg_type == 1){
		kdf_sha3_hmac_ctr(rate, capacity, delimitedSuffix, Kl, Kl_len, Label, Label_len, Context, Context_len, L, h, r, outf);
	}else if(alg_type == 2){
		kdf_sha3_hmac_fb(rate, capacity, delimitedSuffix, Kl, Kl_len, Label, Label_len, Context, Context_len, L, h, r, outf);
	}else {
		kdf_sha3_hmac_dp(rate, capacity, delimitedSuffix, Kl, Kl_len, Label, Label_len, Context, Context_len, L, h, r, outf);
	}
}
