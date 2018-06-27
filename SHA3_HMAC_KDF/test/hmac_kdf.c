#include "hmac_kdf.h"

#include <string.h>

typedef unsigned char BitSequence;

void kdf_sha3_hmac_dp(const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *Kl, unsigned int Kl_len, BitSequence *Label, const unsigned int Label_len, BitSequence *Context, unsigned int Context_len, unsigned int L_len, unsigned int h_len, const unsigned int r, FILE *outf){
	unsigned int n = 0;
	BitSequence output[128];
	int w = 0;
	int num = 0;
	int L_len_to_Hex = L_len;
	int output_len = 0;
	int input_data_len = Label_len + Context_len + 4;
	BitSequence input_data[128] = {'\0', };
	BitSequence a_input_data[128] = {'\0', };
	int a_num = 0;

	n = ceil(L_len/h_len);

	if(n > (pow(2, r) - 1)){
		printf("error !\n");
	}

	w = 1;
	if(Kl_len){
		w += Kl_len;
	}

	for(int j=0; j<Label_len; j++){
		a_input_data[a_num++] = Label[j];
		input_data[w++] = Label[j];
	}
	a_input_data[a_num++] = 0x00;
	input_data[w++] = 0x00;

	for(int j=0; j<Context_len; j++){
		a_input_data[a_num++] = Context[j];
		input_data[w++] = Context[j];
	}

	input_data[w++] = L_len_to_Hex/256;
	input_data[w] = L_len_to_Hex % 256;

	a_input_data[a_num++] = L_len_to_Hex/256;
	a_input_data[a_num] = L_len_to_Hex % 256;

	for(int i=0; i<w; i++){
		printf("%02x", input_data[i]);
	}printf("\n");

	for(int i=0; i<n; i++){

		if(i){
			hmac_digest(capacity / 2, rate, capacity, Kl, Kl_len, a_input_data, a_num, a_input_data);
		}else {
			hmac_digest(capacity / 2, rate, capacity, Kl, Kl_len, a_input_data, a_num, a_input_data);

			a_num = r/8; // have to fix
		}

		w = 0;

		for(int j=0; j< r/8; j++){
			input_data[w++] = a_input_data[j];
		}

		if(Kl_len){
			for(int j=0; j< r/8; j++){
				input_data[w] = i + 1;
			}
		}

		hmac_digest(capacity / 2, rate, capacity, Kl, Kl_len, input_data, input_data_len, Kl);

		for(int j=0; j<capacity / 16; j++){
			output[output_len++] = Kl[j];
		}
	}
	for(int i=0; i<capacity / 8; i++){
		printf("%02x", output[i]);
	}printf("\n");

}

void kdf_sha3_hmac_fb(const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *Kl, unsigned int Kl_len, BitSequence *Label, const unsigned int Label_len, BitSequence *Context, unsigned int Context_len, unsigned int L_len, unsigned int h_len, const unsigned int r, FILE *outf){
	unsigned int n = 0;
	BitSequence output[128];
	int w = 0;
	int num = 0;
	int L_len_to_Hex = L_len;
	int output_len = 0;
	int input_data_len = Label_len + Context_len + 4;
	BitSequence input_data[128] = {'\0', };

	n = ceil(L_len/h_len);

	if(n > (pow(2, r) - 1)){
		printf("error !\n");
	}

	w = 1;
	if(Kl_len){
		w += Kl_len;
	}

	for(int j=0; j<Label_len; j++){
		input_data[w++] = Label[j];
	}
	input_data[w++] = 0x00;

	for(int j=0; j<Context_len; j++){
		input_data[w++] = Context[j];
	}

	input_data[w++] = L_len_to_Hex/256;
	input_data[w] = L_len_to_Hex % 256;

	for(int i=0; i<w; i++){
		printf("%02x", input_data[i]);
	}printf("\n");

	for(int i=0; i<n; i++){
		w = 0;

		for(int j=0; j<Kl_len; j++){
			input_data[w++] = Kl[j];
		}

		if(Kl_len){
			for(int j=0; j< r/8; j++){
				input_data[w] = i + 1;
			}
		}

		for(int j=0; j<input_data_len; j++){
			printf("%02x", input_data[j]);
		}printf("\n");

		hmac_digest(capacity / 2, rate, capacity, Kl, Kl_len, input_data, input_data_len, Kl);
		for(int i=0; i<capacity / 16; i++){
			printf("%02x", Kl[i]);
		}printf("\n");

		for(int j=0; j<capacity / 16; j++){
			output[output_len++] = Kl[j];
		}
	}
	for(int i=0; i<capacity / 8; i++){
		printf("%02x", output[i]);
	}printf("\n");
}

void kdf_sha3_hmac_ctr(const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *Kl, unsigned int Kl_len, BitSequence *Label, const unsigned int Label_len, BitSequence *Context, unsigned int Context_len, unsigned int L_len, unsigned int h_len, const unsigned int r, FILE *outf){
	unsigned int n = 0;
	BitSequence output[128];
	int w = 0;
	int num = 0;
	int L_len_to_Hex = L_len;
	int output_len = 0;
	int input_data_len = Label_len + Context_len + 4;
	BitSequence input_data[128] = {'\0', };
	BitSequence tmp_input_data[128] = {'\0', };

	n = ceil(L_len/h_len);

	if(n > (pow(2, r) - 1)){
		printf("error !\n");
	}

	for(int j=0; j<Label_len; j++){
		input_data[w++] = Label[j];
	}
	input_data[w++] = 0x00;

	for(int j=0; j<Context_len; j++){
		input_data[w++] = Context[j];
	}

	input_data[w++] = L_len_to_Hex/256;
	input_data[w] = L_len_to_Hex % 256;

	for(int i=0; i<w; i++){
		printf("%02x", input_data[i]);
	}printf("\n");

	for(int i=0; i<n; i++){
		if(Kl_len){
			for(num=0; num< r/8; num++){
				tmp_input_data[num] = i + 1;
				printf("%02x", tmp_input_data[num]);
			}
			printf("\n");

			for(int j=0; j<w; j++){
				tmp_input_data[num++] = input_data[j];
			}
		}

		for(int j=0; j<input_data_len; j++){
			printf("%02x", tmp_input_data[j]);
		}printf("\n");

		hmac_digest(capacity / 2, rate, capacity, Kl, Kl_len, input_data, input_data_len, Kl);
		for(int i=0; i<capacity / 16; i++){
			printf("%02x", Kl[i]);
		}printf("\n");

		for(int j=0; j<capacity / 16; j++){
			output[output_len++] = Kl[j];
		}
	}
	for(int i=0; i<capacity / 8; i++){
		printf("%02x", output[i]);
	}printf("\n");
}

void kdf_sha3_hmac(const unsigned int alg_type, const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *Kl, unsigned int Kl_len, BitSequence *Label, const unsigned int Label_len, BitSequence *Context, unsigned int Context_len, unsigned int L_len, unsigned int h_len, const unsigned int r, FILE *outf){

	if(alg_type == 1){
		kdf_sha3_hmac_ctr(rate, capacity, delimitedSuffix, Kl, Kl_len, Label, Label_len, Context, Context_len, L_len, h_len, r, outf);
	}else if(alg_type == 2){
		kdf_sha3_hmac_fb(rate, capacity, delimitedSuffix, Kl, Kl_len, Label, Label_len, Context, Context_len, L_len, h_len, r, outf);
	}else {
		kdf_sha3_hmac_dp(rate, capacity, delimitedSuffix, Kl, Kl_len, Label, Label_len, Context, Context_len, L_len, h_len, r, outf);
	}
}
