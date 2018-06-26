#include <string.h>
#include "hmac_drbg.h"

typedef unsigned char BitSequence;

void drbg_sha3_hmac_print(unsigned int digest_size, BitSequence *digest){
	for(int i = 0 ; i < digest_size ; i++)
		printf("%02x", digest[i]);

	printf("\n");
}

void drbg_sha3_inner_output(struct DRBG_SHA3_HMAC_Context *ctx, BitSequence *V, BitSequence *Key, const BitSequence *entropy, int ent_size, const BitSequence *add_input, int add_size, FILE *outf, int num) {
	BitSequence output[256] = {'\0', };
	BitSequence input[1024] = {'\0', };
	int count = 2;
	int k = 0;
	int r, w;

	for(int i=0; i<count; i++){
		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, V, ctx->capacity / 16, V);

		for(int w=0; w<ctx->capacity / 16; w++){
			output[k++] = V[w];
		}
	}

	{		//***** TEXT OUTPUT - output1 *****//
		fprintf(outf, "output%d = ", num);
		for(int i=0; i<k; i++){
			fprintf(outf, "%02x", output[i]);
			printf("%02x", output[i]);
		}fprintf(outf, "\n\n");
	}printf("\n");

	ctx->reseed_counter++;

	//printf("UPDATE FUNCTION FIRST CALLED AFTER OUTPUT GEN \n");
	for(r=0, w=0; r<ctx->capacity / 16; r++){
			input[w++] = V[r];
	}

	input[w++] = 0x00;

	if(!ctx->setting.is_addinput_null){
		if(ctx->setting.usingaddinput){
			for(r = 0 ; r < add_size ; r++)
				input[w++] = add_input[r];
		}
	}

	/*printf("OUPUT UPDATE FIRST INPUT SIZE: %d: \n", w);
	for(int i = 0 ; i < w ; i++)
		printf("%02x", input[i]);
	printf("\n");

	printf("update input data1\n");*/
	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, input, w, Key);
	//drbg_sha3_hmac_print(ctx->capacity / 16, Key);

	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, V, ctx->capacity / 16, V);
	//drbg_sha3_hmac_print(ctx->capacity / 16, V);


	if(!ctx->setting.is_addinput_null) {
		//printf("UPDATE FUNCTION SECOND CALLED AFTER OUTPUT GEN \n");
		for(int i=0; i<1024; i++){
			input[i] = '\0';
		}

		for(r=0, w=0; r<ctx->capacity / 16; r++){
			input[w++] = V[r];
		}

		input[w++] = 0x01;

		if(ctx->setting.usingaddinput){
			for(r = 0 ; r < add_size ; r++)
				input[w++] = add_input[r];
		}

		/*printf("OUPUT UPDATE SECOND INPUT: ");
		for(int i = 0 ; i < w ; i++)
			printf("%02x", input[i]);
		printf("\n");*/

		//printf("update input data2\n");
		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, input, w, Key);
		//drbg_sha3_hmac_print(ctx->capacity / 16, Key);

		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, V, ctx->capacity / 16, V);
		//drbg_sha3_hmac_print(ctx->capacity / 16, V);
	}

	{		//***** TEXT OUTPUT - *K, *V *****//
		fprintf(outf, "*K = ");
		for(int i = 0 ; i < ctx->capacity / 16; i++)
			fprintf(outf, "%02x", Key[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*V = ");
		for(int i = 0 ; i < ctx->capacity / 16; i++)
			fprintf(outf, "%02x", V[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*reseed_counter = %d", ctx->reseed_counter);
		fprintf(outf, "\n\n");
	}
}

void drbg_sha3_inner_reset(struct DRBG_SHA3_HMAC_Context *ctx, BitSequence *V, BitSequence *Key, const BitSequence *entropy, int ent_size, const BitSequence *add_input, int add_size, FILE *outf) {
	BitSequence input[1024] = {'\0', };
	int r, w;

	if(!ctx->setting.usingaddinput)
		ctx->setting.is_addinput_null = true;
	else if(add_size)
		ctx->setting.is_addinput_null = false;

	if(ctx->reseed_counter == 1){
		{		//***** TEXT OUTPUT - *K, *V *****//
			fprintf(outf, "*K = ");
			for(int i = 0 ; i < ctx->capacity / 16; i++)
				fprintf(outf, "%02x", Key[i]);
			fprintf(outf, "\n");
			fprintf(outf, "*V = ");
			for(int i = 0 ; i < ctx->capacity / 16; i++)
				fprintf(outf, "%02x", V[i]);
			fprintf(outf, "\n");
			fprintf(outf, "*reseed_counter = %d", ctx->reseed_counter);
			fprintf(outf, "\n");
			if(ctx->setting.usingaddinput){
				fprintf(outf, "addInput = ");
				for(int i=0; i < add_size; i++)
					fprintf(outf, "%02x", add_input[i]);
				fprintf(outf, "\n\n");
			}else
				fprintf(outf, "\n");
		}
	}

	for(r=0, w=0; r<ctx->capacity / 16; r++){
		input[w++] = V[r];
	}
	input[w++] = 0x00;

	if(ctx->reseed_counter > ctx->setting.refreshperiod || ctx->setting.predicttolerance){//RESEED FUNCTION
		//printf("RESEED FUNCTION CALLED \n");
		for(r = 0 ; r < ent_size ; r++)
			input[w++] = entropy[r];

		if(ctx->setting.usingaddinput){
			for(r = 0 ; r < add_size ; r++)
				input[w++] = add_input[r];
		}

		/*printf("update input data1 size: %d\n", w);
		printf("INITIAL RESEED FIRST INPUT: ");
		for(int i = 0 ; i < w ; i++)
			printf("%02x", input[i]);
		printf("\n");*/

		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, input, w, Key);
		//drbg_sha3_hmac_print(ctx->capacity / 16, Key);

		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, V, ctx->capacity / 16, V);
		//drbg_sha3_hmac_print(ctx->capacity / 16, V);

		for(r=0, w=0; r<ctx->capacity / 16; r++){
			input[w++] = V[r];
		}
		input[w++] = 0x01;
		for(r = 0 ; r < ent_size ; r++)
			input[w++] = entropy[r];

		if(ctx->setting.usingaddinput){
			for(r = 0 ; r < add_size ; r++)
				input[w++] = add_input[r];
		}

		/*printf("update input data2 size: %d\n", w);
		printf("INITIAL RESEED SECOND INPUT: ");
		for(int i = 0 ; i < w ; i++)
			printf("%02x", input[i]);
		printf("\n");*/

		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, input, w, Key);
		//drbg_sha3_hmac_print(ctx->capacity / 16, Key);

		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, V, ctx->capacity / 16, V);

		//drbg_sha3_hmac_print(ctx->capacity / 16, V);

		ctx->reseed_counter = 1;
		ctx->setting.is_addinput_null = true;
	}else if(!ctx->setting.is_addinput_null) {
		//printf("UPDATE FUNCTION CALLED AT INIT \n");
		if(ctx->setting.usingaddinput){
			for(r = 0 ; r < add_size ; r++)
				input[w++] = add_input[r];
		}

		/*printf("INITIAL UPDATE FIRST INPUT: ");
		for(int i = 0 ; i < w ; i++)
			printf("%02x", input[i]);
		printf("\n");*/

		//printf("update input data1\n");
		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, input, w, Key);
		//drbg_sha3_hmac_print(ctx->capacity / 16, Key);

		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, V, ctx->capacity / 16, V);
		//drbg_sha3_hmac_print(ctx->capacity / 16, V);


		if(!ctx->setting.is_addinput_null) {
			for(int i=0; i<1024; i++){
				input[i] = '\0';
			}

			for(r=0, w=0; r<ctx->capacity / 16; r++){
					input[w++] = V[r];
			}

			input[w++] = 0x01;

			if(ctx->setting.usingaddinput){
				for(r = 0 ; r < add_size ; r++)
					input[w++] = add_input[r];
			}

			/*printf("INITIAL UPDATE SECOND INPUT: ");
			for(int i = 0 ; i < w ; i++)
				printf("%02x", input[i]);
			printf("\n");*/

			//printf("update input data2\n");
			hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, input, w, Key);
			//drbg_sha3_hmac_print(ctx->capacity / 16, Key);

			hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, V, ctx->capacity / 16, V);
			//drbg_sha3_hmac_print(ctx->capacity / 16, V);
		}
	}

	{		//***** TEXT OUTPUT - *K, *V *****//
		fprintf(outf, "*K = ");
		for(int i = 0 ; i < ctx->capacity / 16; i++)
			fprintf(outf, "%02x", Key[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*V = ");
		for(int i = 0 ; i < ctx->capacity / 16; i++)
			fprintf(outf, "%02x", V[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*reseed_counter = %d", ctx->reseed_counter);
		fprintf(outf, "\n\n");
	}

	if(ctx->reseed_counter < 2){
		drbg_sha3_inner_output(ctx, V, Key, entropy, ent_size, add_input, add_size, outf, 1);
	}

}

void drbg_sha3_hmac_init(struct DRBG_SHA3_HMAC_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *nonce, int non_size, const BitSequence *per_string, int per_size, const BitSequence *add_input, int add_size, FILE *outf)
{
	BitSequence input[1024] = {'\0', };
	BitSequence V[128] = {'\0', };
	BitSequence Key[128] = {'\0', };
	BitSequence *target_state_V;
	BitSequence *target_state_Key;

	int STATE_MAX_SIZE;
	int input_size = 0;
	int r, w =0;

	if(ctx->setting.drbgtype == 1152|| ctx->setting.drbgtype == 1088){
		target_state_V = ctx->working_state_V256;
		target_state_Key = ctx->working_state_C256;
		STATE_MAX_SIZE = STATE_MAX_SIZE_256;
	}else if(ctx->setting.drbgtype == 832 || ctx->setting.drbgtype == 576){
		target_state_V = ctx->working_state_V512;
		target_state_Key = ctx->working_state_C512;
		STATE_MAX_SIZE = STATE_MAX_SIZE_512;
	}

	for(int i=0; i<ctx->capacity / 16; i++){
		V[i] = 0x01;
		Key[i] = 0x00;
	}

	{		//***** TEXT OUTPUT - K, V *****//
		fprintf(outf, "K = ");
		for(int i = 0 ; i < ctx->capacity / 16; i++)
			fprintf(outf, "%02x", Key[i]);
		fprintf(outf, "\n");
		fprintf(outf, "V = ");
		for(int i = 0 ; i < ctx->capacity / 16; i++)
			fprintf(outf, "%02x", V[i]);
		fprintf(outf, "\n\n");
	}

	for(r=0, w=0; r<ctx->capacity / 16; r++){
		input[w++] = V[r];
	}

	input[w++] = 0x00;

	for(r = 0; r < ent_size ; r++){
		input[w++] = entropy[r];
	}

	for(r = 0 ; r < non_size ; r++){
		input[w++] = nonce[r];
	}

	if(ctx->setting.usingperstring){
		for(r = 0 ; r < per_size ; r++){
			input[w++] = per_string[r];
		}
		input_size += per_size;
	}

	input_size += (ent_size + non_size + ctx->capacity / 16 + 1);

	/*printf("INITIAL INPUT: " );
	for(int i = 0 ; i < input_size ; i++)
		printf("%02x", input[i]);
	printf("\n");

	printf("update input data1\n");*/
	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, input, input_size, target_state_Key);
	//drbg_sha3_hmac_print(ctx->capacity / 16, target_state_Key);
	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, target_state_Key, ctx->capacity / 16, V, ctx->capacity / 16, target_state_V);
	//drbg_sha3_hmac_print(ctx->capacity / 16, target_state_V);

	for(int i=0; i<1024; i++){
		input[i] = '\0';
	}

	for(r=0, w=0; r<ctx->capacity / 16; r++){
		input[w++] = target_state_V[r];
	}

	input[w++] = 0x01;

	for(r = 0; r < ent_size ; r++){
		input[w++] = entropy[r];
	}

	for(r = 0 ; r < non_size ; r++){
		input[w++] = nonce[r];
	}

	if(ctx->setting.usingperstring){
		for(r = 0 ; r < per_size ; r++){
			input[w++] = per_string[r];
		}
	}

	/*printf("update input data2\n");
	printf("INITIAL INPUT: " );
	for(int i = 0 ; i < w ; i++)
		printf("%02x", input[i]);
	printf("\n");*/

	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, target_state_Key, ctx->capacity / 16, input, input_size, target_state_Key);
	//drbg_sha3_hmac_print(ctx->capacity / 16, target_state_Key);
	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, target_state_Key, ctx->capacity / 16, target_state_V, ctx->capacity / 16, target_state_V);
	//drbg_sha3_hmac_print(ctx->capacity / 16, target_state_V);

	ctx->reseed_counter = 1;

	{		//***** TEXT OUTPUT - *K, *V *****//
		fprintf(outf, "*K = ");
		for(int i = 0 ; i < ctx->capacity / 16; i++)
			fprintf(outf, "%02x", target_state_Key[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*V = ");
		for(int i = 0 ; i < ctx->capacity / 16; i++)
			fprintf(outf, "%02x", target_state_V[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*reseed_counter = %d", ctx->reseed_counter);
		fprintf(outf, "\n\n");
	}

	drbg_sha3_inner_reset(ctx, target_state_V, target_state_Key, entropy + 65, ent_size, add_input, add_size, outf);
}

void drbg_sha3_hmac_output_reset(struct DRBG_SHA3_HMAC_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *add_input, int add_size, int cycle, FILE *outf){
	BitSequence input[1024] = {'\0', };
	BitSequence *target_state_V;
	BitSequence *target_state_Key;
	int STATE_MAX_SIZE;
	int r, w;

	if(!ctx->setting.usingaddinput)
		ctx->setting.is_addinput_null = true;
	else if(add_size)
		ctx->setting.is_addinput_null = false;

	if(ctx->setting.drbgtype == 1152|| ctx->setting.drbgtype == 1088){
		target_state_V = ctx->working_state_V256;
		target_state_Key = ctx->working_state_C256;
		STATE_MAX_SIZE = STATE_MAX_SIZE_256;
	}else if(ctx->setting.drbgtype == 832 || ctx->setting.drbgtype == 576){
		target_state_V = ctx->working_state_V512;
		target_state_Key = ctx->working_state_C512;
		STATE_MAX_SIZE = STATE_MAX_SIZE_512;
	}

	{		//***** TEXT OUTPUT - *K, *V *****//
		fprintf(outf, "*K = ");
		for(int i = 0 ; i < ctx->capacity / 16; i++)
			fprintf(outf, "%02x", target_state_Key[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*V = ");
		for(int i = 0 ; i < ctx->capacity / 16; i++)
			fprintf(outf, "%02x", target_state_V[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*reseed_counter = %d", ctx->reseed_counter);
		fprintf(outf, "\n");
		if(ctx->setting.usingaddinput){
			fprintf(outf, "addInput = ");
			for(int i=0; i < add_size; i++)
				fprintf(outf, "%02x", add_input[i]);
			fprintf(outf, "\n\n");
		}else
			fprintf(outf, "\n");
		fprintf(outf, "entropy = ");
		for(int i=0; i < ent_size; i++)
			fprintf(outf, "%02x", entropy[i]);
		fprintf(outf, "\n");
	}

	for(r=0, w=0; r<ctx->capacity / 16; r++){
		input[w++] = target_state_V[r];
	}
	input[w++] = 0x00;

	if(ctx->reseed_counter > ctx->setting.refreshperiod || ctx->setting.predicttolerance)
	{		//RESEED FUNCTION
		//printf("RESEED FUNCTION CALLED AT AFTER OUTPUT\n");
		for(r = 0 ; r < ent_size ; r++)
			input[w++] = entropy[r];

		if(ctx->setting.usingaddinput){
			for(r = 0 ; r < add_size ; r++)
				input[w++] = add_input[r];
		}

		/*printf("update input data1\n");
		printf("RESEED FIRST INPUT: ");
		for(int i = 0 ; i < w ; i++)
			printf("%02x", input[i]);
		printf("\n");*/

		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, target_state_Key, ctx->capacity / 16, input, w, target_state_Key);
		//drbg_sha3_hmac_print(ctx->capacity / 16, Key);

		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, target_state_Key, ctx->capacity / 16, target_state_V, ctx->capacity / 16, target_state_V);
		//drbg_sha3_hmac_print(ctx->capacity / 16, V);

		for(r=0, w=0; r<ctx->capacity / 16; r++){
			input[w++] = target_state_V[r];
		}
		input[w++] = 0x01;
		for(r = 0 ; r < ent_size ; r++)
			input[w++] = entropy[r];

		if(ctx->setting.usingaddinput){
			for(r = 0 ; r < add_size ; r++)
				input[w++] = add_input[r];
		}

		/*printf("RESEED SECOND INPUT: ");
		for(int i = 0 ; i < w ; i++)
			printf("%02x", input[i]);
		printf("\n");*/

		//printf("update input data2\n");
		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, target_state_Key, ctx->capacity / 16, input, w, target_state_Key);
		//drbg_sha3_hmac_print(ctx->capacity / 16, Key);

		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, target_state_Key, ctx->capacity / 16, target_state_V, ctx->capacity / 16, target_state_V);
		//drbg_sha3_hmac_print(ctx->capacity / 16, V);

		ctx->reseed_counter = 1;
		ctx->setting.is_addinput_null = true;
	}
	else if(!ctx->setting.is_addinput_null) {
		//printf("UPDATE FUNCTION CALLED AT AFTER OUTPUT\n");
		if(ctx->setting.usingaddinput){
			for(r = 0 ; r < add_size ; r++)
				input[w++] = add_input[r];
		}

		/*printf("UPDATE FIRST INPUT: ");
		for(int i = 0 ; i < w ; i++)
			printf("%02x", input[i]);
		printf("\n");*/

		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, target_state_Key, ctx->capacity / 16, input, w, target_state_Key);
		//drbg_sha3_hmac_print(ctx->capacity / 16, Key);

		hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, target_state_Key, ctx->capacity / 16, target_state_V, ctx->capacity / 16, target_state_V);
		//drbg_sha3_hmac_print(ctx->capacity / 16, V);

		if(!ctx->setting.is_addinput_null) {
			for(int i=0; i<1024; i++){
				input[i] = '\0';
			}

			for(r=0, w=0; r<ctx->capacity / 16; r++){
					input[w++] = target_state_V[r];
			}

			input[w++] = 0x01;

			if(ctx->setting.usingaddinput){
				for(r = 0 ; r < add_size ; r++)
					input[w++] = add_input[r];
			}

			/*printf("UPDATE SECOND INPUT: ");
			for(int i = 0 ; i < w ; i++)
				printf("%02x", input[i]);
			printf("\n");*/

			hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, target_state_Key, ctx->capacity / 16, input, w, target_state_Key);
			//drbg_sha3_hmac_print(ctx->capacity / 16, Key);

			hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, target_state_Key, ctx->capacity / 16, target_state_V, ctx->capacity / 16, target_state_V);
			//drbg_sha3_hmac_print(ctx->capacity / 16, V);
		}
	}

	{		//***** TEXT OUTPUT - *K, *V *****//
		fprintf(outf, "*K = ");
		for(int i = 0 ; i < ctx->capacity / 16; i++)
			fprintf(outf, "%02x", target_state_Key[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*V = ");
		for(int i = 0 ; i < ctx->capacity / 16; i++)
			fprintf(outf, "%02x", target_state_V[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*reseed_counter = %d", ctx->reseed_counter);
		fprintf(outf, "\n\n");
	}

	drbg_sha3_inner_output(ctx, target_state_V, target_state_Key, entropy, ent_size, add_input, add_size, outf, 2);
}


void print_32bit(unsigned int val, BitSequence *arr){
	int i, val2;
	BitSequence change[32]; //int가 32비트이므로
	if (val >= 0) { //양수 입력시
		for (i = 0; i < 32; i++) {
			val2 = val % 2; //10진->2진 변환 공식
			val = val / 2;
			change[i] = val2;
			arr[31 - i] = change[i]; //값이 반대로 입력 됐으므로 값 뒤집기
		}
	}
}

void pbkdf_sha3_hmac(const unsigned int rate, const unsigned int capacity, const unsigned char delimitedSuffix, BitSequence *password, unsigned int pass_len, BitSequence *salt, const unsigned int salt_leng, unsigned int IterationCount, unsigned int Klen, unsigned int loopCount, FILE *outf){
	struct DRBG_SHA3_HMAC_Context ctx;

	unsigned int hlen, length = 0;
	int r, c;
	int num = 0;
	int j = 0;
	int w= 0;
	BitSequence T[capacity / 16]; //고쳐야함
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
	printf("%d \n", Klen);
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




void drbg_sha3_hmac_digest(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, BitSequence (*entropy)[65], int ent_size, BitSequence *nonce, int non_size, BitSequence *per_string, int per_size, BitSequence (*add_input)[65], int add_size, int output_bits, int cycle, BitSequence *drbg, FILE *outf)
{
	struct DRBG_SHA3_HMAC_Context ctx;
	ctx.setting.drbgtype = rate;
	ctx.capacity = capacity;
	ctx.delimitedSuffix = delimitedSuffix;

	ctx.setting.refreshperiod = 1;

	ctx.setting.predicttolerance = false;   //예측내성
	ctx.setting.usingperstring = true;      //개별화
	ctx.setting.usingaddinput = false;      //추가입력

	drbg_sha3_hmac_init(&ctx, entropy[0], ent_size, nonce, non_size, per_string, per_size, add_input[0], add_size, outf);

	for(int i = 0 ; i < ctx.setting.refreshperiod; i++){
		if(ctx.setting.predicttolerance || ctx.setting.refreshperiod == 0){
			drbg_sha3_hmac_output_reset(&ctx, entropy[i+2], ent_size, add_input[i+1], add_size, cycle, outf);
			/*for(int k=0; k<ent_size; k++){
				printf("%02x", entropy[i+2][k]);
			}printf("\n");*/
		}else {
			drbg_sha3_hmac_output_reset(&ctx, entropy[i+1], ent_size, add_input[i+1], add_size, cycle, outf);
		}
	}
}
