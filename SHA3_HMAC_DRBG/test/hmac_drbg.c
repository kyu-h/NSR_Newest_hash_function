#include <string.h>
#include "hmac_drbg.h"

typedef unsigned char BitSequence;

void drbg_sha3_hmac_print(unsigned int digest_size, BitSequence *digest){
	for(int i = 0 ; i < digest_size ; i++)
		printf("%02x", digest[i]);

	printf("\n");
}

void drbg_ent_non_pers(struct DRBG_SHA3_HMAC_Context *ctx, BitSequence *input, BitSequence *V, int V_size, const BitSequence *entropy, int ent_size, const BitSequence *nonce, int non_size, const BitSequence *per_string, int per_size){
	int r, w;
	int input_size = 0;

	for(r=0, w=0; r<V_size; r++){
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
	}
}

void drbg_sha3_inner_output(struct DRBG_SHA3_HMAC_Context *ctx, BitSequence *V, BitSequence *Key, const BitSequence *add_input, int add_size, FILE *outf, int num){
	BitSequence output[64] = {'\0', };
	int count = 2;
	int k = 0;

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
		}fprintf(outf, "\n\n");
	}

	ctx->reseed_counter++;

	drbg_sha3_inner_reset(ctx, V, Key, add_input, add_size, outf);
}

void drbg_sha3_inner_reset(struct DRBG_SHA3_HMAC_Context *ctx, BitSequence *V, BitSequence *Key, const BitSequence *add_input, int add_size, FILE *outf){
	BitSequence input[1024] = {'\0', };
	int r, w;

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
			fprintf(outf, "*addInput = ");
			for(int i=0; i<add_size; i++)
				fprintf(outf, "%02x", add_input[i]);
			fprintf(outf, "\n\n");
		}
	}

	for(r=0, w=0; r<ctx->capacity / 16; r++){
			input[w++] = V[r];
	}

	input[w++] = 0x00;

	if(ctx->setting.usingaddinput){
		for(r = 0 ; r < add_size ; r++)
			input[w++] = add_input[r];
	}

	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, input, w, Key);
	//drbg_sha3_hmac_print(ctx->capacity / 16, Key);

	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, V, ctx->capacity / 16, V);
	//drbg_sha3_hmac_print(ctx->capacity / 16, V);

	for(int i=0; i<1024; i++){
		input[i] = '\0';
	}

	for(r=0, w=0; r<ctx->capacity / 16; r++){
			input[w++] = V[r];
	}

	input[w++] = 0x00;

	if(ctx->setting.usingaddinput){
		for(r = 0 ; r < add_size ; r++)
			input[w++] = add_input[r];
	}

	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, input, w, Key);
	//drbg_sha3_hmac_print(ctx->capacity / 16, Key);

	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, V, ctx->capacity / 16, V);
	//drbg_sha3_hmac_print(ctx->capacity / 16, V);

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
		drbg_sha3_inner_output(ctx, V, Key, add_input, add_size, outf, 1);
	}

}

void drbg_sha3_hmac_init(struct DRBG_SHA3_HMAC_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *nonce, int non_size, const BitSequence *per_string, int per_size, const BitSequence *add_input, int add_size, FILE *outf)
{
	BitSequence input[1024] = {'\0', };
	BitSequence V[64] = {'\0', };
	BitSequence Key[64] = {'\0', };
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

	//drbg_ent_non_pers(&ctx, input, V, ctx->capacity / 16, entropy, ent_size, nonce, non_size, per_string, per_size);

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
	}

	input_size = ent_size + non_size + per_size + ctx->capacity / 16 + 1;

	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, Key, ctx->capacity / 16, input, input_size, target_state_Key);
	//drbg_sha3_hmac_print(ctx->capacity / 16, target_state_Key);

	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, target_state_Key, ctx->capacity / 16, V, ctx->capacity / 16, target_state_V);
	//drbg_sha3_hmac_print(ctx->capacity / 16, target_state_V);

	for(int i=0; i<1024; i++){
		input[i] = '\0';
	}

	//drbg_ent_non_pers(&ctx, input, target_state_V, ctx->capacity / 16, entropy, ent_size, nonce, non_size, per_string, per_size);

	for(r=0, w=0; r<ctx->capacity / 16; r++){
		input[w++] = V[r];
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

	drbg_sha3_inner_reset(ctx, target_state_V, target_state_Key, add_input, add_size, outf);
}

void drbg_sha3_hmac_output_reset(struct DRBG_SHA3_HMAC_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *add_input, int add_size, int cycle, FILE *outf){
	BitSequence input[1024] = {'\0', };
	BitSequence *target_state_V;
	BitSequence *target_state_Key;
	int STATE_MAX_SIZE;
	int r, w;

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
		fprintf(outf, "addInput = ");
		for(int i=0; i < add_size; i++)
			fprintf(outf, "%02x", add_input[i]);
		fprintf(outf, "\n\n");
		fprintf(outf, "entropy = ");
		for(int i=0; i < ent_size; i++)
			fprintf(outf, "%02x", entropy[i]);
		fprintf(outf, "\n");
	}

	for(r=0, w=0; r<ctx->capacity / 16; r++){
		input[w++] = target_state_V[r];
	}

	input[w++] = 0x00;

	for(r=0; r<ent_size; r++){
		input[w++] = entropy[r];
	}

	if(ctx->setting.usingaddinput){
		for(r = 0 ; r < add_size ; r++)
			input[w++] = add_input[r];
	}

	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, input, w, target_state_Key, ctx->capacity / 16, target_state_Key);
	//drbg_sha3_hmac_print(ctx->capacity / 16, target_state_Key);

	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, target_state_V, ctx->capacity / 16, target_state_Key, ctx->capacity / 16, target_state_V);
	//drbg_sha3_hmac_print(ctx->capacity / 16, target_state_V);

	for(int i=0; i<1024; i++){
		input[i] = '\0';
	}

	for(r=0, w=0; r<ctx->capacity / 16; r++){
		input[w++] = target_state_V[r];
	}

	input[w++] = 0x00;

	for(r=0; r<ent_size; r++){
		input[w++] = entropy[r];
	}

	if(ctx->setting.usingaddinput){
		for(r = 0 ; r < add_size ; r++)
			input[w++] = add_input[r];
	}

	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, input, w, target_state_Key, ctx->capacity / 16, target_state_Key);
	//drbg_sha3_hmac_print(ctx->capacity / 16, target_state_Key);

	hmac_digest(ctx->capacity / 2, ctx->setting.drbgtype, ctx->capacity, target_state_V, ctx->capacity / 16, target_state_Key, ctx->capacity / 16, target_state_V);
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

	drbg_sha3_inner_output(ctx, target_state_V, target_state_Key, add_input, add_size, outf, 2);
}

void drbg_sha3_hmac_digest(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, BitSequence (*entropy)[65], int ent_size, BitSequence *nonce, int non_size, BitSequence *per_string, int per_size, BitSequence (*add_input)[65], int add_size, int output_bits, int cycle, BitSequence *drbg, FILE *outf)
{
	struct DRBG_SHA3_HMAC_Context ctx;
	ctx.setting.drbgtype = rate;
	ctx.capacity = capacity;
	ctx.delimitedSuffix = delimitedSuffix;

	ctx.setting.refreshperiod = cycle;

	ctx.setting.predicttolerance = false;   //예측내성
	ctx.setting.usingperstring = true;      //개별화
	ctx.setting.usingaddinput = true;      //추가입력

	drbg_sha3_hmac_init(&ctx, entropy[0], ent_size, nonce, non_size, per_string, per_size, add_input[0], add_size, outf);

	for(int i = 0 ; i < ctx.setting.refreshperiod; i++){
		if(ctx.setting.predicttolerance || ctx.setting.refreshperiod == 0){
			drbg_sha3_hmac_output_reset(&ctx, entropy[i+1], ent_size, add_input[i], add_size, cycle, outf);
		}else {
			drbg_sha3_hmac_output_reset(&ctx, entropy[i+1], ent_size, add_input[i+1], add_size, cycle, outf);
		}
	}
}
