#include <string.h>
#include "drbg.h"

typedef unsigned char BitSequence;

void operation_add(unsigned char *arr, int ary_size, int start_index, unsigned int num)
{
	unsigned int current;
	unsigned int carry = 0;
	start_index++;

	current = arr[ary_size - start_index];
	current += num;
	carry = (current >> 8);
	arr[ary_size - start_index] = (unsigned char) current;

    while(carry)
    {
    	start_index++;
    	current = arr[ary_size - start_index];
		current += carry;
		carry = (current >> 8);
		arr[ary_size - start_index] = (unsigned char) current;
    }
}


void drbg_derivation_func(struct DRBG_SHA3_Context *ctx, const BitSequence *data, int data_size, BitSequence *output)
{
	unsigned int Block_Size;
	int Seed_Bit;
	int len_seed;

	BitSequence hash_data[512] = {'\0', };
	BitSequence hash_result[3][128];

	int r, w = 0;
	int flag = 0;
	int output_index;

	if(ctx->setting.drbgtype == 1152|| ctx->setting.drbgtype == 1088)
	{
		if(ctx->setting.drbgtype == 1152)
			Block_Size = 224;
		else
			Block_Size = 256;
		Seed_Bit = 440;
		hash_data[1] = 0x00;
		hash_data[2] = 0x00;
		hash_data[3] = 0x01;
		hash_data[4] = 0xB8;	// N = 440
		output_index = STATE_MAX_SIZE_256;
	}
	else if(ctx->setting.drbgtype == 832 || ctx->setting.drbgtype == 576)
	{
		if(ctx->setting.drbgtype == 832)
			Block_Size = 384;
		else
			Block_Size = 512;
		Seed_Bit = 888;
		hash_data[1] = 0x00;
		hash_data[2] = 0x00;
		hash_data[3] = 0x03;
		hash_data[4] = 0x78;	// N = 888
		output_index = STATE_MAX_SIZE_512;
	}
	len_seed = ceil((double)Seed_Bit / (double)Block_Size);

	for(int i = 0 ; i < len_seed ; i++)
	{
		hash_data[0] = i + 1;	// counter

		if(ctx->setting.drbgtype == 1152|| ctx->setting.drbgtype == 1088)
		{
			hash_data[1] = 0x00;
			hash_data[2] = 0x00;
			hash_data[3] = 0x01;
			hash_data[4] = 0xB8;
		}
		else if(ctx->setting.drbgtype == 832 || ctx->setting.drbgtype == 576)
		{
			hash_data[1] = 0x00;
			hash_data[2] = 0x00;
			hash_data[3] = 0x03;
			hash_data[4] = 0x78;
		}

		w = 5;
		for(r = 0; r < data_size ; r++)
			hash_data[w++] = data[r];

		Keccak(ctx->setting.drbgtype, ctx->capacity, hash_data, (5 + data_size), ctx->delimitedSuffix, hash_result[i], Block_Size / 8);

	}

	w = 0;
	for(int i = 0 ; i < output_index ; i++)
	{
		if(i == Block_Size / 8)
		{
			flag += 1;
			output_index -= Block_Size / 8;
			i = 0;
		}
		output[w++] = hash_result[flag][i];
	}
	for(int ii=0; ii<w; ii++){
		printf("%02x", output[ii]);
	}printf("\n");
}


void drbg_sha3_inner_output_gen(struct DRBG_SHA3_Context *ctx, BitSequence *input, BitSequence *output, int output_bits, FILE *outf)
{
	unsigned int Block_Byte;
	double n;
	int loop_count;
	BitSequence hash_data[112];
	BitSequence hash_result[3][1024];
	int w = 0;
	int flag = 0;
	int seed_bits;
	int output_index = output_bits / 8;

	int STATE_MAX_SIZE;

	if(ctx->setting.drbgtype == 1152|| ctx->setting.drbgtype == 1088)
	{
		if(ctx->setting.drbgtype == 1152)
			Block_Byte = 224;
		else
			Block_Byte = 256;
		seed_bits = 440;
		STATE_MAX_SIZE = STATE_MAX_SIZE_256;
	}
	else if(ctx->setting.drbgtype == 832 || ctx->setting.drbgtype == 576)
	{
		if(ctx->setting.drbgtype == 832)
			Block_Byte = 384;
		else
			Block_Byte = 512;
		seed_bits = 888;
		STATE_MAX_SIZE = STATE_MAX_SIZE_512;
	}
	n = ceil((double) output_bits / (double) Block_Byte);

	for(int a = 0 ; a < STATE_MAX_SIZE ; a++)
		hash_data[a] = input[a];

	for(int i = 0 ; i < (int) n ; i++)
	{
		Keccak(ctx->setting.drbgtype, ctx->capacity, hash_data, STATE_MAX_SIZE, ctx->delimitedSuffix, hash_result[i], Block_Byte / 8);
		operation_add(hash_data, STATE_MAX_SIZE, 0, 0x01);
	}

	w = 0;
	for(int i = 0 ; i < output_index ; i++)
	{
		if(i == Block_Byte / 8)
		{
			flag += 1;
			output_index -= Block_Byte / 8;
			i = 0;
		}

		output[w++] = hash_result[flag][i];
	}
}


void drbg_sha3_init(struct DRBG_SHA3_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *nonce, int non_size, const BitSequence *per_string, int per_size, FILE *outf)
{
	BitSequence input[1024] = {'\0', };
	BitSequence *target_state_V;
	BitSequence *target_state_C;

	int r, w;
	int input_size = 0;
	int STATE_MAX_SIZE;


	if(ctx->setting.drbgtype == 1152|| ctx->setting.drbgtype == 1088)
	{
		target_state_V = ctx->working_state_V256;
		target_state_C = ctx->working_state_C256;
		STATE_MAX_SIZE = STATE_MAX_SIZE_256;
	}
	else if(ctx->setting.drbgtype == 832 || ctx->setting.drbgtype == 576)
	{
		target_state_V = ctx->working_state_V512;
		target_state_C = ctx->working_state_C512;
		STATE_MAX_SIZE = STATE_MAX_SIZE_512;
	}

	for(r = 0, w = 0 ; r < ent_size ; r++){
		input[w++] = entropy[r];
	}

	for(r = 0 ; r < non_size ; r++)
		input[w++] = nonce[r];

	if(ctx->setting.usingperstring)
	{
		for(r = 0 ; r < per_size ; r++)
			input[w++] = per_string[r];
		input_size += per_size;
	}
	input_size += ent_size + non_size;

	drbg_derivation_func(ctx, input, input_size, target_state_V);

	{		//***** TEXT OUTPUT - V *****//
		fprintf(outf, "dfInput = ");
		for(int i = 0 ; i < input_size ; i++)
			fprintf(outf, "%02x", input[i]);
		fprintf(outf, "\n");
		fprintf(outf, "dfOutput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", target_state_V[i]);
		fprintf(outf, "\n\n");
	}
	memset(input, 0x00, 1024);

	input[0] = 0x00;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		input[w++] = target_state_V[r];

	drbg_derivation_func(ctx, input, STATE_MAX_SIZE + 1, target_state_C);

	{		//***** TEXT OUTPUT - C *****//
		fprintf(outf, "dfInput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE + 1 ; i++)
			fprintf(outf, "%02x", input[i]);
		fprintf(outf, "\n");
		fprintf(outf, "dfOutput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", target_state_C[i]);
	}

	ctx->reseed_counter = 1;
}


void drbg_sha3_reseed(struct DRBG_SHA3_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *add_input, int add_size, FILE *outf)
{
	BitSequence input[1024] = {'\0' ,};
	BitSequence *target_state_V;
	BitSequence *target_state_C;

	int r, w;
	int input_size = 0;
	int STATE_MAX_SIZE;

	if(ctx->setting.drbgtype == 1152|| ctx->setting.drbgtype == 1088)
	{
		target_state_V = ctx->working_state_V256;
		target_state_C = ctx->working_state_C256;
		STATE_MAX_SIZE = STATE_MAX_SIZE_256;
	}
	else if(ctx->setting.drbgtype == 832 || ctx->setting.drbgtype == 576)
	{
		target_state_V = ctx->working_state_V512;
		target_state_C = ctx->working_state_C512;
		STATE_MAX_SIZE = STATE_MAX_SIZE_512;
	}

	{
		//***** TEXT OUTPUT - entropy *****//
		fprintf(outf, "entropy = ");
		for(int i = 0 ; i < ent_size ; i++)
			fprintf(outf, "%02x", entropy[i]);
		fprintf(outf, "\n\n");
	}

	input[0] = 0x01;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		input[w++] = target_state_V[r];

	for(r = 0 ; r < ent_size ; r++)
		input[w++] = entropy[r];

	if(ctx->setting.usingaddinput)
	{
		for(r = 0 ; r < add_size ; r++)
			input[w++] = add_input[r];
		input_size += add_size;
	}
	input_size += STATE_MAX_SIZE + ent_size + 1;

	drbg_derivation_func(ctx, input, input_size, target_state_V);

	{		//***** TEXT OUTPUT - V *****//
		fprintf(outf, "dfInput = ");
		for(int i = 0 ; i < input_size ; i++)
			fprintf(outf, "%02x", input[i]);
		fprintf(outf, "\n");
		fprintf(outf, "dfOutput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", target_state_V[i]);
		fprintf(outf, "\n\n");
	}

	memset(input, 0x00, 1024);

	input[0] = 0x00;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		input[w++] = target_state_V[r];

	drbg_derivation_func(ctx, input, STATE_MAX_SIZE + 1, target_state_C);

	{		//***** TEXT OUTPUT - C *****//
		fprintf(outf, "dfInput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE + 1 ; i++)
			fprintf(outf, "%02x", input[i]);
		fprintf(outf, "\n");
		fprintf(outf, "dfOutput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", target_state_C[i]);
		fprintf(outf, "\n\n");
	}

	ctx->reseed_counter = 1;

	if(!ctx->setting.predicttolerance){
		ctx->setting.usingaddinput = false;
	}

	{		//***** TEXT OUTPUT - reseed_counter *****//
		fprintf(outf, "reseed_counter = %d\n\n", ctx->reseed_counter);
	}
}


void drbg_sha3_output_gen(struct DRBG_SHA3_Context *ctx, const BitSequence *entropy, int ent_size, const BitSequence *add_input, int add_size, int output_bits, int cycle, BitSequence *drbg, FILE *outf, int counter)
{
	BitSequence hash_data[512] = {'\0', };
	int hash_data_size;
	BitSequence hash_result[64];
	BitSequence *target_state_V;
	BitSequence *target_state_C;
	int Block_Byte;

	int r, w;
	int STATE_MAX_SIZE;

	int temp = 0;

	if(ctx->setting.drbgtype == 1152|| ctx->setting.drbgtype == 1088)
	{
		if(ctx->setting.drbgtype == 1152)
			Block_Byte = 224;
		else
			Block_Byte = 256;
		target_state_V = ctx->working_state_V256;
		target_state_C = ctx->working_state_C256;
		STATE_MAX_SIZE = STATE_MAX_SIZE_256;
	}
	else if(ctx->setting.drbgtype == 832 || ctx->setting.drbgtype == 576)
	{
		if(ctx->setting.drbgtype == 832)
			Block_Byte = 384;
		else
			Block_Byte = 512;
		target_state_V = ctx->working_state_V512;
		target_state_C = ctx->working_state_C512;
		STATE_MAX_SIZE = STATE_MAX_SIZE_512;
	}

	{		//***** TEXT OUTPUT - V C reseed_counter addInput *****//
		fprintf(outf, "\n\n");
		fprintf(outf, "V = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", target_state_V[i]);
		fprintf(outf, "\n");

		fprintf(outf, "C = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++){
			fprintf(outf, "%02x", target_state_C[i]);
		}

		fprintf(outf, "\n");

		fprintf(outf, "reseed_counter = %d\n", ctx->reseed_counter);

		if(ctx->setting.usingaddinput)
		{
			fprintf(outf, "addInput = ");
			for(int i = 0 ; i < add_size ; i++)
				fprintf(outf, "%02x", add_input[i]);
			fprintf(outf, "\n");
		}
		fprintf(outf, "\n");
	}

	if(ctx->reseed_counter > ctx->setting.refreshperiod || ctx->setting.predicttolerance)
	{
		drbg_sha3_reseed(ctx, entropy, ent_size, add_input, add_size, outf);
	}
	else if(ctx->setting.usingaddinput)
	{	// ****** inner reseed ****** //
		hash_data[0] = 0x02;
		for(r = 0 , w = 1 ; r < STATE_MAX_SIZE ; r++)
			hash_data[w++] = target_state_V[r];

		for(r = 0 ; r < add_size ; r++)
			hash_data[w++] = add_input[r];
		hash_data_size = STATE_MAX_SIZE + add_size + 1;

		Keccak(ctx->setting.drbgtype, ctx->capacity, hash_data, hash_data_size, ctx->delimitedSuffix, hash_result, Block_Byte / 8);

		for(int i = Block_Byte / 8 - 1, start = 0 ; i > -1 ; i--)
			operation_add(target_state_V, STATE_MAX_SIZE, start++, hash_result[i]);

		{		//***** TEXT OUTPUT - w(hash) V *****//
			fprintf(outf, "w = ");
			for(int i = 0 ; i < Block_Byte / 8 ; i++)
				fprintf(outf, "%02x", hash_result[i]);
			fprintf(outf, "\n");
			fprintf(outf, "V = ");
			for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
				fprintf(outf, "%02x", target_state_V[i]);
			fprintf(outf, "\n\n");
		}

	}

	drbg_sha3_inner_output_gen(ctx, target_state_V, drbg, output_bits, outf);

	{		//***** TEXT OUTPUT - output(count) *****//
			printf("output%d = ", counter); // console output
			fprintf(outf, "output%d = ", counter++);
			for(int i = 0 ; i < output_bits / 8 ; i++)
			{
				printf("%02x", drbg[i]);	// console output
				fprintf(outf, "%02x", drbg[i]);
			}
			printf("\n");	// console output
			fprintf(outf, "\n\n");
	}

	hash_data[0] = 0x03;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		hash_data[w++] = target_state_V[r];
	hash_data_size = STATE_MAX_SIZE + 1;

	Keccak(ctx->setting.drbgtype, ctx->capacity, hash_data, hash_data_size, ctx->delimitedSuffix, hash_result, Block_Byte / 8);

	for(int i = Block_Byte / 8 - 1, start = 0 ; i > -1 ; i--)
		operation_add(target_state_V, STATE_MAX_SIZE, start++, hash_result[i]);

	for(int i = STATE_MAX_SIZE - 1, start = 0 ; i > -1 ; i--){ //V + C
		operation_add(target_state_V, STATE_MAX_SIZE, start++, target_state_C[i]);
	}
	operation_add(target_state_V, STATE_MAX_SIZE, 0, ctx->reseed_counter);

	{		//***** TEXT OUTPUT - w(hash) V (after inner reseed) *****//
		fprintf(outf, "w = ");
		for(int i = 0 ; i < Block_Byte /8; i++)
			fprintf(outf, "%02x", hash_result[i]);
		fprintf(outf, "\n");
		fprintf(outf, "V = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", target_state_V[i]);
		fprintf(outf, "\n");
	}

	ctx->reseed_counter++;  ////what?

	{		//***** TEXT OUTPUT - reseed_counter *****//
		fprintf(outf, "reseed_counter = %d", ctx->reseed_counter);
	}
}

void drbg_sha3_digest(unsigned int rate, unsigned int capacity, unsigned char delimitedSuffix, BitSequence (*entropy)[65], int ent_size, BitSequence *nonce, int non_size, BitSequence *per_string, int per_size, BitSequence (*add_input)[65], int add_size, int output_bits, int cycle, BitSequence *drbg, FILE *outf)
{
	struct DRBG_SHA3_Context ctx;

	ctx.setting.drbgtype = rate;
	ctx.capacity = capacity;
	ctx.delimitedSuffix = delimitedSuffix;

	ctx.setting.refreshperiod = cycle;

	/*if(per_size != 0)
		ctx.setting.usingperstring = true;
	else
		ctx.setting.usingperstring = false;
	if(add_size != 0)
		ctx.setting.usingaddinput = true;
	else
		ctx.setting.usingaddinput = false;
	ctx.setting.predicttolerance = false;*/

	ctx.setting.predicttolerance = false;   //예측내성
	ctx.setting.usingperstring = true;      //개별화
	ctx.setting.usingaddinput = true;      //추가입력

	drbg_sha3_init(&ctx, entropy[0], ent_size, nonce, non_size, per_string, per_size, outf);

	for(int i = 0 ; i < ctx.setting.refreshperiod + 1 ; i++){
		if(ctx.setting.predicttolerance || ctx.setting.refreshperiod == 0){
			drbg_sha3_output_gen(&ctx, entropy[i+1], ent_size, add_input[i], add_size, output_bits, cycle, drbg, outf, i+1);
		}else {
			drbg_sha3_output_gen(&ctx, entropy[i], ent_size, add_input[i], add_size, output_bits, cycle, drbg, outf, i+1);
		}
	}
}
