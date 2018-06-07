#include <stdio.h>

typedef unsigned char BitSequence;

struct DRBG_SHA3 {
	BitSequence dfInput[1000];
	BitSequence dfOutput[1000];
	unsigned int Vlen;
	BitSequence dfInput01[1000];
	BitSequence dfOutput01[1000];
	unsigned int reseed_counter;
	BitSequence addInput[1000];
	unsigned int addInput_length;
	BitSequence W_VaddInput[1000];
	unsigned int W_VaddInput_length;
	BitSequence V_Mod[1000];
	unsigned int V_Mod_length;
	BitSequence Output01[1000];
	unsigned int Output01_length;
	BitSequence W_03V[1000];
	unsigned int W_03V_length;
	BitSequence V_wCreseed[1000];
	unsigned int V_wCreseed_03V_length;

	BitSequence V_secondcall[1000];
	unsigned int V_secondcall_length;

	FILE *file_output;
};
