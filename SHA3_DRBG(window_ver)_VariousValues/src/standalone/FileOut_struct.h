#include <stdio.h>

typedef unsigned char BitSequence;

struct DRBG_SHA3 {
	unsigned int rate;

	FILE *file_output;
};
