/*
 ============================================================================
 Name        : SHA3_drbg.c
 Author      : kyu
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>

int main(void) {
	char buf[256];
	int len=256;
	int i=0;

	gcry_create_nonce(buf, len);

	for(i=0; i<len; i++){
		printf("%x", buf[i]);
	}
	printf("\n");
	return 0;
}
