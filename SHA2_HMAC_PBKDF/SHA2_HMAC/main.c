#include "hmac_sha2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void){
	unsigned int mac_224_size, mac_256_size, mac_384_size, mac_512_size;
	unsigned char Keystring[1024], Msgstring[1024];
	int i;

	mac_224_size = 224 / 8;
	mac_256_size = 256 / 8;
	mac_384_size = 384 / 8;
	mac_512_size = 512 / 8;

	int keylen = 0, msglen = 0;
	int mode;

	unsigned char *keys[] = {
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	};

    static char *messages[] ={
        "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
        "what do ya want for nothing?"
    };

    mode = 3;				// 0: 224 , 1: 256, 2: 384, 3: 512

    unsigned char mac[SHA512_DIGEST_SIZE];

	for(int r = 0, w = 0 ; r < strlen(keys[0]); r += 2){
	   unsigned char temp_arr[3] = {keys[0][r], keys[0][r+1], '\0'};
	   Keystring[w++] = strtol(temp_arr, NULL, 16);
	   keylen++;
	}
	//keylen /= 2;

	for(int r = 0, w = 0 ; r < strlen(messages[0]); r += 2){
	   unsigned char temp_arr[3] = {messages[0][r], messages[0][r+1], '\0'};
	   Msgstring[w++] = strtol(temp_arr, NULL, 16);
	   msglen++;
	}
	//msglen /= 2;

	for(int i=0; i<keylen; i++){
		printf("%02x", Keystring[i]);
	}printf("\n");

	for(int i=0; i<msglen; i++){
		printf("%02x", Msgstring[i]);
	}printf("\n");

	if(mode == 0)
	{
		hmac_sha224(Keystring, keylen, Msgstring, msglen, mac, mac_224_size);
		test(mac, mac_224_size);
	}
	else if(mode == 1)
	{
		hmac_sha256(Keystring, keylen, Msgstring, msglen, mac, mac_256_size);
		test(mac, mac_256_size);
	}
	else if(mode == 2)
	{
		hmac_sha384(Keystring, keylen, Msgstring, msglen, mac, mac_384_size);
		test(mac, mac_384_size);
	}
	else if(mode == 3)
	{
		hmac_sha512(Keystring, keylen, Msgstring, msglen, mac, mac_512_size);
		test(mac, mac_512_size);
	}

    return 0;
}
