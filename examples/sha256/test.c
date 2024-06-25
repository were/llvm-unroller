#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "sha256.h"


char message[1024]  = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
uint32_t block_buffer[512];


unsigned char* sha256_to_string(uint32_t* raw) {
	
#define NTH_BYTE(x, n) ((x)>>(8*(n)))&0xff
	static unsigned char result[64 + 1];
	result[32] = '\0';
	for(int i = 0; i < 8; i++){
    	sprintf((char*)&result[8*i + 0], "%02x", (char)NTH_BYTE(raw[i], 3));
    	sprintf((char*)&result[8*i + 2], "%02x", (char)NTH_BYTE(raw[i], 2));
    	sprintf((char*)&result[8*i + 4], "%02x", (char)NTH_BYTE(raw[i], 1));
    	sprintf((char*)&result[8*i + 6], "%02x", (char)NTH_BYTE(raw[i], 0));
	}
#undef NTH_BYTE

	return result;
}

int main(int argc, char **argv){

	const char* output = "4f671028986fea052075ff8c08fc1a0e7741cc60da6607bf0a8f8882465e79af";

  uint32_t result[8];
	uint64_t num_bytes_message = strlen((char*)message);
	sha256sum((unsigned char*)message, result, num_bytes_message, block_buffer);
	unsigned char* result_str = sha256_to_string(result);
  assert(!strcmp(output, (char*)result_str));
	// printf("Result: %s\n", !strcmp(output, (char*)result_str) ? "SUCCESS":"FAILURE");

	return 0;
}
