#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "sha256.h"

/* 
	Algorithm description: http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf 
	The comments through the implementation refer to sections in this paper. */

/* Secure Hash Standard Section 4.1.2
   SHA-256 Functions */
#define CH(x,y,z) ((x) & (y))^(~(x) & (z))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))

#define SHR(x,n) ((x)>>(n))
#define SHL(x,n) ((x)<<(n))

#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))

#define SUM0(x) (ROTR32((x),2)^ROTR32((x),13)^ROTR32((x),22))
#define SUM1(x) (ROTR32((x),6)^ROTR32((x),11)^ROTR32((x),25))

#define SIGMA0(x) (ROTR32((x),7)^ROTR32((x),18)^SHR((x),3))
#define SIGMA1(x) (ROTR32((x),17)^ROTR32((x),19)^SHR((x),10))

#define NTH_BYTE(x, n) ((x)>>(8*(n)))&0xff

/* Secure Hash Standard Section 4.2.2 
   These words represent the first thirty-two bits of the 
   fractional parts ofthe cube roots of the 
   first sixty-four prime numbers */
const int32_t sha256_constants[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint64_t sha256padding(unsigned char* message, uint64_t num_bytes_message) {
	/* Parses the message and returns a 512 bit padded message 

		char* message: the messages to be parsed
		int32_t num_bytes: number of bytes in the final message,
                           to be passed outside of the function through the pointer
	*/

	/* Number of bits of the original message */
	uint64_t len = 8*num_bytes_message;
	

	/* Secure Hash Standards Section 5.1.1
	   k is the number of zero bits to be appended after the zero */
	int mod_lhs = (len+1)%512;
	uint16_t k = (448-mod_lhs>=0)?(448-mod_lhs):(448-mod_lhs)+512;

	uint64_t padded_length = (len + 1 + k + 64)/8;
	unsigned char* padded_message = message;
	
	int64_t i = num_bytes_message;

	/* First byte after message */
	unsigned char first_byte = 128;
	padded_message[i] = first_byte;
	i++;

	/* We had to append k zero bits 
	to the end, but 7 bits have
	already been appended */
	uint16_t bytes_left = (k-7)/8;
	while(bytes_left--){
		padded_message[i] = 0;
		i++;
	}

	/* Slide an all-ones byte through the length to 
	   extract each byte from the 32 bits. */
	for( int byte_num = 7; byte_num >=0; byte_num--){
		padded_message[i] = NTH_BYTE(len, byte_num);
		i++;
	}
	
	return padded_length;
}

void sha256sum(unsigned char* message, uint32_t *result,
               uint64_t num_bytes_message, uint32_t *block_buffer) {

	/* Variables used in the iterations 
	   for each 512-bit block */
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t t1, t2;

	/*Secure Hash Standards Section 6.2.1 Preprocessing */
	uint64_t n = sha256padding(message, num_bytes_message);
	uint32_t H[] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

	/* Secure Hash Standards Section 6.2.2
	   Hash computation is done mod 2^32 by
	   allowing uint32_t to 
	   overflow and "wrap around" */
	n = (n * 8) / 512; /* n is the number of 512-bit blocks */

	for(uint64_t i = 0; i < n; i++){

    uint32_t schedule[64];
		/* Prepare the message schedule */
		for( int t = 0; t < 16; t++){
      uint8_t v[4] = {
        message[i * 64 + t * 4 + 3],
        message[i * 64 + t * 4 + 2],
        message[i * 64 + t * 4 + 1],
        message[i * 64 + t * 4 + 0],
      };
			schedule[t] = *((uint32_t*)v);
		}

		for( int t = 16; t < 64; t++){
			schedule[t] = SIGMA1(schedule[t-2]) + schedule[t-7] + SIGMA0(schedule[t-15]) + schedule[t-16];
		}

		/* Initialize the 
		   working variables */
		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];
		f = H[5];
		g = H[6];
		h = H[7];

		for(int t = 0; t < 64; t++){
			
			t1 = h + (SUM1(e)) + (CH(e,f,g)) + sha256_constants[t] + schedule[t];
			t2 = (SUM0(a)) + (MAJ(a,b,c));

			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}

		H[0] = a + H[0];
		H[1] = b + H[1];
		H[2] = c + H[2];
		H[3] = d + H[3];
		H[4] = e + H[4];
		H[5] = f + H[5];
		H[6] = g + H[6];
		H[7] = h + H[7];
	}

	// free(message_block);
  result[0] = H[0];
  result[1] = H[1];
  result[2] = H[2];
  result[3] = H[3];
  result[4] = H[4];
  result[5] = H[5];
  result[6] = H[6];
  result[7] = H[7];
}

