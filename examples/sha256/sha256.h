#include <stdint.h>

typedef struct {
	uint32_t word[8];
} sha256hash_t;

void sha256sum(unsigned char* message, uint32_t *result,
               uint64_t num_bytes_message, uint32_t *block_buffer);
unsigned char* sha256_to_string(uint32_t *raw);
