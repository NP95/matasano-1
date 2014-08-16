#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/hex_coder.h"

int main(void)
{
	unsigned char plaintext_padded[20];
	unsigned int plaintext_padded_len = pkcs7_padding(plaintext_padded, "YELLOW SUBMARINE", 16, 20);
	unsigned char *plaintext_padded_hex;

	hex_encode(&plaintext_padded_hex, plaintext_padded, plaintext_padded_len);

	printf("plaintext_padded = '%s'\n", plaintext_padded_hex);

	free(plaintext_padded_hex);

	return 0;
}
