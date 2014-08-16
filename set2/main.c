#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/hex2base64.h"
#include "../include/hex_coder.h"

int main(void)
{
	/** Set 2 Challenge 1 **/
	/**  PKCS#7 PADDING   **/
	unsigned char plaintext_padded[20];
	unsigned int plaintext_padded_len = pkcs7_padding(plaintext_padded, "YELLOW SUBMARINE", 16, 20);
	unsigned char *plaintext_padded_hex;

	hex_encode(&plaintext_padded_hex, plaintext_padded, plaintext_padded_len);

	printf("plaintext_padded = '%s'\n", plaintext_padded_hex);

	free(plaintext_padded_hex);

	/** Set 2 Challenge 2 **/
	/**  AES in CBC Mode  **/
	FILE *fp = fopen("10.txt", "r");

	if(fp==NULL)
		return -1;

	unsigned int i;
	unsigned char *cipher;
	unsigned char cipher_b64[8192];
	unsigned int cipher_len=0;
	char *line_str = NULL;
	size_t len=0;
	ssize_t read;
	while((read = getline(&line_str, &len, fp)) != -1) {
		for(i=0; i<read-1; i++) {
			cipher_b64[cipher_len+i] = line_str[i];
		}
		cipher_len += read-1;
	}

	cipher_b64[cipher_len] = '\0';
// 	printf("cipher_b64 = {\n%s\n}\n\n", cipher_b64);
	cipher_len = base64decode(&cipher, cipher_b64, cipher_len);

	if(line_str)
		free(line_str);
	close(fp);

	unsigned char plaintext[cipher_len];
	unsigned int plaintext_len;
	unsigned char iv[16];
	memset(iv, 0, 16);

	plaintext_len = aes_cbc_decrypt(128, plaintext, cipher, cipher_len, "YELLOW SUBMARINE", iv);
// 	printf("plaintext = {\n%s\n}\n\n", plaintext);
	cipher_len = aes_cbc_encrypt(128, cipher, plaintext, plaintext_len, "YELLOW SUBMARINE", iv);
	plaintext_len = aes_cbc_decrypt(128, plaintext, cipher, cipher_len, "YELLOW SUBMARINE", iv);
// 	printf("plaintext = {\n%s\n}\n\n", plaintext);

	free(cipher);

	/** Set 2 Challenge 3 **/
	/** ECB/CBC DETECTION **/
	unsigned char *input = "Terminator X: Bring the noise"; // len: 29
	unsigned int output_len = 0;
	unsigned char output[64];
	unsigned int ecb = 2; // ecb == 0; cbc == 1

	ecb = aes_encryption_oracle(output, &output_len, input, 29);
	
	double hamming_norm = 0.0;

	hamming_norm = norm_hamming_distance(output, output_len, 16);
	printf("[mode: %d, len: %d] hamming_norm = %f\n", ecb, output_len, hamming_norm);

// 	unsigned char *output_hex;
// 	hex_encode(&output_hex, output, output_len);
// 	printf("[mode: %d]\n%s\n", ecb, output_hex);
// 	free(output_hex);

	return 0;
}
