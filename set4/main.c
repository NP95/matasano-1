#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/aes.h"
#include "../include/pkcs.h"
#include "../include/hex2base64.h"
#include "../include/histogram.h"

int main(void)
{
	srand(time(NULL));

	/**           Set 4 Challenge 1           **/
	/** CRCK RANDOM READ/WRITE ACCESS AES CTR **/
	FILE *fp = fopen("25.txt", "r");

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

	if(line_str)
		free(line_str);
	close(fp);

	cipher_b64[cipher_len] = '\0';
// 	printf("[s4c1] cipher_b64 = {\n%s\n}\n\n", cipher_b64);
	cipher_len = base64decode(&cipher, cipher_b64, cipher_len);

// 	printf("[s4c1] file_contents = '%s'\n", cipher);

	unsigned char s4c1_plain[1024];
	unsigned int s4c1_plain_len = 0;
	memset(s4c1_plain, 0, 1024*sizeof(unsigned char));
	s4c1_plain_len = aes_ecb_decrypt(128, s4c1_plain, cipher, cipher_len, "YELLOW SUBMARINE");
	s4c1_plain[s4c1_plain_len] = 0;

	unsigned char s4c1_cipher_ctr[s4c1_plain_len];
	unsigned int s4c1_cipher_ctr_len = 0;

	unsigned int s4c1_nonce = rand();
	unsigned char s4c1_key[16];

	aes_random_key(s4c1_key, 16);

	s4c1_cipher_ctr_len = aes_ctr_crypt(s4c1_cipher_ctr, s4c1_plain, s4c1_plain_len, s4c1_key, s4c1_nonce);

// 	printf("[s4c1] plaintext = {\n%s\n}\n", s4c1_plain);

// 	unsigned char s2c6_plaintext[1024];
// 	unsigned int s2c6_plaintext_len;
// 	unsigned int s2c6_key_len = 0;
// 	memset(s2c6_plaintext, 0, 1024);
// 	aes_ecb_partial_crack2(s2c6_plaintext, &s2c6_plaintext_len, &s2c6_key_len);
// 
// 	printf("[s2c6] plaintext = {\n%s\n}\n", s2c6_plaintext);

	free(cipher);

	return 0;
}
