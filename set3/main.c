#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/aes.h"
#include "../include/pkcs.h"
#include "../include/hex2base64.h"

unsigned int aes_cbc_padding_oracle(unsigned char *ciphertext, unsigned char *key, unsigned char *iv)
{
	unsigned char *strings[10] = {
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
	};

	unsigned char *string_b64 = strings[rand() % 10];
	unsigned char *string;
	unsigned int string_len;

	// base64 decode
	string_len = base64decode(&string, string_b64, strlen(string_b64));
	string[string_len] = '\0';

	// perform PKCS#7 padding
	unsigned int str_pad_len = string_len + (16 - (string_len % 16));
	unsigned char str_pad[str_pad_len];

	str_pad_len = pkcs7_padding(str_pad, string, string_len, 16);

	free(string);

	// cbc encrypt
	return aes_cbc_encrypt(128, ciphertext, str_pad, str_pad_len, key, iv);
}

int aes_cbc_padding_oracle_decrypt(unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *key, unsigned char *iv)
{
	unsigned char plain[ciphertext_len];
	unsigned int plain_len;

	// decrypt
	plain_len = aes_cbc_decrypt(128, plain, ciphertext, ciphertext_len, key, iv);

	// PKCS#7 unpad
	unsigned char unpad[plain_len];

	return pkcs7_unpadding(unpad, plain, plain_len, 16);
}

int main(void) {
	// init rng
	srand((unsigned int) time(NULL));
	
	// init key, iv
	unsigned char key[16], iv[16];

	aes_random_key(key, 16);
	aes_random_key(iv, 16);

	/** Set 3 Challenge 17 **/
	/** CBC Padding Oracle **/
	unsigned char s3c1_cipher[128];
	unsigned int s3c1_cipher_len;

	// call oracle
	s3c1_cipher_len = aes_cbc_padding_oracle(s3c1_cipher, key, iv);

	// call decrypter
	int is_valid;

	is_valid = aes_cbc_padding_oracle_decrypt(s3c1_cipher, s3c1_cipher_len, key, iv);
	printf("[s3c1] valid ... [%s]\n", (is_valid>0) ? "yes": "no");

	return 0;
}
