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

unsigned int aes_cbc_padding_oracle_attack(unsigned char *plaintext, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *key, unsigned char *iv)
{
	// NOTE: we're not going to use the key here
	// it is directly passed to the decryption routine
	int is_valid;
	unsigned int num_blocks = ciphertext_len / 16;
	unsigned char cipher_mod[ciphertext_len];
	unsigned int cipher_mod_len;
	unsigned char *ciphertext_hex;
	unsigned char plain_xor[ciphertext_len];

	int j, m;
	unsigned int i, k, l, hits=0, cnt=0;

	hex_encode(&ciphertext_hex, ciphertext, ciphertext_len);
// 	printf("[%02d] cipher = '%s'\n", 0, ciphertext_hex);
	free(ciphertext_hex);

	for(i=num_blocks; i>=1; i--) {
		// assemble modded ciphertext
		if(i>1) {
			l=0;
			cipher_mod_len = i*16;
			memcpy(cipher_mod, ciphertext, cipher_mod_len*sizeof(unsigned char));
			memset(cipher_mod+cipher_mod_len-32, 0, 16*sizeof(unsigned char));
		}
		else {
			l=1;
			cipher_mod_len = (i+1)*16;
			memset(cipher_mod, 0, cipher_mod_len*sizeof(unsigned char));
			memcpy(cipher_mod+16, ciphertext, 16*sizeof(unsigned char));
		}

		// iterate over byte position of n-1 ciphertext block
		for(j=15; j>=0; j--) {
			cnt++;

			// brute force
			for(k=0; k<256; k++) {
				cipher_mod[(i-2+l)*16+j] = k;
				is_valid = aes_cbc_padding_oracle_decrypt(cipher_mod, cipher_mod_len, key, iv);
				if(is_valid>0) {
					hits++;
					plain_xor[(i-1)*16+j] = (16-j) ^ k;
					// update solved ciphertext bits to match
					// next padding
					for(m=15; m>=j; m--) {
						cipher_mod[(i-2+l)*16+m] ^= (16-j) ^ ((16-j)+1);
					}
					break;
				}
			}

			hex_encode(&ciphertext_hex, cipher_mod, cipher_mod_len);
// 			printf("[%02d] cipher = '%s'\n", j, ciphertext_hex);
			free(ciphertext_hex);
		}
	}
	
// 	printf("len=%d, hits=%d, cnt=%d\n", ciphertext_len, hits, cnt);

	hex_encode(&ciphertext_hex, plain_xor, ciphertext_len);
// 	printf("[%02d] plain_xor = '%s'\n", 0, ciphertext_hex);
	free(ciphertext_hex);

	unsigned char *plain;
	unsigned char cipher_shift[ciphertext_len];

	memset(cipher_shift, 0, ciphertext_len);
	memcpy(cipher_shift, iv, 16*sizeof(unsigned char));
	memcpy(cipher_shift+16, ciphertext, (ciphertext_len-16)*sizeof(unsigned char));

	hex_encode(&ciphertext_hex, cipher_shift, ciphertext_len);
// 	printf("[%02d] cipher_sh = '%s'\n", 0, ciphertext_hex);
	free(ciphertext_hex);

	fixed_xor(&plain, cipher_shift, plain_xor, ciphertext_len);
	
	// remove PKCS#7 padding
	unsigned char unpad[ciphertext_len+1];
	unsigned int unpad_len;

	unpad_len = pkcs7_unpadding(unpad, plain, ciphertext_len, 16);
	memcpy(plaintext, unpad, unpad_len*sizeof(unsigned char));

	free(plain);

	return unpad_len;
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

	// attack
	unsigned char s3c1_plain[s3c1_cipher_len+1];
	memset(s3c1_plain, 0, (s3c1_cipher_len+1)*sizeof(unsigned char));

	aes_cbc_padding_oracle_attack(s3c1_plain, s3c1_cipher, s3c1_cipher_len, key, iv);

	printf("[s3c1] plain = '%s'\n", s3c1_plain);

	return 0;
}
