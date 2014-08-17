#include "../include/aes.h"

unsigned int aes_ecb_encrypt(unsigned int block_len_bits, unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key)
{
	unsigned int i;
	AES_KEY enc_key;
	AES_set_encrypt_key(key, block_len_bits, &enc_key);

	for(i=0; i<plaintext_len; i+=(block_len_bits/8)) {
		AES_ecb_encrypt(plaintext+i, ciphertext+i, &enc_key, AES_ENCRYPT);
	}

	return i;
}

unsigned int aes_ecb_decrypt(unsigned int block_len_bits, unsigned char *plaintext, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *key)
{
	unsigned int i;
	AES_KEY dec_key;
	AES_set_decrypt_key(key, block_len_bits, &dec_key);

	for(i=0; i<ciphertext_len; i+=(block_len_bits/8)) {
		AES_ecb_encrypt(ciphertext+i, plaintext+i, &dec_key, AES_DECRYPT);
	}

	return i;
}

unsigned int aes_cbc_encrypt(unsigned int block_len_bits, unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key, unsigned char *iv)
{
	unsigned int i, j;
	unsigned int block_size = block_len_bits / 8; // block len in bytes
	unsigned int num_blocks = plaintext_len / block_size;
	unsigned char pn[block_size];
	unsigned char cn[block_size];
	unsigned char *qn;
	unsigned int bytes = 0;

	// initialize c0 = IV
	for(i=0; i<(block_size); i++) {
		cn[i] = iv[i];
	}

	for(i=0; i<num_blocks; i++) {
		for(j=0; j<block_size; j++) {
			// initialize plaintext block
			pn[j] = plaintext[j+i*block_size];
		}

		fixed_xor(&qn, pn, cn, block_size);
		bytes += aes_ecb_encrypt(block_len_bits, cn, qn, block_size, key);

		// write cn to output array
		for(j=0; j<block_size; j++) {
			ciphertext[j+i*block_size] = cn[j];
		}

		free(qn);
	}

	return bytes;
}

unsigned int aes_cbc_decrypt(unsigned int block_len_bits, unsigned char *plaintext, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *key, unsigned char *iv)
{
	unsigned int i, j;
	unsigned int block_size = block_len_bits / 8; // block len in bytes
	unsigned int num_blocks = ciphertext_len / block_size;
	unsigned char *pn;
	unsigned char cn[block_size];
	unsigned char cn_1[block_size];
	unsigned char qn[block_size];
	unsigned int bytes = 0;

	// initialize c0 = IV
	for(i=0; i<(block_size); i++) {
		cn_1[i] = iv[i];
	}

	for(i=0; i<num_blocks; i++) {
		for(j=0; j<block_size; j++) {
			// initialize ciphertext block
			cn[j] = ciphertext[j+i*block_size];
		}

		bytes += aes_ecb_decrypt(block_len_bits, qn, cn, block_size, key);
		fixed_xor(&pn, qn, cn_1, block_size);

		// write cn to output array and update cn_1
		for(j=0; j<block_size; j++) {
			plaintext[j+i*block_size] = pn[j];
			cn_1[j] = cn[j];
		}

		free(pn);
	}

	return bytes;
}

void aes_random_key(unsigned char *key, unsigned int key_size)
{
	unsigned int i;
	srand((unsigned int) time(NULL));

	for(i=0; i<key_size; i++) {
		key[i] = rand() % 256;
	}

	return;
}

unsigned int aes_encryption_oracle(unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len)
{
	unsigned char key[16];
	unsigned char iv[16];
	unsigned int header, trailer;
	unsigned int i;

	// chose random key & IV
	aes_random_key(key, 16);
	aes_random_key(iv, 16);

	srand((unsigned int) time(NULL));

	header = 5 + (rand() % 6);
	trailer = 5 + (rand() % 6);

	unsigned char plaintext_mod[header+plaintext_len+trailer];

	// set header
	for(i=0; i<header; i++) {
		plaintext_mod[i] = rand() % 256;
	}

	// set plaintext
	for(i=0; i<header; i++) {
		plaintext_mod[header+i] = plaintext[i];
	}

	// set trailer
	for(i=0; i<trailer; i++) {
		plaintext_mod[header+plaintext_len+i] = rand() % 256;
	}

	// perform PKCS#7 padding
	unsigned int plaintext_mod_padded_len = header + plaintext_len + trailer + (16 - ((header+plaintext_len+trailer) % 16));
	unsigned char plaintext_mod_padded[plaintext_mod_padded_len];

	plaintext_mod_padded_len = pkcs7_padding(plaintext_mod_padded, plaintext_mod, header+plaintext_len+trailer, 16);

	// roll the dice
	unsigned int dice = rand() % 2;

	// encrypt
	switch(dice) {
		case 0: (*ciphertext_len) = aes_ecb_encrypt(128, ciphertext, plaintext_mod_padded, plaintext_mod_padded_len, key);
			break;
		case 1: (*ciphertext_len) = aes_cbc_encrypt(128, ciphertext, plaintext_mod_padded, plaintext_mod_padded_len, key, iv);
			break;
	}

	// return dice value to allow for verification later on
	return dice;
}

unsigned int is_ecb_mode(unsigned char *ciphertext, unsigned int ciphertext_len, unsigned int block_len)
{
	double hn = 0.0;

	hn = norm_hamming_distance(ciphertext, ciphertext_len, block_len);

	if(hn < 2.5)
		return 0;	// ECB mode encrypted cipher detected
	else if(hn > 3)
		return 1;	// CBC mode (or maybe other?) detected

	return 2;	// unknown mode
}

