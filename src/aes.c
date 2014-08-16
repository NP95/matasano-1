#include "../include/aes.h"
#include "../include/xor.h"

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

