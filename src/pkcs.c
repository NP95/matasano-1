#include "../include/pkcs.h"

unsigned int pkcs7_padding(unsigned char *plaintext_padded, unsigned char *plaintext_unpadded, unsigned int plaintext_unpadded_len, unsigned int block_len)
{
	unsigned int plaintext_padded_length = 0;
	unsigned int pad_num = block_len - (plaintext_unpadded_len % block_len);
	unsigned int i;

	for(i=0; i<plaintext_unpadded_len; i++) {
		plaintext_padded[i] = plaintext_unpadded[i];
	}
	for(i=0; i<pad_num; i++) {
		plaintext_padded[plaintext_unpadded_len+i] = (unsigned char) pad_num;
	}

	return (plaintext_unpadded_len+pad_num);
}
