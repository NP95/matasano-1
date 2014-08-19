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

int pkcs7_unpadding(unsigned char *plaintext, unsigned char *plaintext_padded, unsigned int plaintext_padded_len, unsigned int block_len)
{
	unsigned int pad_len;
	unsigned int i;

	pad_len = plaintext_padded[plaintext_padded_len-1];

	// validate padding
	if(plaintext_padded_len % block_len != 0)
		return -1;

	if(pad_len==0)
		return -2;

	for(i=1; i<=pad_len; i++) {
		if(plaintext_padded[plaintext_padded_len-i] != pad_len)
			return -3;
	}

	// remove padding
	memcpy(plaintext, plaintext_padded, plaintext_padded_len-pad_len);
	return plaintext_padded_len-pad_len;
}

