#ifndef __PKCS_H
#define __PKCS_H

#include <stdlib.h>
#include <string.h>

unsigned int pkcs7_padding(unsigned char *plaintext_padded, unsigned char *plaintext_unpadded, unsigned int plaintext_unpadded_len, unsigned int block_len);
int pkcs7_unpadding(unsigned char *plaintext, unsigned char *plaintext_padded, unsigned int plaintext_padded_len, unsigned int block_len);

#endif // __PKCS_H
