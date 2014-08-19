#ifndef __AES_H
#define __AES_H

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#include "hamming.h"
#include "hex_coder.h"
#include "hex2base64.h"
#include "pkcs.h"
#include "xor.h"

unsigned int aes_ecb_encrypt(unsigned int block_len_bits, unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key);
unsigned int aes_ecb_decrypt(unsigned int block_len_bits, unsigned char *plaintext, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *key);
unsigned int aes_cbc_encrypt(unsigned int block_len_bits, unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key, unsigned char *iv);
unsigned int aes_cbc_decrypt(unsigned int block_len_bits, unsigned char *plaintext, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *key, unsigned char *iv);

void aes_random_key(unsigned char *key, unsigned int key_size);

// oracle function for set2 challenge 4
unsigned int aes_encryption_random(unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_key);
// oracle function for set2 challenge 6
unsigned int aes_encryption_random2(unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_header, unsigned int random_header_len, unsigned char *random_key);

unsigned int aes_encryption_oracle(unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len);

// cracking function for set2 challenge 4
unsigned int aes_ecb_partial_crack(unsigned char *unknown_plaintext, unsigned int *unknown_plaintext_length, unsigned int *key_length);
// cracking function for set2 challenge 6
unsigned int aes_ecb_partial_crack2(unsigned char *unknown_plaintext, unsigned int *unknown_plaintext_length, unsigned int *key_length);

unsigned int is_ecb_mode(unsigned char *ciphertext, unsigned int ciphertext_len, unsigned int block_len);

#endif // __AES_H
