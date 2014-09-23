#ifndef __AES_H
#define __AES_H

#include <limits.h>
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

unsigned int aes_ctr_crypt(unsigned char *crypted, unsigned char *uncrypted, unsigned int uncrypted_len, unsigned char *key, unsigned int nonce);

void aes_random_key(unsigned char *key, unsigned int key_size);

unsigned int aes_cbc_oracle(unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_key, unsigned char *iv);
unsigned int aes_ctr_oracle(unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_key, unsigned int nonce);

// oracle function for set2 challenge 4
unsigned int aes_encryption_random(unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_key);
// oracle function for set2 challenge 6
// fixed header len
unsigned int aes_encryption_random2(unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_header, unsigned int random_header_len, unsigned char *random_key);
// dynamic header len
unsigned int aes_encryption_random3(unsigned char *ciphertext, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_key);
unsigned int aes_encryption_random3_sane(unsigned char *sane_ciphertext, unsigned int expected_ct_len, unsigned char *plaintext, unsigned int plaintext_len, unsigned char *random_key);

unsigned int aes_encryption_oracle(unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len);

// CBC checking function for set4 challenge 3 (#27)
unsigned int aes_cbc_decrypt_check(unsigned char *plaintext_error, unsigned char *cipher, unsigned int cipher_len, unsigned char *key, unsigned char *iv);

// cracking function for set2 challenge 4
unsigned int aes_ecb_partial_crack(unsigned char *unknown_plaintext, unsigned int *unknown_plaintext_length, unsigned int *key_length);
// cracking function for set2 challenge 6
unsigned int aes_ecb_partial_crack2(unsigned char *unknown_plaintext, unsigned int *unknown_plaintext_length, unsigned int *key_length);
// cracking function for set2 challenge 6 - dynamic header len
unsigned int aes_ecb_partial_crack3(unsigned char *unknown_plaintext, unsigned int *unknown_plaintext_length, unsigned int *key_length);

unsigned int is_ecb_mode(unsigned char *ciphertext, unsigned int ciphertext_len, unsigned int block_len);

#endif // __AES_H
