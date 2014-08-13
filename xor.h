#ifndef __XOR_H
#define __XOR_H

#include <stdlib.h>
#include <string.h>

void fixed_xor(unsigned char **out, unsigned char *in1, unsigned char *in2, unsigned int in_size);
unsigned int xor_key(unsigned char **out, unsigned char *in, unsigned int in_size, unsigned char *key, unsigned int key_size);
int attack_single_byte_xor(unsigned char **out, unsigned char **key, unsigned char *cipher, unsigned int cipher_size);

#endif // __XOR_H
