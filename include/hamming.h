#ifndef __HAMMING_H
#define __HAMMING_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

unsigned int hamming_distance(const unsigned char *in1, const unsigned char *in2, unsigned int length);
double norm_hamming_distance(const unsigned char *in, unsigned int in_length, unsigned int key_length);

#endif // __HAMMING_H
