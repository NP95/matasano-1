#include "hamming.h"

unsigned int hamming_distance(const unsigned char *in1, const unsigned char *in2, unsigned int length)
{
	unsigned int i, j, distance=0;
	unsigned char mask = 0x01;
	unsigned char *tmp = malloc(length*sizeof(unsigned char));
	memset(tmp, 0, length*sizeof(unsigned char));

	for(i=0; i<length; i++) {
		tmp[i] = in1[i] ^ in2[i];
		mask=0x01;
		for(j=0; j<8; j++) {
			if((tmp[i] & mask) > 0 )
				distance++;
// 			printf("%02x & %02x = %02x\n", tmp[i], mask, tmp[i] & mask);
			mask<<=1;
		}
	}

	free(tmp);

	return distance;
}

double norm_hamming_distance(const unsigned char *in, unsigned int in_length, unsigned int key_length)
{
	unsigned int num_blocks;
	unsigned int hamming = 0;
	double hamming_norm = 0;
	unsigned int i, k;
	unsigned char tmp1[key_length];
	unsigned char tmp2[key_length];

	num_blocks = in_length / key_length;

	for(k=0; k<num_blocks; k++) {
		for(i=0; i<key_length; i++) {
			tmp1[i] = in[i+k*key_length];
			tmp2[i] = in[(i+k*key_length+key_length)%in_length];
		}
		hamming += hamming_distance(tmp1, tmp2, key_length);
	}

	hamming_norm = ((double) hamming) / ((double) num_blocks) / ((double) key_length);
// 	printf("hamming_norm(key_length=%d) = %f\n", key_length, hamming_norm);
	return hamming_norm;
}
