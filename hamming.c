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
