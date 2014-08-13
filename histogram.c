#include "histogram.h"

void init_histogram(max_hist_t *hist)
{
	unsigned int i;

	// init histogram
	for(i=0; i<6; i++) {
		(*hist).byte[i] = 0;
		(*hist).num[i] = 0;
	}
}

max_hist_t print_histogram(unsigned char *input, unsigned int size, unsigned short do_print)
{
	unsigned int i, e = 0;
	unsigned int hist[256];
	max_hist_t max;
	
// 	// init histogram
// 	for(i=0; i<6; i++) {
// 		max.byte[i] = 0;
// 		max.num[i] = 0;
// 	}

	init_histogram(&max);

	// init histogram to all zeroes
	for(i=0; i<256; i++) {
		hist[i] = 0;
	}

	// build histogram
	for(i=0; i<size; i++) {
		hist[input[i]]++;
	}

	// print histogram with 5 most occuring bytes
	for(e=0; e<6; e++) {
		for(i=0; i<256; i++) {
			if(hist[i]!=0) {
				if(do_print>0)
					printf("Byte %02x: %d times\n", i, hist[i]);
				if(hist[i]>max.num[e]) {
					max.byte[e] = i;
					max.num[e] = hist[i];
				}
			}
		}

		// remove element with highest amount
		// in order to catch next element...
		hist[max.byte[e]] = 0;
	}

	// return histogram
	return max;
}

int is_cleartext(unsigned char *in, unsigned int size)
{
	unsigned int i, j, hits=0;
	max_hist_t h;
	init_histogram(&h);

	h = print_histogram(in, size, 0);

	for(i=0; i<6; i++) {
		for(j=0; j<strlen(hist_most_common); j++) {
			if(h.byte[i] == hist_most_common[j])
				hits++;
		}
	}

// 	if(hits > 3)
	if(hits > 4)
		return 0;
	else
		return -1;
}
