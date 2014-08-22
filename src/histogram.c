#include "../include/histogram.h"

void init_histogram(max_hist_t *hist)
{
	unsigned int i;

	// init histogram
	for(i=0; i<HIST_DEPTH; i++) {
		(*hist).byte[i] = 0;
		(*hist).num[i] = 0;
	}
}

void init_histogram2(max_hist2_t *hist)
{
	unsigned int i;

	// init histogram
	for(i=0; i<HIST_DEPTH; i++) {
		(*hist).byte[0][i] = 0;
		(*hist).byte[1][i] = 0;
		(*hist).num[i] = 0;
	}
}

void init_histogram3(max_hist3_t *hist)
{
	unsigned int i;

	// init histogram
	for(i=0; i<HIST_DEPTH; i++) {
		(*hist).byte[0][i] = 0;
		(*hist).byte[1][i] = 0;
		(*hist).byte[2][i] = 0;
		(*hist).num[i] = 0;
	}
}

max_hist_t histogram(unsigned char *input, unsigned int size, unsigned short do_print)
{
	unsigned int i, e = 0;
	unsigned int hist[256];
	max_hist_t max;
	
	// init histogram
	init_histogram(&max);

	// init histogram to all zeroes
	for(i=0; i<256; i++) {
		hist[i] = 0;
	}

	// build histogram
	for(i=0; i<size; i++) {
		hist[input[i]]++;
	}

	// print histogram with 'depth' most occuring bytes
	for(e=0; e<HIST_DEPTH; e++) {
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

max_hist2_t histogram2(unsigned char *input, unsigned int size, unsigned short do_print)
{
	int is_in = -1;
	unsigned int i, j, e = 0;
	unsigned char bigram[2];
	unsigned char hist[size-1][2];
	unsigned int cntr[size-1];
	max_hist2_t max;
	
	// init histogram
	init_histogram2(&max);

	// init histogram to all zeroes
	for(i=0; i<size-1; i++) {
		hist[i][0] = 0;
		hist[i][1] = 0;
		cntr[i] = 0;
	}

	// build histogram
	for(i=0; i<size-1; i++) {
		is_in = -1;
		bigram[0] = input[i];
		bigram[1] = input[i+1];

		// check if bigram already registered
		for(j=0; j<size-1; j++) {
			if((hist[j][0] == bigram[0]) &&
			   (hist[j][1] == bigram[1])) {
				is_in = 0;
				cntr[j]++;
				break;
			}
		}

		if(is_in!=0) {
			// add bigram
			hist[i][0] = bigram[0];
			hist[i][1] = bigram[1];
			cntr[i] = 1;
// 			printf("Adding: '%c%c'\n", hist[i][0], hist[i][1]);
		}
	}

	// print histogram with 'depth' most occuring bytes
	for(e=0; e<HIST_DEPTH; e++) {
		for(i=0; i<size-1; i++) {
			if(cntr[i]>0) {
				if(do_print>0)
					printf("Twogram %02x %02x: %d times\n", hist[i][0], hist[i][1], cntr[i]);
				if(cntr[i]>max.num[e]) {
					max.byte[e][0] = hist[i][0];
					max.byte[e][1] = hist[i][1];
					max.num[e] = cntr[i];
				}
			}
		}
		// remove element with highest amount
		// in order to catch next element...
		for(j=0; j<size-1; j++) {
			if(cntr[j]==max.num[e]) {
				cntr[j] = 0;
				break;
			}
		}
	}

	// return histogram
	return max;
}

max_hist3_t histogram3(unsigned char *input, unsigned int size, unsigned short do_print)
{
	int is_in = -1;
	unsigned int i, j, e = 0;
	unsigned char trigram[3];
	unsigned char hist[size-2][3];
	unsigned int cntr[size-2];
	max_hist3_t max;
	
	// init histogram
	init_histogram3(&max);

	// init histogram to all zeroes
	for(i=0; i<size-2; i++) {
		hist[i][0] = 0;
		hist[i][1] = 0;
		hist[i][2] = 0;
		cntr[i] = 0;
	}

	// build histogram
	for(i=0; i<size-2; i++) {
		is_in = -1;
		trigram[0] = input[i];
		trigram[1] = input[i+1];
		trigram[2] = input[i+2];

		// check if bigram already registered
		for(j=0; j<size-2; j++) {
			if((hist[j][0] == trigram[0]) &&
			   (hist[j][1] == trigram[1]) &&
			   (hist[j][2] == trigram[2])) {
				is_in = 0;
				cntr[j]++;
				break;
			}
		}

		if(is_in!=0) {
			// add bigram
			hist[i][0] = trigram[0];
			hist[i][1] = trigram[1];
			hist[i][2] = trigram[2];
			cntr[i] = 1;
// 			printf("Adding: '%c%c%c'\n", hist[i][0], hist[i][1], hist[i][2]);
		}
	}

	// print histogram with 'depth' most occuring bytes
	for(e=0; e<HIST_DEPTH; e++) {
		for(i=0; i<size-2; i++) {
			if(cntr[i]>0) {
				if(do_print>0)
					printf("Trigram %02x %02x %02x: %d times\n", hist[i][0], hist[i][1], hist[i][2], cntr[i]);
				if(cntr[i]>max.num[e]) {
					max.byte[e][0] = hist[i][0];
					max.byte[e][1] = hist[i][1];
					max.byte[e][2] = hist[i][2];
					max.num[e] = cntr[i];
				}
			}
		}
		// remove element with highest amount
		// in order to catch next element...
		for(j=0; j<size-2; j++) {
			if(cntr[j]==max.num[e]) {
				cntr[j] = 0;
				break;
			}
		}
	}

	// return histogram
	return max;
}

int is_cleartext(unsigned char *in, unsigned int size)
{
	unsigned int i, j, hits=0;
	max_hist_t h;
	init_histogram(&h);

	h = histogram(in, size, 0);

	for(i=0; i<HIST_DEPTH; i++) {
		for(j=0; j<strlen(hist_most_common); j++) {
			if(h.byte[i] == hist_most_common[j])
				hits++;
		}
	}

	if(hits > 3)
// 	if(hits > 4)
		return 0;
	else
		return -1;
}

