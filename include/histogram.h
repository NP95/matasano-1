#ifndef __HISTOGRAM_H
#define __HISTOGRAM_H

#include <stdio.h>
#include <string.h>

#define HIST_DEPTH	15

// single character histogram
struct max_hist {
	unsigned char byte[HIST_DEPTH];
	unsigned int num[HIST_DEPTH];
};
typedef struct max_hist max_hist_t;

// bigram histogram
struct max_hist2 {
	unsigned char byte[HIST_DEPTH][2];
	unsigned int num[HIST_DEPTH];
};
typedef struct max_hist2 max_hist2_t;

// trigram histogram
struct max_hist3 {
	unsigned char byte[HIST_DEPTH][3];
	unsigned int num[HIST_DEPTH];
};
typedef struct max_hist3 max_hist3_t;

static const unsigned char *hist_most_common = "ETAOINSHRDLU etaoinshrdlu";

void init_histogram(max_hist_t *hist);
void init_histogram2(max_hist2_t *hist);
void init_histogram3(max_hist3_t *hist);

max_hist_t histogram(unsigned char *input, unsigned int size, unsigned short do_print);
max_hist2_t histogram2(unsigned char *input, unsigned int size, unsigned short do_print);
max_hist3_t histogram3(unsigned char *input, unsigned int size, unsigned short do_print);

int is_cleartext(unsigned char *in, unsigned int size);

#endif // __HISTOGRAM_H
