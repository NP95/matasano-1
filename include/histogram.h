#ifndef __HISTOGRAM_H
#define __HISTOGRAM_H

#include <stdio.h>
#include <string.h>

#define HIST_DEPTH	10

struct max_hist {
	unsigned char byte[HIST_DEPTH];
	unsigned int num[HIST_DEPTH];
};

typedef struct max_hist max_hist_t;

static const unsigned char *hist_most_common = "ETAOINSHRDLU etaoinshrdlu";

void init_histogram(max_hist_t *hist);
max_hist_t print_histogram(unsigned char *input, unsigned int size, unsigned short do_print);
int is_cleartext(unsigned char *in, unsigned int size);

#endif // __HISTOGRAM_H
