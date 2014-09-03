#ifndef __RRAND_H
#define __RRAND_H

#include <time.h>
#include <unistd.h>

unsigned int mt19937_state[624];
unsigned int mt19937_index;

void mt19937_srand(unsigned int seed);
void mt19937_generate(void);
unsigned int mt19937_rand(void);

unsigned int mt19937_oracle(void);
unsigned int mt19937_brute_timeseed(void);
unsigned int mt19937_crack(unsigned int *outputs);

/**
 * following code borrowed from:
 * https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html
 **/
unsigned int unBitshiftRightXor(unsigned int value, unsigned int shift);
unsigned int unBitshiftLeftXor(unsigned int value, unsigned int shift, unsigned int mask);
#endif // __RRAND_H
