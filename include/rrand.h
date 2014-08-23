#ifndef __RRAND_H
#define __RRAND_H

#include <time.h>
#include <unistd.h>

unsigned int mt19937_state[624];
unsigned int mt19937_index;

void mt19937_srand(unsigned int seed);
void mt19937_generate(void);
unsigned int mt19937_rand(void);

unsigned int mt19937_crack_seed(void);

#endif // __RRAND_H
