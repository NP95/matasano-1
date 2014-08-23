#include "../include/rrand.h"

void mt19937_srand(unsigned int seed)
{
	unsigned int i;
	unsigned long tmp;

	mt19937_index = 0;
	mt19937_state[0] = seed;

	for(i=1; i<624; i++) {
// 		MT[i] := lowest 32 bits of(1812433253 * (MT[i-1] xor (right shift by 30 bits(MT[i-1]))) + i) // 0x6c078965
		tmp = (1812433253 * (mt19937_state[i-1] ^ (mt19937_state[i-1]>>30)) + i);
		tmp = 0x00000000FFFFFFFF & tmp;
		mt19937_state[i] = (unsigned int) tmp;
	}
}

void mt19937_generate(void)
{
	unsigned int i, y;

	for(i=0; i<623; i++) {
		y = (mt19937_state[i] & 0x80000000) + (mt19937_state[(i+1) % 624] & 0x7fffffff);
		mt19937_state[i] = mt19937_state[(i+397) % 624] ^ (y >> 1);

		if((y % 2) != 0)
			mt19937_state[i] ^= 0x9908b0df;
	}
}

unsigned int mt19937_rand(void)
{
	if(mt19937_index==0)
		mt19937_generate();

	unsigned int y = mt19937_state[mt19937_index];

	y = y ^ (y >> 11);
	y = y ^ ((y << 7) & 0x9d2c5680);
	y = y ^ ((y << 15) & 0xefc60000);
	y = y ^ (y >> 18);

	mt19937_index = (mt19937_index + 1) % 624;
	return y;
}

unsigned int mt19937_crack_seed(void)
{
	unsigned int sleep_time = 40 + rand() % 960;

	sleep(sleep_time);
	mt19937_srand((unsigned int) time(NULL));

	sleep_time = 40 + rand() % 960;
	sleep(sleep_time);

	return mt19937_rand();
}

