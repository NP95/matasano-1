#include <stdio.h>
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

void mt19937_srand_states(unsigned int *states)
{
	unsigned int i;

	mt19937_index = 0;
	for(i=0; i<624; i++) {
		mt19937_state[i] = states[i];
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
// 	printf("[s3c6] real_state = %08x\n", y);

	y = y ^ (y >> 11);
// 	printf("[s3c6] real_state = %08x\n", y);
	y = y ^ ((y << 7) & 0x9d2c5680);
// 	printf("[s3c6] real_state = %08x\n", y);
	y = y ^ ((y << 15) & 0xefc60000);
	y = y ^ (y >> 18);

	mt19937_index = (mt19937_index + 1) % 624;
	return y;
}

unsigned int mt19937_brute_timeseed(void)
{
	unsigned int start_time = time(NULL);
	unsigned int out = mt19937_oracle();
	unsigned int stop_time = time(NULL);

	unsigned int i=0;

	// brute force seed in range of possible values
	for(i=start_time; i<stop_time; i++) {
		mt19937_srand(i);
		if(mt19937_rand() == out)
			return i;
	}

	return 0;
}
	
unsigned int mt19937_recover_states(unsigned int *outputs, unsigned int *recovered_states)
{
	unsigned int *y = outputs;
	unsigned int state[624];
	unsigned int i;

	for(i=0; i<624; i++) {
		state[i] = unBitshiftRightXor(y[i], 18);
		state[i] = unBitshiftLeftXor(state[i], 15, 0xefc60000);
		state[i] = unBitshiftLeftXor(state[i], 7, 0x9d2c5680);
		state[i] = unBitshiftRightXor(state[i], 11);
	}

	memcpy(recovered_states, state, 624 * sizeof(unsigned int));
// 	printf("[s3c6] crck_state = %08x\n", y);

	return state[0];
}

unsigned int mt19937_oracle(void)
{
	unsigned int sleep_time = 40 + rand() % 960;
	unsigned int seed = 0;

	sleep(sleep_time);
	seed = (unsigned int) time(NULL);
	printf("[s3c6] seed = %08x\n", seed);
	mt19937_srand(seed);

	sleep_time = 40 + rand() % 960;
	sleep(sleep_time);

	return mt19937_rand();
}

/**
 * following code borrowed from:
 * https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html
 **/
unsigned int unBitshiftRightXor(unsigned int value, unsigned int shift)
{
	// we part of the value we are up to (with a width of shift bits)
	unsigned int i = 0;
	// we accumulate the result here
	unsigned int result = 0;
	// iterate until we've done the full 32 bits
	while (i * shift < 32) {
		// create a mask for this part
		unsigned int partMask = (0xffffffff << (32 - shift)) >>/*>*/ (shift * i);
		// obtain the part
		unsigned int part = value & partMask;
		// unapply the xor from the next part of the integer
		value ^= part >>/*>*/ shift;
		// add the part to the result
		result |= part;
		i++;
	}
	return result;
}

unsigned int unBitshiftLeftXor(unsigned int value, unsigned int shift, unsigned int mask)
{
	// we part of the value we are up to (with a width of shift bits)
	unsigned int i = 0;
	// we accumulate the result here
	unsigned int result = 0;
	// iterate until we've done the full 32 bits
	while (i * shift < 32) {
		// create a mask for this part
		unsigned int partMask = (0xffffffff >>/*>*/ (32 - shift)) << (shift * i);
		// obtain the part
		unsigned int part = value & partMask;
		// unapply the xor from the next part of the integer
		value ^= (part << shift) & mask;
		// add the part to the result
		result |= part;
		i++;
	}
	return result;
}
