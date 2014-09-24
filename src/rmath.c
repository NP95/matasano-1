#include "../include/rmath.h"

int gcf(int a, int b)
{
	int result = 0;

	if(b != 0)
		result = gcf(b, a % b);
	else
		result = a;

	return result;
}

unsigned long modexp(unsigned long base, unsigned long exp, unsigned long p)
{
	unsigned int i;
	unsigned long m = base;

	for(i=1; i<exp; i++) {
		m = (m * base) % p;
	}

	return m;
}
