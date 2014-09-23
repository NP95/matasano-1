#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/dh.h"

int main(int argc, char *argv[])
{
	/** SET 5 CHALLENGE 33 **/
	/**  DH KEY EXCHANGE   **/
	unsigned long long a, A, b, B, s1, s2;

	srand(time(NULL));

	dh_generate_keypair(&a, &A);
	dh_generate_keypair(&b, &B);

	s1 = dh_generate_session_key(a, B);
	s2 = dh_generate_session_key(b, A);

	printf("[s5c1] a = %lld, A = %lld, b = %lld, B = %lld, s = %lld ?= %lld\n", a, A, b, B, s1, s2);

	return 0;
}
