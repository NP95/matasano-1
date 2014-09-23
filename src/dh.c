#include "../include/dh.h"


void dh_generate_keypair(unsigned long long *priv_key, unsigned long long *pub_key)
{
	unsigned long long a = rand() % p;
	(*priv_key) = a;
	unsigned long long A = g;
	unsigned int i;
       
	for(i=1; i<a; i++) {
		A = (A * g) % p;
	}

	(*pub_key) = A;
}

unsigned long long dh_generate_session_key(unsigned long long local_priv_key, unsigned long long remote_pub_key)
{
	unsigned long long s = remote_pub_key;
	unsigned int i;
		
	for(i=1; i<local_priv_key; i++) {
		s = (s * remote_pub_key) % p;
	}

	return s;
}
