#include "../include/dh.h"
#include "../include/rmath.h"

void dh_generate_keypair_smallint(unsigned long *priv_key, unsigned long *pub_key)
{
	unsigned long a = rand() % p_smallint;
	(*priv_key) = a;

	(*pub_key) = modexp(g_smallint, a, p_smallint);
}

unsigned long dh_generate_session_key_smallint(unsigned long local_priv_key, unsigned long remote_pub_key)
{
	return modexp(remote_pub_key, local_priv_key, p_smallint);
}
