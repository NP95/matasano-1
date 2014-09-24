#include "../include/dh.h"
#include "../include/rmath.h"

/** SMALL NUM FUNCS **/
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

/** BIG NUM FUNCS **/
void dh_init(BIGNUM *p, BIGNUM *g)
{
	BN_init(p);
	BN_init(g);

	if(BN_hex2bn(&p, BN_p_str)==0)
		printf("Error: dh_init(): BN_hex2bn()!\n");

	if(BN_hex2bn(&g, BN_g_str)==0)
		printf("Error: dh_init(): BN_hex2bn()!\n");

	// initialize OpenSSL RNG (in a shitty way)
	while(RAND_status()==0) {
		unsigned int t = (unsigned int) time(NULL);
		RAND_seed(&t, 4);
	}
}

void dh_clear(BIGNUM *p, BIGNUM *g)
{
	BN_clear(p);
	BN_clear(g);
}

void dh_generate_keypair(BIGNUM *priv_key, BIGNUM *pub_key, BIGNUM *g, BIGNUM *p)
{
	BN_CTX *ctx = BN_CTX_new();
	BN_CTX_init(ctx);

	BN_rand_range(priv_key, p);
	BN_mod_exp(pub_key, g, priv_key, p, ctx);

	BN_CTX_free(ctx);
}

void dh_generate_session_key(BIGNUM *session_key, BIGNUM *priv_key, BIGNUM *pub_key, BIGNUM *p)
{
	BN_CTX *ctx = BN_CTX_new();
	BN_CTX_init(ctx);

	BN_mod_exp(session_key, pub_key, priv_key, p, ctx);

	BN_CTX_free(ctx);
}

