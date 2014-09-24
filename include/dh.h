#ifndef __DH_H
#define __DH_H

#include <math.h>
#include <openssl/bn.h>

static const unsigned int p_smallint = 37;
static const unsigned int g_smallint = 5;

void dh_generate_keypair_smallint(unsigned long *priv_key, unsigned long *pub_key);
unsigned long dh_generate_session_key_smallint(unsigned long priv_key, unsigned long pub_key);

#endif // __DH_H
