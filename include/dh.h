#ifndef __DH_H
#define __DH_H

#include <math.h>
#include <openssl/bn.h>

static const unsigned int p = 37;
static const unsigned int g = 5;

void dh_generate_keypair(unsigned long long *priv_key, unsigned long long *pub_key);
unsigned long long dh_generate_session_key(unsigned long long priv_key, unsigned long long pub_key);

#endif // __DH_H
