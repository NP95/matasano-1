/*
 * rsa.h
 *
 *  Created on: 25.10.2014
 *      Author: rc0r
 */

#ifndef INCLUDE_RSA_H_
#define INCLUDE_RSA_H_

#include <openssl/bn.h>
#include <openssl/rand.h>

struct egcd_result {
	BIGNUM *a;
	BIGNUM *u;
	BIGNUM *v;
};

typedef struct egcd_result egcd_result_t;

/** Helper functions **/
// calculate extended greatest common div. (euclidean algo.)
void egcd(egcd_result_t *result, BIGNUM *a, BIGNUM *b);
// calculate multiplicative inverse (invmod)
int inv_mod(BIGNUM *result, BIGNUM *a, BIGNUM *b);

#endif /* INCLUDE_RSA_H_ */
