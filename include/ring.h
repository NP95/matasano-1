/*
 * ring.h
 *
 * Created on: 07.11.2014
 * Author:     rc0r
 */

#ifndef INCLUDE_RING_H_
#define INCLUDE_RING_H_

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

struct egcd_result {
	BIGNUM *a;
	BIGNUM *u;
	BIGNUM *v;
};

typedef struct egcd_result egcd_result_t;

// calculate extended greatest common div. (euclidean algo.)
void egcd(egcd_result_t *o_result, BIGNUM *i_a, BIGNUM *i_b);
// calculate multiplicative inverse (invmod)
int inv_mod(BIGNUM *o_result, BIGNUM *i_a, BIGNUM *i_b);
// calculate Chinese remainder theorem
int crt(BIGNUM *o_result, BIGNUM *o_result_nonmod, BIGNUM **i_n, BIGNUM **i_a, unsigned int i_len);
// calculate n-th (i_n) root of a BIGNUM (i_num)
void nthroot(BIGNUM *o_result, BIGNUM *i_num, BIGNUM *i_n);

/** test funcs **/
void egcd_test(void);
void inv_mod_test(void);
void crt_test(void);
void nthroot_test(void);

#endif /* INCLUDE_RING_H_ */
