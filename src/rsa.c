/*
 * rsa.c
 *
 *  Created on: 25.10.2014
 *      Author: rc0r
 */

#include "../include/rsa.h"
/*
 * Calculates extended euclidean algorithm of two numbers.
 * @NOTE: Might give wrong results for negative numbers a, b.
 *
 * #TODO:
 * Make this work correctly for negative numbers (see:
 * http://rosettacode.org/wiki/Modular_inverse)!
 */
void egcd(egcd_result_t *result, BIGNUM *a, BIGNUM *b)
{
	BIGNUM *q = BN_new();
	BIGNUM *r = BN_new();
	BIGNUM *s = BN_new();
	BIGNUM *t = BN_new();

	BIGNUM *C0 = BN_new();
	BIGNUM *T0 = BN_new();
	BIGNUM *T1 = BN_new();

	BN_CTX *ctx = BN_CTX_new();

	BN_zero(s);
	BN_one(t);
	BN_one(result->u);
	BN_zero(result->v);
	BN_zero(C0);

	unsigned int i = 0;

	while(BN_cmp(b, C0) > 0) {
		BN_div(q, r, a, b, ctx);

		// a, b = b, a-q*b
		BN_mul(T0, q, b, ctx);
		BN_sub(T1, a, T0);
		BN_copy(a, b);
		BN_copy(b, T1);

		// u, s = s, u-q*s
		BN_mul(T0, q, s, ctx);
		BN_sub(T1, result->u, T0);
		BN_copy(result->u, s);
		BN_copy(s, T1);

		// v, t = t, v-q*t
		BN_mul(T0, q, t, ctx);
		BN_sub(T1, result->v, T0);
		BN_copy(result->v, t);
		BN_copy(t, T1);
	}

	BN_copy(result->a, a);

	BN_free(q);
	BN_free(r);
	BN_free(s);
	BN_free(t);
	BN_free(C0);
	BN_free(T0);
	BN_free(T1);
	BN_CTX_free(ctx);
}

/*
 * Calculates modular multiplicative inverse using the extended
 * euclidean algorthim.
 * @NOTE: Might give wrong results for negative parameters op1, op2
 * since we're using egcd() here!
 *
 * #TODO:
 * Make this work correctly for negative numbers (see:
 * http://rosettacode.org/wiki/Modular_inverse)!
 */
int inv_mod(BIGNUM *result, BIGNUM *op1, BIGNUM *op2)
{
	BIGNUM *op1_saved = BN_new();

	egcd_result_t res;

	res.a = BN_new();
	res.u = BN_new();
	res.v = BN_new();

	BN_copy(op1_saved, op1);

	egcd(&res, op1, op2);

	if(!BN_is_one(res.a)) {
		return -1;
	}

	if(BN_is_negative(res.v)) {
		BN_add(result, res.v, op1_saved);
	}
	else {
		BN_copy(result, res.v);
	}

	BN_free(op1_saved);
	BN_free(res.a);
	BN_free(res.u);
	BN_free(res.v);

	return 0;
}
