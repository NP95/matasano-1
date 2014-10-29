/*
 * rsa.c
 *
 *  Created on: 25.10.2014
 *  Author:     rc0r
 */

#include "../include/hex_coder.h"
#include "../include/rsa.h"

void rsa_generate_keypair(rsa_key_t *o_pubkey, rsa_key_t *o_privkey, unsigned long i_bits)
{
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *t = BN_new();

	BIGNUM *C1 = BN_new();
	BIGNUM *T0 = BN_new();
	BIGNUM *T1 = BN_new();

	BN_CTX *ctx = BN_CTX_new();

	// set e = BN_e_str (=3)
	BN_hex2bn(&o_pubkey->e, BN_e_str);

	// generate primes p, q (p != q)
	BN_generate_prime_ex(p, i_bits, 1, NULL, NULL, NULL);
	do {
		BN_generate_prime_ex(q, i_bits, 1, NULL, NULL, NULL);
	} while(!BN_cmp(p, q));

	// n = p*q
	BN_mul(o_pubkey->n, p, q, ctx);
	BN_copy(o_privkey->n, o_pubkey->n);

	// t = (p-1)*(q-1) = 1 + p*q - (p + q)
	BN_one(C1);
	BN_mod_mul(T0, p, q, o_pubkey->n, ctx);
	BN_mod_add(T1, C1, T0, o_pubkey->n, ctx);
	BN_mod_add(T0, p, q, o_pubkey->n, ctx);
	BN_mod_sub(t, T1, T0, o_pubkey->n, ctx);

	// e' = d = invmod(e, t)
	// ok we're cheating here. using our own buggy invmod
	// func seems not to be a good idea. needs improving
	// first.
	BN_mod_inverse(o_privkey->e, o_pubkey->e, t, ctx);

	BN_free(p);
	BN_free(q);
	BN_free(t);

	BN_free(T0);
	BN_free(T1);

	BN_CTX_free(ctx);
}

void rsa_bn_encrypt(BIGNUM *o_crypted, BIGNUM *i_plain, rsa_key_t *i_pubkey)
{
	BN_CTX *ctx = BN_CTX_new();
	// c = m^e % n
	BN_mod_exp(o_crypted, i_plain, i_pubkey->e, i_pubkey->n, ctx);
	BN_CTX_free(ctx);
}

void rsa_bn_decrypt(BIGNUM *o_plain, BIGNUM *i_crypted, rsa_key_t *i_privkey)
{
	BN_CTX *ctx = BN_CTX_new();
	// m = c^d % n
	BN_mod_exp(o_plain, i_crypted, i_privkey->e, i_privkey->n, ctx);
	BN_CTX_free(ctx);
}

unsigned int rsa_encrypt(unsigned char **o_crypt, unsigned char *i_plain, unsigned int i_plain_len, rsa_key_t *i_pubkey)
{
	unsigned char *plain_hex = NULL;
	unsigned char *crypt_hex = NULL;
	unsigned int crypt_len = 0;
	hex_encode(&plain_hex, i_plain, i_plain_len);

	BIGNUM *plain = BN_new();
	BIGNUM *crypt = BN_new();

	BN_hex2bn(&plain, plain_hex);

	rsa_bn_encrypt(crypt, plain, i_pubkey);

	crypt_hex = BN_bn2hex(crypt);
	crypt_len = hex_decode(o_crypt, crypt_hex, strlen(crypt_hex));

	BN_free(plain);
	BN_free(crypt);

	OPENSSL_free(crypt_hex);
	free(plain_hex);

	return crypt_len;
}

unsigned int rsa_decrypt(unsigned char **o_plain, unsigned char *i_crypt, unsigned int i_crypt_len, rsa_key_t *i_privkey)
{
	unsigned char *plain_hex = NULL;
	unsigned char *crypt_hex = NULL;
	unsigned int plain_len = 0;
	hex_encode(&crypt_hex, i_crypt, i_crypt_len);

	BIGNUM *plain = BN_new();
	BIGNUM *crypt = BN_new();

	BN_hex2bn(&crypt, crypt_hex);

	rsa_bn_decrypt(plain, crypt, i_privkey);

	plain_hex = BN_bn2hex(plain);
//	plain_len = 2*BN_num_bytes(plain);
	plain_len = strlen(plain_hex);

	plain_len = hex_decode(o_plain, plain_hex, plain_len);

	BN_free(plain);
	BN_free(crypt);

	OPENSSL_free(plain_hex);
	free(crypt_hex);

	return plain_len;
}

/*
 * Performs RSA broadcast attack as follows:
 * Provide a series of cipher texts (i_crypted[]) that correspond
 * to the *same* plain text but were encrypted using different
 * public keys (i_pubkeys[]).
 * The Chinese remainder theorem is applied to decrypt the provided
 * message.
 *
 * @NOTE: Might give wrong results since we're using possibly
 *         buggy egcd() here!
 *
 * @return
 * 		Length of decrypted plain text, -1 on error.
 *
 * @param o_plain
 * 		Will contain the decrypted plain text.
 * @param i_crypted
 * 		Array containing different cipher texts (for the *same*
 * 		plain text).
 * @param i_crypted_len
 * 		Array containing the message lengths of the different
 * 		cipher texts provided in i_crypted.
 * @param i_pubkeys
 * 		Array containing the respective RSA public keys used to
 * 		encrypt the provided cipher texts.
 * @param len
 * 		Number of provided cipher texts and RSA public keys
 * 		(number of elements in the provided arrays).
 */
int rsa_broadcast_attack(unsigned char **o_plain, unsigned char *i_crypted[], unsigned int i_crypted_len[], rsa_key_t *i_pubkeys[], unsigned int len)
{
	unsigned char *crypted_hex[len];
	unsigned char *hex_plain = NULL;
	unsigned int hex_plain_len;
	BIGNUM *n[len];
	BIGNUM *BN_crypt[len];
	BIGNUM *BN_plain = BN_new();
	BIGNUM *C3 = BN_new();
	BIGNUM *C1 = BN_new();
	BIGNUM *prod = BN_new();
	BIGNUM *T0 = BN_new();

	BN_CTX *ctx = BN_CTX_new();

	BN_dec2bn(&C3, "3");
	BN_dec2bn(&C1, "1");
	BN_one(prod);

	unsigned int i;

	// initialize and convert input strings to BN
	for(i=0; i<len; i++) {
		crypted_hex[i] = NULL;
		BN_crypt[i] = BN_new();
		n[i] = BN_new();

		hex_encode(&crypted_hex[i], ((unsigned char *)i_crypted[i]), ((unsigned int)i_crypted_len[i]));
		if(!BN_hex2bn(&(BN_crypt[i]), crypted_hex[i]))
			return -1;

		BN_copy(n[i], ((rsa_key_t *)(i_pubkeys[i]))->n);

		BN_mul(prod, prod, n[i], ctx);
	}

	BIGNUM *crt_res = BN_new();
	BIGNUM *crt_res_nm = BN_new();

//	c_i = m^3 (mod n_i), i = [1..3]
	crt(crt_res, crt_res_nm, n, BN_crypt, len);

	BN_set_word(C3, (unsigned long) len);
	nthroot(BN_plain, crt_res, C3);

	hex_plain = BN_bn2hex(BN_plain);
	hex_plain_len = strlen(hex_plain);

	hex_plain_len = hex_decode(o_plain, hex_plain, hex_plain_len);

	// free memory
	BN_free(crt_res);
	BN_free(crt_res_nm);
	BN_free(BN_plain);
	BN_free(C3);
	BN_free(C1);
	BN_free(prod);
	BN_free(T0);

	OPENSSL_free(hex_plain);

	for(i=0; i<len; i++) {
		free(crypted_hex[i]);
		BN_free(BN_crypt[i]);
	}

	BN_CTX_free(ctx);

	return hex_plain_len;
}

/*
 * Provides a simple test case for rsa_broadcast_attack().
 */
void rsa_broadcast_attack_test(void)
{
	BIO *out = BIO_new(BIO_s_file());
	BIO_set_fp(out, stdout, BIO_NOCLOSE);

	unsigned int i;
	unsigned int num = 3;

	rsa_key_t *puk[num];
	rsa_key_t pik[num];
	unsigned char *plain = "THE KING IS GONE BUT NOT FORGOTTEN!"; // 35
//	unsigned char *plain = "\x02"; // 1
	unsigned int plain_len = strlen(plain);
	unsigned char *crypt[num];
	unsigned int crypt_len[num];
	unsigned char *decrypt = NULL;
	unsigned int decrypt_len = 0;

	for(i=0; i<num; i++) {
		puk[i] = malloc(sizeof(rsa_key_t *));
		puk[i]->e = BN_new();
		puk[i]->n = BN_new();
		pik[i].e = BN_new();
		pik[i].n = BN_new();

		/*
		 * ATTENTION: In order for this attack to work, you need
		 *             to pay attention to the key size:
		 *             plain < n[i] !!! ( < plain^3)
		 *
		 *             If plain^3 < n[i] then you'll get three
		 *             identical cipher texts...
		 */
		rsa_generate_keypair(puk[i], &pik[i], 256);

		/*
		 * I'll leave this in the code, it helps debugging and
		 * understanding the attack with small numbers.
		 * Use plain = "\x02" as input!
		 */
//		switch(i) {
//		case 0:
//			BN_dec2bn(&(puk[i]->n), "3"); // 3
//			break;
//		case 1:
//			BN_dec2bn(&(puk[i]->n), "5"); // 5
//			break;
//		case 2:
//			BN_dec2bn(&(puk[i]->n), "7"); // 7
//			break;
//		}

		crypt[i] = NULL;

		crypt_len[i] = rsa_encrypt(&(crypt[i]), plain, plain_len, puk[i]);
	}

	decrypt_len = rsa_broadcast_attack(&decrypt, crypt, crypt_len, puk, num);

	printf("[s5c8] crt_decrypt(%2d) = '%s'\n", decrypt_len, decrypt);

	for(i=0; i<num; i++) {
		free(crypt[i]);
		BN_free(puk[i]->e);
		BN_free(puk[i]->n);
		BN_free(pik[i].e);
		BN_free(pik[i].n);
		free(puk[i]);
	}

	free(decrypt);
	BIO_free(out);
}

/*** Helper functions ***/
/*
 * Calculates extended euclidean algorithm of two numbers.
 * @NOTE: Might give wrong results for negative numbers a, b.
 *
 * #TODO:
 * Make this work correctly for negative numbers (see:
 * http://rosettacode.org/wiki/Modular_inverse)!
 */
void egcd(egcd_result_t *o_result, BIGNUM *i_a, BIGNUM *i_b)
{
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();

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
	BN_one(o_result->u);
	BN_zero(o_result->v);
	BN_zero(C0);

	BN_copy(a, i_a);
	BN_copy(b, i_b);

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
		BN_sub(T1, o_result->u, T0);
		BN_copy(o_result->u, s);
		BN_copy(s, T1);

		// v, t = t, v-q*t
		BN_mul(T0, q, t, ctx);
		BN_sub(T1, o_result->v, T0);
		BN_copy(o_result->v, t);
		BN_copy(t, T1);
	}

	BN_copy(o_result->a, a);

	BN_free(a);
	BN_free(b);
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
 * Provides a simple test case for egcd().
 */
void egcd_test(void)
{
	BIGNUM *egcd_a = BN_new();
	BIGNUM *egcd_b = BN_new();
	BIGNUM *minv   = BN_new();

	egcd_result_t res;

	res.a = BN_new();
	res.u = BN_new();
	res.v = BN_new();

	BN_dec2bn(&egcd_a, "3120");
	BN_dec2bn(&egcd_b, "17");
	egcd(&res, egcd_a, egcd_b);

	BIO *out = BIO_new(BIO_s_file());
	BIO_set_fp(out, stdout, BIO_NOCLOSE);

	printf("[s5c7] egcd.a = ");
	BN_print(out, res.a);
	printf("\n[s5c7] egcd.u = ");
	BN_print(out, res.u);
	printf("\n[s5c7] egcd.v = ");
	BN_print(out, res.v);
	printf("\n");

	//	[s5c7] egcd.a = 1
	//	[s5c7] egcd.u = 2
	//	[s5c7] egcd.v = -16F
	unsigned char *ca = BN_bn2hex(res.a);
	unsigned char *cu = BN_bn2hex(res.u);
	unsigned char *cv = BN_bn2hex(res.v);

	if(strcmp(ca, "01") || strcmp(cu, "02") || strcmp(cv, "-016F")) {
		printf("[s5c7] egcd_test failed(01 != %s, 02 != %s, -016F != %s)!\n", ca, cu, cv);
	}

	OPENSSL_free(ca);
	OPENSSL_free(cu);
	OPENSSL_free(cv);

	BN_free(egcd_a);
	BN_free(egcd_b);
	BN_free(res.a);
	BN_free(res.u);
	BN_free(res.v);

	BIO_free(out);
}

/*
 * Calculates modular multiplicative inverse using the extended
 * euclidean algorthim:
 * Returns 'result' where (op1*result) % op2 == 1.
 *
 * @NOTE: Might give wrong results for negative parameters op1, op2
 *         since we're using possibly buggy egcd() here!
 *
 * #TODO:
 * Make this work correctly for negative numbers (see:
 * http://rosettacode.org/wiki/Modular_inverse)!
 */
int inv_mod(BIGNUM *result, BIGNUM *op1, BIGNUM *op2)
{
	egcd_result_t res;

	res.a = BN_new();
	res.u = BN_new();
	res.v = BN_new();

	egcd(&res, op1, op2);

	if(!BN_is_one(res.a)) {
		return -1;
	}

	if(BN_is_negative(res.v)) {
		BN_add(result, res.v, op1);
	}
	else {
		BN_copy(result, res.v);
	}

	BN_free(res.a);
	BN_free(res.u);
	BN_free(res.v);

	return 0;
}

/*
 * Provides a simple test case for inv_mod().
 */
void inv_mod_test(void)
{
	BIGNUM *egcd_a = BN_new();
	BIGNUM *egcd_b = BN_new();
	BIGNUM *minv   = BN_new();

	egcd_result_t res;

	res.a = BN_new();
	res.u = BN_new();
	res.v = BN_new();

	BN_dec2bn(&egcd_a, "3120");
	BN_dec2bn(&egcd_b, "17");

	BIO *out = BIO_new(BIO_s_file());
	BIO_set_fp(out, stdout, BIO_NOCLOSE);

	if(!inv_mod(minv, egcd_a, egcd_b)) {
		printf("[s5c7] inv_mod = ");
		BN_print(out, minv);
		printf("\n");
	} else {
		printf("[s5c7] No inverse found!\n");
	}

//	[s5c7] inv_mod = AC1
	unsigned char *cminv = BN_bn2hex(minv);
	if(strcmp(cminv, "0AC1")) {
		printf("[s5c7] inv_mod_test failed (0AC1 != %s)!\n", cminv);
	}
	OPENSSL_free(cminv);

	BN_free(egcd_a);
	BN_free(egcd_b);
	BN_free(res.a);
	BN_free(res.u);
	BN_free(res.v);

	BIO_free(out);
}

/*
 * Calculates Chinese remainder theorem.
 *
 * @NOTE: Might give wrong results since we're using possibly
 *         buggy egcd() here!
 *
 * Source: http://rosettacode.org/wiki/Chinese_remainder_theorem
 */
int crt(BIGNUM *o_result, BIGNUM *o_result_nonmod, BIGNUM *i_n[], BIGNUM *i_a[], unsigned int i_len)
{
	BIGNUM *p = BN_new();
	BIGNUM *prod = BN_new();
	BIGNUM *sum = BN_new();
	BIGNUM *rem = BN_new();

	BIGNUM *T0 = BN_new();
	BIGNUM *T1 = BN_new();
	BIGNUM *T2 = BN_new();

	BN_CTX *ctx = BN_CTX_new();

	unsigned int i, failed = 0;

	BN_one(prod);
	BN_zero(sum);

	for(i=0; i<i_len; i++) {
		BN_mul(prod, prod, ((BIGNUM *)i_n[i]), ctx);
	}

	for(i=0; i<i_len; i++) {
		BN_div(p, rem, prod, ((BIGNUM *)i_n[i]), ctx);

		if(!inv_mod(T0, ((BIGNUM *)i_n[i]), p)) {
//		if(BN_mod_inverse(T0, p, ((BIGNUM *)i_n[i]), ctx)!=NULL) {
			BN_mul(T1, T0, p, ctx);
			BN_mul(T2, T1, ((BIGNUM *)i_a[i]), ctx);
			BN_add(sum, sum, T2);
		}
		else {
			failed = 1;
			break;
		}
	}

	BN_copy(o_result_nonmod, sum);
	BN_mod(o_result, sum, prod, ctx);

	BN_free(p);
	BN_free(prod);
	BN_free(sum);
	BN_free(rem);

	BN_free(T0);
	BN_free(T1);
	BN_free(T2);

	BN_CTX_free(ctx);

	if(failed) {
		return -1;
	} else {
		return 0;
	}
}

void crt_test(void)
{
	unsigned int i;
	unsigned int BN_len = 3;
	BIGNUM *BN_a[BN_len], *BN_n[BN_len];

	BIO *out = BIO_new(BIO_s_file());
	BIO_set_fp(out, stdout, BIO_NOCLOSE);

	for(i=0; i<BN_len; i++) {
		BN_a[i] = BN_new();
		BN_n[i] = BN_new();
	}

	// test our CRT implementation
	// res = 23d = 17h
	BN_dec2bn(&BN_a[0], "2");
	BN_dec2bn(&BN_a[1], "3");
	BN_dec2bn(&BN_a[2], "2");

	BN_dec2bn(&BN_n[0], "3");
	BN_dec2bn(&BN_n[1], "5");
	BN_dec2bn(&BN_n[2], "7");

	// res = 2785d = 0AE1h
//	BN_dec2bn(&BN_a[0], "2");
//	BN_dec2bn(&BN_a[1], "3");
//	BN_dec2bn(&BN_a[2], "2");
//
//	BN_dec2bn(&BN_n[0], "11");
//	BN_dec2bn(&BN_n[1], "13");
//	BN_dec2bn(&BN_n[2], "23");

	BIGNUM *BN_res = BN_new();
	BIGNUM *BN_res_nomod = BN_new();

	if(!crt(BN_res, BN_res_nomod, BN_n, BN_a, BN_len)) {
		printf("[s5c8] crt_res = '");
		BN_print(out, BN_res);
		printf("'\n[s5c8] crt_rnm = '");
		BN_print(out, BN_res_nomod);
		printf("'\n");
	} else {
		printf("[s5c8] Sorry CRT could note be solved!\n");
	}

	unsigned char *cb = BN_bn2hex(BN_res);
	if(strcmp(cb, "17")) {
		printf("[s5c7] crt_test failed (17 != %s)!\n", cb);
	}
	OPENSSL_free(cb);

	BN_free(BN_res);
	BN_free(BN_res_nomod);

	for(i=0; i<BN_len; i++) {
		BN_free(BN_a[i]);
		BN_free(BN_n[i]);
	}

	BIO_free(out);
}

/*
 * Calculates n-th root of a BIGNUM.
 *
 * @return void
 * @param o_result
 * 		Pointer to BIGNUM that will hold the result.
 * @param i_num
 * 		BIGNUM to be rooted.
 * @param i_n
 * 		BIGNUM holding n parameter (choose n=2 for sqrt,
 * 		n=3 for cbrt, ...).
 */
void nthroot(BIGNUM *o_result, BIGNUM *i_num, BIGNUM *i_n)
{
	BIGNUM *x = BN_new();
	BIGNUM *p = BN_new();
	BIGNUM *T0 = BN_new();
	BIGNUM *T1 = BN_new();
	BIGNUM *T2 = BN_new();
	BIGNUM *C1 = BN_new();
	BIGNUM *C0 = BN_new();
	BIGNUM *R = BN_new();
	BIGNUM *N = BN_new();

	BN_CTX *ctx = BN_CTX_new();

	BN_one(C1);
	BN_zero(C0);
	BN_copy(T0, i_num);
	BN_copy(x, i_num);
	BN_sub(N, i_n, C1);

	while(BN_cmp(T0, C0)==1) {
		BN_copy(p, x);
		BN_mul(T0, N, p, ctx);
		BN_exp(T1, p, N, ctx);
		BN_div(T2, R, i_num, T1, ctx);
		BN_add(T1, T0, T2);
		BN_div(x, R, T1, i_n, ctx);

		BN_sub(T0, p, x);
	}

	BN_copy(o_result, x);

	BN_free(x);
	BN_free(p);
	BN_free(T0);
	BN_free(T1);
	BN_free(T2);
	BN_free(C0);
	BN_free(C1);
	BN_free(R);
	BN_free(N);

	BN_CTX_free(ctx);
}

void nthroot_test(void)
{
	BIGNUM *test1 = BN_new();
	BIGNUM *test2 = BN_new();
	BIGNUM *test3 = BN_new();

	BIO *out = BIO_new(BIO_s_file());
	BIO_set_fp(out, stdout, BIO_NOCLOSE);

	BN_dec2bn(&test1, "729");
	BN_dec2bn(&test2, "3");

	nthroot(test3, test1, test2);

	printf("[s5c8] cbrt(729) = ");
	BN_print(out, test3);
	printf("\n");

	unsigned char *cb = BN_bn2hex(test3);
	if(strcmp(cb, "09")) {
		printf("[s5c7] nthroot_test failed (09 != %s)!\n", cb);
	}
	OPENSSL_free(cb);

	BN_free(test1);
	BN_free(test2);
	BN_free(test3);
	BIO_free(out);
}
