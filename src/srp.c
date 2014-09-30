#include <stdio.h>
#include <string.h>

#include "../include/srp.h"

/** SRP Helper Funcs **/
void srp_generate_salted_password_hash(BIGNUM *o_intHash, unsigned char *o_strHash, unsigned char *i_salt, unsigned char *i_password)
{
	unsigned char hash_in[1024];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned int i;

	memset(hash_in, 0, 1024);
	// str = Salt | Pass
	strcpy(hash_in, i_salt);
	strcat(hash_in, i_password);

	// generate sha256 hash
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, hash_in, 1024);
	SHA256_Final(hash, &sha256);
	for(i = 0; i<SHA256_DIGEST_LENGTH; i++) {
		sprintf(o_strHash + (2*i), "%02X", hash[i]);
	}
	o_strHash[SHA256_DIGEST_LENGTH*2] = 0;
	
// 	printf("%s\n", o_strHash);

	// convert hash to int (BIGNUM)
	// x = int(SHA256_hash)
	BN_hex2bn(&o_intHash, o_strHash);
}

void srp_generate_pubkey_hash(BIGNUM *o_intHash, BIGNUM *i_A, BIGNUM *i_B)
{
	unsigned int i;

	// convert A to string
	unsigned int len = BN_num_bytes(i_A);
	unsigned char strA[2*len];
	strncpy(strA, BN_bn2hex(i_A), 2*len);

	// convert B to string
	len = BN_num_bytes(i_B);
	unsigned char strB[2*len];
	strncpy(strB, BN_bn2hex(i_B), 2*len);

	unsigned char str_hash[2*SHA256_DIGEST_LENGTH];
	srp_generate_salted_password_hash(o_intHash, str_hash, strA, strB);
}

/** SRP Protocol Simulation Funcs **/
void srp_server_init(unsigned char *o_salt, BIGNUM *o_v, BIGNUM *o_b, BIGNUM *o_B, unsigned char *i_password, BIGNUM *i_g, BIGNUM *i_N)
{
	unsigned char hash_in[1024];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char str_hash[2*SHA256_DIGEST_LENGTH];
	unsigned int salt, i;

	// needs prior seeding calling srand() apropriately
	salt = rand();
	snprintf(o_salt, 9, "%08X", salt);
	
	BIGNUM x;
	BN_init(&x);

// 	// str = Salt | Pass
	srp_generate_salted_password_hash(&x, str_hash, o_salt, i_password);

	// v = g^x % N
	BN_CTX *ctx = BN_CTX_new();

	BN_mod_exp(o_v, i_g, &x, i_N, ctx);

	// calculate B = k*v      + (g^b % N)
	//               3*v (B3) + dh pub key (B2)
	BIGNUM B2, B3, C3;
	BN_init(&B2);
	BN_init(&B3);
	BN_init(&C3);

	// C3 = 3
	BN_set_word(&C3, 3);

	// B3 = 3*v
	BN_mul(&B3, &C3, o_v, ctx);

	// B2 = dh pub key
	dh_generate_keypair(o_b, &B2, i_g, i_N);

	// B = B3 + B2
	BN_add(o_B, &B3, &B2);

	BN_clear_free(&x);
	BN_clear_free(&B2);
	BN_clear_free(&B3);
	BN_clear_free(&C3);
	BN_CTX_free(ctx);
}

void srp_client_init(BIGNUM *o_a, BIGNUM *o_A, BIGNUM *i_g, BIGNUM *i_N)
{
	dh_generate_keypair(o_a, o_A, i_g, i_N);
}

void srp_server_calc_session_key(unsigned char *o_hash_S, BIGNUM *o_S, BIGNUM *i_A, BIGNUM *i_b, BIGNUM *i_B, BIGNUM *i_v, BIGNUM *i_N)
{
	BIGNUM u, T1, T2;
	BN_init(&u);
	BN_init(&T1);
	BN_init(&T2);
	
	// calc u
	srp_generate_pubkey_hash(&u, i_A, i_B);

	BN_CTX *ctx = BN_CTX_new();

	// S = (A*v^u)^b % N
	// T1 = v^u
// 	printf("calc T1\n");
	BN_mod_exp(&T1, i_v, &u, i_N, ctx);

	// T2 = A*v^u
// 	printf("calc T2\n");
	BN_mod_mul(&T2, i_A, &T1, i_N, ctx);

	// S = T2^b % N
// 	printf("calc S\n");
	BN_mod_exp(o_S, &T2, i_b, i_N, ctx);

	// convert S to string
// 	printf("toString(S)\n");
	unsigned int len = BN_num_bytes(o_S);
	unsigned char strS[2*len];
	strncpy(strS, BN_bn2hex(o_S), 2*len);

	// generate SHA256(S)
// 	printf("hash(S)\n");
	srp_generate_salted_password_hash(&T2, o_hash_S, "", strS);
// 	printf("done\n");

	BN_clear_free(&u);
	BN_clear_free(&T1);
	BN_clear_free(&T2);
	BN_CTX_free(ctx);
}

void srp_client_calc_session_key(unsigned char *o_hash_S, BIGNUM *o_S, unsigned char *i_salt, unsigned char *i_password, BIGNUM *i_a, BIGNUM *i_A, BIGNUM *i_B, BIGNUM *i_g, BIGNUM *i_N)
{
	BIGNUM u, x;
	BN_init(&u);
	BN_init(&x);

	// u = SHA256(A|B)
	srp_generate_pubkey_hash(&u, i_A, i_B);

	// x = SHA256(salt|password)
	unsigned char str_hash[2*SHA256_DIGEST_LENGTH];	// tmp var
	srp_generate_salted_password_hash(&x, str_hash, i_salt, i_password);

	// S = (B - k*g^x) ^ (a + u*x) % N
	//   = ( B^(a + u*x) - k*g^(x*(a + u*x)) ) % N
	//   = ( B^T2 - k*g^(x*T2) ) % N
	//   = (   T3 -  T1 ^ T2 ) % N
	BIGNUM T1, T2, T3, T4, C3;

	BN_init(&C3);
	BN_init(&T1);
	BN_init(&T2);
	BN_init(&T3);
	BN_init(&T4);

	BN_set_word(&C3, 3);

	BN_CTX *ctx = BN_CTX_new();

	// T1 = u*x
	BN_mod_mul(&T1, &u, &x, i_N, ctx);

	// T2 = a + u*x = a + T1
	BN_mod_add(&T2, i_a, &T1, i_N, ctx);

	// T3 = g^x
	BN_mod_exp(&T3, i_g, &x, i_N, ctx);

	// T4 = k*g^x = k*T3
	BN_mod_mul(&T4, &C3, &T3, i_N, ctx);

	// T3 = B - k*g^x = B - T4
	BN_mod_sub(&T3, i_B, &T4, i_N, ctx);

	// S = T3 ^ (a+u*x)
	//    = T3 ^ T2
	BN_mod_exp(o_S, &T3, &T2, i_N, ctx);

	// convert S to string
	unsigned int len = BN_num_bytes(o_S);
	unsigned char strS[2*len];
	strncpy(strS, BN_bn2hex(o_S), 2*len);

	// generate SHA256(S)
	srp_generate_salted_password_hash(&T2, o_hash_S, "", strS);

	BN_clear_free(&u);
	BN_clear_free(&x);
	BN_clear_free(&C3);
	BN_clear_free(&T1);
	BN_clear_free(&T2);
	BN_clear_free(&T3);
	BN_clear_free(&T4);
	BN_CTX_free(ctx);
}
