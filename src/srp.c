#include "../include/hash.h"
#include "../include/srp.h"

/** SRP Helper Funcs **/
void srp_generate_salted_password_hash(BIGNUM *o_intHash, unsigned char *o_strHash, const unsigned char *i_salt, const unsigned char *i_password)
{
	unsigned char hash_in[1024];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned int i;

	memset(hash_in, 0, 1024);
	// str = Salt | Pass
	strcpy(hash_in, i_salt);
	strcat(hash_in, i_password);

	hash_sha256(o_strHash, hash_in, 1024);

	// convert hash to int (BIGNUM)
	// x = int(SHA256_hash)
	BN_hex2bn(&o_intHash, o_strHash);

	return;
}

void srp_generate_pubkey_hash(BIGNUM *o_intHash, BIGNUM *i_A, BIGNUM *i_B)
{
	unsigned int i;

	// convert A to string
	unsigned char *strA = BN_bn2hex(i_A);

	// convert B to string
	unsigned char *strB = BN_bn2hex(i_B);

	unsigned char str_hash[2*SHA256_DIGEST_LENGTH];
	srp_generate_salted_password_hash(o_intHash, str_hash, strA, strB);

	OPENSSL_free(strA);
// 	OPENSSL_free(strB);	// SIGABRT -> invalid pointer?! wtf?!
}

/** SRP Protocol Simulation Funcs **/
void srp_server_init(unsigned char *o_salt, BIGNUM *o_v, BIGNUM *o_b, BIGNUM *o_B, unsigned char *i_password, BIGNUM *i_g, BIGNUM *i_N)
{
	unsigned char hash_in[1024];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char str_hash[2*SHA256_DIGEST_LENGTH+1];
	unsigned int salt, i;

	// needs prior seeding calling srand() apropriately
	salt = rand();
	snprintf(o_salt, 9, "%08X", salt);
	
	BIGNUM *x;
	x = BN_new();

// 	// str = Salt | Pass
	srp_generate_salted_password_hash(x, str_hash, o_salt, i_password);

	// v = g^x % N
	BN_CTX *ctx = BN_CTX_new();

	BN_mod_exp(o_v, i_g, x, i_N, ctx);

	// calculate B = k*v      + g^b % N
	//               3*v (B3) + dh pub key (B2)
	BIGNUM *B2, *B3, *C3;
	B2 = BN_new();
	B3 = BN_new();
	C3 = BN_new();

	// C3 = 3
	BN_set_word(C3, 3);

	// B3 = 3*v
	BN_mod_mul(B3, C3, o_v, i_N, ctx);

	// B2 = dh pub key
	dh_generate_keypair(o_b, B2, i_g, i_N);

	// B = B3 + B2
	BN_mod_add(o_B, B3, B2, i_N, ctx);

	BN_clear_free(x);
	BN_clear_free(B2);
	BN_clear_free(B3);
	BN_clear_free(C3);
	BN_CTX_free(ctx);
}

void srp_client_init(BIGNUM *o_a, BIGNUM *o_A, BIGNUM *i_g, BIGNUM *i_N)
{
	dh_generate_keypair(o_a, o_A, i_g, i_N);
}

void srp_server_calc_session_key(unsigned char *o_hash_S, BIGNUM *o_S, BIGNUM *i_A, BIGNUM *i_b, BIGNUM *i_B, BIGNUM *i_v, BIGNUM *i_N)
{
	BIGNUM *u, *T1, *T2;
	u = BN_new();
	T1 = BN_new();
	T2 = BN_new();

	// calc u
	srp_generate_pubkey_hash(u, i_A, i_B);

	BN_CTX *ctx = BN_CTX_new();

	// S = (A*v^u)^b % N
	// T1 = v^u
	BN_mod_exp(T1, i_v, u, i_N, ctx);

	// T2 = A*v^u
	BN_mod_mul(T2, i_A, T1, i_N, ctx);

	// S = T2^b % N
	BN_mod_exp(o_S, T2, i_b, i_N, ctx);

	// convert S to string
	unsigned char *strS = BN_bn2hex(o_S);

	// generate SHA256(S)
	srp_generate_salted_password_hash(T2, o_hash_S, "", strS);

	OPENSSL_free(strS);
	BN_clear_free(u);
	BN_clear_free(T1);
	BN_clear_free(T2);
	BN_CTX_free(ctx);
}

void srp_client_calc_session_key(unsigned char *o_hash_S, BIGNUM *o_S, unsigned char *i_salt, unsigned char *i_password, BIGNUM *i_a, BIGNUM *i_A, BIGNUM *i_B, BIGNUM *i_g, BIGNUM *i_N)
{
	BIGNUM *u, *x;
	u = BN_new();
	x = BN_new();

	// u = SHA256(A|B)
	srp_generate_pubkey_hash(u, i_A, i_B);

	// x = SHA256(salt|password)
	unsigned char str_hash[2*SHA256_DIGEST_LENGTH];	// tmp var
	srp_generate_salted_password_hash(x, str_hash, i_salt, i_password);

	// S = (B - k*g^x) ^ (a + u*x) % N
	//   = ( B^(a + u*x) - k*g^(x*(a + u*x)) ) % N
	//   = ( B^T2 - k*g^(x*T2) ) % N
	//   = (   T3 -  T1 ^ T2 ) % N
	BIGNUM *T1, *T2, *T3, *T4, *T5, *C3;

	C3 = BN_new();
	T1 = BN_new();
	T2 = BN_new();
	T3 = BN_new();
	T4 = BN_new();
	T5 = BN_new();

	BN_set_word(C3, 3);

	BN_CTX *ctx = BN_CTX_new();

	// T1 = u*x
	BN_mod_mul(T1, u, x, i_N, ctx);

	// T2 = a + u*x = a + T1
	BN_mod_add(T2, i_a, T1, i_N, ctx);

	// T3 = g^x
	BN_mod_exp(T3, i_g, x, i_N, ctx);

	// T4 = k*g^x = k*T3
	BN_mod_mul(T4, C3, T3, i_N, ctx);

	// T5 = B - k*g^x = B - T4
	BN_mod_sub(T5, i_B, T4, i_N, ctx);

	// S = T5 ^ (a+u*x)
	//    = T5 ^ T2
	BN_mod_exp(o_S, T5, T2, i_N, ctx);

	// convert S to string
	unsigned char *strS = BN_bn2hex(o_S);

	// generate SHA256(S)
	srp_generate_salted_password_hash(T2, o_hash_S, "", strS);

	OPENSSL_free(strS);
	BN_clear_free(u);
	BN_clear_free(x);
	BN_clear_free(C3);
	BN_clear_free(T1);
	BN_clear_free(T2);
	BN_clear_free(T3);
	BN_clear_free(T4);
	BN_clear_free(T5);
	BN_CTX_free(ctx);
}

/** Simplified SRP protocol simulation funcs **/
void ssrp_server_init(unsigned char *o_salt, BIGNUM *o_v, BIGNUM *o_b, BIGNUM *o_B, BIGNUM *o_u, unsigned char *i_password, BIGNUM *i_g, BIGNUM *i_N)
{
	unsigned char hash_in[1024];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char str_hash[2*SHA256_DIGEST_LENGTH];
	unsigned int salt, i;

	// needs prior seeding calling srand() apropriately
	salt = rand();
	snprintf(o_salt, 9, "%08X", salt);
	
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *x;
	x = BN_new();

	// str = Salt | Pass
	srp_generate_salted_password_hash(x, str_hash, o_salt, i_password);

	// v = g^x % N
	BN_mod_exp(o_v, i_g, x, i_N, ctx);

	// B = dh pub key
	dh_generate_keypair(o_b, o_B, i_g, i_N);

	// generate random 128 bit number
	// !!proper seeding needed here!!
	unsigned int rseed = time(NULL);
	void *buf = &rseed;
	RAND_seed(buf, 9);

	BN_rand(o_u, 128, 0, 0);

	BN_clear_free(x);
	BN_CTX_free(ctx);
}

void ssrp_server_calc_session_key(unsigned char *o_hash_S, BIGNUM *o_S, BIGNUM *i_A, BIGNUM *i_b, BIGNUM *i_u, BIGNUM *i_v, BIGNUM *i_N)
{
	BIGNUM *T1, *T2;
	T1 = BN_new();
	T2 = BN_new();

	BN_CTX *ctx = BN_CTX_new();

	// S = (A*v^u)^b % N
	// T1 = v^u
	BN_mod_exp(T1, i_v, i_u, i_N, ctx);

	// T2 = A*v^u
	BN_mod_mul(T2, i_A, T1, i_N, ctx);

	// S = T2^b % N
	BN_mod_exp(o_S, T2, i_b, i_N, ctx);

	// convert S to string
	unsigned char *strS = BN_bn2hex(o_S);

	// generate SHA256(S)
	srp_generate_salted_password_hash(T2, o_hash_S, "", strS);

	OPENSSL_free(strS);
	BN_clear_free(T1);
	BN_clear_free(T2);
	BN_CTX_free(ctx);
}


void ssrp_client_init(BIGNUM *o_a, BIGNUM *o_A, BIGNUM *i_g, BIGNUM *i_N)
{
	dh_generate_keypair(o_a, o_A, i_g, i_N);
}

void ssrp_client_calc_session_key(unsigned char *o_hash_S, BIGNUM *o_S, unsigned char *i_salt, unsigned char *i_password, BIGNUM *i_a, BIGNUM *i_B, BIGNUM *i_u, BIGNUM *i_N)
{
	BIGNUM *x;
	x = BN_new();

	// x = SHA256(salt|password)
	unsigned char str_hash[2*SHA256_DIGEST_LENGTH];	// tmp var
	srp_generate_salted_password_hash(x, str_hash, i_salt, i_password);

	// S = B ^ (a + u*x) % N
	BIGNUM *T1, *T2;
	T1 = BN_new();
	T2 = BN_new();

	BN_CTX *ctx = BN_CTX_new();

	// T1 = u*x
	BN_mod_mul(T1, i_u, x, i_N, ctx);

	// T2 = a + u*x = a + T1
	BN_mod_add(T2, i_a, T1, i_N, ctx);

	// S = B ^ (a+u*x)
	//   = B ^ T2
	BN_mod_exp(o_S, i_B, T2, i_N, ctx);

	// convert S to string
	unsigned char *strS = BN_bn2hex(o_S);

	// generate SHA256(S)
	srp_generate_salted_password_hash(T2, o_hash_S, "", strS);

	OPENSSL_free(strS);
	BN_clear_free(x);
	BN_clear_free(T1);
	BN_clear_free(T2);
	BN_CTX_free(ctx);
}

int ssrp_dictionary_attack(unsigned char *o_passwd, unsigned char *i_client_hmac, unsigned char *i_dict_file, BIGNUM *i_A, BIGNUM *i_g, BIGNUM *i_N)
{
	/*
	 * S = B^(a+ux) = B^a*B^ux = A^b*B^ux
	 * we assume client was provided with:
	 * b=1, B=g=2, u=1, salt=""
	 * --> S = B^a*B^ux = A^1*B^x (= A*2^x)
	 *     with x = SHA256(pass)
	 */
	FILE *fp = fopen(i_dict_file, "r");

	if(fp==NULL) {
		printf("Error: Can't read dictionary file %s!\n", i_dict_file);
		return -2;
	}

	short cracked=0;
	char *line_str = NULL;
	size_t len=0;
	ssize_t read;
	unsigned char str_hash[2*SHA256_DIGEST_LENGTH+1];	// tmp var
	unsigned char o_hash_S[2*SHA256_DIGEST_LENGTH+1];
	unsigned char hmac[SHA256_DIGEST_LENGTH];
	unsigned int hmac_len;

	unsigned char *strS;

	BIGNUM *S, *T1, *T2, *x;
	BN_CTX *ctx = BN_CTX_new();

	unsigned int i;

	while((read = getline(&line_str, &len, fp)) != -1) {
		S = BN_new();
		T1 = BN_new();
		T2 = BN_new();
		x = BN_new();

		line_str[read-1]=0;
		// str = Salt | Pass
		srp_generate_salted_password_hash(x, str_hash, "", line_str);

		// T1 = B^x = g^x
		BN_mod_exp(T1, i_g, x, i_N, ctx);

		// S = A^b*B^x = A^1*g^x = A*T1
		BN_mod_mul(S, i_A, T1, i_N, ctx);

		// K = SHA256(S)
		// convert S to string
		strS = BN_bn2hex(S);
		srp_generate_salted_password_hash(T2, o_hash_S, "", strS);

		// L' = HMAC(K, S)
		hmac_len = sha256_secret_prefix_mac(hmac, o_hash_S, strlen(o_hash_S), "", 0);

		// compare to client provided
		if(!strncmp(hmac, i_client_hmac, hmac_len)) {
			strncpy(o_passwd, line_str, read);
			printf("[s5c6] crackd: HMAC(K,\"\") = ");
			for(i=0; i<hmac_len; i++) {
				printf("%02x", hmac[i]);
			}
			printf("\n");

			cracked=1;
		}

		OPENSSL_free(strS);
		BN_free(S);
		BN_free(T1);
		BN_free(T2);

		if(cracked)
			break;
	}

	if(line_str)
		free(line_str);
	close(fp);

	BN_CTX_free(ctx);

	if(cracked)
		return read;
	else
		return -1;
}
