/*
 * rsa.c
 *
 *  Created on: 25.10.2014
 *  Author:     rc0r
 */

//#include <openssl/sha.h>

#include "../include/hash.h"
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
	BN_free(C1);

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

	// c_i = m^3 (mod n_i), i = [1..3]
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

/*
 * Implements an RSA oracle that takes user encrypted cipher texts,
 * decrypts them and returns the corresponding plain texts.
 * In the original sense the oracle rejects requests containing the same
 * cipher text more than once.
 * For simplicity we'll omit this part. And assume the attacker supplies
 * captured cipher texts (that were already used) modified according to #41
 * in order to trick the oracle into decrypting them.
 *
 * @return
 * 		void
 * @param o_plain
 * 		Pointer to BIGNUM containing the decrypted message (needs to be
 * 		converted to unsigned char * by th user).
 * @param i_cipher
 * 		Pointer to BIGNUM containing the cipher text to be decrypted.
 * @param i_privkey
 * 		Private key to use for decryption. (In a real world application
 * 		this key would be stored on the server and would obviously *NOT* be
 * 		provided by the client/user.)
 */
void rsa_unpadded_msg_oracle(BIGNUM *o_plain, BIGNUM *i_cipher, rsa_key_t *i_privkey)
{
	// a simple RSA decrypt on BIGNUMs is all we need...
	rsa_bn_decrypt(o_plain, i_cipher, i_privkey);
}

/*
 * Performs the attack on the rsa_unpadded_msg_oracle() by modifying
 * captured messages. Fed into the oracle, the original plain texts are
 * recovered from the oracles response. So basically, we're tricking the
 * oracle into decrypting a message it has already seen.
 *
 * @return
 * 		Length in bytes of the recovered plain text, -1 on error.
 * @param o_plain
 * 		Pointer to string containing the recovered plain text.
 * @param i_ciphertext
 * 		The original, captured input that was already fed into the oracle.
 * @param i_ciphertext_len
 * 		The length in bytes of the original plain text.
 * @param i_pubkey
 * 		The public key that was used to encrypt the original message.
 * @param i_privkey
 * 		The private key used by the server. (Again, this key would/should
 * 		not	cross any wire in a real world setup. We're providing it here
 * 		to simplify the use of the "attack simulation" funcs.)
 */
int rsa_unpadded_msg_oracle_attack(unsigned char **o_plain, unsigned char *i_ciphertext, unsigned int i_ciphertext_len, rsa_key_t *i_pubkey, rsa_key_t *i_privkey)
{
	unsigned char *crypt_hex = NULL;
	unsigned char *plain_hex = NULL;
	int plain_hex_len = 0;
	unsigned int failed = 0;

	BIGNUM *crypt = BN_new();
	BIGNUM *T0 = BN_new();
	BIGNUM *S = BN_new();
	BIGNUM *C_mod = BN_new();
	BIGNUM *plain_mod = BN_new();
	BIGNUM *plain = BN_new();

	BN_CTX *ctx = BN_CTX_new();

	// #TODO: proper seed needed a-priori!
	BN_rand(T0, 128, 0, 0);
	BN_mod(S, T0, i_pubkey->n, ctx);

	hex_encode(&crypt_hex, i_ciphertext, i_ciphertext_len);
	BN_hex2bn(&crypt, crypt_hex);

	// C' = ((S^E mod n) * C) mod n = (S*P)^E mod n
	BN_mod_exp(T0, S, i_pubkey->e, i_pubkey->n, ctx);
	BN_mod_mul(C_mod, T0, crypt, i_pubkey->n, ctx);

	// feed the oracle
	rsa_unpadded_msg_oracle(plain_mod, C_mod, i_privkey);

	// reconstruct the original plain text
	// P' = S*P mod n
	// P = P'*S' mod n (S' = modinv(S, n)
	if(!inv_mod(T0, i_pubkey->n, S)) {
		BN_mod_mul(plain, plain_mod, T0, i_pubkey->n, ctx);
	}
	else {
		failed = 1;
	}

	plain_hex = BN_bn2hex(plain);
	plain_hex_len = strlen(plain_hex);

	plain_hex_len = hex_decode(o_plain, plain_hex, plain_hex_len);

	OPENSSL_free(plain_hex);

	free(crypt_hex);
	BN_free(crypt);
	BN_free(S);
	BN_free(T0);
	BN_free(C_mod);
	BN_free(plain);
	BN_free(plain_mod);

	BN_CTX_free(ctx);

	if(failed) {
		return -1;
	} else {
		return plain_hex_len;
	}
	return -1;
}

/*
 * Provides a test case for rsa_unpadded_msg_oracle_attack().
 */
void rsa_unpadded_msg_oracle_attack_test(void)
{
	rsa_key_t puk;
	rsa_key_t pik;

	puk.e = BN_new();
	puk.n = BN_new();
	pik.e = BN_new();
	pik.n = BN_new();

	unsigned char *msg = "IS THIS THE STORY OF JOHNNY ROTTEN?!"; // 36
	unsigned int msg_len = strlen(msg);

	unsigned char *crypted = NULL;
	unsigned int crypted_len = 0;

	unsigned char *recovered_plain = NULL;
	int recovered_plain_len = 0;

	// pay attention to the key size!
	// be sure to choose n, that:
	//		m < n
	// (m being the plain text, n the pub key modulus)
	rsa_generate_keypair(&puk, &pik, 256);

	crypted_len = rsa_encrypt(&crypted, msg, msg_len, &puk);

	if((recovered_plain_len = rsa_unpadded_msg_oracle_attack(&recovered_plain, crypted, crypted_len, &puk, &pik)) < 0) {
		printf("[s6c1] RSA unpadded message oracle attack failed (returned -1)!\n");
	} else {
		printf("[s6c1] Recovered plain text: '%s'\n", recovered_plain);
	}

	free(crypted);
	free(recovered_plain);
}

/*
 * Pads a message similarly to PKCS#1 v1.5 encoding scheme,
 * but simply inserts a hard coded ASN.1 field.
 *
 * @return
 * 		Length of the padded message, <0 on error.
 * 		Returns -1 if desired length in bytes of the padded
 * 		message is too short.
 * @param o_padded_msg
 * 		Padded message.
 * @param i_msg
 * 		Input message that needs padding.
 * @param i_msg_len
 * 		Length in bytes of input message.
 * @param i_padded_msg_len
 * 		Desired length in bytes of the padded message.
 */
int rsa_simple_pad(unsigned char *o_padded_msg, unsigned char *i_msg, unsigned int i_msg_len, unsigned int i_padded_msg_len, unsigned char i_pad_char)
{
	unsigned int i;

	// 00 01 Nx(PP) FF 00 ASN.1 DD .. DD, N>=4
	// constant length = 4
	if(i_padded_msg_len < (i_msg_len+4+ASN1_field_len)) {
		return -1;
	}

	memset(o_padded_msg, 0, i_padded_msg_len*sizeof(unsigned char));
	memcpy(o_padded_msg, "\x00\x01", 2);

	// add variable length padding
	for(i=0; i<(i_padded_msg_len-(i_msg_len+4+ASN1_field_len)); i++) {
		memset(o_padded_msg+2+i, i_pad_char, 1);
	}

	// add end of padding 0xff 0x00
	memcpy(o_padded_msg+2+i, "\xff\x00", 2);
	// add  and ASN.1 field
	memcpy(o_padded_msg+4+i, ASN1_field, ASN1_field_len*sizeof(unsigned char));
	// add original data
	memcpy(o_padded_msg+4+ASN1_field_len+i, i_msg, i_msg_len*sizeof(unsigned char));

	return i_padded_msg_len;
}

/*
 * Provides a simple test case for rsa_simple_pad().
 */
void rsa_simple_pad_test(void)
{
	unsigned char pad[1024];
	unsigned int pad_len;
	unsigned char *msg = "test";

	memset(pad, 0, 1024);
	pad_len = rsa_simple_pad(pad, msg, 4, 32, 0xff);

	unsigned char *pad_hex;

	hex_encode(&pad_hex, pad, pad_len);

	printf("[s6c2] rsa_simple_pad('test') = %s\n", pad_hex);

	free(pad_hex);
	return;
}

/*
 * Sign a message using SHA-256.
 *
 * Pseudo code for the algorithm:
 * H = SHA256(M) 			// (M being the message)
 * H'= rsa_simple_pad(H)	// (0x) 00 01 PP 00 | ASN1 | H
 * 							// PP being padding sequence (0xff)
 * 							// of sufficient length
 * 							// #TODO: determine sufficient length
 * S = RSA_priv_encrypt(H')
 *
 * Originally rsa_simple_pad() would implement PKCS#1 v1.5
 * encoding, which we'll omit here for simplicity:
 * H'= PKCS1.5_pad(H)		// (0x) 00 01 PP 00 | ASN.1 | H
 *
 * @return
 * 		Length in bytes of the RSA signature, -1 on error.
 * @param o_signature
 * 		Pointer to string containing the RSA signature of
 * 		the provided message.
 * @param i_msg
 * 		Message to be signed.
 * @param i_msg_len
 * 		Length in bytes of the message to be signed.
 * @param i_privkey
 * 		RSA private key that will be used for signing.
 */
int rsa_sign(unsigned char **o_signature, unsigned char *i_msg, unsigned int i_msg_len, rsa_key_t *i_privkey)
{
	unsigned int i;
	unsigned char *hash;
	unsigned char hash_str[SHA256_DIGEST_LENGTH*2+1];
	unsigned int hash_len;

	// calculate SHA256 hash of message
	hash_len = hash_sha256(hash_str, i_msg, i_msg_len);
	hash_len = hex_decode(&hash, hash_str, hash_len);

	unsigned int pad_len;
	unsigned char hash_pad[128];	// <-- this shouldn't be a fixed value!
									// better: determine from privkey size?

	// pad the hash
	if((pad_len = rsa_simple_pad(hash_pad, hash, hash_len, 128, 0xff))<0) {
		free(hash);
		return pad_len;
	}

	// encrypt with private key
	int signature_length;

	signature_length = rsa_encrypt(o_signature, hash_pad, pad_len, i_privkey);

	free(hash);
	return signature_length;
}

/*
 * Verifies the RSA (SHA-256) signature for a given
 * message in a vulnerable way.
 *
 * @return
 * 		Returns 1 if the signature was successfully
 * 		verified, 0 if the signature could not be verified
 * 		and -1 on error.
 * @param i_msg
 * 		Message to verify.
 * @param i_msg_len
 * 		Length in bytes of the message.
 * @param i_sign
 * 		RSA signature of the message.
 * @param i_sign_len
 * 		Length in bytes of the RSA signature.
 * @param i_pubkey
 * 		RSA public key to use for verification.
 */
int rsa_sign_verify(unsigned char *i_msg, unsigned int i_msg_len, unsigned char *i_sign, unsigned int i_sign_len, rsa_key_t *i_pubkey)
{
	unsigned int failed = 0;
	// decrypt signature
	unsigned char *dec_pad_msg = NULL;
	unsigned int dec_pad_msg_len = 0;

	unsigned char msg_hash_hex[SHA256_DIGEST_LENGTH*2+1];
	unsigned char *msg_hash;
	unsigned int msg_hash_len;

	dec_pad_msg_len = rsa_decrypt(&dec_pad_msg, i_sign, i_sign_len, i_pubkey);

	// generate sha256 hash from message
	msg_hash_len = hash_sha256(msg_hash_hex, i_msg, i_msg_len);
	msg_hash_len = hex_decode(&msg_hash, msg_hash_hex, msg_hash_len);
	// dumb verify
	if(dec_pad_msg[0] != 0x01) {
		failed = 1;
	}

	unsigned int i=0;
	unsigned char cmp[ASN1_field_len+2];

	memcpy(cmp, "\xff\x00", 2);
	memcpy(cmp+2, ASN1_field, ASN1_field_len*sizeof(unsigned char));

	// skip the padding until we reach (0xff 0x00 ASN.1) fields
	for(i=1; i<dec_pad_msg_len; i++) {
		if(!memcmp((dec_pad_msg+i), cmp, ASN1_field_len+2)) {
			break;
		}
	}

//	unsigned char *dec_hash_hex;
//
//	hex_encode(&dec_hash_hex, dec_pad_msg+i+ASN1_field_len+2, msg_hash_len);
//	printf("[s6c2] sha256_dec(msg) = %s\n", dec_hash_hex);
//	free(dec_hash_hex);

	// verify sha256 hash
	if(memcmp((dec_pad_msg+i+ASN1_field_len+2), msg_hash, msg_hash_len)) {
		failed = 1;
	}

	free(msg_hash);
	free(dec_pad_msg);

	if(failed) {
		return 0;
	} else {
		return 1;
	}
}

/*
 * Forges an RSA signature with the help of Bleichenbacher's
 * RSA (e=3) attack. We're exploiting the dumb signature checking
 * function here...
 *
 * @return
 * 		Length in bytes of the forged signature, -1 on error.
 * @param o_sign_forged
 * 		Pointer to string that will contain the forged RSA signature.
 * @param i_msg
 * 		Message for which we want to forge an RSA signature.
 * @param i_msg_len
 * 		Length in bytes of the message.
 * @param i_pubkey
 * 		RSA public key with e=3.
 */
int rsa_sign_forge(unsigned char **o_sign_forged, unsigned char *i_msg, unsigned int i_msg_len, rsa_key_t *i_pubkey)
{
	unsigned char msg_hash_hex[SHA256_DIGEST_LENGTH*2+1];
	unsigned char *msg_hash;
	unsigned int msg_hash_len = 0;

	unsigned char pad_sign[256]; // 128
	unsigned int pad_sign_len = 0;

	unsigned char *pad_sign_hex = NULL;

	// calculate sha256 hash of msg
	msg_hash_len = hash_sha256(msg_hash_hex, i_msg, i_msg_len);
//	printf("[s6c2] sha256(msg) =     %s\n", msg_hash_hex);
	msg_hash_len = hex_decode(&msg_hash, msg_hash_hex, msg_hash_len);

//	msg_hash[msg_hash_len-1]++;

	// pad message as needed
	memset(pad_sign, 0, 256); // 128
	if((pad_sign_len = rsa_simple_pad(pad_sign, msg_hash, msg_hash_len, msg_hash_len+4+ASN1_field_len, 0x00))<0) {
		free(msg_hash);
		return -1;
	}

	free(msg_hash);

	// with the nthroot method we'll achieve a sha256 checksum, that's
	// off by the last byte, so we need to increase our number by
	// replacing the trailing zeroes with some garbage until the hashes
	// match --> set the following bits high
	// #TODO: automate this
	pad_sign[pad_sign_len] = 0xf0;
	hex_encode(&pad_sign_hex, pad_sign, pad_sign_len+69);

	// cube root
	BIGNUM *sign = BN_new();
	BIGNUM *num = BN_new();

	BN_hex2bn(&num, pad_sign_hex);

	nthroot(sign, num, i_pubkey->e);

	unsigned char *sign_forged_hex = NULL;
	unsigned int sign_forged_hex_len = 0;

	sign_forged_hex = BN_bn2hex(sign);
	sign_forged_hex_len = strlen(sign_forged_hex);

	sign_forged_hex_len = hex_decode(o_sign_forged, sign_forged_hex, sign_forged_hex_len);

	free(pad_sign_hex);
	OPENSSL_free(sign_forged_hex);
	BN_free(sign);
	BN_free(num);

	return sign_forged_hex_len;
}
