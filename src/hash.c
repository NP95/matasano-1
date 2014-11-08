/*
 * hash.c
 *
 * Created on: 04.11.2014
 * Author:     rc0r
 */

#include "../include/hash.h"

unsigned int hash_sha256(unsigned char *o_hash_str, unsigned char *i_msg, unsigned int i_msg_len)
{
	unsigned int i;

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, i_msg, i_msg_len);
	SHA256_Final(hash, &sha256);
	for(i = 0; i<SHA256_DIGEST_LENGTH; i++) {
		sprintf(o_hash_str + (2*i), "%02x", hash[i]);
	}
	o_hash_str[SHA256_DIGEST_LENGTH*2] = 0;

	return SHA256_DIGEST_LENGTH*2;
}

unsigned int hash_sha1(unsigned char *o_hash_str, unsigned char *i_msg, unsigned int i_msg_len)
{
	unsigned int i;

	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA_CTX sha;
	SHA1_Init(&sha);
	SHA1_Update(&sha, i_msg, i_msg_len);
	SHA1_Final(hash, &sha);
	for(i = 0; i<SHA_DIGEST_LENGTH; i++) {
		sprintf(o_hash_str + (2*i), "%02x", hash[i]);
	}
	o_hash_str[SHA_DIGEST_LENGTH*2] = 0;

	return SHA_DIGEST_LENGTH*2;
}
