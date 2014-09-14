#include <math.h>
#include <string.h>
#include "../include/mac.h"

unsigned int md4_secret_prefix_mac(unsigned char *mac, unsigned char *msg, unsigned int msg_len, unsigned char *key, unsigned int key_len)
{
	MD4_CTX ctx;
	MD4_Init(&ctx);

	unsigned int input_len = key_len+msg_len;
	unsigned char mac_input[input_len];

	memset(mac_input, 0, input_len*sizeof(unsigned char));
	memcpy(mac_input, key, key_len*sizeof(unsigned char));
	memcpy(mac_input+key_len, msg, msg_len*sizeof(unsigned char));

	MD4_Update(&ctx, mac_input, input_len);

	MD4_Final(mac, &ctx);
	
	return 16; // 16 bit, 128 bit
}

unsigned int md4_secret_prefix_mac_forge(unsigned char *mac, unsigned char *msg, unsigned int msg_len, unsigned char *orig_hash)
{
	MD4_CTX ctx;

	unsigned int *init = (unsigned int *) orig_hash;

	MD4_Init_Mod(&ctx, init);

	MD4_Update(&ctx, msg, msg_len);
	MD4_Final_Forge(mac, &ctx);

	return 16;
}

unsigned int md4_secret_prefix_mac_auth(unsigned char *mac, unsigned char *msg, unsigned int msg_len, unsigned char *key, unsigned int key_len)
{
	unsigned char msg_mac[16];
	unsigned int i;

	if(md4_secret_prefix_mac(msg_mac, msg, msg_len, key, key_len)==16)
	{
		for(i=0; i<16; i++) {
			if(mac[i]!=msg_mac[i])
				return 1;
		}

		return 0;
	}

	return 1;
}

unsigned int md4_generate_padding(unsigned char *padding, unsigned long message_len)
{
	unsigned int pad_len = sha1_generate_padding(padding, message_len);
	unsigned int i;

	unsigned char pad_tmp[8];

	memcpy(pad_tmp, padding+pad_len-8, 8);

	// convert endianess according to md4
	for(i=0; i<8; i++) {
		padding[pad_len-8+i] = pad_tmp[7-(i % 8)];
	}

	return pad_len;
}

unsigned int sha1_hmac(unsigned int *hmac, unsigned char *msg, unsigned int msg_len, unsigned char *key, unsigned int key_len)
{
	// HMAC = H(key ^ opad, H(key ^ ipad, msg))
	// ipad = 0x36
	// opad = 0x5c
	const unsigned int hash_blocklen = 64;
	unsigned int hmac_key[5];

	// prepare key
	if(key_len > hash_blocklen) {
		sha1_secret_prefix_mac(hmac_key, key, key_len, NULL, 0);
	}
}

unsigned int sha1_secret_prefix_mac(unsigned int *mac, unsigned char *msg, unsigned int msg_len, unsigned char *key, unsigned int key_len)
{
	SHA1Context sc;
	SHA1Reset(&sc);

	unsigned int input_len = key_len+msg_len;
	unsigned char mac_input[input_len];

	memset(mac_input, 0, input_len*sizeof(unsigned char));
	if(key!=NULL)
		memcpy(mac_input, key, key_len*sizeof(unsigned char));
	if(msg!=NULL)
		memcpy(mac_input+key_len, msg, msg_len*sizeof(unsigned char));

	SHA1Input(&sc, mac_input, input_len);

	if(SHA1Result(&sc) == 1) {
		memcpy(mac, sc.Message_Digest, 5*sizeof(unsigned int));
		return 20; // 20 byte, 160 bit
	}
	
	return 0;
}

unsigned int sha1_secret_prefix_mac_forge(unsigned int *mac, unsigned char *msg, unsigned int msg_len, unsigned int *orig_hash)
{
	SHA1Context sc;
	SHA1Reset_Mod(&sc, orig_hash);

	SHA1Input(&sc, msg, msg_len);

	if(SHA1Result_Forged(&sc) == 1) {
		memcpy(mac, sc.Message_Digest, 5*sizeof(unsigned int));
		return 20; // 20 byte, 160 bit
	}

	return 0;
}

unsigned int sha1_secret_prefix_mac_auth(unsigned int *mac, unsigned char *msg, unsigned int msg_len, unsigned char *key, unsigned int key_len)
{
	unsigned int msg_mac[5];
	unsigned int i;

	if(sha1_secret_prefix_mac(msg_mac, msg, msg_len, key, key_len)==20)
	{
		for(i=0; i<5; i++) {
			if(mac[i]!=msg_mac[i])
				return 1;
		}

		return 0;
	}

	return 1;
}

unsigned int sha1_generate_padding(unsigned char *padding, unsigned long message_len)
{
	unsigned int padding_len = 0;
	unsigned int i;

	padding_len = (64 - message_len % 64);

	padding_len = (padding_len < 9) ? padding_len+64 : padding_len;

	memset(padding, 0, padding_len*sizeof(unsigned char));
	padding[0] = 0x80;

	for(i=0; i<8; i++) {
		padding[padding_len-1-i] = ((message_len*8) >> i*8) & 0xFF;
	}

	return padding_len;
}
