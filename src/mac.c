#include <string.h>
#include "../include/mac.h"

unsigned int sha1_secret_prefix_mac(unsigned int *mac, unsigned char *msg, unsigned int msg_len, unsigned char *key, unsigned int key_len)
{
	SHA1Context sc;
	SHA1Reset(&sc);

	unsigned char mac_input[key_len+msg_len];

	memset(mac_input, 0, (key_len+msg_len)*sizeof(unsigned char));
	memcpy(mac_input, key, key_len*sizeof(unsigned char));
	memcpy(mac_input+key_len, msg, msg_len*sizeof(unsigned char));

	SHA1Input(&sc, mac_input, key_len+msg_len);

	if(SHA1Result(&sc) == 1) {
		memcpy(mac, sc.Message_Digest, 5*sizeof(unsigned int));
		return 160;
	}
	else
		return 0;
}

unsigned int sha1_secret_prefix_mac_auth(unsigned int *mac, unsigned char *msg, unsigned int msg_len, unsigned char *key, unsigned int key_len)
{
	unsigned int msg_mac[5];
	unsigned int i;

	if(sha1_secret_prefix_mac(msg_mac, msg, msg_len, key, key_len)==160)
	{
		for(i=0; i<5; i++) {
			if(mac[i]!=msg_mac[i])
				return 1;
		}

		return 0;
	}

	return 1;
}

