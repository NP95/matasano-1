#include "../include/get.h"

unsigned int decode_from_get(kv_t *kv_pairs, unsigned char *get_request)
{
	unsigned int i = 0;
	char *key;
	char *value;
	key = strtok(get_request, "=");

	while((key!=NULL) && ((value = strtok(NULL, "&"))!=NULL)) {
// 		printf(" %s: '%s'\n", key, value);
		strcpy(kv_pairs[i].key, key);
		strcpy(kv_pairs[i].value, value);

		key=strtok(NULL, "=");
		i++;
	}

	return i;
}

unsigned int encode_to_get(unsigned char *get_request, kv_t *kv_pairs, unsigned int kv_entries)
{
	unsigned int i=0;

	strcpy(get_request, kv_pairs[0].key);
	strcat(get_request, "=");
	strcat(get_request, kv_pairs[0].value);
	strcat(get_request, "&");
	for(i=1; i<kv_entries; i++) {
		strcat(get_request, kv_pairs[i].key);
		strcat(get_request, "=");
		strcat(get_request, kv_pairs[i].value);
		if(i<kv_entries-1)
			strcat(get_request, "&");
	}

	return strlen(get_request);
}

unsigned int profile_for(unsigned char *encoded_profile, kv_t *profile, unsigned char *mail, unsigned char *key)
{
	unsigned int i, encoded_profile_str_len;
	unsigned char encoded_profile_str[256];

	unsigned char mail_sanitized[strlen(mail)];
// 	// sanitize input
	for(i=0; i<strlen(mail); i++) {
		if(mail[i] == '&' || mail[i] == '=' )
			mail_sanitized[i] = '_';
		else
			mail_sanitized[i] = mail[i];
	}

	// generate profile
	strcpy(profile[0].key, "email");
// 	profile[0].value = mail_sanitized;
	strcpy(profile[0].value, mail_sanitized);

	strcpy(profile[1].key, "uid");
	strcpy(profile[1].value, "10");

	strcpy(profile[2].key, "role");
	strcpy(profile[2].value, "user");

	encoded_profile_str_len = encode_to_get(encoded_profile_str, profile, 3);
// 	printf("encoded_profile = '%s'\n", encoded_profile_str);

	// encrypt encoded profile
	// perform PKCS#7 padding
	unsigned int plaintext_pad_len = encoded_profile_str_len + (16 - (encoded_profile_str_len % 16));
	unsigned char plaintext_pad[plaintext_pad_len];

	plaintext_pad_len = pkcs7_padding(plaintext_pad, encoded_profile_str, encoded_profile_str_len, 16);

	// encrypt
	return aes_ecb_encrypt(128, encoded_profile, plaintext_pad, plaintext_pad_len, key);
}

