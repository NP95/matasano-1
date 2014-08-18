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

	for(i=0; i<kv_entries; i++) {
		strcat(get_request, kv_pairs[i].key);
		strcat(get_request, "=");
		strcat(get_request, kv_pairs[i].value);
		if(i<kv_entries-1)
			strcat(get_request, "&");
	}

	return strlen(get_request);
}

unsigned int profile_for(unsigned char *encoded_profile, kv_t *profile, unsigned char *mail)
{
	unsigned int i;
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

	return encode_to_get(encoded_profile, profile, 3);
}

