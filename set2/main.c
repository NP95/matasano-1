#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/get.h"
#include "../include/hex2base64.h"
#include "../include/hex_coder.h"
#include "../include/hamming.h"

int main(void)
{
	/** Set 2 Challenge 1 **/
	/**  PKCS#7 PADDING   **/
	unsigned char plaintext_padded[20];
	unsigned int plaintext_padded_len = pkcs7_padding(plaintext_padded, "YELLOW SUBMARINE", 16, 20);
	unsigned char *plaintext_padded_hex;

	hex_encode(&plaintext_padded_hex, plaintext_padded, plaintext_padded_len);

	printf("[s2c1] plaintext_padded = '%s'\n", plaintext_padded_hex);

	free(plaintext_padded_hex);

	/** Set 2 Challenge 2 **/
	/**  AES in CBC Mode  **/
	FILE *fp = fopen("10.txt", "r");

	if(fp==NULL)
		return -1;

	unsigned int i;
	unsigned char *cipher;
	unsigned char cipher_b64[8192];
	unsigned int cipher_len=0;
	char *line_str = NULL;
	size_t len=0;
	ssize_t read;
	while((read = getline(&line_str, &len, fp)) != -1) {
		for(i=0; i<read-1; i++) {
			cipher_b64[cipher_len+i] = line_str[i];
		}
		cipher_len += read-1;
	}

	cipher_b64[cipher_len] = '\0';
// 	printf("cipher_b64 = {\n%s\n}\n\n", cipher_b64);
	cipher_len = base64decode(&cipher, cipher_b64, cipher_len);

	if(line_str)
		free(line_str);
	close(fp);

	unsigned char plaintext[cipher_len];
	unsigned int plaintext_len;
	unsigned char iv[16];
	memset(iv, 0, 16);

	plaintext_len = aes_cbc_decrypt(128, plaintext, cipher, cipher_len, "YELLOW SUBMARINE", iv);
// 	printf("plaintext = {\n%s\n}\n\n", plaintext);
	cipher_len = aes_cbc_encrypt(128, cipher, plaintext, plaintext_len, "YELLOW SUBMARINE", iv);
	plaintext_len = aes_cbc_decrypt(128, plaintext, cipher, cipher_len, "YELLOW SUBMARINE", iv);
// 	printf("plaintext = {\n%s\n}\n\n", plaintext);

	free(cipher);

	/** Set 2 Challenge 3 **/
	/** ECB/CBC DETECTION **/
	unsigned int output_len = 0;
	unsigned char output[plaintext_len];
	unsigned int ecb = 2; // ecb == 0; cbc == 1

	ecb = aes_encryption_oracle(output, &output_len, plaintext, plaintext_len);
	
	printf("[s2c3] [mode: %d, len: %d] DETECTED MODE: %s\n", ecb, output_len, (is_ecb_mode(output, output_len, 16)==0) ? "ECB" : "CBC");

	/** Set 2 Challenge 4 **/
	/** ECB SINGLE-BYTE DECRYPTION **/
	unsigned char s2c4_plaintext[1024];
	unsigned int s2c4_plaintext_len;
	unsigned int key_len = 0;
	aes_ecb_partial_crack(s2c4_plaintext, &s2c4_plaintext_len, NULL, &key_len);

	printf("[s2c4] plaintext = {\n%s\n}\n", s2c4_plaintext);

	/** Set 2 Challenge 5 **/
	/**  ECB cut-n-paste  **/
	kv_t kv[10];

	for(i=0; i<10; i++) {
		kv[i].key = malloc(128);
		kv[i].value = malloc(128);
	}
	unsigned int kv_num = 0;

	char getstr[] = "foo=bar&bac=qux&zap=zazzle";
	char encoded_getstr[1024];
	unsigned int encoded_getstr_len;
// 	memset(encoded_getstr, 0, 1024*sizeof(char));

// 	kv_num = decode_from_get(kv, getstr);

// 	printf("{\n");
// 	for(i=0; i<kv_num; i++) {
// 		printf(" %s: '%s'%s\n", kv[i].key, kv[i].value, (i==(kv_num-1))?"":",");
// 	}
// 	printf("}\n");

// 	encode_to_get(encoded_getstr, kv, kv_num);

// 	printf("encoded: '%s'\n", encoded_getstr);

	unsigned char key[16];
	aes_random_key(key, 16);

	memset(encoded_getstr, 0, 1024*sizeof(char));
	encoded_getstr_len = profile_for(encoded_getstr, kv, "rc0r@husmail.com&role=admin", key);

	printf("send: {\n");
	kv_num = 3;
	for(i=0; i<kv_num; i++) {
		printf(" %s: '%s'%s\n", kv[i].key, kv[i].value, (i==(kv_num-1))?"":",");
	}
	printf("}\n");
// 	printf("encoded: '%s'\n", encoded_getstr);

// 	// encrypt encoded profile
// 	// perform PKCS#7 padding
// 	unsigned int plaintext_pad_len = strlen(encoded_getstr) + (16 - (strlen(encoded_getstr) % 16));
// 	unsigned char plaintext_pad[plaintext_pad_len];
// 
// 	plaintext_pad_len = pkcs7_padding(plaintext_pad, encoded_getstr, strlen(encoded_getstr), 16);
// 
// 	// encrypt
// 	unsigned char s2c5_cipher[128];
	unsigned int s2c5_plain_len;
	unsigned char s2c5_plain[128];
// 	unsigned int s2c5_cipher_len;
// 	unsigned char key[16];
// 	aes_random_key(key, 16);
// 
// 	s2c5_cipher_len = aes_ecb_encrypt(128, s2c5_cipher, plaintext_pad, plaintext_pad_len, key);

	// transmit to attacker MITMing profile setup process ...
	// attacker constructing ciphertexts
	kv_t kv_a1[10], kv_a2[10];
	for(i=0; i<10; i++) {
		kv_a1[i].key = malloc(128);
		kv_a1[i].value = malloc(128);
		kv_a2[i].key = malloc(128);
		kv_a2[i].value = malloc(128);
	}
	unsigned char attack_str1[512];
	unsigned int attack_str1_len;
	unsigned char attack_str2[512];
	unsigned int attack_str2_len;
	unsigned char attack_str[512];

	// create ciphertext with first two blocks containing:
	// 'email=root@ubox.com&uid=10&role='
	memset(attack_str1, 0, 512);
	attack_str1_len = profile_for(attack_str1, kv_a1, "root@ubox.com", key);

	// create another ciphertext with 2nd block containing
	// 'admin&uid=10&rol'
	memset(attack_str2, 0, 512);
	attack_str2_len = profile_for(attack_str2, kv_a2, "rt@box.comadmin", key);
	
	// assemble our attack string
	memset(attack_str, 0, 512);
	memcpy(attack_str, attack_str1, 32*sizeof(unsigned char));
	memcpy(attack_str+32, attack_str2+16, 16*sizeof(unsigned char));

	// receive request
	// decrypt original
// 	s2c5_plain_len = aes_ecb_decrypt(128, s2c5_plain, encoded_getstr, encoded_getstr_len, key);

	// decrypt attack_str
	s2c5_plain_len = aes_ecb_decrypt(128, s2c5_plain, attack_str, 48, key);
	printf("recv string: '%s'\n", s2c5_plain);

	// decode
	kv_num = decode_from_get(kv, s2c5_plain);

	printf("recv: {\n");
	kv_num = 3;
	for(i=0; i<kv_num; i++) {
		printf(" %s: '%s'%s\n", kv[i].key, kv[i].value, (i==(kv_num-1))?"":",");
	}
	printf("}\n");

	for(i=0; i<10; i++) {
		free(kv[i].key);
		free(kv[i].value);
		free(kv_a1[i].key);
		free(kv_a1[i].value);
		free(kv_a2[i].key);
		free(kv_a2[i].value);
	}
	return 0;
}
