#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/aes.h"
#include "../include/pkcs.h"
#include "../include/hex2base64.h"
#include "../include/histogram.h"

unsigned int aes_ctr_edit(unsigned char *edited_cipher, unsigned char *cipher, unsigned int cipher_len, unsigned char *key, unsigned int nonce, unsigned int offset, unsigned char *plaintext, unsigned int plaintext_len)
{
	if(offset >= cipher_len)
		return 0;

	unsigned int block_len = 16;
	unsigned int block_num = plaintext_len / block_len + 1;
	unsigned int start_block = offset / block_len;

	unsigned int uncrypted_len = block_num * block_len;
	unsigned int uncrypted_bytes;
	unsigned int decrypt_len = (plaintext_len > (cipher_len-block_len*start_block)) ? (cipher_len-block_len*start_block): uncrypted_len;

	unsigned char uncrypted[uncrypted_len];

	unsigned int i;

	// decrypt blocks that need editing
	uncrypted_bytes = aes_ctr_crypt(uncrypted, cipher+start_block*block_len, decrypt_len, key, nonce+start_block);

// 	printf("Uncrypted(%d) = {\n%s\n}\n", offset, uncrypted);

	// assemble new plaintext
	memcpy(uncrypted+(offset-start_block*block_len), plaintext, plaintext_len*sizeof(unsigned char));

// 	printf("New Plain(%d) = {\n%s\n}\n", offset, uncrypted);

	// encrypt new plaintext
	unsigned char edit_crypted[block_num*block_len];
	unsigned int edit_crypted_len = 0;

	edit_crypted_len = aes_ctr_crypt(edit_crypted, uncrypted, block_num*block_len, key, nonce+start_block);

	// put edited ciphertext in place
	memcpy(edited_cipher, cipher, cipher_len*sizeof(unsigned char));
	memcpy(edited_cipher+start_block*block_len, edit_crypted, edit_crypted_len*sizeof(unsigned char));

	unsigned int remaining_len = (plaintext_len > (cipher_len-offset)) ? plaintext_len : cipher_len-offset;

	return remaining_len+offset;
}

unsigned int aes_ctr_edit_crack(unsigned char *plaintext, unsigned char *cipher, unsigned int cipher_len, unsigned char *key, unsigned int nonce)
{
	unsigned char edit[cipher_len];

	unsigned int j, k;

	// init plaintext, key
	memset(plaintext, 0, cipher_len*sizeof(unsigned char));

	for(k=0; k<cipher_len-1; k++) {
		// bf plaintext byte
		for(j=0; j<256; j++) {
			plaintext[k] = j;

			aes_ctr_edit(edit, cipher, cipher_len, key, nonce, 0, plaintext, k+1);

			if(!memcmp(cipher, edit, k+1)) {
// 				printf("hit %d, %c\n", k, j);
				break;
			}
		}
	}

	return cipher_len;
}

int main(void)
{
	srand(time(NULL));

	/**           Set 4 Challenge 1           **/
	/** CRCK RANDOM READ/WRITE ACCESS AES CTR **/
	FILE *fp = fopen("25.txt", "r");

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

	if(line_str)
		free(line_str);
	close(fp);

	cipher_b64[cipher_len] = '\0';
	cipher_len = base64decode(&cipher, cipher_b64, cipher_len);

	unsigned char s4c1_plain[1024];
	unsigned int s4c1_plain_len = 0;
	memset(s4c1_plain, 0, 1024*sizeof(unsigned char));
	s4c1_plain_len = aes_ecb_decrypt(128, s4c1_plain, cipher, cipher_len, "YELLOW SUBMARINE");
	s4c1_plain[s4c1_plain_len] = 0;

	free(cipher);

	unsigned char s4c1_cipher_ctr[s4c1_plain_len];
	unsigned int s4c1_cipher_ctr_len = 0;

	unsigned int s4c1_nonce = rand();
	unsigned char s4c1_key[16];

	aes_random_key(s4c1_key, 16);

	s4c1_cipher_ctr_len = aes_ctr_crypt(s4c1_cipher_ctr, s4c1_plain, s4c1_plain_len, s4c1_key, s4c1_nonce);

	unsigned char s4c1_edit_crypt[s4c1_cipher_ctr_len];
	unsigned int s4c1_edit_crypt_len = 0;

	// we assume the aes_ctr_edit() function internally knows
	// key and nonce, so we provide it here (but we don't know it actually)
	s4c1_edit_crypt_len = aes_ctr_edit_crack(s4c1_edit_crypt, s4c1_cipher_ctr, s4c1_cipher_ctr_len, s4c1_key, s4c1_nonce);
// 	s4c1_edit_crypt[s4c1_edit_crypt_len] = 0;
	printf("[s4c1] recovered plain (%d) = '%s'\n", s4c1_edit_crypt_len, s4c1_edit_crypt);

	// debug
// 	s4c1_edit_crypt_len = aes_ctr_edit(s4c1_edit_crypt, s4c1_cipher_ctr, s4c1_cipher_ctr_len, s4c1_key, s4c1_nonce, 17, "test", 4);
// 
// 	printf("[s4c1] cipher_len = %d\n", s4c1_cipher_ctr_len);
// 	printf("[s4c1] edit_crypt_len = %d\n", s4c1_edit_crypt_len);
// 
// 	unsigned char s4c1_edit_plain[s4c1_cipher_ctr_len];
// 	unsigned int s4c1_edit_plain_len = 0;
// 
// 	s4c1_edit_plain_len = aes_ctr_crypt(s4c1_edit_plain, s4c1_edit_crypt, s4c1_edit_crypt_len, s4c1_key, s4c1_nonce);
// 	s4c1_edit_plain[s4c1_edit_plain_len] = 0;
// 	printf("[s4c1] edited plaintext = {\n%s\n}\n", s4c1_edit_plain);

	/** Set 4 CHallenge 2 **/
	/** CTR BITFLIP ATTAX **/
	unsigned char *s4c2_plain = "12345:admin<true"; // 16
	unsigned char s4c2_key[16];
	unsigned int s4c2_nonce = rand();
	unsigned char s4c2_cipher_orig[128];
	unsigned int s4c2_cipher_orig_len;
	unsigned char s4c2_cipher_mod[128];
	unsigned int s4c2_cipher_mod_len;

	aes_random_key(s4c2_key, 16);
	s4c2_cipher_orig_len = aes_ctr_oracle(s4c2_cipher_orig, s4c2_plain, 16, s4c2_key, s4c2_nonce);
	
	memcpy(s4c2_cipher_mod, s4c2_cipher_orig, s4c2_cipher_orig_len);
	// flip bits in ciphertext block 2
	// prepending our controlled buffer
	s4c2_cipher_mod[37] ^= 0x01;
	s4c2_cipher_mod[43] ^= 0x01;

	// decrypt
	unsigned char s4c2_dec[128];
	unsigned int s4c2_dec_len;

	s4c2_dec_len = aes_ctr_crypt(s4c2_dec, s4c2_cipher_mod, s4c2_cipher_orig_len, s4c2_key, s4c2_nonce);
	printf("[s4c2] plain='%s'\n", s4c2_dec);

	return 0;
}
