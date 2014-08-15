#include "../include/hex_coder.h"

unsigned int hex_encode(unsigned char **dst_str, const unsigned char *src_hex, unsigned int src_size)
{
	unsigned int i;
	unsigned int chars = 0;
	char tmp[3];

	chars = src_size * 2;
	(*dst_str) = malloc((chars+1) * sizeof(char));
	memset((*dst_str), 0, (chars+1) * sizeof(char));

	for(i=0; (i<src_size); i++) {
		sprintf(tmp, "%02x", (unsigned char) src_hex[i]);
		strncat((*dst_str), tmp, 3);
	}

	return chars;
}

unsigned int hex_decode(unsigned char **dst_hex, const unsigned char *src_str, unsigned int src_len)
{
	unsigned int i, a;
	unsigned int bytes = 0;

	bytes = src_len / 2;
	(*dst_hex) = malloc((bytes+1) * sizeof(unsigned char));
	memset((*dst_hex), 0, (bytes+1) * sizeof(unsigned char));

	for(i=0; i<bytes; i++) {
		sscanf(src_str, "%2X", &a);
		(*dst_hex)[i] = a;
		src_str+=2;
	}

	return bytes;
}

// int main(void)
// {
// 	unsigned char *byte_str = "\xDE\xAD\xBE\xEF";
// 	char *hex_str;
// 	unsigned char *byte_str_2;
// 
// 	int c = hex_encode(&hex_str, byte_str, 4);
// 	printf("c = %d\nin: %s\nout: %s\n", c, byte_str, hex_str);
// 
// 	int b = hex_decode(&byte_str_2, hex_str, c);
// 	printf("\nb = %d\nin: %s\nout: %s\n", b, hex_str, byte_str_2);
// 
// 	free(byte_str_2);
// 	free(hex_str);
// 	return 0;
// }
