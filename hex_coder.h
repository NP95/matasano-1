#ifndef __HEX_CODER_H
#define __HEX_CODER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int hex_encode(unsigned char **dst_str, const unsigned char *src_hex, unsigned int src_size);
unsigned int hex_decode(unsigned char **dst_hex, const unsigned char *src_str, unsigned int src_len);

#endif // __HEX_CODER_H
