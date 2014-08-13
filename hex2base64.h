#ifndef __HEX2BASE64_H
#define __HEX2BASE64_H

#include <string.h>
#include <openssl/pem.h>

char * base64encode(const void *b64_encode_me, int encode_this_many_bytes);
unsigned int base64decode(unsigned char **output, void *input, int length);

#endif // __HEX2BASE64_H
