all: set1 set2

set1: src/aes.o src/pkcs.o src/hex2base64.o src/hex_coder.o src/xor.o src/histogram.o src/hamming.o set1/main.o
	gcc -ggdb -lcrypto src/aes.c src/pkcs.o src/hex2base64.c src/hex_coder.c src/xor.c src/histogram.c src/hamming.c set1/main.c -o set1/main.out

set2:  src/hamming.o src/histogram.o src/hex2base64.o src/xor.o src/aes.o src/hex_coder.o src/pkcs.o set2/main.o
	gcc -ggdb -lcrypto src/hamming.c src/histogram.c src/hex2base64.c src/xor.c src/aes.c src/hex_coder.c src/pkcs.c set2/main.c -o set2/main.out
