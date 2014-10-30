/*
 * main.c for set 6 of the matasano crypto challenges
 *
 *  Created on: 29.10.2014
 *  Author:     rc0r
 */

#include <stdio.h>
#include <stdlib.h>

#include "../include/rsa.h"

int main(int argc, char *argv[])
{
	/**       Set 6 Challenge 41       **/
	/** RSA unpadded msg oracle attack **/
	rsa_unpadded_msg_oracle_attack_test();

	return 0;
}
