#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "Lyra.h"
#include "Sponge.h"

#define SALT_SIZE 16

/*Reads the parameters tCost and nRows (nCols = 64) and calls Lyra with the parameters*/
int main(int argc, char *argv[]) {
	int kLen = 64;

		unsigned char *K = calloc(sizeof K, (kLen));

		int t = 3;
	        int r = 100;
	        int i;
		int result = 1;

		if (argc  != 6)
	    {
	        printf("Usage: \n");
	        printf("       Lyra tCost nRows pwd pwdSize salt\n\n");
	        printf("Inputs:\n");
	        printf(" - tCost: the time cost parameter\n");
	        printf(" - nRows: the number of rows parameter\n");
	        printf(" - pwd: the password\n");
	        printf(" - pwdSize: the password length\n");
	        printf(" - salt: the salt\n");
	        printf("(obs: nCols fixed to 64)\n");
	        return -1;
	    }

		t = atoi(argv[1]);
		r = atoi(argv[2]);
		char *pwd = argv[3];
		int pwdSize = atoi(argv[4]);
		char *salt = argv[5];

		result = PHS(K, kLen, pwd, pwdSize, salt, SALT_SIZE, t, r);

		if(result != 0){
			printf("Error executing Lyra.\n");
			return -1;
		}

		printf("inlen: %d\n", pwdSize);
		printf("t_cost: %d\n", t);
		printf("m_cost: %d\n", r);
		printf("outlen: %d\n", kLen);

		printf("In: ");
			for ( i = 0 ; i < pwdSize ; i++){
				printf("%02x ", pwd[i]);
			}
		printf("\n");

		printf("Salt: ");
		for ( i = 0 ; i < SALT_SIZE ; i++){
			printf("%02x ", salt[i]);
		}
		printf("\n");

		printf("Out: ");
		for ( i = 0 ; i < kLen ; i++){
			printf("%02x ", K[i]);
		}
		printf("\n");

		free(K);




		return 0;
}
