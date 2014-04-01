/**
 * A simple main function for running the Lyra Password Hashing Scheme (PHS).
 * 
 * Author: The Lyra PHC team (http://www.lyra-kdf.net/).
 * 
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "Lyra.h"
#include "Sponge.h"

/*Reads the parameters tCost and nRows (nCols = 64) and calls Lyra with the parameters*/
int main(int argc, char *argv[]) {
    int kLen = 64;

    unsigned char *K = calloc(sizeof K, (kLen));

    int t = 3;
    int r = 100;
    int i;
    int result = 1;

    if (argc != 7) {
	printf("Usage: \n");
	printf("       Lyra tCost nRows pwd pwdlen salt\n\n");
	printf("Inputs:\n");
	printf(" - tCost: the time cost parameter\n");
	printf(" - nRows: the number of rows parameter\n");
	printf(" - pwd: the password\n");
	printf(" - pwdlen: the password length\n");
	printf(" - salt: the salt\n");
	printf(" - salt: the salt length\n");
	printf("(obs: nCols fixed to 64)\n");
	return -1;
    }

    t = atoi(argv[1]);
    r = atoi(argv[2]);
    char *pwd = argv[3];
    int pwdlen = atoi(argv[4]);
    char *salt = argv[5];
    int saltlen = atoi(argv[6]);
    

    result = lyra(K, kLen, (unsigned char*) pwd, pwdlen, (unsigned char*) salt, saltlen, t, r, N_COLS);

    if (result != 0) {
	printf("Error executing Lyra.\n");
	return -1;
    }

    printf("inlen: %d\n", pwdlen);
    printf("t_cost: %d\n", t);
    printf("m_cost: %d\n", r);
    printf("outlen: %d\n", kLen);

    printf("In: ");
    for (i = 0; i < pwdlen; i++) {
	printf("%02x ", pwd[i]);
    }
    printf("\n");

    printf("Salt: ");
    for (i = 0; i < saltlen; i++) {
	printf("%02x ", salt[i]);
    }
    printf("\n");

    printf("Out: ");
    for (i = 0; i < kLen; i++) {
	printf("%02x ", K[i]);
    }
    printf("\n");

    free(K);




    return 0;
}
