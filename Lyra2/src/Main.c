/**
 * A simple main function for running the Lyra2 Password Hashing Scheme (PHS).
 * 
 * Author: The Lyra PHC team (http://www.lyra2.net/) -- 2015.
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
#include <time.h>
#include <sys/time.h>

#include "Lyra2.h"
#include "Sponge.h"

#ifndef BENCH
        #define BENCH 0
#endif

/**
 * Generates the test vectors for Lyra2.
 *
 * @param t     Parameter to determine the processing time (T)
 * @param r     Memory cost parameter (defines the number of rows of the memory matrix, R)
 */
int testVectors(unsigned int t, unsigned int m_cost) {
    //=================== Basic variables, with default values =======================//
    int kLen = 64;
    unsigned char *pwd;
    int pwdLen = 11;
    unsigned char *salt;
    int saltLen = 16;

    srand(time(NULL));

    int i;
    int countSample;
    int indexSalt = 0;
    //==========================================================================/

    unsigned char *K = malloc(kLen);

    /* Generating vectors with the input size varying from 0 to 128 bytes,
     * and values varying from 0 to 127. The salt size is fixed in 16 bytes, 
     * and its value varies from 0 to 256.
     */
    for (countSample = 0; countSample <= 128; countSample++) {
        pwdLen = countSample;
        int count;
        pwd = malloc(sizeof (pwd) * pwdLen);
        for (count = 0; count < pwdLen; count++) {
                pwd[count] = count;
        }


        salt = malloc(sizeof (salt) * saltLen);
        for (count = 0; count < saltLen; count++) {
                salt[count] = saltLen * indexSalt + count;
        }
        indexSalt++;
        if (indexSalt == saltLen)
                indexSalt = 0;


        PHS(K, kLen, pwd, pwdLen, salt, saltLen, t, m_cost);

        printf("\ninlen: %d\n", pwdLen);
        printf("outlen: %d\n", kLen);
        printf("t_costs: %d\n", t);
        printf("m_costs: \tR: %d \tC: %d\n", m_cost, N_COLS);
        printf("parallelism: %u\n", nPARALLEL);
    
        char *spongeName ="";
        if (SPONGE==0){
            spongeName = "Blake2";
        }
        else if (SPONGE==1){
            spongeName = "BlaMka";
        }
        else{
            spongeName = "half-round BlaMka";
        }

        printf("sponge: %s\n", spongeName);
        printf("sponge blocks (bitrate): %u = %u bits\n", BLOCK_LEN_INT64, BLOCK_LEN_INT64*64);


        printf("In: ");
        for (i = 0; i < pwdLen; i++) {
                printf("%02x ", pwd[i]);
        }


        printf("\n");

        printf("Salt: ");
        for (i = 0; i < saltLen; i++) {
                printf("%02x ", salt[i]);
        }
        printf("\n");


        printf("Out: ");
        for (i = 0; i < kLen; i++) {
                printf("%02x ", K[i]);
        }
        printf("\n");
    }

    /* Generating vectors with the input size varying from 0 to 128 bytes,
     * and values varying from 128 to 255. The salt size is fixed in 16 bytes, 
     * and its value varies from 0 to 256.
     */
    for (countSample = 128; countSample <= 256; countSample++) {
	pwdLen = countSample - 127;
	int count;
	pwd = malloc(sizeof (pwd) * pwdLen);
	for (count = 0; count < pwdLen; count++) {
	    pwd[count] = count + 128;
	}

	salt = malloc(sizeof (salt) * saltLen);
	for (count = 0; count < saltLen; count++) {
	    salt[count] = saltLen * indexSalt + count;
	}
	indexSalt++;
	if (indexSalt == saltLen)
	    indexSalt = 0;

	PHS(K, kLen, pwd, pwdLen, salt, saltLen, t, m_cost);

	printf("\ninlen: %d\n", pwdLen);
        printf("outlen: %d\n", kLen);
        printf("t_costs: %d\n", t);
        printf("m_costs: \tR: %d \tC: %d\n", m_cost, N_COLS);
        printf("parallelism: %u\n", nPARALLEL);
    
        char *spongeName ="";
        if (SPONGE==0){
            spongeName = "Blake2";
        }
        else if (SPONGE==1){
            spongeName = "BlaMka";
        }
        else{
            spongeName = "half-round BlaMka";
        }

        printf("sponge: %s\n", spongeName);
        printf("sponge blocks (bitrate): %u = %u bits\n", BLOCK_LEN_INT64, BLOCK_LEN_INT64*64);

	printf("In: ");
	for (i = 0; i < pwdLen; i++) {
	    printf("%02x ", pwd[i]);
	}
	printf("\n");

	printf("Salt: ");
	for (i = 0; i < saltLen; i++) {
	    printf("%02x ", salt[i]);
	}
	printf("\n");

	printf("Out: ");
	for (i = 0; i < kLen; i++) {
	    printf("%02x ", K[i]);
	}
	printf("\n");
    }
    return 0;
}

int main(int argc, char *argv[]) {
    //=================== Basic variables, with default values =======================//
    unsigned int kLen = 64;
    unsigned int t_cost = 0;
    unsigned int m_cost = 0;


    char *pwd = "Lyra2 PHS";
    unsigned int pwdLen = 9;
    char *salt = "saltsaltsaltsalt";
    unsigned int saltLen = 16;
    //==========================================================================/

    switch (argc) {
        case 2:
            if (strcmp(argv[1], "--help") == 0) {
                printf("Usage: \n");
                printf("       %s pwd salt kLen tCost nRows \n\n", argv[0]);
                printf("Inputs:\n");
                printf(" - pwd: the password\n");
                printf(" - salt: the salt\n");
                printf(" - kLen: output size\n");
                printf(" - tCost: the time cost parameter\n");
                printf(" - nRows: the number of rows parameter\n");
                printf("\n");
                printf("Or:\n");
                printf("       %s tCost nRows --testVectors     (to generate test vectors and test Lyra2 operation)\n\n", argv[0]);
                return 0;
            } else {
                printf("Invalid options.\nFor more information, try \"%s --help\".\n", argv[0]);
                return 0;
            }
            break;

        case 6:
            pwd = argv[1];
            pwdLen = strlen(pwd);
            salt = argv[2];
            saltLen = strlen(salt);
            kLen = atol(argv[3]);
            t_cost = atol(argv[4]);
            m_cost = atol(argv[5]);
            break;
        case 4:
            if (strcmp(argv[3], "--testVectors") == 0) {
                t_cost = atoi(argv[1]);
                m_cost = atoi(argv[2]);
                testVectors(t_cost, m_cost);
                return 0;
            } else {
                printf("Invalid options.\nFor more information, try \"%s --help\".\n", argv[0]);
                return 0;
            }
            break;

        default:
            printf("Invalid options.\nTry \"%s --help\".\n", argv[0]);
            return 0;
    }

    if (m_cost < 3) {
        printf("nRows must be >= 3\n");
        return 1;
    }

    if ((m_cost / 2) % nPARALLEL != 0) {
        printf("(nRows / 2) mod p must be = 0\n");
        return 1;
    }
    
    unsigned char *K = malloc(kLen);
   
    printf("Inputs: \n");
    printf("\tPassword: %s\n", pwd);
    printf("\tPassword Length: %u\n", pwdLen);
    printf("\tSalt: %s\n", salt);
    printf("\tSalt Length: %u\n", saltLen);
    printf("\tOutput Length: %u\n", kLen);
    printf("------------------------------------------------------------------------------------------------------------------------------------------\n");

    printf("Parameters: \n");
    printf("\tT: %u\n", t_cost);
    printf("\tR: %u\n", m_cost);
    printf("\tC: %u\n", N_COLS);
    printf("\tParallelism: %u\n", nPARALLEL);
    
    char *spongeName ="";
    if (SPONGE==0){
        spongeName = "Blake2";
    }
    else if (SPONGE==1){
        spongeName = "BlaMka";
    }
    else{
        spongeName = "half-round BlaMka";
    }
    
    printf("\tSponge: %s\n", spongeName);
    printf("\tSponge Blocks (bitrate): %u = %u bits\n", BLOCK_LEN_INT64, BLOCK_LEN_INT64*64);
    
    size_t sizeMemMatrix = (size_t) ((size_t)m_cost * (size_t)ROW_LEN_BYTES);

    if(sizeMemMatrix > (1610612736)){
    printf("\tMemory: %ld bytes (IMPORTANT: This implementation is known to have "
            "issues for such a large memory usage)\n", sizeMemMatrix);
    }else{
        printf("\tMemory: %ld bytes\n", sizeMemMatrix);
    }
        

    printf("------------------------------------------------------------------------------------------------------------------------------------------\n");
    
#if (BENCH == 1)
    struct timeval start;
    struct timeval end;
    gettimeofday(&start, NULL);
#endif
    int result;
    
    result = PHS(K, kLen, pwd, pwdLen, salt, saltLen, t_cost, m_cost);
    
#if (BENCH == 1)
    gettimeofday(&end, NULL);
    unsigned long elapsed = (end.tv_sec-start.tv_sec)*1000000 + end.tv_usec-start.tv_usec;
    printf("Execution Time: %lu us\n", elapsed);
    printf("------------------------------------------------------------------------------------------------------------------------------------------\n");
#endif

    switch (result) {
        case 0:
            printf("Output: \n");

            printf("\n\tK: ");
            int i;
            for (i = 0; i < kLen; i++) {
                printf("%x|", K[i]);
            }
            break;
        case -1:
            printf("Error: unable to allocate memory (nRows too large?)\n");
            break;
        default:
            printf("Unexpected error\n");
            break;
    }

    printf("\n");
    printf("------------------------------------------------------------------------------------------------------------------------------------------\n");
    free(K);

    return 0;
}

