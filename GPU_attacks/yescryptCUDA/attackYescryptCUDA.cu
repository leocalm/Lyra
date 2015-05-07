/**
 * Implementation of the GPU Attack to Yescrypt Password Hashing Scheme (PHS).
 * Based on the Yescrypt Reference Implementation by Alexander Peslyak (Copyright 2013-2015)
 * and Colin Percival (Copyright 2009).
 *
 * Author: The Lyra2 PHC team (http://www.lyra-kdf.net/) -- 2015.
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "yescrypt.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/times.h>
#include <time.h>
#include <sys/time.h>

#define BENCH 1

void multPasswordCUDA(unsigned int t_cost, unsigned int m_cost, unsigned int totalPasswords, unsigned int gridSize, unsigned int blockSize, unsigned int printKeys){
    //=================== Basic variables, with default values =======================//
    size_t kLen = 32;
    size_t pwdLen = 10;
    size_t saltLen = 10;
    int i, j;
	int result;
    //==========================================================================/

	printf("Total time cost: %d \n", t_cost);
	printf("Total memory cost: %d \n", m_cost);
	printf("Total number of password: %d \n", totalPasswords);
	printf("Password length: %d \n", pwdLen);
	printf("Parallelism inside password derivation: %d \n", YESCRYPT_P);
	printf("Grid Size (blocks): %d\n", gridSize);
	printf("Grid Size Parallel Region (blocks): %d\n", gridSize*YESCRYPT_P);
	printf("Block Size (threads): %d\n", blockSize);
	printf("BlockSize x GridSize (threads): %d\n", gridSize*blockSize);
	printf("Total number of threads (passwords x parallelism): %d \n", YESCRYPT_P*totalPasswords);
	uint64_t memoriaBytes = (uint64_t)((YESCRYPT_BASE_N << m_cost)*128*YESCRYPT_R);
    printf("Memory per password: %llu bytes (%llu MB)\n", memoriaBytes, memoriaBytes/(1024*1024));
	printf("Total Memory: %llu bytes (%llu MB)\n", (uint64_t)memoriaBytes*totalPasswords, (uint64_t)((memoriaBytes * totalPasswords)/(1024*1024)));
	printf("Aditional Memory: %llu bytes (%llu MB)\n", (uint64_t)((1024*11)*(totalPasswords*YESCRYPT_P)), (uint64_t)((1024*11)*(totalPasswords*YESCRYPT_P)/(1024*1024)));
	fflush(stdout);

    if (YESCRYPT_P > 32){
        printf("Too much parallelism: not tested\n");
        exit(EXIT_FAILURE);
    }
    if ((YESCRYPT_P & (YESCRYPT_P - 1)) != 0){
        printf("Parallelims must be: 2^n\n");
        exit(EXIT_FAILURE);
    }
    if (YESCRYPT_P < 1){
        printf("Parallelims must be > 0\n");
        exit(EXIT_FAILURE);
    }

    if (!(totalPasswords == (gridSize)*(blockSize))) {
        printf("Geometry error: Passwords must be equal to gridSize x blockSize\n");
        exit(EXIT_FAILURE);
    }

	// All Keys:
	unsigned char *K = (unsigned char *)malloc(totalPasswords * kLen * sizeof(unsigned char));

	//Passwords:
	uint8_t *passwords = (uint8_t *)malloc(totalPasswords * pwdLen * sizeof (uint8_t));
	    if (passwords == NULL) {
        printf("Memory allocation error in file: %s and line: %d\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
    }

	//Salts
	uint8_t *salts = (uint8_t *)malloc(totalPasswords * saltLen * sizeof (uint8_t));
	    if (salts == NULL) {
        printf("Memory allocation error in file: %s and line: %d\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
    }

    //fills passwords and salts
	for (i = 0; i < totalPasswords; i++) {
		for (j = 0; j < pwdLen; j++) {

#ifndef SAMEPASSWORD
	#define SAMEPASSWORD 0
#endif

#if SAMEPASSWORD == 1
			//Same password:
			passwords[i*pwdLen+j] = (0x30+j);
#else
			//Different passwords:
			passwords[i*pwdLen+j] = (0x30+j+i*pwdLen)%255;
#endif
			salts[i*pwdLen+j] = (0x30+j);
		}
	}

#define PRINTPASSWORDS 0
#if PRINTPASSWORDS == 1
	printf("Number of Passwords: %d\n", totalPasswords);
	//Prints passwords
	printf("Passwords:\n");
	for (i = 0; i < totalPasswords; i++) {
        printf("%6d: ", i);
		for (j = 0; j < pwdLen; j++) {
			printf("%2x|", passwords[i*pwdLen + j]);
		}
		printf("\n");
	}

	//Prints salts
	printf("Salts:\n");
	for (i = 0; i < totalPasswords; i++) {
		for (j = 0; j < saltLen; j++) {
			printf("%2x|", salts[i*saltLen + j]);
		}
		printf("\n");
	}
#endif // PRINTPASSWORDS


#if (BENCH == 1)
    struct timeval start;
    struct timeval end;
    gettimeofday(&start, NULL);
#endif

	result = yescrypt_kdf((const uint8_t *)passwords, pwdLen, (const uint8_t *)salts, saltLen, (uint64_t)YESCRYPT_BASE_N << m_cost,
	                       YESCRYPT_R, t_cost, 0, (uint8_t *)K, kLen, totalPasswords, gridSize, blockSize);

#if (BENCH == 1)
    gettimeofday(&end, NULL);
    unsigned long elapsed = (end.tv_sec-start.tv_sec)*1000000 + end.tv_usec-start.tv_usec;

#endif
	if (result >= 0){
		//Prints returned keys
		if (printKeys == 1) {
			printf("Result of %d Keys:\n", totalPasswords);
			for (i = 0; i < totalPasswords; i++) {
				printf("Key #: %3d: ", i);
				for (j = 0; j < kLen; j++) {
					printf("%2x|", K[i*kLen + j]);
				}
				printf("\n");
			}
		}
	}
#if (BENCH == 1)

	if (result < 0) {
		printf("Execution Error!!!\n");
	} else {
		printf("Execution Time: %lu us (%.3f ms, %.3f seg)\n", elapsed, (float)elapsed/1000, (float)elapsed/(1000*1000));
		printf("Execution Time per password: %.3f us (%.3f ms, %.3f seg)\n", (float)((float)elapsed/totalPasswords), (float)(((float)elapsed/totalPasswords)/1000), (float)(((float)elapsed/totalPasswords)/(1000*1000)));
	}
    printf("------------------------------------------------------------------------------------------------------------------------------------------\n");
#endif

	cudaDeviceReset();
	free(passwords);
	free(salts);
	free(K);
}

int main(int argc, char *argv[])
{

    //=================== Basic variables, with default values =======================//
    unsigned int t_cost = 0;
    unsigned int m_cost = 0;
	unsigned int gridSize;
	unsigned int blockSize;
	unsigned int numberPasswds;
    //==========================================================================/

	//	Defines in which GPU will execute
    cudaSetDevice(0);
    //Resets the GPU:
    //cudaDeviceReset();

    switch (argc) {
        case 2:
            if (strcmp(argv[1], "--help") == 0) {
                printf("Usage: \n");
                printf("%s tCost nRows --multPasswordCUDA totalPasswordsToTest totalBlocksToUse threadsPerBlock [optional print hash] (to test multiple GPU derivations in parallel)\n\n", argv[0]);
                return 0;
            } else {
                printf("Invalid options.\nFor more information, try \"%s --help\".\n", argv[0]);
                return 0;
            }
        case 7:
            if (strcmp(argv[3], "--multPasswordCUDA") == 0) {
                t_cost = atoi(argv[1]);
                m_cost = atoi(argv[2]);
                numberPasswds = atoi(argv[4]);
                gridSize = atoi(argv[5]);
                blockSize = atoi(argv[6]);
                multPasswordCUDA(t_cost, m_cost, numberPasswds, gridSize, blockSize, 0);
                return 0;
            }
            break;

        case 8:
            if (strcmp(argv[3], "--multPasswordCUDA") == 0) {
                t_cost = atoi(argv[1]);
                m_cost = atoi(argv[2]);
                numberPasswds = atoi(argv[4]);
                gridSize = atoi(argv[5]);
                blockSize = atoi(argv[6]);
                multPasswordCUDA(t_cost, m_cost, numberPasswds, gridSize, blockSize, 1);
                return 0;
            }
            break;
        default:
            printf("Invalid options.\nTry \"%s --help\" for help.\n", argv[0]);
            return 0;
    }
}

