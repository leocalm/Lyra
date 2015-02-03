/**
 * A simple attack against Lyra2 Password Hashing Scheme (PHS).
 * This is a specific implementation, used only to start
 * evaluating GPU attacks. This implementation needs improvement
 * in specific GPU optimization technics.
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

#include "attackLyra2.h"
#include "attackSponge.h"

#ifndef BENCH
        #define BENCH 0
#endif

/**
 * Generates the passwords for Lyra2 attack.
 *
 * @param t_cost            Parameter to determine the processing time (T)
 * @param m_cost            Memory cost parameter (defines the number of rows of the memory matrix, R)
 * @param totalPasswords    Total number of passwords being tested
 * @param gridSize          GPU grid configuration
 * @param blockSize         GPU block configuration
 * @param printKeys         Defines if the resulting keys will be in the output
 */
void multPasswordCUDA(unsigned int t_cost, unsigned int m_cost, unsigned int totalPasswords, unsigned int gridSize, unsigned int blockSize, unsigned int printKeys) {
    //=================== Basic variables, with default values =======================//
    int kLen = 32;
    unsigned char *ptrChar;
    int pwdLen = 10;
    int saltLen = 10;
    int i, j;
    int result;
    //==========================================================================/

    if (m_cost / nPARALLEL < 4) {
        printf("Number of rows too small\n");
        exit(0);
    }

    size_t sizeMemMatrix = (size_t) ((size_t) m_cost * (size_t) ROW_LEN_BYTES);

    printf("Total time cost: %d \n", t_cost);
    printf("Total number of rows: %d \n", m_cost);
    printf("Total number of cols: %d \n", N_COLS);
    char *spongeName = "";
    if (SPONGE == 0) {
        spongeName = "Blake2";
    } else if (SPONGE == 1) {
        spongeName = "BlaMka";
    } else {
        spongeName = "half-round BlaMka";
    }
    printf("Sponge: %s\n", spongeName);
    printf("Total number of password: %d \n", totalPasswords);
    printf("Password length: %d \n", pwdLen);
    printf("Parallelism inside password derivation: %d \n", nPARALLEL);
    printf("Grid Size (blocks): %d\n", gridSize);
    printf("Block Size (threads): %d\n", blockSize);
    printf("BlockSize x GridSize (threads): %d\n", gridSize * blockSize);
    printf("Total number of threads: %d \n", nPARALLEL * totalPasswords);
    printf("Memory per password: %ld bytes (%ld MB)\n", (long int) sizeMemMatrix, (long int) (sizeMemMatrix) / (1024 * 1024));
    printf("Total Memory: %ld bytes (%ld MB)\n", (long int) sizeMemMatrix * totalPasswords, (long int) (sizeMemMatrix * totalPasswords) / (1024 * 1024));
    fflush(stdout);

    // All Keys:
    unsigned char *K = (unsigned char *) malloc(totalPasswords * kLen * sizeof (unsigned char));

    //Pointer to each passwords in the Matrix:
    unsigned char **passwords = (unsigned char **) malloc(totalPasswords * sizeof (unsigned char *));
    if (passwords == NULL) {
        printf("Memory allocation error in file: %s and line: %d\n", __FILE__, __LINE__);
        exit(EXIT_FAILURE);
    }

    //Matrix with all passwords:
    unsigned char *passwdMatrix = (unsigned char *) malloc(totalPasswords * pwdLen * sizeof (unsigned char));
    if (passwdMatrix == NULL) {
        printf("Memory allocation error in file: %s and line: %d\n", __FILE__, __LINE__);
        exit(EXIT_FAILURE);
    }

    //Pointer to each salt in the Matrix:
    unsigned char **salts = (unsigned char **) malloc(totalPasswords * sizeof (unsigned char *));
    if (salts == NULL) {
        printf("Memory allocation error in file: %s and line: %d\n", __FILE__, __LINE__);
        exit(EXIT_FAILURE);
    }

    //Matrix with all salts:
    unsigned char *saltMatrix = (unsigned char *) malloc(totalPasswords * saltLen * sizeof (unsigned char));
    if (saltMatrix == NULL) {
        printf("Memory allocation error in file: %s and line: %d\n", __FILE__, __LINE__);
        exit(EXIT_FAILURE);
    }

    //Places the pointers in the correct positions
    ptrChar = passwdMatrix;
    for (i = 0; i < totalPasswords; i++) {
        passwords[i] = ptrChar;
        ptrChar += pwdLen; // pwdLen * sizeof (unsigned char);
    }

    //Places the pointers in the correct positions
    ptrChar = saltMatrix;
    for (i = 0; i < totalPasswords; i++) {
        salts[i] = ptrChar;
        ptrChar += saltLen; // pwdLen * sizeof (unsigned char);
    }

    //fills passwords
    for (i = 0; i < totalPasswords; i++) {
        for (j = 0; j < pwdLen; j++) {
            //Different passwords
            //passwords[i][j] = (j+i*pwdLen)%255;
            //Same password
            passwords[i][j] = (0x30 + j);
        }
    }

    //fills salts
    for (i = 0; i < totalPasswords; i++) {
        for (j = 0; j < saltLen; j++) {
            salts[i][j] = (0x30 + j);
        }
    }

/*
	printf("Number of Passwords: %d\n", totalPasswords);
	//Prints passwords
	printf("Passwords:\n");
	for (i = 0; i < totalPasswords; i++) {
		for (j = 0; j < pwdLen; j++) {
			printf("%2x|", passwords[i][j]);
		}
		printf("\n");
	}

	//Prints salts
	printf("Salts:\n");
	for (i = 0; i < totalPasswords; i++) {
		for (j = 0; j < saltLen; j++) {
			printf("%x|", salts[i][j]);
		}
		printf("\n");
	}
*/	
	
#if (BENCH == 1)
    struct timeval start;
    struct timeval end;
    gettimeofday(&start, NULL);
#endif

    //Calls the interface to the GPU program
    result = gpuMult(K, kLen, passwords, pwdLen, salts, saltLen, t_cost, m_cost, N_COLS, totalPasswords, gridSize, blockSize);

#if (BENCH == 1)
    gettimeofday(&end, NULL);
    unsigned long elapsed = (end.tv_sec-start.tv_sec)*1000000 + end.tv_usec-start.tv_usec;
#endif
    if (result >= 0) {
        //Prints returned keys
        if (printKeys == 1) {
            printf("Result of %d Keys:\n", totalPasswords);
            for (i = 0; i < totalPasswords; i++) {
                printf("Key #: %3d: ", i);
                for (j = 0; j < kLen; j++) {
                    printf("%2x|", K[i * kLen + j]);
                }
                printf("\n");
            }
        }
    }
    
#if (BENCH == 1)
    if (result < 0) {
        printf("Execution Error!!!\n");
    } else {
        printf("Execution Time: %lu us (%.3f ms, %.3f seg)\n", elapsed, (float) elapsed / 1000, (float) elapsed / (1000 * 1000));
        printf("Execution Time per password: %.3f us (%.3f ms, %.3f seg)\n", (float) ((float) elapsed / totalPasswords), (float) (((float) elapsed / totalPasswords) / 1000), (float) (((float) elapsed / totalPasswords) / (1000 * 1000)));
    }
    printf("------------------------------------------------------------------------------------------------------------------------------------------\n");
#endif
    
    cudaDeviceReset();
    free(passwords);
    free(passwdMatrix);
    free(saltMatrix);
    free(salts);
    free(K);
}


int main(int argc, char *argv[]) {
    //=================== Basic variables, with default values =======================//
    unsigned int t_cost = 0;
    unsigned int m_cost = 0;
    unsigned int gridSize;
    unsigned int blockSize;
    unsigned int numberPasswds;
    //==========================================================================/

    //	Defines in which GPU will execute
    cudaSetDevice(0);

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

