/**
 Implementation of Lyra.

 Author: Leonardo de Campos Almeida.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Lyra.h"
#include "Sponge.h"

/**
 Executes Lyra based on the G function from Blake 2.

 Number of columns set to 64.

 Inputs:
 	 in - user password
 	 inlen - password size
 	 salt - salt
 	 saltlen - salt size
 	 t_cost - parameter to determine the processing time
 	 m_cost - number or rows of the inner matrix, determining the memory cost.
 	 outlen - derived key length
 Output:
 	 out - derived key
 */
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost){
	return lyra(in, inlen, salt, t_cost, m_cost, outlen, out);
}

/**
 Executes Lyra based on the G function from Blake 2.

 Inputs:
         pwd - user password
         pwdSize - password size (this implementation accepts passwords having up to 46 bytes)
         salt - salt
         saltSize - salt size
         timeCost - parameter to determine the processing time
         nCols - number of columns of the inner matrix
         nRows - number or rows of the inner matrix
         kLen - derived key length, in bytes
 Output:
         K - derived key
 */
int lyra(const unsigned char *pwd, int pwdSize, const unsigned char *salt, int timeCost, int nRows, int kLen, unsigned char *K) {

	//Memory matrix: indexes nRows, of each which having nCols blocks, each block having 512 bits (8 uint64_t)
    uint64_t **MemMatrix = malloc(nRows * sizeof (uint64_t*));
    //Sponge state (initialized to zeros): 16 uint64_t, 8 of them for the bitrate (b) and the remainder 8 for the capacity (c)
    uint64_t *state = malloc(16 * sizeof (uint64_t));


    
    int row; //index of row to be processed
    int col; //index of column to be processed

    int i, j;
    
    //============== Initialing the Sponge State =============/
    initState(state);
    //========================================================//

    //====== Getting the password + salt padded with 10*1 ===== //

    //Initializes the first row of the matrix, which will temporarily hold the password: not for saving memory, but ensures
    //that the password will be overwritten during the process
    MemMatrix[0] = (uint64_t*) malloc(ROW_LEN_BYTES);

    //Prepends the salt to the password
    byte *ptrMem = (byte*) MemMatrix[0];
    memcpy(ptrMem, salt, SALT_LEN_BYTES);

    //Concatenates the password
    ptrMem += SALT_LEN_BYTES;
    memcpy(ptrMem, pwd, pwdSize);

    //Now comes the padding
    ptrMem += pwdSize;
    *ptrMem = 0x80; //first byte

    ptrMem = (byte*) (MemMatrix[0]);
    ptrMem += BLOCK_LEN_BYTES - 1;
    *ptrMem = 0x01; //last byte

    //========================================================//


    //================== Setup Phase =====================//
    absorbBlock(state, MemMatrix[0]);
    reducedSqueezeRow(state, (uint64_t*) MemMatrix[0]);
    for (row = 1; row < nRows; row++) {
             MemMatrix[row] = malloc(ROW_LEN_BYTES);
             reducedDuplexRowSetup(state, (uint64_t*) MemMatrix[row], MemMatrix[row-1]);
    }
    //========================================================//

    //================== Wandering phase =========================//
    row = 0;
    for (i = 0; i < timeCost; i++) {
        for (j = 0; j < nRows; j++) {
            reducedDuplexRow(state, (uint64_t*) MemMatrix[row]);
            col = MemMatrix[row][N_COLS - 1] & 63u;
            row = duplexBlock(state, (uint64_t*) & MemMatrix[row][col]) % nRows;
        }
    }
    //========================================================//
    
    //================= Wrap-up phase ========================//

    //Absorbs the salt   
    absorbPaddedSalt(state, (uint64_t*) salt);
    
    //Squeezes the key
    squeeze(state, K, kLen);
    
    //========================================================//

    //=============== Freeing the memory =====================//
    for (i = 0; i < nRows; i++) {
        free(MemMatrix[i]);
    }
    free(MemMatrix);
    free(state);
    //========================================================//

    return 0;
}



