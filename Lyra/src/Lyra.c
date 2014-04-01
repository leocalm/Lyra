/**
 * Implementation of the Lyra Password Hashing Scheme (PHS).
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
#include "Lyra.h"
#include "Sponge.h"

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

/**
 * Executes Lyra2 based on the G function from Blake2b. The number of columns of the memory matrix is set to nCols = 64.
 * This version supports salts and passwords whose combined length is smaller than the size of the memory matrix, 
 * (i.e., (nRows x nCols x b) bits,  where "b" is the underlying sponge's bitrate) 
 * 
 * @param out     The derived key to be output by the algorithm
 * @param outlen  Desired key length
 * @param in      User password
 * @param inlen   Password length
 * @param salt    Salt
 * @param saltlen Salt length
 * @param t_cost  Parameter to determine the processing time (T)
 * @param m_cost  Memory cost parameter (defines the number of rows of the memory matrix, R)
 * 
 * @return          0 if the key is generated correctly; -1 if there is an error (usually due to lack of memory for allocation)
 */
/*
int lyra(unsigned char *K, int kLen, const unsigned char *pwd, int pwdlen, const unsigned char *salt, int saltlen, int timeCost, int nRows) {
    return lyra(K, kLen, pwd, pwdlen, salt, saltlen, timeCost, nRows, N_COLS);
}
*/

/**
 * Executes Lyra2 based on the G function from Blake2b. This version supports salts and passwords
 * whose combined length is smaller than the size of the memory matrix, (i.e., (nRows x nCols x b) bits, 
 * where "b" is the underlying sponge's bitrate) 
 * 
 * @param K         The derived key to be output by the algorithm
 * @param kLen      Desired key length
 * @param pwd       User password
 * @param pwdlen    Password length
 * @param salt      Salt
 * @param saltlen   Salt length
 * @param timeCost  Parameter to determine the processing time (T)
 * @param nRows     Number or rows of the memory matrix (R)
 * @param nCols     Number of columns of the memory matrix (C)
 * 
 * @return          0 if the key is generated correctly; -1 if there is an error (usually due to lack of memory for allocation)
 */
int lyra(unsigned char *K, int kLen, const unsigned char *pwd, int pwdlen, const unsigned char *salt, int saltlen, int timeCost, int nRows, int nCols) {

    //============================= Basic variables ============================//
    int i, j; //auxiliary iteration counters
    int row; //index of row to be processed
    int col; //index of column to be processed
    //==========================================================================/

    //========== Initializing the Memory Matrix and pointers to it =============//
    //Allocates enough space for the whole memory matrix
    uint64_t *wholeMatrix = malloc(nRows * ROW_LEN_BYTES);
    if (wholeMatrix == NULL) {
        return -1;
    }
    //Allocates pointers to each row of the matrix
    uint64_t **memMatrix = malloc(nRows * sizeof (uint64_t*));
    if (memMatrix == NULL) {
        return -1;
    }
    //Places the pointers in the correct positions
    uint64_t *ptrWord = wholeMatrix;
    for (i = 0; i < nRows; i++) {
        memMatrix[i] = ptrWord;
        ptrWord += ROW_LEN_INT64;
    }
    //==========================================================================/

    //============= Getting the password + salt padded with 10*1 ===============//

    //OBS.:The memory matrix will temporarily hold the password: not for saving memory, 
    //but this ensures that the password copied locally will be overwritten as soon as possible

    //First, we clean enough blocks for the password, salt and padding
    int nBlocksInput = ((saltlen + pwdlen) / BLOCK_LEN_BYTES) + 1;
    byte *ptrByte = (byte*) wholeMatrix;
    memset(ptrByte, 0, nBlocksInput * BLOCK_LEN_BYTES);

    //Prepends the salt to the password
    memcpy(ptrByte, salt, saltlen);

    //Concatenates the password
    ptrByte += saltlen;
    memcpy(ptrByte, pwd, pwdlen);

    //Now comes the padding
    ptrByte += pwdlen;
    *ptrByte = 0x80; //first byte of padding: right after the password
    ptrByte = (byte*) wholeMatrix; //resets the pointer to the start of the memory matrix
    ptrByte += nBlocksInput * BLOCK_LEN_BYTES - 1; //sets the pointer to the correct position: end of incomplete block
    *ptrByte ^= 0x01; //last byte of padding: at the end of the last incomplete block
    //==========================================================================/


    //======================= Initializing the Sponge State ====================//
    //Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)
    uint64_t *state = malloc(16 * sizeof (uint64_t));
    if (state == NULL) {
        return -1;
    }
    initState(state);
    //==========================================================================/

    //================================ Setup Phase =============================//

    //Absorbing salt and password
    ptrWord = wholeMatrix;
    for (i = 0; i < nBlocksInput; i++) {
        absorbBlock(state, ptrWord); //absorbs each block of pad(salt || pwd)
        ptrWord += BLOCK_LEN_INT64; //goes to next block of pad(salt || pwd)
    }


    //Initializing M[0]]
    reducedSqueezeRow(state, (uint64_t*) memMatrix[0]); //The locally copied password is most likely overwritten here
    for (row = 1; row < nRows; row++) {
        //Initializing remainder rows
        reducedDuplexRowSetup(state, (uint64_t*) memMatrix[row], memMatrix[row - 1]);
    }
    //==========================================================================/


    //================== Wandering phase =========================//
    row = 0;
    for (i = 0; i < timeCost; i++) {
        for (j = 0; j < nRows; j++) {
            reducedDuplexRow(state, (uint64_t*) memMatrix[row]);
            //col = memMatrix[row][N_COLS - 1] & (nCols-1);				//(USE THIS IF nCols IS A POWER OF 2)
            col = memMatrix[row][nCols - 1] % nCols;                                   //(USE THIS FOR THE "GENERIC" CASE of nCols)
            //row = duplexBlock(state, (uint64_t*) & memMatrix[row][col]) & (nRows-1);	//(USE THIS IF nRows IS A POWER OF 2)
            row = duplexBlock(state, (uint64_t*) & memMatrix[row][col]) % nRows;        //(USE THIS FOR THE "GENERIC" CASE of nRows)
        }
    }
    //========================================================//

    //================= Wrap-up phase ========================//

    //Absorbs the salt   
    absorbPaddedSalt(state, (uint64_t*) salt, saltlen);

    //Squeezes the key
    squeeze(state, K, kLen);

    //========================================================//

    //=============== Freeing the memory =====================//
    free(memMatrix);
    free(wholeMatrix);
    free(state);
    //========================================================//

    return 0;
}



