/**
 * A simple implementation of Blake2b's internal permutation 
 * in the form of a sponge.
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
#include <string.h>
#include <stdio.h>
#include "Sponge.h"
#include "Lyra.h"
#include <time.h>

/**
 Prints an array of unsigned chars
 */
void printArray(unsigned char *array, unsigned int size, char *name) {
    int i;
    printf("%s: ", name);
    for (i = 0; i < size; i++) {
        printf("%2x|", array[i]);
    }
    printf("\n");
}

/**
 * Initializes the Sponge State. The first 512 bits are set to zeros and the remainder 
 * receive Blake2b's IV as per Blake2b's specification. <b>Note:</b> Even though sponges
 * typically have their internal state initialized with zeros, Blake2b's G function
 * has a fixed point: if the internal state and message are both filled with zeros. the 
 * resulting permutation will always be a block filled with zeros; this happens because 
 * Blake2b does not use the constants originally employed in Blake2 inside its G function, 
 * relying on the IV for avoiding possible fixed points.
 * 
 * @param state         The 1024-bit array to be initialized
 */
void inline initState(uint64_t state[/*16*/]){
    memset(state, 0, 64); //first 512 bis are zeros
    state[8] = blake2b_IV[0];
    state[9] = blake2b_IV[1];
    state[10] = blake2b_IV[2];
    state[11] = blake2b_IV[3];
    state[12] = blake2b_IV[4];
    state[13] = blake2b_IV[5];
    state[14] = blake2b_IV[6];
    state[15] = blake2b_IV[7];
}

/**
 * Execute Blake2b's G function, with all 12 rounds.
 * 
 * @param v     A uint64_t array to be processed by Blake2b's G function
 */
static inline void blake2bLyra(uint64_t *v) {
    ROUND_LYRA(0);
    ROUND_LYRA(1);
    ROUND_LYRA(2);
    ROUND_LYRA(3);
    ROUND_LYRA(4);
    ROUND_LYRA(5);
    ROUND_LYRA(6);
    ROUND_LYRA(7);
    ROUND_LYRA(8);
    ROUND_LYRA(9);
    ROUND_LYRA(10);
    ROUND_LYRA(11);
}

/**
 * Executes a reduced version of Blake2b's G function with only one round
 * @param v     A uint64_t array to be processed by Blake2b's G function
 */
static inline void reducedBlake2bLyra(uint64_t *v) {
    ROUND_LYRA(0);
}

/**
 * Performs a squeeze operation, using Blake2b's G function as the 
 * internal permutation
 * 
 * @param state         The sponge state
 * @param out           Array that will receive the data squeezed
 * @param len        The number of bytes to be squeezed into the "out" array
 */
void squeeze(uint64_t *state, byte *out, unsigned int len) {
    int fullBlocks = len / BLOCK_LEN_BYTES;
    byte *ptr = out;
    int i;
    //Squeezes full blocks
    for (i = 0; i < fullBlocks; i++) {
        memcpy(ptr, state, BLOCK_LEN_BYTES);
        blake2bLyra(state);
        ptr += BLOCK_LEN_BYTES;
    }
    
    //Squeezes remaining bytes
    memcpy(ptr, state, (len % BLOCK_LEN_BYTES));
}

/**
 * Performs an absorb operation for a single block (BLOCK_LEN_INT64 words
 * of type uint64_t), using Blake2b's G function as the internal permutation
 * 
 * @param state The current state of the sponge 
 * @param in    The block to be absorbed (BLOCK_LEN_INT64 words)
 */
void absorbBlock(uint64_t *state, const uint64_t *in) {
    //XORs the first BLOCK_LEN_INT64 words of "in" with the current state
    state[0] ^= in[0];
    state[1] ^= in[1];
    state[2] ^= in[2];
    state[3] ^= in[3];
    state[4] ^= in[4];
    state[5] ^= in[5];
    state[6] ^= in[6];
    state[7] ^= in[7];

#if (BLOCK_LEN_INT64 == 10)
    state[8] ^= in[8];
    state[9] ^= in[9];
#endif
    
#if (BLOCK_LEN_INT64 == 12)
    state[8] ^= in[8];
    state[9] ^= in[9];
    state[10] ^= in[10];
    state[11] ^= in[11];
#endif

    //Applies the transformation f to the sponge's state
    blake2bLyra(state);
}

/**
 * Absorbs the salt, applying the required 10*1 padding
 * @param state The current state of the sponge 
 * @param salt	The salt to be absorbed
 * @param saltlen  The lenght of the salt, in bytes
 */
void absorbPaddedSalt(uint64_t *state, uint64_t *salt, int saltlen) {
    int i;
    int nBlocksSalt = saltlen / BLOCK_LEN_BYTES;
    
    //Absorbs full blocks
    uint64_t *ptrWord = salt;
    for(i = nBlocksSalt ; i > 0; i--){
	absorbBlock(state, ptrWord);
	ptrWord += BLOCK_LEN_INT64;
    }
        
    //Absorbs trailing bytes with padding
    byte *ptrByteState = (byte*) state;
    byte *ptrByteSalt = (byte*) salt;
    //Absorbs the padded salt
    for(i = saltlen - nBlocksSalt*BLOCK_LEN_BYTES ; i > 0 ; i--){
	*ptrByteState ^= *ptrByteSalt;
	ptrByteState++;
	ptrByteSalt++;
    }
    *ptrByteState ^= 0x80;		//first byte of padding: right after the salt
    state[7] ^= 0x0100000000000000ULL;	//last byte of padding: at the end of the state    
   
    //Applies the transformation f to the sponge's state
    blake2bLyra(state);
}

/**
 * 
 * Performs an absorb operation for a single block (BLOCK_LEN_INT64 words
 * of type uint64_t), using reduced-round Blake2b's G function as the internal permutation
 * @param state The current state of the sponge 
 * @param in    The uint64_t array to be absorbed
 */
void reducedAbsorbBlock(uint64_t *state, const uint64_t *in) {
    //XORs the first BLOCK_LEN_INT64 words of "in" with the current state
    state[0] ^= in[0];
    state[1] ^= in[1];
    state[2] ^= in[2];
    state[3] ^= in[3];
    state[4] ^= in[4];
    state[5] ^= in[5];
    state[6] ^= in[6];
    state[7] ^= in[7];
    
#if (BLOCK_LEN_INT64 == 10)
    state[8] ^= in[8];
    state[9] ^= in[9];
#endif
    
#if (BLOCK_LEN_INT64 == 12)
    state[8] ^= in[8];
    state[9] ^= in[9];
    state[10] ^= in[10];
    state[11] ^= in[11];
#endif

    reducedBlake2bLyra(state);
}

/** 
 * Performs a squeeze operation for an entire row, using reduced 
 * Blake2b's G function as the internal permutation
 * 
 * @param state         The sponge state
 * @param out           Array that will receive the data squeezed
 */
void reducedSqueezeRow(uint64_t* state, uint64_t* row) {
    uint64_t* ptr64 = row; //pointer to position to be filled
    int i;
    for (i = 0; i < N_COLS; i++) {
        memcpy(ptr64, state, BLOCK_LEN_BYTES);
        ptr64 += BLOCK_LEN_INT64;
        reducedBlake2bLyra(state);
    }
}

/** 
 * Performs a duplex operation for an entire row, using reduced-round 
 * Blake2b's G function as the internal permutation, already XORing 
 * the output with the provided input
 * 
 * @param state         The sponge state
 * @param out           Array that will be absorbed and XORed with the data squeezed
 */
void reducedDuplexRow(uint64_t *state, uint64_t *row) {
    uint64_t* ptr64 = row; //pointer to position to be XORed
    int i;
    for (i = 0; i < N_COLS; i++){
        //Absorbing the block
        reducedAbsorbBlock(state, ptr64);

        //Squeezing the block and using this opportunity to XOR it to the row
        ptr64[0] ^= state[0];
        ptr64[1] ^= state[1];
        ptr64[2] ^= state[2];
        ptr64[3] ^= state[3];
        ptr64[4] ^= state[4];
        ptr64[5] ^= state[5];
        ptr64[6] ^= state[6];
        ptr64[7] ^= state[7];

#if (BLOCK_LEN_INT64 == 10)
        ptr64[8] ^= state[8];
        ptr64[9] ^= state[9];
#endif

#if (BLOCK_LEN_INT64 == 12)
        ptr64[8] ^= state[8];
        ptr64[9] ^= state[9];
        ptr64[10] ^= state[10];
        ptr64[11] ^= state[11];
#endif

        //Goes to next block
        ptr64 += BLOCK_LEN_INT64;
    }
}

/**
 * <b>OK</b>
 *
 * Performs a duplex operation for an entire row, using reduced-round
 * Blake2b's G function as the internal permutation, taking row-1 as input
 * and row as output
 *
 * @param state         The sponge state
 * @param row           Array that will receive the data squeezed
 * @param oldRow        Array that will be absorbed
 */
void reducedDuplexRowSetup(uint64_t *state, uint64_t *row, uint64_t *oldRow) {
    uint64_t* ptr64 = oldRow; //pointer to position to be XORed
    uint64_t* newPtr64 = row;
    int i;
    for (i = 0; i < N_COLS; i++){
        //Absorbing the block
        reducedAbsorbBlock(state, ptr64);

        //Squeezing the block and using this opportunity to XOR it to the row
        newPtr64[0] = state[0];
        newPtr64[1] = state[1];
        newPtr64[2] = state[2];
        newPtr64[3] = state[3];
        newPtr64[4] = state[4];
        newPtr64[5] = state[5];
        newPtr64[6] = state[6];
        newPtr64[7] = state[7];

#if (BLOCK_LEN_INT64 == 10)
        newPtr64[8] = state[8];
        newPtr64[9] = state[9];
#endif

#if (BLOCK_LEN_INT64 == 12)
        newPtr64[8] = state[8];
        newPtr64[9] = state[9];
        newPtr64[10] = state[10];
        newPtr64[11] = state[11];
#endif
        
        //Goes to next block
        ptr64 += BLOCK_LEN_INT64;
        newPtr64 += BLOCK_LEN_INT64;
    }
}


/**
 * <b>OK</b>
 * 
 * Performs a duplex operation for an single block, (BLOCK_LEN_INT64 words
 * of type uint64_t), using Blake2b's G function as the internal permutation, 
 * and returning a single uint64_t (i.e., the first uint64_t of the resulting 
 * state) as result
 * 
 * @param state The sponge state
 * @param in    The uint64_t array to be duplexed
 * @return      The first uint64_t of the resulting state
 */
uint64_t duplexBlock(uint64_t *state, const uint64_t *in) {
    //Absorbing the block
    absorbBlock(state, in);
    
    //Squeezing a single uint64_t as response
    return state[0];
}

////////////////////////////////////////////////////////////////////////////////////////////////
