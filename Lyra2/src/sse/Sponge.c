/**
 * A simple implementation of Blake2b's internal permutation 
 * in the form of a sponge. SSE-optimized implementation.
 * 
 * Author: The Lyra PHC team (http://www.lyra-kdf.net/) -- 2014.
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
#include <time.h>
#include <immintrin.h>
#include "blake2b-round.h"
#include "Sponge.h"
#include "Lyra2.h"


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
inline void initState(__m128i state[/*8*/]){
    memset(state, 0, 64); //first 512 bits are zeros
    state[4] = _mm_load_si128((__m128i *) &blake2b_IV[0]);
    state[5] = _mm_load_si128((__m128i *) &blake2b_IV[2]);
    state[6] = _mm_load_si128((__m128i *) &blake2b_IV[4]);
    state[7] = _mm_load_si128((__m128i *) &blake2b_IV[6]);
}

/**
 * Execute Blake2b's G function, with all 12 rounds.
 * 
 * @param v     A 1024-bit (16 uint64_t) array to be processed by Blake2b's G function
 */
static inline void blake2bLyra(__m128i *v){
    __m128i t0, t1;

    ROUND(0);
    ROUND(1);
    ROUND(2);
    ROUND(3);
    ROUND(4);
    ROUND(5);
    ROUND(6);
    ROUND(7);
    ROUND(8);
    ROUND(9);
    ROUND(10);
    ROUND(11);
}

/**
 * Executes a reduced version of Blake2b's G function with only one round
 * @param v     A 1024-bit (16 uint64_t) array to be processed by Blake2b's G function
 */
static inline void reducedBlake2bLyra(__m128i *v){
    __m128i t0, t1;

    ROUND(0);    
}

/**
 * Performs a squeeze operation, using Blake2b's G function as the 
 * internal permutation
 * 
 * @param state      The current state of the sponge 
 * @param out        Array that will receive the data squeezed
 * @param len        The number of bytes to be squeezed into the "out" array
 */
void squeeze(__m128i *state, byte *out, unsigned int len) {
    int fullBlocks = len / BLOCK_LEN_BYTES;
    byte *ptr = out;
    int i;
    //Squeezes full blocks
    for (i = 0; i < fullBlocks; i++) {
        memcpy(ptr, state, BLOCK_LEN_BYTES);
        blake2bLyra(state);

        ptr += BLOCK_LEN_BYTES;
    }
    memcpy(ptr, state, (len % BLOCK_LEN_BYTES));
}

/**
 * Performs an absorb operation for a single block (BLOCK_LEN_INT64 words
 * of type uint64_t), using Blake2b's G function as the internal permutation
 * 
 * @param state The current state of the sponge 
 * @param in    The block to be absorbed 
 */
void absorbBlock(__m128i *state, const __m128i *in){
    state[0] = _mm_xor_si128(state[0], in[0]);
    state[1] = _mm_xor_si128(state[1], in[1]);
    state[2] = _mm_xor_si128(state[2], in[2]);
    state[3] = _mm_xor_si128(state[3], in[3]);
    state[4] = _mm_xor_si128(state[4], in[4]);
    state[5] = _mm_xor_si128(state[5], in[5]);

    //Applies the transformation f to the sponge's state
    blake2bLyra(state);
}

/**
 * Performs an absorb operation for a single block (BLOCK_LEN_BLAKE2_SAFE_INT64 
 * words of type uint64_t), using Blake2b's G function as the internal permutation
 * 
 * @param state The current state of the sponge 
 * @param in    The block to be absorbed (BLOCK_LEN_BLAKE2_SAFE_INT64 words)
 */
inline void absorbBlockBlake2Safe(__m128i *state, const __m128i *in) {
    //XORs the first BLOCK_LEN_BLAKE2_SAFE_INT64 words of "in" with the current state
    state[0] = _mm_xor_si128(state[0], in[0]);
    state[1] = _mm_xor_si128(state[1], in[1]);
    state[2] = _mm_xor_si128(state[2], in[2]);
    state[3] = _mm_xor_si128(state[3], in[3]);

    //Applies the transformation f to the sponge's state
    blake2bLyra(state);
}

/** 
 * Performs a reduced squeeze operation for a single row, from the highest to 
 * the lowest index, using the reduced-round Blake2b's G function as the 
 * internal permutation
 * 
 * @param state     The current state of the sponge 
 * @param rowOut    Row to receive the data squeezed
 */
inline void reducedSqueezeRow0(__m128i* state, __m128i* rowOut) {
    __m128i* ptrWord = rowOut + (N_COLS-1)*BLOCK_LEN_INT128; //In Lyra2: pointer to M[0][C-1]
    int i;
    //M[row][C-1-col] = H.reduced_squeeze()    
    for (i = 0; i < N_COLS; i++) {
	ptrWord[0] = state[0];
        ptrWord[1] = state[1];
        ptrWord[2] = state[2];
        ptrWord[3] = state[3];
        ptrWord[4] = state[4];
        ptrWord[5] = state[5];

        //Goes to next block (column) that will receive the squeezed data
        ptrWord -= BLOCK_LEN_INT128;

        //Applies the reduced-round transformation f to the sponge's state
        reducedBlake2bLyra(state);
    }
}


/** 
 * Performs a reduced duplex operation for a single row, from the highest to 
 * the lowest index, using the reduced-round Blake2b's G function as the 
 * internal permutation
 * 
 * @param state		The current state of the sponge 
 * @param rowIn		Row to feed the sponge
 * @param rowOut	Row to receive the sponge's output
 */
inline void reducedDuplexRow1(__m128i *state, __m128i *rowIn, __m128i *rowOut) {
    __m128i* ptrWordIn = rowIn;				//In Lyra2: pointer to prev
    __m128i* ptrWordOut = rowOut + (N_COLS-1)*BLOCK_LEN_INT128; //In Lyra2: pointer to row
    int i;

    for (i = 0; i < N_COLS; i++) {

	//Absorbing "M[prev][col]"
	state[0] = _mm_xor_si128(state[0], ptrWordIn[0]);
	state[1] = _mm_xor_si128(state[1], ptrWordIn[1]);
	state[2] = _mm_xor_si128(state[2], ptrWordIn[2]);
	state[3] = _mm_xor_si128(state[3], ptrWordIn[3]);
	state[4] = _mm_xor_si128(state[4], ptrWordIn[4]);
	state[5] = _mm_xor_si128(state[5], ptrWordIn[5]);

	//Applies the reduced-round transformation f to the sponge's state
	reducedBlake2bLyra(state);

	//M[row][C-1-col] = M[prev][col] XOR rand
	ptrWordOut[0] = _mm_xor_si128(state[0], ptrWordIn[0]);
	ptrWordOut[1] = _mm_xor_si128(state[1], ptrWordIn[1]);
	ptrWordOut[2] = _mm_xor_si128(state[2], ptrWordIn[2]);
	ptrWordOut[3] = _mm_xor_si128(state[3], ptrWordIn[3]);
	ptrWordOut[4] = _mm_xor_si128(state[4], ptrWordIn[4]);
	ptrWordOut[5] = _mm_xor_si128(state[5], ptrWordIn[5]);	

	//Input: next column (i.e., next block in sequence)
	ptrWordIn += BLOCK_LEN_INT128;
	//Output: goes to previous column
	ptrWordOut -= BLOCK_LEN_INT128;
    }
}

/**
 * Performs a duplex operation over "M[rowInOut] XOR M[rowIn]", writing the output "rand"
 * on M[rowOut] and making "M[rowInOut] =  M[rowInOut] XOR rotW(rand)", where rotW is a 64-bit 
 * rotation to the left.
 *
 * @param state          The current state of the sponge 
 * @param rowIn          Row used only as input
 * @param rowInOut       Row used as input and to receive output after rotation
 * @param rowOut         Row receiving the output
 * @param nCols          Number of Columns
 *
 */
inline void reducedDuplexRowSetup(__m128i *state, __m128i *rowIn, __m128i *rowInOut, __m128i *rowOut){
    __m128i* ptrWordIn = rowIn; 	//In Lyra2: pointer to prev
    __m128i* ptrWordInOut = rowInOut; 	//In Lyra2: pointer to row*
    __m128i* ptrWordOut = rowOut + (N_COLS-1)*BLOCK_LEN_INT128;	//In Lyra2: pointer to row
    int i;
     
    for (i = 0; i < N_COLS; i++){
        //Absorbing "M[prev] [+] M[row*]"
	state[0] = _mm_xor_si128(state[0], ptrWordIn[0]  + ptrWordInOut[0]);
	state[1] = _mm_xor_si128(state[1], ptrWordIn[1]  + ptrWordInOut[1]);
	state[2] = _mm_xor_si128(state[2], ptrWordIn[2]  + ptrWordInOut[2]);
	state[3] = _mm_xor_si128(state[3], ptrWordIn[3]  + ptrWordInOut[3]);
	state[4] = _mm_xor_si128(state[4], ptrWordIn[4]  + ptrWordInOut[4]);
	state[5] = _mm_xor_si128(state[5], ptrWordIn[5]  + ptrWordInOut[5]);
     
        //Applies the reduced-round transformation f to the sponge's state
        reducedBlake2bLyra(state);

	//M[row][col] = M[prev][col] XOR rand
	ptrWordOut[0] = _mm_xor_si128(ptrWordIn[0], state[0]);
	ptrWordOut[1] = _mm_xor_si128(ptrWordIn[1], state[1]);
	ptrWordOut[2] = _mm_xor_si128(ptrWordIn[2], state[2]);
	ptrWordOut[3] = _mm_xor_si128(ptrWordIn[3], state[3]);
	ptrWordOut[4] = _mm_xor_si128(ptrWordIn[4], state[4]);
	ptrWordOut[5] = _mm_xor_si128(ptrWordIn[5], state[5]);

	ptrWordInOut[0] = _mm_xor_si128(ptrWordInOut[0], state[5]);
    ptrWordInOut[1] = _mm_xor_si128(ptrWordInOut[1], state[0]);
    ptrWordInOut[2] = _mm_xor_si128(ptrWordInOut[2], state[1]);
    ptrWordInOut[3] = _mm_xor_si128(ptrWordInOut[3], state[2]);
    ptrWordInOut[4] = _mm_xor_si128(ptrWordInOut[4], state[3]);
    ptrWordInOut[5] = _mm_xor_si128(ptrWordInOut[5], state[4]);

	//Goes to next column (i.e., next block in sequence)
        ptrWordInOut += BLOCK_LEN_INT128;
        ptrWordIn += BLOCK_LEN_INT128;
        ptrWordOut -= BLOCK_LEN_INT128;
    }
}

/**
 * Performs a duplex operation over "M[rowInOut] XOR M[rowIn]", using the output "rand"
 * to make "M[rowOut][col] = M[rowOut][col] XOR rand" and "M[rowInOut] = M[rowInOut] XOR rotW(rand)", 
 * where rotW is a 64-bit rotation to the left.
 *
 * @param state          The current state of the sponge 
 * @param rowIn          Row used only as input
 * @param rowInOut       Row used as input and to receive output after rotation
 * @param rowOut         Row receiving the output
 * @param nCols          Number of Columns
 *
 */
void reducedDuplexRow(__m128i *state, __m128i *rowIn, __m128i *rowInOut, __m128i *rowOut) {
    __m128i* ptrWordInOut = rowInOut;     //pointer to row
    __m128i* ptrWordIn = rowIn;           //pointer to row'
    __m128i* ptrWordOut = rowOut;         //pointer to row*

    int i;
    for (i = 0; i < N_COLS; i++) {
        //Absorbing "M[prev] [+] M[row*]"
	state[0] = _mm_xor_si128(state[0], ptrWordIn[0]  + ptrWordInOut[0]);
	state[1] = _mm_xor_si128(state[1], ptrWordIn[1]  + ptrWordInOut[1]);
	state[2] = _mm_xor_si128(state[2], ptrWordIn[2]  + ptrWordInOut[2]);
	state[3] = _mm_xor_si128(state[3], ptrWordIn[3]  + ptrWordInOut[3]);
	state[4] = _mm_xor_si128(state[4], ptrWordIn[4]  + ptrWordInOut[4]);
	state[5] = _mm_xor_si128(state[5], ptrWordIn[5]  + ptrWordInOut[5]);

        //Applies the reduced-round transformation f to the sponge's state
        reducedBlake2bLyra(state);

        //M[rowOut][col] = M[rowOut][col] XOR rand
        ptrWordOut[0] = _mm_xor_si128(ptrWordOut[0], state[0]);
        ptrWordOut[1] = _mm_xor_si128(ptrWordOut[1], state[1]);
        ptrWordOut[2] = _mm_xor_si128(ptrWordOut[2], state[2]);
        ptrWordOut[3] = _mm_xor_si128(ptrWordOut[3], state[3]);
        ptrWordOut[4] = _mm_xor_si128(ptrWordOut[4], state[4]);
        ptrWordOut[5] = _mm_xor_si128(ptrWordOut[5], state[5]);

        ptrWordInOut[0] = _mm_xor_si128(ptrWordInOut[0], state[5]);
        ptrWordInOut[1] = _mm_xor_si128(ptrWordInOut[1], state[0]);
        ptrWordInOut[2] = _mm_xor_si128(ptrWordInOut[2], state[1]);
        ptrWordInOut[3] = _mm_xor_si128(ptrWordInOut[3], state[2]);
        ptrWordInOut[4] = _mm_xor_si128(ptrWordInOut[4], state[3]);
        ptrWordInOut[5] = _mm_xor_si128(ptrWordInOut[5], state[4]);

        //Goes to next block
        ptrWordOut += BLOCK_LEN_INT128;
        ptrWordInOut += BLOCK_LEN_INT128;
        ptrWordIn += BLOCK_LEN_INT128;
    }
}

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
////////////////////////////////////////////////////////////////////////////////////////////////
