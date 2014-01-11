/*
  Implementation of a sponge function that uses the F function from Blake 2

  Author: Leonardo de Campos Almeida
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
    memset(state, 0,            BLOCK_LEN_BYTES);
    memcpy(state + BLOCK_LEN_INT64, blake2b_IV,   BLOCK_LEN_BYTES);
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
    int fullBlocks = len / 64;
    byte *ptr = out;
    int i;
    //Squeezes full blocks
    for (i = 0; i < fullBlocks; i++) {
        memcpy(ptr, state, BLOCK_LEN_BYTES);
        blake2bLyra(state);
        ptr += BLOCK_LEN_BYTES;
    }
    
    //Squeezes remaining bytes
    memcpy(ptr, state, (len % 64));
}

/**
 * Performs an absorb operation for a single block (BLOCK_LEN_INT64 words
 * of type uint64_t), using Blake2b's G function as the internal permutation
 * 
 * @param state The current state of the sponge 
 * @param in    The uint64_t array to be absorbed
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
    //printArray(state, 128, "state");

    blake2bLyra(state);
}

/**
 * <b>OK</b>
 * 
 * Performs an absorb operation a 128-bit salt, applying the required 10*1 padding
 * @param state The current state of the sponge 
 * @param salt  The 128-bit salt to be absorbed
 */
void absorbPaddedSalt(uint64_t *state, const uint64_t *salt) {
    //XORs the first BLOCK_LEN_INT64 words of "in" with the current state
    state[0] ^= salt[0];
    state[1] ^= salt[1];
    state[2] ^= 0x80;
    state[7] ^= 0x0100000000000000ULL;
   
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

    reducedBlake2bLyra(state);
}

/** 
 * <b>OK: Verify whether to use memcpy or copy by hand</b>
 * 
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
 * <b>OK</b>
 * 
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
