/**
 * Header file for Blake2b's and BlaMka's internal permutation in the form of a sponge.
 * This code is based on the original Blake2b's implementation provided by
 * Samuel Neves (https://blake2.net/)
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
#ifndef SPONGE_H_
#define SPONGE_H_

#include <stdint.h>

typedef unsigned char byte;

#if defined(__GNUC__)
#define ALIGN __attribute__ ((aligned(32)))
#elif defined(_MSC_VER)
#define ALIGN __declspec(align(32))
#else
#define ALIGN
#endif

//Block length required so Blake2's Initialization Vector (IV) is not overwritten (THIS SHOULD NOT BE MODIFIED)
#define BLOCK_LEN_BLAKE2_SAFE_INT64 8                                   //512 bits (=64 bytes, =8 uint64_t)
#define BLOCK_LEN_BLAKE2_SAFE_BYTES (BLOCK_LEN_BLAKE2_SAFE_INT64 * 8)   //same as above, in bytes

//default block lenght: 768 bits
#ifndef BLOCK_LEN_INT64
        #define BLOCK_LEN_INT64 12                                      //Block length: 768 bits (=96 bytes, =12 uint64_t)
#endif

#define BLOCK_LEN_BYTES (BLOCK_LEN_INT64 * 8)                           //Block length, in bytes

#define STATESIZE_INT64 16
#define STATESIZE_BYTES (16 * sizeof (uint64_t))

#ifndef SPONGE
        #define SPONGE 0                                                //SPONGE 0 = BLAKE2, SPONGE 1 = BLAMKA and SPONGE 2 = HALF-ROUND BLAMKA
#endif

#ifndef RHO
        #define RHO 1                                                   //Number of reduced rounds performed
#endif

/*Blake2b IV Array*/
__device__ static const uint64_t blake2b_IV[8] =
{
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/*Blake2b's rotation*/
__device__ static inline uint64_t rotr64( const uint64_t w, const unsigned c ){
    return ( w >> c ) | ( w << ( 64 - c ) );
}

/*Main change compared with Blake2b*/
__device__ static inline uint64_t fBlaMka(uint64_t x, uint64_t y){
    uint32_t lessX = (uint32_t) x;
    uint32_t lessY = (uint32_t) y;

    uint64_t lessZ = (uint64_t) lessX;
    lessZ = lessZ * lessY;
    lessZ = lessZ << 1;

    uint64_t z = lessZ + x + y;

    return z;
}

#define DIAGONALIZE(r,v) \
    t0=v[4];                      v[4]=v[5]; v[5]=v[6]; v[6]=v[7]; v[7]=t0; \
    t0=v[8]; t1=v[9];             v[8]=v[10]; v[9]=v[11]; v[10]=t0; v[11]=t1; \
    t0=v[12]; t1=v[13]; t2=v[14]; v[12]=v[15]; v[13]=t0; v[14]=t1; v[15]=t2;

/*Blake2b's G function*/
#define G(r,i,a,b,c,d) \
  do { \
    a = a + b; \
    d = rotr64(d ^ a, 32); \
    c = c + d; \
    b = rotr64(b ^ c, 24); \
    a = a + b; \
    d = rotr64(d ^ a, 16); \
    c = c + d; \
    b = rotr64(b ^ c, 63); \
  } while(0)

/*BLAMKA's G function*/
#define GBLAMKA(r,i,a,b,c,d) \
  do { \
    a = fBlaMka(a,b); \
    d = rotr64(d ^ a, 32); \
    c = fBlaMka(c,d); \
    b = rotr64(b ^ c, 24); \
    a = fBlaMka(a,b); \
    d = rotr64(d ^ a, 16); \
    c = fBlaMka(c,d); \
    b = rotr64(b ^ c, 63); \
  } while(0)

/*One Round of the Blake2b's compression function*/
#define ROUND_LYRA(r)  \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]);

/*One Round of the BlaMka's compression function*/
#define ROUND_LYRA_BLAMKA(r)  \
    GBLAMKA(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    GBLAMKA(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    GBLAMKA(r,2,v[ 2],v[ 6],v[10],v[14]); \
    GBLAMKA(r,3,v[ 3],v[ 7],v[11],v[15]); \
    GBLAMKA(r,4,v[ 0],v[ 5],v[10],v[15]); \
    GBLAMKA(r,5,v[ 1],v[ 6],v[11],v[12]); \
    GBLAMKA(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    GBLAMKA(r,7,v[ 3],v[ 4],v[ 9],v[14]);

/*Half Round of the BlaMka's compression function*/
#define HALF_ROUND_LYRA_BLAMKA(r)  \
    GBLAMKA(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    GBLAMKA(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    GBLAMKA(r,2,v[ 2],v[ 6],v[10],v[14]); \
    GBLAMKA(r,3,v[ 3],v[ 7],v[11],v[15]); \
    DIAGONALIZE(r,v);

//---- Initialization
__global__ void bootStrapGPU(uint64_t * memMatrixGPU, unsigned char * pkeysGPU, unsigned int kLen, unsigned char *pwdGPU, unsigned int pwdlen, unsigned char *saltGPU, unsigned int saltlen, unsigned int timeCost, unsigned int nRows, unsigned int nCols, uint64_t nBlocksInput, unsigned int totalPasswords);

//---- Housekeeping
__global__ void initState(uint64_t state[/*16*/], unsigned int totalPasswords);

//---- Squeezes
__global__ void reducedSqueezeRow0(uint64_t* row, uint64_t* state, unsigned int totalPasswords);
__global__ void squeeze(uint64_t *state, byte *out, unsigned int len, unsigned int totalPasswords);

//---- Absorbs
__global__ void absorbInput(uint64_t * memMatrixGPU, uint64_t * stateThreadGPU, uint64_t *stateIdxGPU, uint64_t nBlocksInput, unsigned int totalPasswords);

//---- Duplexes
__global__ void reducedDuplexRow1and2(uint64_t *rowIn, uint64_t *state, unsigned int totalPasswords, int first, int second);

//---- Setup and Wandering
__global__ void setupPhaseWanderingGPU(uint64_t * memMatrixGPU, uint64_t * stateThreadGPU, uint64_t sizeSlice, unsigned int totalPasswords, unsigned int timeCost);
__global__ void setupPhaseWanderingGPU_P1(uint64_t * memMatrixGPU, uint64_t * stateThreadGPU, uint64_t sizeSlice, unsigned int totalPasswords, unsigned int timeCost);

//---- Misc
void printArray(unsigned char *array, unsigned int size, char *name);

#endif /* SPONGE_H_ */
