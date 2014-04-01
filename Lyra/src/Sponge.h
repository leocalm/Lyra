/*
 * Sponge.h
 *
 *  Created on: Apr 21, 2013
 *      Author: leonardo
 */

#ifndef SPONGE_H_
#define SPONGE_H_

#include <stdint.h>

#if defined(__GNUC__)
#define ALIGN __attribute__ ((aligned(32)))
#elif defined(_MSC_VER)
#define ALIGN __declspec(align(32))
#else
#define ALIGN
#endif

/*Blake 2b IV Array*/
static const uint64_t blake2b_IV[8] =
{
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};


static inline uint64_t rotr64( const uint64_t w, const unsigned c ){
    return ( w >> c ) | ( w << ( 64 - c ) );
}

/*Blake's G function*/
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


/*One Round of the Blake's 2 compression function*/
#define ROUND_LYRA(r)  \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]);

void initState(uint64_t state[/*16*/]);

void squeeze(uint64_t *state, unsigned char *out, unsigned int len);

void absorbBlock(uint64_t *state, const uint64_t *in);

void absorbPaddedSalt(uint64_t *state, const uint64_t *salt);

void reducedAbsorbBlock(uint64_t *state, const uint64_t *in);

void reducedSqueezeRow(uint64_t* state, uint64_t* row);

void reducedDuplexRow(uint64_t *state, uint64_t *row);

void reducedDuplexRowSetup(uint64_t *state, uint64_t *row, uint64_t *oldRow);

uint64_t duplexBlock(uint64_t *state, const uint64_t *in);

void printArray(unsigned char *array, unsigned int size, char *name);

#endif /* SPONGE_H_ */
