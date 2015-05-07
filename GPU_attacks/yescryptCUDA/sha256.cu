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

/*-
 * Copyright 2005,2007,2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include "sysendian.h"
#include "sha256.h"
#include "yescrypt.h"
#include <stdio.h>
#include "gpucommon.h"


__device__ void SHA256_Update_GPU(SHA256_CTX * ctx, const void *in, size_t len, unsigned int totalPasswords);

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
__device__ static void be32enc_vect_GPU(unsigned char *dst, const uint32_t *src, size_t len, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

        size_t i;

        for (i = 0; i < len / 4; i++)
            be32enc_GPU(dst + i * 4, src[i]);
    }
}

/*
 * Decode a big-endian length len vector of (unsigned char) into a length
 * len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
 */
__device__ static void be32dec_vect_GPU(uint32_t *dst, const unsigned char *src, size_t len, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){
        size_t i;

        for (i = 0; i < len / 4; i++)
            dst[i] = be32dec_GPU(src + i * 4);
    }
}


/* Elementary functions used by SHA256 */
#define Ch(x, y, z)	((x & (y ^ z)) ^ z)
#define Maj(x, y, z)	((x & (y | z)) | (y & z))
#define SHR(x, n)	(x >> n)
#define ROTR(x, n)	((x >> n) | (x << (32 - n)))
#define S0(x)		(ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)		(ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)		(ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x)		(ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/* SHA256 round function */
#define RND(a, b, c, d, e, f, g, h, k)			\
	t0 = h + S1(e) + Ch(e, f, g) + k;		\
	t1 = S0(a) + Maj(a, b, c);			\
	d += t0;					\
	h  = t0 + t1;

/* Adjusted round function for rotating state */
#define RNDr(S, W, i, k)			\
	RND(S[(64 - i) % 8], S[(65 - i) % 8],	\
	    S[(66 - i) % 8], S[(67 - i) % 8],	\
	    S[(68 - i) % 8], S[(69 - i) % 8],	\
	    S[(70 - i) % 8], S[(71 - i) % 8],	\
	    W[i] + k)

/*
 * SHA256 block compression function.  The 256-bit state is transformed via
 * the 512-bit input block to produce a new state.
 */
__device__ static void SHA256_Transform_GPU(uint32_t * state, const unsigned char block[64], unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

        uint32_t W[64];
        uint32_t S[8];
        uint32_t t0, t1;
        int i;

        /* 1. Prepare message schedule W. */
        be32dec_vect_GPU(W, block, 64, totalPasswords);
        for (i = 16; i < 64; i++)
            W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];

        /* 2. Initialize working variables. */
        memcpy(S, state, 32);

        /* 3. Mix. */
        RNDr(S, W, 0, 0x428a2f98);
        RNDr(S, W, 1, 0x71374491);
        RNDr(S, W, 2, 0xb5c0fbcf);
        RNDr(S, W, 3, 0xe9b5dba5);
        RNDr(S, W, 4, 0x3956c25b);
        RNDr(S, W, 5, 0x59f111f1);
        RNDr(S, W, 6, 0x923f82a4);
        RNDr(S, W, 7, 0xab1c5ed5);
        RNDr(S, W, 8, 0xd807aa98);
        RNDr(S, W, 9, 0x12835b01);
        RNDr(S, W, 10, 0x243185be);
        RNDr(S, W, 11, 0x550c7dc3);
        RNDr(S, W, 12, 0x72be5d74);
        RNDr(S, W, 13, 0x80deb1fe);
        RNDr(S, W, 14, 0x9bdc06a7);
        RNDr(S, W, 15, 0xc19bf174);
        RNDr(S, W, 16, 0xe49b69c1);
        RNDr(S, W, 17, 0xefbe4786);
        RNDr(S, W, 18, 0x0fc19dc6);
        RNDr(S, W, 19, 0x240ca1cc);
        RNDr(S, W, 20, 0x2de92c6f);
        RNDr(S, W, 21, 0x4a7484aa);
        RNDr(S, W, 22, 0x5cb0a9dc);
        RNDr(S, W, 23, 0x76f988da);
        RNDr(S, W, 24, 0x983e5152);
        RNDr(S, W, 25, 0xa831c66d);
        RNDr(S, W, 26, 0xb00327c8);
        RNDr(S, W, 27, 0xbf597fc7);
        RNDr(S, W, 28, 0xc6e00bf3);
        RNDr(S, W, 29, 0xd5a79147);
        RNDr(S, W, 30, 0x06ca6351);
        RNDr(S, W, 31, 0x14292967);
        RNDr(S, W, 32, 0x27b70a85);
        RNDr(S, W, 33, 0x2e1b2138);
        RNDr(S, W, 34, 0x4d2c6dfc);
        RNDr(S, W, 35, 0x53380d13);
        RNDr(S, W, 36, 0x650a7354);
        RNDr(S, W, 37, 0x766a0abb);
        RNDr(S, W, 38, 0x81c2c92e);
        RNDr(S, W, 39, 0x92722c85);
        RNDr(S, W, 40, 0xa2bfe8a1);
        RNDr(S, W, 41, 0xa81a664b);
        RNDr(S, W, 42, 0xc24b8b70);
        RNDr(S, W, 43, 0xc76c51a3);
        RNDr(S, W, 44, 0xd192e819);
        RNDr(S, W, 45, 0xd6990624);
        RNDr(S, W, 46, 0xf40e3585);
        RNDr(S, W, 47, 0x106aa070);
        RNDr(S, W, 48, 0x19a4c116);
        RNDr(S, W, 49, 0x1e376c08);
        RNDr(S, W, 50, 0x2748774c);
        RNDr(S, W, 51, 0x34b0bcb5);
        RNDr(S, W, 52, 0x391c0cb3);
        RNDr(S, W, 53, 0x4ed8aa4a);
        RNDr(S, W, 54, 0x5b9cca4f);
        RNDr(S, W, 55, 0x682e6ff3);
        RNDr(S, W, 56, 0x748f82ee);
        RNDr(S, W, 57, 0x78a5636f);
        RNDr(S, W, 58, 0x84c87814);
        RNDr(S, W, 59, 0x8cc70208);
        RNDr(S, W, 60, 0x90befffa);
        RNDr(S, W, 61, 0xa4506ceb);
        RNDr(S, W, 62, 0xbef9a3f7);
        RNDr(S, W, 63, 0xc67178f2);

        /* 4. Mix local working variables into global state */
        for (i = 0; i < 8; i++)
            state[i] += S[i];

        /* Clean the stack. */
        memset(W, 0, 256);
        memset(S, 0, 32);
        t0 = t1 = 0;
    }
}


__device__ static unsigned char PAD_GPU[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


/* Add padding and terminating bit-count. */
__device__ static void SHA256_Pad_GPU(SHA256_CTX * ctx, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

        unsigned char len[8];
        uint32_t r, plen;

        // Convert length to a vector of bytes -- we do this now rather
        // than later because the length will change after we pad.
        be32enc_vect_GPU(len, ctx->count, 8, totalPasswords);

        /* Add 1--64 bytes so that the resulting length is 56 mod 64 */
        r = (ctx->count[1] >> 3) & 0x3f;
        plen = (r < 56) ? (56 - r) : (120 - r);
        SHA256_Update_GPU(ctx, PAD_GPU, (size_t)plen, totalPasswords);

        /* Add the terminating bit-count */
        SHA256_Update_GPU(ctx, len, 8, totalPasswords);
    }
}


/* SHA-256 initialization.  Begins a SHA-256 operation. */
__device__ void SHA256_Init_GPU(SHA256_CTX * ctx, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

        /* Zero bits processed so far */
        ctx->count[0] = ctx->count[1] = 0;

        /* Magic initialization constants */
        ctx->state[0] = 0x6A09E667;
        ctx->state[1] = 0xBB67AE85;
        ctx->state[2] = 0x3C6EF372;
        ctx->state[3] = 0xA54FF53A;
        ctx->state[4] = 0x510E527F;
        ctx->state[5] = 0x9B05688C;
        ctx->state[6] = 0x1F83D9AB;
        ctx->state[7] = 0x5BE0CD19;
    }
}


/* Add bytes into the hash */
__device__ void SHA256_Update_GPU(SHA256_CTX * ctx, const void *in, size_t len, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

        uint32_t bitlen[2];
        uint32_t r;
        const unsigned char *src = (const unsigned char *)in;

        /* Number of bytes left in the buffer from previous updates */
        r = (ctx->count[1] >> 3) & 0x3f;

        /* Convert the length into a number of bits */
        bitlen[1] = ((uint32_t)len) << 3;
        bitlen[0] = (uint32_t)(len >> 29);

        /* Update number of bits */
        if ((ctx->count[1] += bitlen[1]) < bitlen[1])
            ctx->count[0]++;
        ctx->count[0] += bitlen[0];

        /* Handle the case where we don't need to perform any transforms */
        if (len < 64 - r) {
            memcpy(&ctx->buf[r], src, len);
            return;
        }

        /* Finish the current block */
        memcpy(&ctx->buf[r], src, 64 - r);
        SHA256_Transform_GPU(ctx->state, ctx->buf, totalPasswords);
        src += 64 - r;
        len -= 64 - r;

        /* Perform complete blocks */
        while (len >= 64) {
            SHA256_Transform_GPU(ctx->state, src, totalPasswords);
            src += 64;
            len -= 64;
        }

        /* Copy left over data into buffer */
        memcpy(ctx->buf, src, len);
    }
}

/*
 * SHA-256 finalization.  Pads the input data, exports the hash value,
 * and clears the context state.
 */
__device__ void SHA256_Final_GPU(unsigned char digest[32], SHA256_CTX * ctx, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){
        /* Add padding */
        SHA256_Pad_GPU(ctx, totalPasswords);

        /* Write the hash */
        be32enc_vect_GPU(digest, ctx->state, 32, totalPasswords);

        /* Clear the context state */
        memset((void *)ctx, 0, sizeof(*ctx));
    }
}


/* Initialize an HMAC-SHA256 operation with the given key. */
__device__ void HMAC_SHA256_Init_GPU(HMAC_SHA256_CTX * ctx, const void * _K, size_t Klen, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

        unsigned char pad[64];
        unsigned char khash[32];
        const unsigned char * K = (const unsigned char *)_K;
        size_t i;

        // If Klen > 64, the key is really SHA256(K).
        if (Klen > 64) {
            SHA256_Init_GPU(&ctx->ictx, totalPasswords);
            SHA256_Update_GPU(&ctx->ictx, K, Klen, totalPasswords);
            SHA256_Final_GPU(khash, &ctx->ictx, totalPasswords);
            K = khash;
            Klen = 32;
        }

        // Inner SHA256 operation is SHA256(K xor [block of 0x36] || data).
        SHA256_Init_GPU(&ctx->ictx, totalPasswords);
        memset(pad, 0x36, 64);
        for (i = 0; i < Klen; i++)
            pad[i] ^= K[i];
        SHA256_Update_GPU(&ctx->ictx, pad, 64, totalPasswords);

        // Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash).
        SHA256_Init_GPU(&ctx->octx, totalPasswords);
        memset(pad, 0x5c, 64);
        for (i = 0; i < Klen; i++)
            pad[i] ^= K[i];
        SHA256_Update_GPU(&ctx->octx, pad, 64, totalPasswords);

        // Clean the stack.
        memset(khash, 0, 32);
	}

}


/* Add bytes to the HMAC-SHA256 operation. */
__device__ void HMAC_SHA256_Update_GPU(HMAC_SHA256_CTX * ctx, const void *in, size_t len, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){
        /* Feed data to the inner SHA256 operation. */
        SHA256_Update_GPU(&ctx->ictx, in, len, totalPasswords);
    }
}


/* Finish an HMAC-SHA256 operation. */
__device__ void HMAC_SHA256_Final_GPU(unsigned char digest[32], HMAC_SHA256_CTX * ctx, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){
        unsigned char ihash[32];

        /* Finish the inner SHA256 operation. */
        SHA256_Final_GPU(ihash, &ctx->ictx, totalPasswords);

        /* Feed the inner hash to the outer SHA256 operation. */
        SHA256_Update_GPU(&ctx->octx, ihash, 32, totalPasswords);

        /* Finish the outer SHA256 operation. */
        SHA256_Final_GPU(digest, &ctx->octx, totalPasswords);

        /* Clean the stack. */
        memset(ihash, 0, 32);
    }
}


/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
__device__ void PBKDF2_SHA256_GPU(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
    size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

        HMAC_SHA256_CTX PShctx, hctx;
        size_t i;
        uint8_t ivec[4];
        uint8_t U[32];
        uint8_t T[32];
        uint64_t j;
        int k;
        size_t clen;

        // Compute HMAC state after processing P and S.
        HMAC_SHA256_Init_GPU(&PShctx, passwd, passwdlen, totalPasswords);
        HMAC_SHA256_Update_GPU(&PShctx, salt, saltlen, totalPasswords);

        // Iterate through the blocks.
        for (i = 0; i * 32 < dkLen; i++) {
        //for (i = 0; i < 1; i++) {
            // Generate INT(i + 1).
            be32enc_GPU(ivec, (uint32_t)(i + 1));

            // Compute U_1 = PRF(P, S || INT(i)).
            memcpy(&hctx, &PShctx, sizeof(HMAC_SHA256_CTX));
            HMAC_SHA256_Update_GPU(&hctx, ivec, 4, totalPasswords);
            HMAC_SHA256_Final_GPU(U, &hctx, totalPasswords);

            // T_i = U_1 ...
            memcpy(T, U, 32);

            for (j = 2; j <= c; j++) {
                // Compute U_j.
                HMAC_SHA256_Init_GPU(&hctx, passwd, passwdlen, totalPasswords);
                HMAC_SHA256_Update_GPU(&hctx, U, 32, totalPasswords);
                HMAC_SHA256_Final_GPU(U, &hctx, totalPasswords);

                // ... xor U_j ...
                for (k = 0; k < 32; k++)
                    T[k] ^= U[k];
            }

            // Copy as many bytes as necessary into buf.
            clen = dkLen - i * 32;
            if (clen > 32)
                clen = 32;
            memcpy(&buf[i*32], T, clen);

        }

        // Clean PShctx, since we never called _Final on it.
        memset(&PShctx, 0, sizeof(HMAC_SHA256_CTX));
    }
}


__global__ void HMAC_SHA256_GPU(uint32_t prehash, uint8_t *passwd_GPU, size_t passwdlen, uint32_t *sha256_GPU, size_t sha_size,
    uint8_t *salt_GPU, size_t saltlen, uint32_t *B_GPU, size_t B_size, unsigned int totalPasswords){

    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

        uint8_t * newPtr;
        size_t B_totalCells = B_size/sizeof(uint32_t);

        HMAC_SHA256_CTX ctx;

        HMAC_SHA256_Init_GPU(&ctx, "yescrypt-prehash", prehash ? 16 : 8, totalPasswords);

        HMAC_SHA256_Update_GPU(&ctx, &passwd_GPU[threadNumber*passwdlen], passwdlen, totalPasswords);

        HMAC_SHA256_Final_GPU((uint8_t *)&sha256_GPU[8*threadNumber], &ctx, totalPasswords);

        newPtr = (uint8_t *)&sha256_GPU[8*threadNumber];

        /* 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen) */
        PBKDF2_SHA256_GPU(&newPtr[0], sha_size, &salt_GPU[saltlen*threadNumber], saltlen, 1, (uint8_t *)&B_GPU[B_totalCells*threadNumber], B_size, totalPasswords);

        blkcpy_GPU((uint32_t *)&sha256_GPU[8*threadNumber], (uint32_t *)&B_GPU[B_totalCells*threadNumber], 8, totalPasswords);
    }
}


__global__ void HMAC_SHA256_GPU_2(uint32_t prehash, uint8_t *passwd_GPU, size_t passwdlen, uint32_t *sha256_GPU, size_t sha_size, uint32_t *B_GPU, size_t B_size,
    uint8_t * buf_GPU, size_t buflen, unsigned int totalPasswords){

    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

        size_t B_totalCells = B_size/sizeof(uint32_t);
        uint8_t dk[32];
        uint8_t * dkp;

        dkp = &buf_GPU[threadNumber*buflen];

        if (buflen < sha_size) {
            PBKDF2_SHA256_GPU(&passwd_GPU[threadNumber*passwdlen], passwdlen, (uint8_t *)&B_GPU[threadNumber*B_totalCells], B_size, 1, dk, /*sizeof(dk)*/sha_size, totalPasswords);
            dkp = dk;
        }

        // 5: DK <-- PBKDF2(P, B, 1, dkLen)
        PBKDF2_SHA256_GPU(&passwd_GPU[threadNumber*passwdlen], passwdlen, (uint8_t *)&B_GPU[threadNumber*B_totalCells], B_size, 1, &buf_GPU[threadNumber*buflen], buflen, totalPasswords);

        if (!(prehash)) {
            // Compute ClientKey
            {
                HMAC_SHA256_CTX ctx;
                HMAC_SHA256_Init_GPU(&ctx, dkp, sha_size/*sizeof(dk)*/, totalPasswords);
                HMAC_SHA256_Update_GPU(&ctx, "Client Key", 10, totalPasswords);
                HMAC_SHA256_Final_GPU((uint8_t *)&sha256_GPU[threadNumber*8], &ctx, totalPasswords);
            }
            // Compute StoredKey
            {
                SHA256_CTX ctx;
                size_t clen = buflen;
                if (clen > sha_size/*sizeof(dk)*/)
                    clen = sha_size/*sizeof(dk)*/;
                SHA256_Init_GPU(&ctx, totalPasswords);
                SHA256_Update_GPU(&ctx, (uint8_t *)&sha256_GPU[threadNumber*8], sha_size, totalPasswords);
                SHA256_Final_GPU(dk, &ctx, totalPasswords);
                memcpy(&buf_GPU[threadNumber*buflen], dk, clen);
            }
        }
    }
}




