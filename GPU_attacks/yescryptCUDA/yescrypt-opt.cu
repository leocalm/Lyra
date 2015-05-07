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
 * Copyright 2009 Colin Percival
 * Copyright 2013-2015 Alexander Peslyak
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
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 *
 * This is the reference implementation.  Its purpose is to provide a simple
 * human- and machine-readable specification that implementations intended
 * for actual use should be tested against.  It is deliberately mostly not
 * optimized, and it is not meant to be used in production.  Instead, use
 * yescrypt-best.c or one of the source files included from there.
*/

//#warning "This reference implementation is deliberately mostly not optimized. Use yescrypt-best.c instead unless you're testing (against) the reference implementation on purpose."

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sha256.h"
#include "sysendian.h"

#include "yescrypt.h"

#define FAZ_PRE_HASH 1
#define NAO_FAZ_PRE_HASH 0

#define FAZ_XOR 1
#define NAO_FAZ_XOR 0

#define COPIA_BLOCO 1
#define NAO_COPIA_BLOCO 0

#include "gpucommon.h"

typedef union {
	uint32_t w[16];
	uint64_t d[8];
} salsa20_blk_t;

__device__ static inline void blkxor_GPU(uint64_t * dest, const uint64_t * src, size_t count)
{
    do {
        *dest++ ^= *src++; *dest++ ^= *src++;
        *dest++ ^= *src++; *dest++ ^= *src++;
    } while (count -= 4);

}

__device__  static inline void salsa20_simd_shuffle(const salsa20_blk_t * Bin, salsa20_blk_t * Bout)
{
#define COMBINE(out, in1, in2) \
	Bout->d[out] = Bin->w[in1 * 2] | ((uint64_t)Bin->w[in2 * 2 + 1] << 32);
	COMBINE(0, 0, 2)
	COMBINE(1, 5, 7)
	COMBINE(2, 2, 4)
	COMBINE(3, 7, 1)
	COMBINE(4, 4, 6)
	COMBINE(5, 1, 3)
	COMBINE(6, 6, 0)
	COMBINE(7, 3, 5)
#undef COMBINE
}

__device__ static inline void salsa20_simd_unshuffle(const salsa20_blk_t * Bin, salsa20_blk_t * Bout)
{
#define UNCOMBINE(out, in1, in2) \
	Bout->w[out * 2] = Bin->d[in1]; \
	Bout->w[out * 2 + 1] = Bin->d[in2] >> 32;
	UNCOMBINE(0, 0, 6)
	UNCOMBINE(1, 5, 3)
	UNCOMBINE(2, 2, 0)
	UNCOMBINE(3, 7, 5)
	UNCOMBINE(4, 4, 2)
	UNCOMBINE(5, 1, 7)
	UNCOMBINE(6, 6, 4)
	UNCOMBINE(7, 3, 1)
#undef UNCOMBINE
}


/**
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
 */
__device__  static void salsa20_8_GPU64(uint64_t B[8])
{
	size_t i;
	salsa20_blk_t X;
#define x X.w

	salsa20_simd_unshuffle((const salsa20_blk_t *)B, &X);

	for (i = 0; i < 8; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
		// Operate on columns
		x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
		x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);

		x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
		x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);

		x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
		x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);

		x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
		x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);

		// Operate on rows
		x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
		x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);

		x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
		x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);

		x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
		x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);

		x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
		x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
#undef R
	}
#undef x

	{
		salsa20_blk_t Y;
		salsa20_simd_shuffle(&X, &Y);
		for (i = 0; i < 16; i += 4) {
			((salsa20_blk_t *)B)->w[i] += Y.w[i];
			((salsa20_blk_t *)B)->w[i + 1] += Y.w[i + 1];
			((salsa20_blk_t *)B)->w[i + 2] += Y.w[i + 2];
			((salsa20_blk_t *)B)->w[i + 3] += Y.w[i + 3];
		}
	}
}

/**
 * blockmix_salsa8(B, Y, r):
 * Compute B = BlockMix_{salsa20/8, r}(B).  The input B must be 128r bytes in
 * length; the temporary space Y must also be the same size.
*/
__device__ static void blockmix_salsa8_GPU(const uint64_t * Bin, uint64_t * Bout, uint64_t * X, size_t r, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){
        size_t i;
        // 1: X <-- B_{2r - 1}
        blkcpy_GPU64(X, &Bin[(2 * r - 1) * 8], 8);
        // 2: for i = 0 to 2r - 1 do
        for (i = 0; i < 2 * r; i += 2) {
            // 3: X <-- H(X \xor B_i)
            blkxor_GPU(X, &Bin[i * 8], 8);
            salsa20_8_GPU64(X);
            // 4: Y_i <-- X
            blkcpy_GPU64(&Bout[i * 4], X, 8);
            // 3: X <-- H(X \xor B_i)
            blkxor_GPU(X, &Bin[i * 8 + 8], 8);
            salsa20_8_GPU64(X);
            // 4: Y_i <-- X
            blkcpy_GPU64(&Bout[i * 4 + r * 8], X, 8);
        }
    }
}

// These are tunable
#define PWXsimple 2
#define PWXgather 4
#define PWXrounds 6
#define Swidth 8

// Derived values.  Not tunable on their own.
#define PWXbytes (PWXgather * PWXsimple * 8)
//#define PWXwords (PWXbytes / sizeof(uint32_t))
#define PWXwords (PWXbytes / sizeof(uint64_t))
#define Sbytes (2 * (1 << Swidth) * PWXsimple * 8)
//#define Swords (Sbytes / sizeof(uint32_t))
#define Swords (Sbytes / sizeof(uint64_t))
#define Smask (((1 << Swidth) - 1) * PWXsimple * 8)
#define Smask2 (((uint64_t)Smask << 32) | Smask)
#define rmin ((PWXbytes + 127) / 128)

//#include "yescrypt2.c"
#if PWXbytes % 32 != 0
#error "blkcpy() and blkxor() currently work on multiples of 32."
#endif

/**
 * pwxform(B):
 * Transform the provided block using the provided S-boxes.
*/
__device__ static void pwxform_GPU(uint64_t * B, const uint64_t * S, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

		size_t i, j;

		uint64_t (*X)[PWXsimple] = (uint64_t (*)[PWXsimple])B;
		const uint8_t *S0 = (const uint8_t *)S;
		const uint8_t *S1 = (const uint8_t *)S + Sbytes / 2;

		/* 2: for j = 0 to PWXgather do */
		for (j = 0; j < PWXgather; j++) {
			uint64_t *Xj = X[j];
			uint64_t x0 = Xj[0];
			uint64_t x1 = Xj[1];

			/* 1: for i = 0 to PWXrounds do */
			for (i = 0; i < PWXrounds; i++) {
				uint64_t x = x0 & Smask2;
				const uint64_t *p0, *p1;

				/* 3: p0 <-- (lo(B_{j,0}) & Smask) / (PWXsimple * 8) */
				p0 = (const uint64_t *)(S0 + (uint32_t)x);
				/* 4: p1 <-- (hi(B_{j,0}) & Smask) / (PWXsimple * 8) */
				p1 = (const uint64_t *)(S1 + (x >> 32));

				/* 5: for k = 0 to PWXsimple do */
				/* 6: B_{j,k} <-- (hi(B_{j,k}) * lo(B_{j,k}) + S0_{p0,k}) \xor S1_{p1,k} */
				x0 = (uint64_t)(x0 >> 32) * (uint32_t)x0;
				x0 += p0[0];
				x0 ^= p1[0];

				/* 6: B_{j,k} <-- (hi(B_{j,k}) * lo(B_{j,k}) + S0_{p0,k}) \xor S1_{p1,k} */
				x1 = (uint64_t)(x1 >> 32) * (uint32_t)x1;
				x1 += p0[1];
				x1 ^= p1[1];
			}
			Xj[0] = x0;
			Xj[1] = x1;
		}
	}

}

/**
 * blockmix_pwxform(B, Y, S, r):
 * Compute B = BlockMix_pwxform{salsa20/8, S, r}(B).  The input B must be 128r
 * bytes in length; the temporary space Y must be at least PWXbytes.
*/
__device__ static void blockmix_pwxform_GPU(const uint64_t * Bin, uint64_t * Bout, uint64_t * S, size_t r, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){
        size_t r1, r2, i;
        /* Convert 128-byte blocks to PWXbytes blocks */
        /* 1: r_1 <-- 128r / PWXbytes */
        //r1 = r * 128 / PWXbytes;
        r1 = YESCRYPT_R * 128 / PWXbytes;
        /* 2: X <-- B'_{r_1 - 1} */
        blkcpy_GPU64(Bout, &Bin[(r1 - 1) * PWXwords], PWXwords);
        /* 3: for i = 0 to r_1 - 1 do */
        /* 4: if r_1 > 1 */
        //if (r1 > 1) {
            /* 5: X <-- X \xor B'_i */
            blkxor_GPU(Bout, Bin, PWXwords);
        //}
        /* 7: X <-- pwxform(X) */
        /* 8: B'_i <-- X */
        pwxform_GPU(Bout, S, totalPasswords);
        /* 3: for i = 0 to r_1 - 1 do */
        for (i = 1; i < r1; i++) {
            /* 5: X <-- X \xor B'_i */
            blkcpy_GPU64(&Bout[i * PWXwords], &Bout[(i - 1) * PWXwords], PWXwords);
            blkxor_GPU(&Bout[i * PWXwords], &Bin[i * PWXwords], PWXwords);
            /* 7: X <-- pwxform(X) */
            /* 8: B'_i <-- X */
            pwxform_GPU(&Bout[i * PWXwords], S, totalPasswords);
        }
        /* 10: i <-- floor((r_1 - 1) * PWXbytes / 64) */
        i = (r1 - 1) * PWXbytes / 64;
        /* Convert 128-byte blocks to 64-byte blocks */
        //r2 = r * 2;
        r2 = YESCRYPT_R * 2;
        /* 11: B_i <-- H(B_i) */
        salsa20_8_GPU64(&Bout[i * 8]);
        for (i++; i < r2; i++) {
            /* 13: B_i <-- H(B_i \xor B_{i-1}) */
            blkxor_GPU(&Bout[i * 8], &Bout[(i - 1) * 8], 8);
            salsa20_8_GPU64(&Bout[i * 8]);
        }
	}
}


/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
*/
__device__ static uint64_t integerify_GPU(const uint64_t * B, size_t r)
{
 // Our 32-bit words are in host byte order, and word 13 is the second word of
 // B_{2r-1} due to SIMD shuffling.  The 64-bit value we return is also in host
 // byte order, as it should be.
    const uint64_t * X = &B[(2 * r - 1) * 8];
	uint32_t lo = X[0];
	uint32_t hi = X[6] >> 32;
	return ((uint64_t)hi << 32) + lo;
}


/**
 * p2floor(x):
 * Largest power of 2 not greater than argument.
*/
__device__ static uint64_t p2floor_GPU(uint64_t x)
{
    uint64_t y;
    while ((y = x & (x - 1)))
        x = y;
    return x;

}

/**
 * smix1(B, r, N, flags, V, NROM, VROM, XY, S):
 * Compute first loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r bytes in length.
*/
__device__ static void smix1_GPU(uint64_t * B_GPU, size_t r, uint64_t N, uint32_t fazXOR, uint64_t * V_GPU, uint64_t * XY_GPU, uint64_t * S_GPU, unsigned int totalPasswords)
{

    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){
        // r = 8, s = 256
        size_t s = 16 * r;
        // XY is 2K
        uint64_t * X = V_GPU;
        uint64_t * Y = &XY_GPU[s];
        uint64_t * Z = S_GPU ? S_GPU : &XY_GPU[2 * s];
        uint64_t n, i, j;
        size_t k;

        /* 1: X <-- B */
        /* 3: V_i <-- X */
        for (i = 0; i < 2 * r; i++) {
            const salsa20_blk_t *src = (const salsa20_blk_t *)&B_GPU[i * 8];
            salsa20_blk_t *tmp = (salsa20_blk_t *)Y;
            salsa20_blk_t *dst = (salsa20_blk_t *)&X[i * 8];
            for (k = 0; k < 16; k++)
                tmp->w[k] = le32dec_GPU(&src->w[k]);
            salsa20_simd_shuffle(tmp, dst);
        }//*/

        /* 4: X <-- H(X) */
        /* 3: V_i <-- X */
        //blockmix(X, Y, Z, r);
        if (S_GPU) {
            blockmix_pwxform_GPU(X, Y, Z, r, totalPasswords);
        } else {
            blockmix_salsa8_GPU(X, Y, Z, r, totalPasswords);
        }

        blkcpy_GPU64(&V_GPU[s], Y, s);

        X = XY_GPU;

        /* 4: X <-- H(X) */
        //blockmix(Y, X, Z, r);
        if (S_GPU) {
            blockmix_pwxform_GPU(Y, X, Z, r, totalPasswords);
        } else {
            blockmix_salsa8_GPU(Y, X, Z, r, totalPasswords);
        }

        /* 2: for i = 0 to N - 1 do */
        for (n = 1, i = 2; i < N; i += 2) {
            /* 3: V_i <-- X */
            blkcpy_GPU64(&V_GPU[i * s], X, s);

            if (fazXOR) {
                if ((i & (i - 1)) == 0)
                    n <<= 1;

                /* j <-- Wrap(Integerify(X), i) */
                j = integerify_GPU(X, r) & (n - 1);
                j += i - n;

                /* X <-- X \xor V_j */
                blkxor_GPU(X, &V_GPU[j * s], s);
            }

            /* 4: X <-- H(X) */
            //blockmix(X, Y, Z, r);
            if (S_GPU) {
                blockmix_pwxform_GPU(X, Y, Z, r, totalPasswords);
            } else {
                blockmix_salsa8_GPU(X, Y, Z, r, totalPasswords);
            }

            /* 3: V_i <-- X */
            blkcpy_GPU64(&V_GPU[(i + 1) * s], Y, s);

            if (fazXOR) {
                /* j <-- Wrap(Integerify(X), i) */
                j = integerify_GPU(Y, r) & (n - 1);
                j += (i + 1) - n;

                /* X <-- X \xor V_j */
                blkxor_GPU(Y, &V_GPU[j * s], s);
            }

            /* 4: X <-- H(X) */
            //blockmix(Y, X, Z, r);
            if (S_GPU) {
                blockmix_pwxform_GPU(Y, X, Z, r, totalPasswords);
            } else {
                blockmix_salsa8_GPU(Y, X, Z, r, totalPasswords);
            }
        }


        // B' <-- X
        for (i = 0; i < 2 * r; i++) {
            const salsa20_blk_t *src = (const salsa20_blk_t *)&X[i * 8];
            salsa20_blk_t *tmp = (salsa20_blk_t *)Y;
            salsa20_blk_t *dst = (salsa20_blk_t *)&B_GPU[i * 8];
            for (k = 0; k < 16; k++)
                le32enc_GPU(&tmp->w[k], src->w[k]);
            salsa20_simd_unshuffle(tmp, dst);
        }
    }
}

/**
 * smix2(B, r, N, Nloop, flags, V, NROM, VROM, XY, S):
 * Compute second loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r bytes in length.  The value N must be a power of 2
 * greater than 1.
*/

__device__ static void smix2_GPU(uint64_t * B, uint64_t N, uint64_t Nloop, uint32_t copiaBloco, uint64_t * V, uint64_t * XY, uint64_t * S, unsigned int totalPasswords)
{

    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

        // r = 8, portanto s = 256
        size_t s = 16 * YESCRYPT_R;
        uint64_t * X = XY;
        uint64_t * Y = &XY[s];
        uint64_t * Z = S ? S : &XY[2 * s];
        uint64_t i, j;
        size_t k;

        if (Nloop == 0)
            return;

        /* X <-- B' */
        for (i = 0; i < 2 * YESCRYPT_R; i++) {
            const salsa20_blk_t *src = (const salsa20_blk_t *)&B[i * 8];
            salsa20_blk_t *tmp = (salsa20_blk_t *)Y;
            salsa20_blk_t *dst = (salsa20_blk_t *)&X[i * 8];
            for (k = 0; k < 16; k++)
                tmp->w[k] = le32dec_GPU(&src->w[k]);
            salsa20_simd_shuffle(tmp, dst);
        }

        /* 6: for i = 0 to N - 1 do */
        i = Nloop / 2;
        do {
            /* 7: j <-- Integerify(X) mod N */
            j = integerify_GPU(X, YESCRYPT_R) & (N - 1);

            /* 8: X <-- H(X \xor V_j) */
            blkxor_GPU(X, &V[j * s], s);
            /* V_j <-- Xprev \xor V_j */
            if (copiaBloco)
                blkcpy_GPU64(&V[j * s], X, s);

            //blockmix(X, Y, Z, YESCRYPT_R);
            if (S)
                blockmix_pwxform_GPU(X, Y, Z, YESCRYPT_R, totalPasswords);
            else
                blockmix_salsa8_GPU(X, Y, Z, YESCRYPT_R, totalPasswords);

            /* 7: j <-- Integerify(X) mod N */
            j = integerify_GPU(Y, YESCRYPT_R) & (N - 1);

            /* 8: X <-- H(X \xor V_j) */
            blkxor_GPU(Y, &V[j * s], s);
            /* V_j <-- Xprev \xor V_j */
            if (copiaBloco)
                blkcpy_GPU64(&V[j * s], Y, s);

            //blockmix(Y, X, Z, YESCRYPT_R);
            if (S)
                blockmix_pwxform_GPU(Y, X, Z, YESCRYPT_R, totalPasswords);
            else
                blockmix_salsa8_GPU(Y, X, Z, YESCRYPT_R, totalPasswords);

        } while (--i);

        /* 10: B' <-- X */
        for (i = 0; i < 2 * YESCRYPT_R; i++) {
            const salsa20_blk_t *src = (const salsa20_blk_t *)&X[i * 8];
            salsa20_blk_t *tmp = (salsa20_blk_t *)Y;
            salsa20_blk_t *dst = (salsa20_blk_t *)&B[i * 8];
            for (k = 0; k < 16; k++)
                le32enc_GPU(&tmp->w[k], src->w[k]);
            salsa20_simd_unshuffle(tmp, dst);
        }
    }
}

/**
 * smix(B, r, N, p, t, flags, V, NROM, VROM, XY, S):
 * Compute B = SMix_r(B, N).  The input B must be 128rp bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * XY must be 256r bytes in length.  The value N must be a power of 2 greater
 * than 1.
*/
__global__ static void smix_GPU(uint64_t * B_GPU, size_t B_size, uint64_t N, uint32_t t, uint64_t * V_GPU, size_t V_size,
 uint64_t * XY_GPU, size_t XY_size, uint64_t * S_GPU, size_t S_size, unsigned int totalPasswords)
{

    uint32_t threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){
        size_t S_totalCells = S_size/sizeof(uint64_t);
        size_t B_totalCells = B_size/sizeof(uint64_t);
        size_t V_totalCells = V_size/sizeof(uint64_t);
        size_t XY_totalCells = XY_size/sizeof(uint64_t);

        size_t idxPassword = threadNumber/YESCRYPT_P;
        size_t baseThread  = idxPassword * YESCRYPT_P;
        size_t idxThread   = threadNumber - baseThread;

        // r = 8, s = 256
        size_t s = 16 * YESCRYPT_R;
        uint64_t Nchunk, Nloop_all, Nloop_rw, Vchunk;

        // 1: n <-- N / p
        Nchunk = N / YESCRYPT_P;

        // 2: Nloop_all <-- fNloop(n, t, flags)
        Nloop_all = Nchunk;

        if (t <= 1) {
            if (t)
                Nloop_all *= 2; // 2/3
            Nloop_all = (Nloop_all + 2) / 3; // 1/3, round up
        } else {
            Nloop_all *= t - 1;
        }

        // 6: Nloop_rw <-- 0
        Nloop_rw = 0;
        // 4: Nloop_rw <-- Nloop_all / p
        Nloop_rw = Nloop_all / YESCRYPT_P;

        // 8: n <-- n - (n mod 2)
        Nchunk &= ~(uint64_t)1; // round down to even
        // 9: Nloop_all <-- Nloop_all + (Nloop_all mod 2)
        Nloop_all++; Nloop_all &= ~(uint64_t)1; // round up to even
        // 10: Nloop_rw <-- Nloop_rw - (Nloop_rw mod 2)
        Nloop_rw &= ~(uint64_t)1; // round down to even

        // 11: for i = 0 to p - 1 do
        // 12: v <-- in
        Vchunk = idxThread * Nchunk;

            // 13: if i = p - 1
            // 14:   n <-- N - v
            // 15: end if
            // 16: w <-- v + n - 1
            uint64_t Np = (idxThread < YESCRYPT_P - 1) ? Nchunk : (N - Vchunk);
            uint64_t * Bp = &B_GPU[idxPassword*B_totalCells + idxThread * s];
            uint64_t * Vp = &V_GPU[idxPassword*V_totalCells + Vchunk * s];

            // 17: if YESCRYPT_RW flag is set
            uint64_t * Sp = &S_GPU[idxPassword*S_totalCells] ? &S_GPU[idxPassword*S_totalCells + idxThread * Swords] : &S_GPU[idxPassword*S_totalCells];

            // 18: SMix1_1(B_i, Sbytes / 128, S_i, flags excluding YESCRYPT_RW)
            smix1_GPU(Bp, 1, Sbytes / 128, NAO_FAZ_XOR, Sp, &XY_GPU[idxPassword*XY_totalCells + idxThread*(2*s+8)], NULL, totalPasswords);

            smix1_GPU(Bp, YESCRYPT_R, Np, FAZ_XOR, Vp, &XY_GPU[idxPassword*XY_totalCells + idxThread * (2 * s + 8)], Sp, totalPasswords);
            // 21: SMix2_r(B_i, p2floor(n), Nloop_rw, V_{v..w}, flags)
            smix2_GPU(Bp, p2floor_GPU(Np), Nloop_rw, COPIA_BLOCO, Vp, &XY_GPU[idxPassword*XY_totalCells + idxThread * (2 * s + 8)], Sp, totalPasswords);

            // 23: for i = 0 to p - 1 do
            Bp = &B_GPU[idxPassword*B_totalCells + idxThread * s];
            Sp = &S_GPU[idxPassword*S_totalCells] ? &S_GPU[idxPassword*S_totalCells + idxThread * Swords] : &S_GPU[idxPassword*S_totalCells];
            smix2_GPU(Bp, N, Nloop_all - Nloop_rw, NAO_COPIA_BLOCO, &V_GPU[idxPassword*V_totalCells], &XY_GPU[idxPassword*XY_totalCells + idxThread * (2 * s + 8)], Sp, totalPasswords);
    }
}


/**
 * yescrypt_kdf_body(shared, local, YESCRYPT_Rpasswd, passwdlen, salt, saltlen,
 *     N, r, p, t, flags, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen), or a revision of scrypt as requested by flags and shared, and
 * write the result into buf.  The parameters r, p, and buflen must satisfy
 * r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N must be a power
 * of 2 greater than 1.
 *
 * t controls computation time while not affecting peak memory usage.  shared
 * and flags may request special modes as described in yescrypt.h.  local is
 * the thread-local data structure, allowing optimized implementations to
 * preserve and reuse a memory allocation across calls, thereby reducing its
 * overhead (this reference implementation does not make that optimization).
 *
 * Return 0 on success; or -1 on error.
 */
static int
yescrypt_kdf_body(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt, size_t saltlen,
uint64_t N, uint32_t t, uint32_t prehash, uint8_t * buf, size_t buflen,
unsigned int totalPasswords, unsigned int gridSize, unsigned int blockSize)
{
    //
	int retval = -1;
	size_t B_size, V_size, sha_size, S_size, XY_size, dk_size;
    cudaError_t errorCUDA;

	// Sanity-check parameters
    if ((N / YESCRYPT_P <= 1) || (YESCRYPT_R < rmin)) {
        errno = EINVAL;
        return -1;
    }


	// Allocate memory
	// 128*(r=8)*(8*2^Ninput) -> N * 1024
	V_size = (size_t)128 * YESCRYPT_R * N;

    // GPUs RAM
    uint64_t *V_GPU;
    errorCUDA = cudaMalloc((void**) &V_GPU, V_size*totalPasswords);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

	// 1k bytes per thread.
    B_size = (size_t)128 * YESCRYPT_R * YESCRYPT_P;

    uint64_t *B_GPU;
    errorCUDA = cudaMalloc((void**) &B_GPU, B_size*totalPasswords);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

    // 2k bytes per thread
    uint64_t *XY_GPU;
    XY_size = (size_t)(256 * YESCRYPT_R + 64)* YESCRYPT_P;
    errorCUDA = cudaMalloc((void**) &XY_GPU, XY_size * totalPasswords);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

	// Sbytes = 8k per thread.
    uint64_t *S_GPU;
    S_size = (size_t)Sbytes * YESCRYPT_P;
    errorCUDA = cudaMalloc((void**) &S_GPU, S_size * totalPasswords);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

    sha_size = (size_t)4*sizeof(uint64_t);
	uint64_t *sha256_GPU;
    errorCUDA = cudaMalloc((void**) &sha256_GPU, (size_t)(sha_size*totalPasswords));
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

	uint8_t *dk_GPU;   //[4*8]
	dk_size = (size_t)4*sizeof(uint64_t);
	errorCUDA = cudaMalloc((void**) &dk_GPU, dk_size*totalPasswords);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

	uint8_t *passwd_GPU;
	errorCUDA = cudaMalloc((void**) &passwd_GPU, (size_t)passwdlen*totalPasswords);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

	uint8_t *salt_GPU;
	errorCUDA = cudaMalloc((void**) &salt_GPU, (size_t)saltlen*totalPasswords);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;;
    }


    uint8_t * buf_GPU;
    errorCUDA = cudaMalloc((void**) &buf_GPU, (size_t)buflen*totalPasswords);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

	// Transfers the password to GPU.
	errorCUDA = cudaMemcpy(passwd_GPU, passwd, passwdlen*totalPasswords, cudaMemcpyHostToDevice);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory copy error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

	// Transfers the salt to GPU.
	errorCUDA = cudaMemcpy(salt_GPU, salt, saltlen*totalPasswords, cudaMemcpyHostToDevice);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory copy error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

// Sets L1 cache size to 48kB:
//	cudaDeviceSetCacheConfig(cudaFuncCachePreferL1);

    HMAC_SHA256_GPU<<<gridSize, blockSize>>>(prehash, passwd_GPU, passwdlen, (uint32_t *)sha256_GPU, sha_size, salt_GPU, saltlen, (uint32_t *)B_GPU, B_size, totalPasswords);

	cudaThreadSynchronize();
	errorCUDA = cudaGetLastError();
	if ( cudaSuccess != errorCUDA ){
		printf( "CUDA kernel call error in file %s, line %d!\n",  __FILE__, __LINE__  );
		printf( "Error: %s \n", cudaGetErrorString(errorCUDA) );
		retval = -2;
		goto errorOut;
	}

	smix_GPU<<<YESCRYPT_P*gridSize, blockSize>>>(B_GPU, B_size, N, t, V_GPU, V_size, XY_GPU, XY_size, S_GPU, S_size, totalPasswords);

	cudaThreadSynchronize();
	errorCUDA = cudaGetLastError();
	if ( cudaSuccess != errorCUDA ){
		printf( "CUDA kernel call error in file %s, line %d!\n",  __FILE__, __LINE__  );
		printf( "Error: %s \n", cudaGetErrorString(errorCUDA) );
		retval = -2;
		goto errorOut;
	}

    HMAC_SHA256_GPU_2<<<gridSize, blockSize>>>(prehash, (uint8_t *)sha256_GPU, 8*sizeof(uint32_t), (uint32_t *)sha256_GPU, sha_size, (uint32_t *)B_GPU, B_size, buf_GPU, buflen, totalPasswords);

	cudaThreadSynchronize();
	errorCUDA = cudaGetLastError();
	if ( cudaSuccess != errorCUDA ){
		printf( "CUDA kernel call error in file %s, line %d!\n",  __FILE__, __LINE__  );
		printf( "Error: %s \n", cudaGetErrorString(errorCUDA) );
		retval = -2;
		goto errorOut;
	}

	// Getting the key back.
	errorCUDA = cudaMemcpy(buf, buf_GPU, buflen*totalPasswords, cudaMemcpyDeviceToHost);
	if ( cudaSuccess != errorCUDA ) {
	    printf( "CUDA memory copy error in file %s, line %d!\n",  __FILE__, __LINE__  );
		printf( "Error: %s \n", cudaGetErrorString(errorCUDA) );
		retval = -2;
		goto errorOut;
	}

    // Frees everything:
    cudaFree(buf_GPU);
    cudaFree(salt_GPU);
	cudaFree(passwd_GPU);
    cudaFree(dk_GPU);
    cudaFree(sha256_GPU);
    cudaFree(S_GPU);
	cudaFree(XY_GPU);
	cudaFree(B_GPU);
    cudaFree(V_GPU);

	// Success!
	retval = 0;
errorOut:
	// Clear GPU by caller
	return retval;
}

/**
 * yescrypt_kdf(shared, local, passwd, passwdlen, salt, saltlen,
 *     N, r, p, t, g, flags, buf, buflen):
 * Compute scrypt or its revision as requested by the parameters.  The inputs
 * to this function are the same as those for yescrypt_kdf_body() above, with
 * the addition of g, which controls hash upgrades (0 for no upgrades so far).
*/
int
yescrypt_kdf(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt, size_t saltlen,
    uint64_t N, uint32_t r, uint32_t t, uint32_t g, uint8_t * buf, size_t buflen,
    unsigned int totalPasswords, unsigned int gridSize, unsigned int blockSize)
{
	uint8_t dk[32];

	if (YESCRYPT_P >= 1 && N / YESCRYPT_P >= 0x100 && N / YESCRYPT_P * YESCRYPT_R >= 0x20000) {

		int retval = yescrypt_kdf_body(passwd, passwdlen, salt, saltlen, N >> 6, 0, FAZ_PRE_HASH, dk, sizeof(dk), totalPasswords, gridSize, blockSize);
		if (retval)
			return retval;
		passwd = dk;
		passwdlen = sizeof(dk);
	}

	int retval = yescrypt_kdf_body(passwd, passwdlen, salt, saltlen, N, t, NAO_FAZ_PRE_HASH, buf, buflen, totalPasswords, gridSize, blockSize);
	if (retval)
		return retval;
	return 0;
}
