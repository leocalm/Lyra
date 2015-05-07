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

__device__ static inline void blkxor_GPU(uint32_t * dest, const uint32_t * src, size_t count, unsigned int totalPasswords)
{
    do {
        *dest++ ^= *src++; *dest++ ^= *src++;
        *dest++ ^= *src++; *dest++ ^= *src++;
    } while (count -= 4);

}

/**
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
*/
__device__ static void salsa20_8_GPU(uint32_t B[16], unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

		uint32_t x[16];
        size_t i;

        // SIMD unshuffle
        for (i = 0; i < 16; i++)
            x[i * 5 % 16] = B[i];

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

        // SIMD shuffle
        for (i = 0; i < 16; i++)
            B[i] += x[i * 5 % 16];

    }
}


/**
 * blockmix_salsa8(B, Y, r):
 * Compute B = BlockMix_{salsa20/8, r}(B).  The input B must be 128r bytes in
 * length; the temporary space Y must also be the same size.
*/
__device__ static void blockmix_salsa8_GPU(uint32_t * B, uint32_t * Y, size_t r, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

		uint32_t X[16];
        size_t i;

        // 1: X <-- B_{2r - 1}
        blkcpy_GPU(X, &B[(2 * r - 1) * 16], 16, totalPasswords);

        // 2: for i = 0 to 2r - 1 do
        for (i = 0; i < 2 * r; i++) {
            // 3: X <-- H(X \xor B_i)
            blkxor_GPU(X, &B[i * 16], 16, totalPasswords);
            salsa20_8_GPU(X, totalPasswords);

            // 4: Y_i <-- X
            blkcpy_GPU(&Y[i * 16], X, 16, totalPasswords);
        }

        // 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1})
        for (i = 0; i < r; i++)
            blkcpy_GPU(&B[i * 16], &Y[(i * 2) * 16], 16, totalPasswords);
        for (i = 0; i < r; i++)
            blkcpy_GPU(&B[(i + r) * 16], &Y[(i * 2 + 1) * 16], 16, totalPasswords);
    }
}

// These are tunable
#define PWXsimple 2
#define PWXgather 4
#define PWXrounds 6
#define Swidth 8

// Derived values.  Not tunable on their own.
#define PWXbytes (PWXgather * PWXsimple * 8)
#define PWXwords (PWXbytes / sizeof(uint32_t))
#define Sbytes (2 * (1 << Swidth) * PWXsimple * 8)
#define Swords (Sbytes / sizeof(uint32_t))
#define Smask (((1 << Swidth) - 1) * PWXsimple * 8)
#define Smask2 (((uint64_t)Smask << 32) | Smask)
#define rmin ((PWXbytes + 127) / 128)


/**
 * pwxform(B):
 * Transform the provided block using the provided S-boxes.
*/
__device__ static void pwxform_GPU(uint32_t * B, const uint32_t * S, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){
		//ORIGINAL:
        uint32_t (*X)[PWXsimple][2] = (uint32_t (*)[PWXsimple][2])B;
        const uint32_t (*S0)[2] = (const uint32_t (*)[2])S;
        const uint32_t (*S1)[2] = S0 + Sbytes / 2 / sizeof(*S0);
        size_t i, j, k;

        // 1: for i = 0 to PWXrounds do
        for (i = 0; i < PWXrounds; i++) {
            // 2: for j = 0 to PWXgather do
            for (j = 0; j < PWXgather; j++) {
                uint32_t xl;
                uint32_t xh;
                const uint32_t (*p0)[2], (*p1)[2];

				xl = X[j][0][0];
				xh = X[j][0][1];

                // 3: p0 <-- (lo(B_{j,0}) & Smask) / (PWXsimple * 8)
                p0 = S0 + (xl & Smask) / sizeof(*S0);
                // 4: p1 <-- (hi(B_{j,0}) & Smask) / (PWXsimple * 8)
                p1 = S1 + (xh & Smask) / sizeof(*S1);

				// 5: for k = 0 to PWXsimple do
                for (k = 0; k < PWXsimple; k++) {
                    uint64_t x, s0, s1;

                    // 6: B_{j,k} <-- (hi(B_{j,k}) * lo(B_{j,k}) + S0_{p0,k}) \xor S1_{p1,k}
                    s0 = ((uint64_t)p0[k][1] << 32) + p0[k][0];
                    s1 = ((uint64_t)p1[k][1] << 32) + p1[k][0];

                    xl = X[j][k][0];
                    xh = X[j][k][1];

                    x = (uint64_t) xh * xl;
                    x += s0;
                    x ^= s1;

                    X[j][k][0] = x;
                    X[j][k][1] = x >> 32;
                }
            }
        }
	}

}

/**
 * blockmix_pwxform(B, Y, S, r):
 * Compute B = BlockMix_pwxform{salsa20/8, S, r}(B).  The input B must be 128r
 * bytes in length; the temporary space Y must be at least PWXbytes.
*/
__device__ static void blockmix_pwxform_GPU(uint32_t * B, uint32_t * Y, const uint32_t * S, size_t r, unsigned int totalPasswords)
{
    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

        size_t r1, i;
        // 1: r_1 <-- 128r / PWXbytes
        r1 = 128 * r / PWXbytes;
        // 2: X <-- B'_{r_1 - 1}
        blkcpy_GPU(Y, &B[(r1 - 1) * PWXwords], PWXwords, totalPasswords);
        // 3: for i = 0 to r_1 - 1 do
        for (i = 0; i < r1; i++) {
            // 4: if r_1 > 1
            if (r1 > 1) {
                // 5: X <-- X \xor B'_i
                blkxor_GPU(Y, &B[i * PWXwords], PWXwords, totalPasswords);
            }
            // 7: X <-- pwxform(X)
            pwxform_GPU(Y, S, totalPasswords);
            // 8: B'_i <-- X
            blkcpy_GPU(&B[i * PWXwords], Y, PWXwords, totalPasswords);
        }
        // 10: i <-- floor((r_1 - 1) * PWXbytes / 64)
        i = (r1 - 1) * PWXbytes / 64;
        // 11: B_i <-- H(B_i)
        salsa20_8_GPU(&B[i * 16], totalPasswords);
        // 12: for i = i + 1 to 2r - 1 do
        for (i++; i < 2 * r; i++) {
            // 13: B_i <-- H(B_i \xor B_{i-1})
            blkxor_GPU(&B[i * 16], &B[(i - 1) * 16], 16, totalPasswords);
            salsa20_8_GPU(&B[i * 16], totalPasswords);
        }
	}
}


/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
*/
__device__ static uint64_t integerify_GPU(const uint32_t * B, size_t r)
{
 // Our 32-bit words are in host byte order, and word 13 is the second word of
 // B_{2r-1} due to SIMD shuffling.  The 64-bit value we return is also in host
 // byte order, as it should be.
    const uint32_t * X = &B[(2 * r - 1) * 16];
    return ((uint64_t)X[13] << 32) + X[0];
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
 * wrap(x, i):
 * Wrap x to the range 0 to i-1.
*/
__device__ static uint64_t wrap_GPU(uint64_t x, uint64_t i)
{
        uint64_t n = p2floor_GPU(i);
        return (x & (n - 1)) + (i - n);
}


/**
 * smix1(B, r, N, flags, V, NROM, VROM, XY, S):
 * Compute first loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r bytes in length.
*/
__device__ static void smix1_GPU(uint32_t * B_GPU, size_t r, uint64_t N, uint32_t fazXOR, uint32_t * V_GPU, uint32_t * XY_GPU, uint32_t * S_GPU, unsigned int totalPasswords)
{

    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){


        // r = 8, s = 256
        size_t s = 32 * r;
        // XY is 2K
        uint32_t * X = XY_GPU;
        uint32_t * Y = &XY_GPU[s];
        uint64_t i, j;
        size_t k;

        // 1: X <-- B
        for (k = 0; k < 2 * r; k++)
            for (i = 0; i < 16; i++) {
                X[k * 16 + i] = B_GPU[k * 16 + (i * 5 % 16)];
            }

        // 2: for i = 0 to N - 1 do
        for (i = 0; i < N; i++) {
            // 3: V_i <-- X
            blkcpy_GPU(&V_GPU[i * s], X, s, totalPasswords);

            if ((fazXOR) && i > 1) {
                // j <-- Wrap(Integerify(X), i)
                // Wrap x to the range 0 to i-1
                j = wrap_GPU(integerify_GPU(X, r), i);

                // X <-- X \xor V_j
                blkxor_GPU(X, &V_GPU[j * s], s, totalPasswords);
            }

            // 4: X <-- H(X)
            if (S_GPU)
                blockmix_pwxform_GPU(X, Y, S_GPU, r, totalPasswords);
            else
                blockmix_salsa8_GPU(X, Y, r, totalPasswords);
        }
        // B' <-- X
        for (k = 0; k < 2 * r; k++)
            for (i = 0; i < 16; i++)
                le32enc_GPU(&B_GPU[k * 16 + (i * 5 % 16)], X[k * 16 + i]);
    }
}


/**
 * smix2(B, r, N, Nloop, flags, V, NROM, VROM, XY, S):
 * Compute second loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r bytes in length.  The value N must be a power of 2
 * greater than 1.
*/

__device__ static void smix2_GPU(uint32_t * B, size_t r, uint64_t N, uint64_t Nloop, uint32_t copiaBloco, uint32_t * V, uint32_t * XY, uint32_t * S, unsigned int totalPasswords)
{

    unsigned int threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){

        // r = 8, s = 256
        size_t s = 32 * r;
        uint32_t * X = XY;
        uint32_t * Y = &XY[s];
        uint64_t i, j;
        size_t k;

        // X <-- B
        for (k = 0; k < 2 * r; k++)
            for (i = 0; i < 16; i++)
                X[k * 16 + i] = le32dec_GPU(&B[k * 16 + (i * 5 % 16)]);

        // 6: for i = 0 to N - 1 do
        for (i = 0; i < Nloop; i++) {
            // 7: j <-- Integerify(X) mod N
            j = integerify_GPU(X, r) & (N - 1);

            // 8.1: X <-- X \xor V_j
            blkxor_GPU(X, &V[j * s], s, totalPasswords);
            // V_j <-- X

            if (copiaBloco)
                blkcpy_GPU(&V[j * s], X, s, totalPasswords);

            // 8.2: X <-- H(X)
            if (S)
                blockmix_pwxform_GPU(X, Y, S, r, totalPasswords);
            else
                blockmix_salsa8_GPU(X, Y, r, totalPasswords);
        }

        // 10: B' <-- X
        for (k = 0; k < 2 * r; k++)
            for (i = 0; i < 16; i++)
                le32enc_GPU(&B[k * 16 + (i * 5 % 16)], X[k * 16 + i]);
    }
}



/**
 * smix(B, r, N, p, t, flags, V, NROM, VROM, XY, S):
 * Compute B = SMix_r(B, N).  The input B must be 128rp bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * XY must be 256r bytes in length.  The value N must be a power of 2 greater
 * than 1.
*/
__global__ static void smix_GPU(uint32_t * B_GPU, size_t B_size, size_t r, uint64_t N, uint32_t t, uint32_t * V_GPU, size_t V_size,
 uint32_t * XY_GPU, size_t XY_size, uint32_t * S_GPU, size_t S_size, unsigned int totalPasswords)
{

    uint32_t threadNumber = (blockIdx.x * blockDim.x) + threadIdx.x;
    if (threadNumber < (YESCRYPT_P*totalPasswords)){
        size_t S_totalCells = S_size/sizeof(uint32_t);
        size_t B_totalCells = B_size/sizeof(uint32_t);
        size_t V_totalCells = V_size/sizeof(uint32_t);
        size_t XY_totalCells = XY_size/sizeof(uint32_t);

        size_t idxPassword = threadNumber/YESCRYPT_P;
        size_t baseThread  = idxPassword * YESCRYPT_P;
        size_t idxThread   = threadNumber - baseThread;

        // r = 8, s = 256
        size_t s = 32 * r;
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
            uint32_t * Bp = &B_GPU[idxPassword*B_totalCells + idxThread * s];
            uint32_t * Vp = &V_GPU[idxPassword*V_totalCells + Vchunk * s];

            // 17: if YESCRYPT_RW flag is set
            uint32_t * Sp = &S_GPU[idxPassword*S_totalCells] ? &S_GPU[idxPassword*S_totalCells + idxThread * Swords] : &S_GPU[idxPassword*S_totalCells];

            if (Sp) {
                // 18: SMix1_1(B_i, Sbytes / 128, S_i, flags excluding YESCRYPT_RW)
                smix1_GPU(Bp, 1, Sbytes / 128, NAO_FAZ_XOR, Sp, &XY_GPU[idxPassword*XY_totalCells + idxThread*(2*s+8)], NULL, totalPasswords);
            }
            smix1_GPU(Bp, r, Np, FAZ_XOR, Vp, &XY_GPU[idxPassword*XY_totalCells + idxThread * (2 * s + 8)], Sp, totalPasswords);
            // 21: SMix2_r(B_i, p2floor(n), Nloop_rw, V_{v..w}, flags)
            smix2_GPU(Bp, r, p2floor_GPU(Np), Nloop_rw, COPIA_BLOCO, Vp, &XY_GPU[idxPassword*XY_totalCells + idxThread * (2 * s + 8)], Sp, totalPasswords);

            // 23: for i = 0 to p - 1 do
            Bp = &B_GPU[idxPassword*B_totalCells + idxThread * s];
            Sp = &S_GPU[idxPassword*S_totalCells] ? &S_GPU[idxPassword*S_totalCells + idxThread * Swords] : &S_GPU[idxPassword*S_totalCells];
            smix2_GPU(Bp, r, N, Nloop_all - Nloop_rw, NAO_COPIA_BLOCO, &V_GPU[idxPassword*V_totalCells], &XY_GPU[idxPassword*XY_totalCells + idxThread * (2 * s + 8)], Sp, totalPasswords);
    }
}


/**
 * yescrypt_kdf_body(shared, local, passwd, passwdlen, salt, saltlen,
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
uint64_t N, uint32_t r, uint32_t t, uint32_t prehash, uint8_t * buf, size_t buflen,
unsigned int totalPasswords, unsigned int gridSize, unsigned int blockSize)
{
    //
	int retval = -1;
	size_t B_size, V_size, sha_size, S_size, XY_size, dk_size;
    cudaError_t errorCUDA;

	// Sanity-check parameters
    if ((N / YESCRYPT_P <= 1) || (r < rmin)) {
        errno = EINVAL;
        return -1;
    }


	// Allocate memory
	// 128*(r=8)*(8*2^Ninput) -> N * 1024
	V_size = (size_t)128 * r * N;

    // GPUs RAM
    uint32_t *V_GPU;
    errorCUDA = cudaMalloc((void**) &V_GPU, V_size*totalPasswords);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

	// 1k bytes per thread.
    B_size = (size_t)128 * r * YESCRYPT_P;

    uint32_t *B_GPU;
    errorCUDA = cudaMalloc((void**) &B_GPU, B_size*totalPasswords);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

    // 2k bytes per thread
    uint32_t *XY_GPU;
    XY_size = (size_t)(256 * r + 64)* YESCRYPT_P;
    errorCUDA = cudaMalloc((void**) &XY_GPU, XY_size * totalPasswords);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

	// Sbytes = 8k per thread.
    uint32_t *S_GPU;
    S_size = (size_t)Sbytes * YESCRYPT_P;
    errorCUDA = cudaMalloc((void**) &S_GPU, S_size * totalPasswords);
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

    sha_size = (size_t)8*sizeof(uint32_t);
	uint32_t *sha256_GPU;
    errorCUDA = cudaMalloc((void**) &sha256_GPU, (size_t)(sha_size*totalPasswords));
    if (cudaSuccess != errorCUDA) {
        printf("CUDA memory allocation error in file %s, line %d!\n", __FILE__, __LINE__);
        printf("Error: %s \n", cudaGetErrorString(errorCUDA));
		retval = -2;
		goto errorOut;
    }

	uint8_t *dk_GPU;   //[8*4]
	dk_size = (size_t)8*sizeof(uint32_t);
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

    HMAC_SHA256_GPU<<<gridSize, blockSize>>>(prehash, passwd_GPU, passwdlen, sha256_GPU, sha_size, salt_GPU, saltlen, B_GPU, B_size, totalPasswords);

	cudaThreadSynchronize();
	errorCUDA = cudaGetLastError();
	if ( cudaSuccess != errorCUDA ){
		printf( "CUDA kernel call error in file %s, line %d!\n",  __FILE__, __LINE__  );
		printf( "Error: %s \n", cudaGetErrorString(errorCUDA) );
		retval = -2;
		goto errorOut;
	}

	smix_GPU<<<YESCRYPT_P*gridSize, blockSize>>>(B_GPU, B_size, r, N, t, V_GPU, V_size, XY_GPU, XY_size, S_GPU, S_size, totalPasswords);

	cudaThreadSynchronize();
	errorCUDA = cudaGetLastError();
	if ( cudaSuccess != errorCUDA ){
		printf( "CUDA kernel call error in file %s, line %d!\n",  __FILE__, __LINE__  );
		printf( "Error: %s \n", cudaGetErrorString(errorCUDA) );
		retval = -2;
		goto errorOut;
	}

    HMAC_SHA256_GPU_2<<<gridSize, blockSize>>>(prehash, (uint8_t *)sha256_GPU, 8*sizeof(uint32_t), sha256_GPU, sha_size, B_GPU, B_size, buf_GPU, buflen, totalPasswords);

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

	if (YESCRYPT_P >= 1 && N / YESCRYPT_P >= 0x100 && N / YESCRYPT_P * r >= 0x20000) {

		int retval = yescrypt_kdf_body(passwd, passwdlen, salt, saltlen, N >> 6, r, 0, FAZ_PRE_HASH, dk, sizeof(dk), totalPasswords, gridSize, blockSize);
		if (retval)
			return retval;
		passwd = dk;
		passwdlen = sizeof(dk);
	}

	int retval = yescrypt_kdf_body(passwd, passwdlen, salt, saltlen, N, r, t, NAO_FAZ_PRE_HASH, buf, buflen, totalPasswords, gridSize, blockSize);
	if (retval)
		return retval;
	return 0;
}
