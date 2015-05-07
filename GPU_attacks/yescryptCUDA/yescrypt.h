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
 */
#ifndef _YESCRYPT_H_
#define _YESCRYPT_H_

#include <stdint.h>
#include <stdlib.h>

#ifndef YESCRYPT_P
    #define YESCRYPT_P 1
#endif

#define YESCRYPT_BASE_N 8
#define YESCRYPT_R 8

/**
 * Internal type used by the memory allocator.  Please do not use it directly.
 * Use yescrypt_shared_t and yescrypt_local_t as appropriate instead, since
 * they might differ from each other in a future version.
 */
typedef struct {
	void * base, * aligned;
	size_t base_size, aligned_size;
} yescrypt_region_t;

/**
 * Types for shared (ROM) and thread-local (RAM) data structures.
 */
typedef yescrypt_region_t yescrypt_local_t;

/**
 * yescrypt_init_local(local):
 * Initialize the thread-local (RAM) data structure.  Actual memory allocation
 * is currently fully postponed until a call to yescrypt_kdf() or yescrypt_r().
 *
 * Return 0 on success; or -1 on error.
 *
 * MT-safe as long as local is local to the thread.
 */
extern int yescrypt_init_local(yescrypt_local_t * __local);

/**
 * yescrypt_free_local(local):
 * Free memory that may have been allocated for an initialized thread-local
 * (RAM) data structure.
 *
 * Return 0 on success; or -1 on error.
 *
 * MT-safe as long as local is local to the thread.
 */
extern int yescrypt_free_local(yescrypt_local_t * __local);

/**
 * yescrypt_kdf(shared, local, passwd, passwdlen, salt, saltlen,
 *     N, r, p, t, g, flags, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen), or a revision of scrypt as requested by flags and shared, and
 * write the result into buf.  The parameters N, r, p, and buflen must satisfy
 * the same conditions as with crypto_scrypt().  t controls computation time
 * while not affecting peak memory usage.  g controls hash upgrades (0 for no
 * upgrades so far).  shared and flags may request special modes as described
 * below.  local is the thread-local data structure, allowing to preserve and
 * reuse a memory allocation across calls, thereby reducing its overhead.
 *
 * Return 0 on success; or -1 on error.
 *
 * t controls computation time.  t = 0 is optimal in terms of achieving the
 * highest area-time for ASIC attackers.  Thus, higher computation time, if
 * affordable, is best achieved by increasing N rather than by increasing t.
 * However, if the higher memory usage (which goes along with higher N) is not
 * affordable, or if fine-tuning of the time is needed (recall that N must be a
 * power of 2), then t = 1 or above may be used to increase time while staying
 * at the same peak memory usage.  t = 1 increases the time by 25% and
 * decreases the normalized area-time to 96% of optimal.  (Of course, in
 * absolute terms the area-time increases with higher t.  It's just that it
 * would increase slightly more with higher N*r rather than with higher t.)
 * t = 2 increases the time by another 20% and decreases the normalized
 * area-time to 89% of optimal.  Thus, these two values are reasonable to use
 * for fine-tuning.  Values of t higher than 2 result in further increase in
 * time while reducing the efficiency much further (e.g., down to around 50% of
 * optimal for t = 5, which runs 3 to 4 times slower than t = 0, with exact
 * numbers varying by the flags settings).
 *
 * Classic scrypt is available by setting t = 0, flags = 0, and shared = NULL.
 * In this mode, the thread-local memory region (RAM) is first sequentially
 * written to and then randomly read from.  This algorithm is friendly towards
 * time-memory tradeoffs (TMTO), available both to defenders (albeit not in
 * this implementation) and to attackers.
 *
 * Setting YESCRYPT_WORM enables only minimal enhancements relative to classic
 * scrypt: support for the t parameter, and pre- and post-hashing.
 *
 * Setting YESCRYPT_RW adds extra random reads and writes to the thread-local
 * memory region (RAM), which makes TMTO a lot less efficient.  This may be
 * used to slow down the kinds of attackers who would otherwise benefit from
 * classic scrypt's efficient TMTO.  Since classic scrypt's TMTO allows not
 * only for the tradeoff, but also for a decrease of attacker's area-time (by
 * up to a constant factor), setting YESCRYPT_RW substantially increases the
 * cost of attacks in area-time terms as well.  Yet another benefit of it is
 * that optimal area-time is reached at an earlier time than with classic
 * scrypt, and t = 0 actually corresponds to this earlier completion time,
 * resulting in quicker hash computations (and thus in higher request rate
 * capacity).  Due to these properties, YESCRYPT_RW should almost always be
 * set, except when compatibility with classic scrypt or TMTO-friendliness are
 * desired.
 *
 * YESCRYPT_RW also moves parallelism that is present with p > 1 to a
 * lower level as compared to where it is in classic scrypt.  This reduces
 * flexibility for efficient computation (for both attackers and defenders) by
 * requiring that, short of resorting to TMTO, the full amount of memory be
 * allocated as needed for the specified p, regardless of whether that
 * parallelism is actually being fully made use of or not.  (For comparison, a
 * single instance of classic scrypt may be computed in less memory without any
 * CPU time overhead, but in more real time, by not making full use of the
 * parallelism.)  This may be desirable when the defender has enough memory
 * with sufficiently low latency and high bandwidth for efficient full parallel
 * execution, yet the required memory size is high enough that some likely
 * attackers might end up being forced to choose between using higher latency
 * memory than they could use otherwise (waiting for data longer) or using TMTO
 * (waiting for data more times per one hash computation).  The area-time cost
 * for other kinds of attackers (who would use the same memory type and TMTO
 * factor or no TMTO either way) remains roughly the same, given the same
 * running time for the defender.
 *
 * As a side effect of differences between the algorithms, setting YESCRYPT_RW
 * also changes the way the total processing time (combined for all threads)
 * and memory allocation (if the parallelism is being made use of) is to be
 * controlled from N*r*p (for classic scrypt) to N*r (in this modification).
 * Obviously, these only differ for p > 1.
 *
 * Passing a shared structure, with ROM contents previously computed by
 * yescrypt_init_shared(), enables the use of ROM and requires YESCRYPT_RW for
 * the thread-local RAM region.  In order to allow for initialization of the
 * ROM to be split into a separate program, the shared->aligned and
 * shared->aligned_size fields may be set by the caller of yescrypt_kdf()
 * manually rather than with yescrypt_init_shared().
 *
 * local must be initialized with yescrypt_init_local().
 *
 * MT-safe as long as local and buf are local to the thread.
 */

extern int yescrypt_kdf(const uint8_t * __passwd, size_t __passwdlen,
    const uint8_t * __salt, size_t __saltlen,
    uint64_t __N, uint32_t __r, uint32_t __t, uint32_t __g,
    uint8_t * __buf, size_t __buflen, unsigned int totalPasswords, unsigned int gridSize, unsigned int blockSize); //, unsigned int printKeys);


void occupancyCalculator (int memorySize);
#endif /* !_YESCRYPT_H_ */
