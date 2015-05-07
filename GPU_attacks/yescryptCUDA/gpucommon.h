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
//
// Just for debug
#define IMPRIME1(vetor, texto)  \
    uint8_t *ptr = (uint8_t *)vetor;  \
    int iPTR = 0; \
    printf("%s%2d: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x \n", texto, threadNumber, ptr[iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR]);  \

//
#define IMPRIME2(vetor, texto)  \
    ptr = (uint8_t *)vetor;  \
    iPTR = 0; \
    printf("%s%2d: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x \n", texto, threadNumber, \
    ptr[iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], \
    ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR], ptr[++iPTR]);  \

__device__ static void blkcpy_GPU(uint32_t * dest, const uint32_t * src, size_t count, unsigned int totalPasswords)
{
        do {
            *dest++ = *src++; *dest++ = *src++;
			*dest++ = *src++; *dest++ = *src++;
		} while (count -= 4);
}

__device__ static inline void blkcpy_GPU64(uint64_t * dest, const uint64_t * src, size_t count)
{
        do {
            *dest++ = *src++; *dest++ = *src++;
			*dest++ = *src++; *dest++ = *src++;
		} while (count -= 4);
}

