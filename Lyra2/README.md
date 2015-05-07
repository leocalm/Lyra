-------------------------------------------------------------------------------------------
# Introduction of Lyra2
-------------------------------------------------------------------------------------------

Lyra2 is a password hashing scheme (PHS) based on cryptographic sponges. 

Lyra2 was designed to be strictly sequential (i.e., not easily parallelizable), 
providing strong security even against attackers that uses multiple processing 
cores (e.g., custom hardware or a powerful GPU).

At the same time, it is intended to be simple to implement in software and to allow 
legitimate users to fine tune its memory and processing costs according to the desired
level of security against brute force password-guessing attacks.

Lyra2 is an improvement of the recently proposed Lyra algorithm, providing an even
higher security level against different attack venues and overcoming some limitations
of this and other existing schemes.

For more information, we recommend reading the Reference Guide (./Lyra2ReferenceGuide.pdf)
that is part of this package.

-------------------------------------------------------------------------------------------
## Overview of this package
-------------------------------------------------------------------------------------------

####	./README.txt

This file.

####	./Lyra2ReferenceGuide.pdf

Manual containing all the architectural details of Lyra2, security analysis, discussions
about possible extensions, performance, etc.

####	./src

Contains the Makefile and the reference implementation (i.e., without optimizations).

####	./src/bench

Files that can be used to replicate the benchmarks shown in the Reference Guide.

####	./src/cuda

CUDA implementations, both for attacks (i.e., many password tests performed in parallel) 
and for legitimate users (i.e., for running a single password test).

####	./src/sse

Optimized implementation (i.e., SSE-oriented implementation). We note that, albeit many
optimizations were included in the code, there may still be further optimizations to be 
explored.

-------------------------------------------------------------------------------------------
## Building
-------------------------------------------------------------------------------------------


### Build Requirements
------------------------------------------------
	make
	gcc     (tested with version 4.9.2 and 4.6.2)
 	openmp  (distribuited with gcc)
	cuda    (tested with driver version 6.5 and runtime version 5.0)

### Compile
------------------------------------------------

To build Lyra2, type:
      make **OPTION** [**PARAMETERS**]()
 
where **OPTION** can be one of the following:
generic-x86-64                      For x86-64 Unix-like system, with gcc or similar
linux-x86-64-sse                    Linux x86-64, with SSE 
cygwin-x86-64                       Windows x86-64, Cygwin
cygwin-x86-64-sse                   Windows x86-64, Cygwin, with SSE
linux-x86-64-cuda                   Linux x86-64, with CUDA 
linux-x86-64-cuda-attack            Linux x86-64, attack using CUDA
 
where **PARAMETERS** can be:
      nCols = (number of columns)
      nThreads = (number of threads)
      nRoundsSponge = (number of Rounds performed for reduced sponge function [1 - 12]())
      bSponge = (number of sponge blocks, bitrate, 8 or 10 or 12)
      sponge = (0, 1 or 2) 0 means Blake2b, 1 means BlaMka and 2 means half-round BlaMka
 
-------------------------------------------------------------------------------------------
