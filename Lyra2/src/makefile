#
# This file is part of Lyra2, a password hashing scheme
# Copyright (c) 2013-2015 by Lyra2 Project -- <http://www.lyra2.net/>
#

CC?=gcc
NVCC=nvcc

CFLAGS=-std=c99 -Wall -pedantic -O3 -msse2 -ftree-vectorizer-verbose=1 -fopenmp -funroll-loops -march=native -Ofast -mprefer-avx128 -flto 

BINDIR=../bin
CUDADIR=cuda/
SSEDIR=sse/
BIN=$(BINDIR)/Lyra2
BINCUDA=$(BINDIR)/Lyra2CUDA
BINCUDATTACK=$(BINDIR)/Lyra2CUDAttack

nCols=256
nThreads=2
nRoundsSponge=1
bSponge=12
sponge=1
bench=0

parameters=-DN_COLS=$(nCols)  -DnPARALLEL=$(nThreads) -DRHO=$(nRoundsSponge) -DBLOCK_LEN_INT64=$(bSponge) -DSPONGE=$(sponge) -DBENCH=$(bench)
cudaparams=-arch=compute_$(PTX)  -code=sm_$(SM)

# CUDA Flags
PTX = 35  # Must suits the GPU board used.
SM = 35   # Must suits the GPU board used.

default:
	@echo " "
	@echo "To build Lyra2, type:"
	@echo "      make OPTION [PARAMETERS]"
	@echo " "
	@echo "where OPTION can be one of the following:"
	@echo "generic-x86-64                      For x86-64 Unix-like system, with gcc or similar (i.e., Linux, FreeBSD, Mac OS, etc.)"
	@echo "linux-x86-64-sse                    Linux x86-64, with SSE (beta version, needs improvement)"
	@echo "cygwin-x86-64                       Windows x86-64, Cygwin"
	@echo "cygwin-x86-64-sse                   Windows x86-64, Cygwin, with SSE (beta version, needs improvement)"
	@echo "linux-x86-64-cuda                   Linux x86-64, with CUDA (beta version, needs improvement)"
	@echo "linux-x86-64-cuda-attack            Linux x86-64, attack using CUDA (beta version, needs improvement)"
	@echo " "
	@echo "where PARAMETERS can be:"
	@echo "      nCols = (number of columns, default is 256)"
	@echo "      nThreads = (number of threads, default is 2)"
	@echo "      nRoundsSponge = (number of Rounds performed for reduced sponge function [1 - 12], default is 1)"
	@echo "      bSponge = (number of sponge blocks, bitrate, 8 or 10 or 12, default is 12)"
	@echo "      sponge = (0, 1 or 2, default is 1) 0 means Blake2b, 1 means BlaMka and 2 means half-round BlaMka"
	@echo " "
	@echo "Notes:"
	@echo "Lyra2 was tested with nCols=16, 32, 64, 96, 128, 256, 512, 1024 and 2046"
	@echo "This implementation is known to have issues for large memory usage. The maximum tested memory usage was 1.6 GB "
	@echo " "
	@echo "***When using OpenMP 3.1, execute 'export GOMP_CPU_AFFINITY=0,2,4,6,1,3,5,7' to define affinity in parallel version of Lyra2! (verify computer architecture!!)***"
	@echo "***When using OpenMP 4, execute 'export OMP_PLACES=CORES' to define affinity in parallel version of Lyra2! ***"


makeTests=nThreadsTest nRoundsSpongeTest bSpongeTest spongeTest

nThreadsError=[nThreads error] The "nThreads" must be a positive number. For more information see the Reference Guide
nRoundsSpongeError=[nRoundsSponge error] The "nRoundsSponge" must be a value between 1 and 12 (inclusive). For more information see the Reference Guide
bSpongeTestError=[bSponge error] The "bSponge" must be: 8, 10 or 12. For more information see the Reference Guide
spongeTestError=[Sponge error] The "sponge" must be: 0, 1 or 2. For more information see the Reference Guide

nThreadsTest:
ifeq "$(findstring -,$(nThreads))" ""
else
	$(error $(nThreadsError))
endif

nRoundsSpongeTest:
ifeq ($(nRoundsSponge),$(filter $(nRoundsSponge),1 2 3 4 5 6 7 8 9 10 11 12))
else
	$(error $(nRoundsSpongeError))
endif

bSpongeTest: 
ifeq ($(bSponge),$(filter $(bSponge),8 10 12))
else
	$(error $(bSpongeTestError))
endif

spongeTest: 
ifeq ($(sponge),$(filter $(sponge),0 1 2))
else
	$(error $(spongeTestError))
endif

generic-x86-64:	    Lyra2.c Sponge.c Main.c Lyra2.h Sponge.h $(makeTests)
	mkdir -p $(BINDIR)	
	$(CC) $(CFLAGS) Sponge.c Lyra2.c Main.c -o $(BIN) $(parameters)
	@echo "Build completed, binaries in $(BIN)"

linux-x86-64-sse:	$(SSEDIR)Lyra2.c $(SSEDIR)Sponge.c Main.c $(SSEDIR)Lyra2.h $(SSEDIR)Sponge.h $(makeTests)
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(SSEDIR)Sponge.c $(SSEDIR)Lyra2.c Main.c -o $(BIN) $(parameters)
	@echo "Build completed, binaries in $(BIN)"
cygwin-x86-64:	    generic-x86-64

cygwin-x86-64-sse:	linux-x86-64-sse
linux-x86-64-cuda:  $(CUDADIR)Lyra2.cu $(CUDADIR)Sponge.cu $(CUDADIR)Main.cu $(CUDADIR)Lyra2.h $(CUDADIR)Sponge.h $(makeTests)
	mkdir -p $(BINDIR)
	$(NVCC) $(CUDADIR)Lyra2.cu $(CUDADIR)Sponge.cu $(CUDADIR)Main.cu -O3 -o $(BINCUDA) -lcudart $(parameters)  -arch=compute_$(PTX)  -code=sm_$(SM)
	@echo "Build completed, binaries in $(BINCUDA)"

linux-x86-64-cuda-attack:  $(CUDADIR)attackLyra2.cu $(CUDADIR)attackSponge.cu $(CUDADIR)attackMain.cu $(CUDADIR)attackLyra2.h $(CUDADIR)attackSponge.h
	mkdir -p $(BINDIR)
	$(NVCC) $(CUDADIR)attackLyra2.cu $(CUDADIR)attackSponge.cu $(CUDADIR)attackMain.cu -O3 -o $(BINCUDATTACK) -lcudart $(parameters) -arch=compute_$(PTX)  -code=sm_$(SM)
	@echo "Build completed, binaries in $(BINCUDATTACK)"
clean:
	rm -rf *.o $(BIN) $(BINCUDA) $(BINDIR)


