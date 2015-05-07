# Implementation of the GPU Attack to Yescrypt Password Hashing Scheme (PHS).
# Based on the Yescrypt Reference Implementation by Alexander Peslyak (Copyright 2013-2015)
# and Colin Percival (Copyright 2009).
#
# Author: The Lyra2 PHC team (http://www.lyra-kdf.net/) -- 2015.
#
# This software is hereby placed in the public domain.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Copyright 2013,2014 Alexander Peslyak
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

CC = gcc
LD = $(CC)
RM = rm -f
OMPFLAGS = -fopenmp
OMPFLAGS_MAYBE = $(OMPFLAGS)
CFLAGS = -Wall -march=native -O2 -funroll-loops -fomit-frame-pointer $(OMPFLAGS_MAYBE)
LDFLAGS = -s $(OMPFLAGS_MAYBE)

NVCC=nvcc
BINCUDATTACK=attackYescryptCUDA

# CUDA Flags
PTX = 35  # Must suits the GPU board used.
SM = 35   # Must suits the GPU board used.

OPT = linux-x86-64-cuda-attack-64bits
PROJ = linux-x86-64-cuda-attack
OBJS_REF = yescrypt-ref.o
OBJS_PHC_S = $(OBJS_REF) sha256.o  phc-testSimplificado.o
OBJS_RM = yescrypt-*.o

PAR=1

all: $(OPT)

check: tests phc-test
	@echo 'Running main tests'
	@time ./tests | tee TESTS-OUT
	@diff -U0 TESTS-OK TESTS-OUT && echo PASSED || echo FAILED
	@if [ -e PHC-TEST-OK ]; then \
		echo 'Running PHC tests'; \
		time ./phc-test > PHC-TEST-OUT; \
		cmp PHC-TEST-OK PHC-TEST-OUT && echo PASSED || echo FAILED; \
	fi


#linux-x86-64-cuda-attack:  attackYescryptCUDA.cu sha256.cu yescrypt-ref.cu sha256.h sysendian.h yescrypt.h gpucommon.h
#	$(NVCC) attackYescryptCUDA.cu yescrypt-ref.cu sha256.cu -O3 -o $(BINCUDATTACK) -lcudart -DTEST -DYESCRYPT_P=$(PAR) -arch=compute_$(PTX) -code=sm_$(SM)
	# -arch=sm_$(SM)
	# -arch=compute_$(PTX)  -code=sm_$(SM)
#	@echo "Build completed."


linux-x86-64-cuda-attack-64bits:  attackYescryptCUDA.cu sha256.cu yescrypt-opt.cu sha256.h sysendian.h yescrypt.h gpucommon.h
	$(NVCC) attackYescryptCUDA.cu yescrypt-opt.cu sha256.cu -O3 -o $(BINCUDATTACK) -lcudart -DTEST -DYESCRYPT_P=$(PAR) -arch=compute_$(PTX) -code=sm_$(SM)
	@echo "Build completed."

#.c.o:
#	$(CC) -c $(CFLAGS) $*.c

clean:
	$(RM) $(PROJ)
	$(RM) $(OBJS_REF) $(OBJS_PHC_S)
	$(RM) $(OBJS_RM)
	$(RM) $(BINCUDA)
	$(RM) $(BINCUDATTACK)

