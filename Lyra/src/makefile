#
# This file is part of Lyra, a password hashing scheme
# Copyright (c) 2013-2014 by Lyra Project - - <http://www.lyra-kdf.net/>
#


CC?=gcc
CFLAGS=-std=c99 -Wall -pedantic -O3

BINDIR=../bin
BIN=$(BINDIR)/Lyra
nCols=64
bSponge=64
nBlocks=8

SSEDIR=sse/

ifeq ($(bSponge), 64)
	nBlocks=8
else
ifeq ($(bSponge), 512)
	nBlocks=8
else
ifeq ($(bSponge), 80)
	nBlocks=10
else
ifeq ($(bSponge), 640)
	nBlocks=10
else
ifeq ($(bSponge), 96)
	nBlocks=12	
else
ifeq ($(bSponge), 768)
	nBlocks=12	
endif
endif
endif
endif
endif
endif

default:
	
	@echo " "
	@echo "To build Lyra, type:"
	@echo "      make OPTION [nCols=(number of columns, default 64)] [bSponge=(number of bytes in each column, accepted values: 64, 80, 96. Default 64)]"
	@echo " "
	@echo "where OPTION can be one of the following:"
	@echo "generic-x86-64                      For x86-64 Unix-like system, with gcc (i.e., Linux, FreeBSD, Mac OS, etc.)"
	@echo "windows-x86-64                      Windows x86-64, Cygwin"
	@echo " "
	@echo "Note:"
	@echo "Lyra was tested with nCols=16, nCols=32, nCols=64, nCols=96 and nCols=128 and bSponge=64 "
	@echo " "


generic-x86-64:	    Lyra.c Sponge.c Main.c Lyra.h Sponge.h
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) Sponge.c Lyra.c Main.c -o $(BIN) -DN_COLS=$(nCols) -DBLOCK_LEN_INT64=$(nBlocks)
	@echo "Build completed, binaries in $(BIN)"

windows-x86-64:	    Lyra.c Sponge.c Main.c Lyra.h Sponge.h
	mkdir -p $(BINDIR)		
	$(CC) $(CFLAGS) Sponge.c Lyra.c Main.c -o $(BIN) -DN_COLS=$(nCols) -DBLOCK_LEN_INT64=$(nBlocks)
	@echo "Build completed, binaries in $(BIN)"

clean:
	rm -rf *.o $(BIN) $(BINDIR)


