#
# This file is part of Lyra, a password hashing scheme
# Copyright (c) 2013-2014 by Lyra Project - - <http://www.lyra-kdf.net/>
#


CC?=gcc
CFLAGS=-std=c99 -Wall -pedantic -O3

BIN=../bin/Lyra
nCols=64

SSEDIR=sse/

default:
	
	@echo " "
	@echo "To build Lyra, type:"
	@echo "      make OPTION [nCols=(number of columns, default 64)]"
	@echo " "
	@echo "where OPTION can be one of the following:"
	@echo "generic-x86-64                      For x86-64 Unix-like system, with gcc (i.e., Linux, FreeBSD, Mac OS, etc.)"
	@echo "linux-x86-64-sse2                   Linux x86-64, with SSE2 (beta version, needs improvement)"
	@echo "windows-x86-64                      Windows x86-64, Cygwin"
	@echo "win-cygwin-x86-64-sse2              Windows x86-64, Cygwin, with SSE2 (beta version, needs improvement)"
	@echo " "
	@echo "Note:"
	@echo "Lyra was tested with nCols=16, nCols=32, nCols=64, nCols=96, and nCols=128 "
	@echo " "


generic-x86-64:	    Lyra.c Sponge.c Main.c Lyra.h Sponge.h
	$(CC) $(CFLAGS) Sponge.c Lyra.c Main.c -o $(BIN) -DN_COLS=$(nCols) -O3
	@echo "Build completed, binaries in $(BIN)"

linux-x86-64-sse2:	$(SSEDIR)Lyra.c $(SSEDIR)Sponge.c Main.c $(SSEDIR)Lyra.h $(SSEDIR)Sponge.h
	$(CC) $(CFLAGS) $(SSEDIR)Sponge.c $(SSEDIR)Lyra.c Main.c -o $(BIN) -DN_COLS=$(nCols) -O3
	@echo "Build completed, binaries in $(BIN)"
	
windows-x86-64:	    Lyra.c Sponge.c Main.c Lyra.h Sponge.h
	$(CC) $(CFLAGS) Sponge.c Lyra.c Main.c -o $(BIN) -DN_COLS=$(nCols) -O3
	@echo "Build completed, binaries in $(BIN)"

win-cygwin-x86-64-sse2:	$(SSEDIR)Lyra.c $(SSEDIR)Sponge.c Main.c $(SSEDIR)Lyra.h $(SSEDIR)Sponge.h
	$(CC) $(CFLAGS) $(SSEDIR)Sponge.c $(SSEDIR)Lyra.c Main.c -o $(BIN) -DN_COLS=$(nCols) -O3
	@echo "Build completed, binaries in $(BIN)"
	
clean:
	rm -rf *.o $(BIN)


