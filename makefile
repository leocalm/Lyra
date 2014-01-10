CC?=gcc
CFLAGS=-std=c99 -Wall -pedantic -O3 -lm

all:		Lyra

Lyra:	Lyra.c
		$(CC) Lyra.c Sponge.c Main.c -o $@ $(CFLAGS)
		
clean:		
		rm -rf *.o Lyra
