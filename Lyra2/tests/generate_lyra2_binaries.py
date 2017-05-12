#!/usr/bin/env python3

from itertools import product

from build_lyra2 import build_lyra2

if __name__ == "__main__":
    options  = ["generic-x86-64"]
    mcosts   = [16, 96, 1024]
    nthreads = [1]
    nrounds  = [1, 12]
    nblocks  = [8, 10, 12]
    sponges  = [0, 1, 2]

    for option, mcost, nthread, nround, nblock, sponge in product(
            options, mcosts, nthreads, nrounds, nblocks, sponges
    ):
        build_lyra2(
            option=option,
            nCols=mcost,
            nThreads=nthread,
            nRoundsSponge=nround,
            bSponge=nblock,
            sponge=sponge
        )

    
