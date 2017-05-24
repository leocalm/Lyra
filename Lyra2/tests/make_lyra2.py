#!/usr/bin/env python3

import os
import subprocess

from pathlib import Path

class CompilerFlags:

    def __init__(cflags=None):
        self.cflags = {} if cflags is None else cflags

    def __str__(self):
        pass

def make_lyra2(
        makefile=None, option=None, bindir=None, binname=None,
        nCols=256, nThreads=1, nRoundsSponge=1, bSponge=1, sponge=1, bench=0,
        CFLAGS=None
):
    """
    Build Lyra2 using the existing makefile

    The provided makefile has a number of variables that can be
    configured before the build (i.e. number of columns/number of
    threads, etc.) This script automates the process of building
    various flavors of Lyra2 using that makefile.

    Documentation for many of the parameters can be found:
    1. Below in the if __name__ == '__main__' section
    2. In the original makefile
    3. In the implementation reference .pdf
    """

    if makefile is None:
        # Assume we are in Lyra2/tests and makefile is in Lyra2/src
        makefile = Path(__file__).resolve().parent.parent.joinpath(
            "src", "makefile"
        )

    if option is None:
        option = "generic-x86-64"

    if bindir is None:
        bindir = makefile.parent.parent.joinpath("bin")

    if binname is None:
        name = "lyra2-" + option
        name += "-cols-" + str(nCols)
        name += "-threads-" + str(nThreads)
        name += "-nrounds-" + str(nRoundsSponge)
        name += "-nblocks-" + str(bSponge)
        name += "-sponge-" + str(sponge)

        binname = bindir.joinpath(name)

    parameters="""parameters=\
    -DN_COLS={} -DnPARALLEL={} -DRHO={} -DBLOCK_LEN_INT64={} -DSPONGE={} -DBENCH={}\
    """.format(nCols, nThreads, nRoundsSponge, bSponge, sponge, bench)

    CFLAGS="""\
    -std=c99 -g -Wall -pedantic -O3 -msse2 \
    -ftree-vectorizer-verbose=1 -fopenmp \
    -funroll-loops -march=native -Ofast \
    -mprefer-avx128 -flto \
    """

    process = subprocess.run([
        "make", option,
        "BINDIR={}".format(bindir),
        "BIN={}".format(binname),
        parameters,
        "CFLAGS={}".format(CFLAGS),
        "--makefile", makefile,
        "--directory", makefile.parent,
    ])


if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Friendly compilation frontend")

    parser.add_argument(
        "option", default="generic-x86-64", choices=[
            "generic-x86-64", "linux-x86-64-sse",
            "cygwin-x86-64", "cygwin-x86-64-sse",
            "linux-x86-64-cuda", "linux-x86-64-cuda-attack",
            "clean"
        ], help="Compilation target for make"
    )

    parser.add_argument(
        "--mcost", type=int, default=256, choices=[
            16, 32, 64, 96, 128, 256, 512, 1024, 2048
        ], help="Number of columns, only use tested values"
    )

    parser.add_argument(
        "--nthreads", type=int, default=1,
        help="Number of threads to use, must be positive"
    )

    parser.add_argument(
        "--nrounds", type=int, default=1, choices=list(range(1, 13)),
        help="Number of rounds performed by reduced sponge function"
    )

    parser.add_argument(
        "--nblocks", type=int, default=12, choices=[8, 10, 12],
        help="Number of sponge blocks, bitrate"
    )

    parser.add_argument(
        "--sponge", type=int, default=1, choices=[0, 1, 2],
        help="Sponge function to use "\
        "(0 is Blake2b, 1 is BlaMka, 2 is half-round BlaMka)"
    )

    parser.add_argument(
        "--bench", type=bool, default=False,
        help="Executable with built-in benchmarking"
    )

    args = parser.parse_args()

    if args.nthreads <= 0:
        raise RuntimeError(
            "--nthreads must be positive, was {}".format(args.nthreads)
        )

    make_lyra2(
        option=args.option,
        nCols=args.mcost,
        nThreads=args.nthreads,
        nRoundsSponge=args.nrounds,
        bSponge=args.nblocks,
        sponge=args.sponge
    )
