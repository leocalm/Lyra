import os
import subprocess

from pathlib import Path

def build_lyra2(
        makefile=None, option=None, bindir=None, binname=None,
        nCols=256, nThreads=1, nRoundsSponge=1, bSponge=1, sponge=1, bench=0,
        CFLAGS=None
):

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

    print(process.args)


if __name__ == "__main__":
    build_lyra2(nCols=128)
