#!/usr/bin/env python3

import os
import sys
import yaml
import subprocess
import itertools

from pathlib import Path


def to_list(x):
    return x if isinstance(x, list) else [x]

def make_lyra2(params):
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

    try:
        build_path = Path(params['build_path']).resolve()
    except KeyError:
        sys.exit('Please specify build_path')

    try:
        makefile_path = Path(params['makefile_path']).resolve()
    except KeyError:
        sys.exit('Please specify makefile_path')

    try:
        matrix = params['matrix']
    except KeyError:
        sys.exit('Please specify build matrix')

    try:
        option = to_list(matrix['option'])
    except KeyError:
        sys.exit('Please specify option')

    try:
        threads = to_list(matrix['threads'])
    except KeyError:
        sys.exit('Please specify threads')

    try:
        columns = to_list(matrix['columns'])
    except KeyError:
        sys.exit('Please specify columns')

    try:
        sponge = to_list(matrix['sponge'])
    except KeyError:
        sys.exit('Please specify sponge')

    try:
        rounds = to_list(matrix['rounds'])
    except KeyError:
        sys.exit('Please specify rounds')

    try:
        blocks = to_list(matrix['blocks'])
    except KeyError:
        sys.exit('Please specify blocks')

    try:
        bench = to_list(matrix['bench'])
    except KeyError:
        sys.exit('Please specify bench')

    try:
        CFLAGS = ' '.join(to_list(params['CFLAGS']))
    except KeyError:
        CFLAGS = ''

    for option, threads, columns, sponge, rounds, blocks, bench in itertools.product(
            option, threads, columns, sponge, rounds, blocks, bench
    ):

        name = 'lyra2-' + option
        name += '-threads-' + str(threads)
        name += '-columns-' + str(columns)
        name += '-sponge-' + str(sponge)
        name += '-rounds-' + str(rounds)
        name += '-blocks-' + str(blocks)

        parameters = 'parameters='
        parameters += ' -DnPARALLEL=' + str(threads)
        parameters += ' -DN_COLS=' + str(columns)
        parameters += ' -DSPONSE=' + str(sponge)
        parameters += ' -DRHO=' + str(rounds)
        parameters += ' -DBLOCK_LEN_INT64=' + str(blocks)
        parameters += ' -DBENCH=' + str(bench)

        process = subprocess.run([
            'make', option,
            'BINDIR=' + str(build_path),
            'BIN=' + name,
            parameters,
            'CFLAGS=' + CFLAGS,
            '--makefile', str(makefile_path),
            '--directory', str(makefile_path.parent),
        ])


if __name__ == '__main__':
    import yaml

    with open('lyra2.yml', 'r') as config:
        make_lyra2(yaml.load(config))

    # from argparse import ArgumentParser

    # parser = ArgumentParser(description="Friendly compilation frontend")

    # parser.add_argument(
    #     "option", default="generic-x86-64", choices=[
    #         "generic-x86-64", "linux-x86-64-sse",
    #         "cygwin-x86-64", "cygwin-x86-64-sse",
    #         "linux-x86-64-cuda", "linux-x86-64-cuda-attack",
    #         "clean"
    #     ], help="Compilation target for make"
    # )

    # parser.add_argument(
    #     "--mcost", type=int, default=256, choices=[
    #         16, 32, 64, 96, 128, 256, 512, 1024, 2048
    #     ], help="Number of columns, only use tested values"
    # )

    # parser.add_argument(
    #     "--nthreads", type=int, default=1,
    #     help="Number of threads to use, must be positive"
    # )

    # parser.add_argument(
    #     "--nrounds", type=int, default=1, choices=list(range(1, 13)),
    #     help="Number of rounds performed by reduced sponge function"
    # )

    # parser.add_argument(
    #     "--nblocks", type=int, default=12, choices=[8, 10, 12],
    #     help="Number of sponge blocks, bitrate"
    # )

    # parser.add_argument(
    #     "--sponge", type=int, default=1, choices=[0, 1, 2],
    #     help="Sponge function to use "\
    #     "(0 is Blake2b, 1 is BlaMka, 2 is half-round BlaMka)"
    # )

    # parser.add_argument(
    #     "--bench", type=bool, default=False,
    #     help="Executable with built-in benchmarking"
    # )

    # args = parser.parse_args()

    # if args.nthreads <= 0:
    #     raise RuntimeError(
    #         "--nthreads must be positive, was {}".format(args.nthreads)
    #     )

    # make_lyra2(
    #     option=args.option,
    #     nCols=args.mcost,
    #     nThreads=args.nthreads,
    #     nRoundsSponge=args.nrounds,
    #     bSponge=args.nblocks,
    #     sponge=args.sponge
    # )
