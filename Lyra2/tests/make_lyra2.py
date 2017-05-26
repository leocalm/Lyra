#!/usr/bin/env python3

import os
import sys
import yaml
import subprocess
import itertools

from pathlib import Path

def to_list(x):
    return x if isinstance(x, list) else [x]

def unlist_values(dictionary):
    """
    Convert a dictionary into a generator of dictionaries

    Example: {key1: [value1, value2], key2: value3} will be converted
    to a generator that produces two dictionaries: {key1: value1,
    key2: value3} and {key1: value2, key2: value3}
    """
    for value in itertools.product(*map(to_list, dictionary.values())):
        yield dict(zip(dictionary, value))

def valid_lyra2_params_or_exit(params):
    try:
        build_path = Path(params['build_path'])
    except KeyError:
        sys.exit('Please specify build_path')

    try:
        makefile_path = Path(params['makefile_path'])
    except KeyError:
        sys.exit('Please specify makefile_path')

    try:
        valid = params['valid']
    except KeyError:
        sys.exit('Please specify valid')

    try:
        matrix = params['matrix']
    except KeyError:
        sys.exit('Please specify build matrix')

    try:
        option = to_list(matrix['option'])
    except KeyError:
        sys.exit('Please specify matrix: option:')

    try:
        voptions = to_list(valid['option'])
    except KeyError:
        sys.exit('Please specify valid: option:')

    for o in option:
        if o not in voptions:
            sys.exit('Option ' + o + ' is not valid')

    try:
        threads = to_list(matrix['threads'])
    except KeyError:
        sys.exit('Please specify matrix: threads:')

    try:
        vthreads = to_list(valid['threads'])
    except KeyError:
        sys.exit('Please specify valid: threads:')

    for t in threads:
        if t not in vthreads:
            sys.exit('Thread ' + t + ' is not valid')

    try:
        columns = to_list(matrix['columns'])
    except KeyError:
        sys.exit('Please specify matrix: columns:')

    try:
        vcolumns = to_list(valid['columns'])
    except KeyError:
        sys.exit('Please specify valid: columns:')

    for c in columns:
        if c not in columns:
            sys.exit('Columns ' + c + ' is not valid')

    try:
        sponge = to_list(matrix['sponge'])
    except KeyError:
        sys.exit('Please specify matrix: sponge:')

    try:
        vsponge = to_list(valid['sponge'])
    except KeyError:
        sys.exit('Please specify valid: sponge:')

    for s in sponge:
        if s not in vsponge:
            sys.exit('Sponge ' + s + ' is not valid')

    try:
        rounds = to_list(matrix['rounds'])
    except KeyError:
        sys.exit('Please specify rounds')

    try:
        vrounds = to_list(valid['rounds'])
    except KeyError:
        sys.exit('Please specify valid: rounds:')

    for r in rounds:
        if r not in vrounds:
            sys.exit('Rounds ' + r + ' is not valid')

    try:
        blocks = to_list(matrix['blocks'])
    except KeyError:
        sys.exit('Please specify blocks')

    try:
        vblocks = to_list(valid['blocks'])
    except KeyError:
        sys.exit('Please specify valid: blocks:')

    for b in blocks:
        if b not in vblocks:
            sys.exit('Blocks ' + b + ' is not valid')

    try:
        bench = to_list(matrix['bench'])
    except KeyError:
        sys.exit('Please specify matrix: bench:')

    try:
        vbench = to_list(valid['bench'])
    except KeyError:
        sys.exit('Please specify valid: bench:')

    for b in bench:
        if b not in vbench:
            sys.exit('Bench ' + b + ' is not valid')


def valid_lyra2_hashes_or_exit(params):
    valid_lyra2_params_or_exit(params)

    try:
        data = params['data']
    except KeyError:
        sys.exit('Please specify data:')

    try:
        pwd = data['pwd']
    except KeyError:
        sys.exit('Please specify data: pwd:')

    try:
        salt = data['salt']
    except KeyError:
        sys.exit('Please specify data: salt:')

    try:
        klen = data['klen']
    except KeyError:
        sys.exit('Please specify data: klen:')

    try:
        tcost = data['tcost']
    except KeyError:
        sys.exit('Please specify data: tcost:')

    try:
        mcost = data['mcost']
    except KeyError:
        sys.exit('Please specify data: mcost:')

def compose_lyra2_name(option, threads, columns, sponge, rounds, blocks):
    return \
        'lyra2-'    + option       + \
        '-threads-' + str(threads) + \
        '-columns-' + str(columns) + \
        '-sponge-'  + str(sponge)  + \
        '-rounds-'  + str(rounds)  + \
        '-blocks-'  + str(blocks)

def compose_sponge_name(sponge):
    sponge = '-'.join(sponge.lower().split(' '))

    if sponge == 'blake2b':
        return [sponge, 0]
    elif sponge == 'blamka':
        return [sponge, 1]
    elif sponge == 'half-round-blamka':
        return [sponge, 2]

def build_lyra2(params):
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

    valid_lyra2_params_or_exit(params)

    path = Path(__file__).parent

    build_path = Path(path, params['build_path']).resolve()
    makefile_path = Path(path, params['makefile_path']).resolve()

    try:
        CFLAGS = ' '.join(to_list(params['CFLAGS']))
    except KeyError:
        CFLAGS = ''

    for matrix in unlist_values(params['matrix']):
        option = matrix['option']

        threads = matrix['threads']
        columns = matrix['columns']

        sponge = matrix['sponge']
        rounds = matrix['rounds']
        blocks = matrix['blocks']

        bench = matrix['bench']

        [sponge, sponge_idx] = compose_sponge_name(sponge)

        name = compose_lyra2_name(
            option, threads, columns, sponge, rounds, blocks
        )

        parameters = 'parameters='
        parameters += ' -DnPARALLEL=' + str(threads)
        parameters += ' -DN_COLS=' + str(columns)
        parameters += ' -DSPONGE=' + str(sponge_idx)
        parameters += ' -DRHO=' + str(rounds)
        parameters += ' -DBLOCK_LEN_INT64=' + str(blocks)
        parameters += ' -DBENCH=' + str(bench)

        print('Trying to call make with these:')
        print(makefile_path, makefile_path.parent)

        process = subprocess.run([
            'make', option,
            'BINDIR=' + str(build_path),
            'BIN=' + str(build_path.joinpath(name)),
            parameters,
            'CFLAGS=' + CFLAGS,
            '--makefile', str(makefile_path),
            '--directory', str(makefile_path.parent),
        ])

def compute_data(params):
    valid_lyra2_hashes_or_exit(params)

    path = Path(__file__).parent

    build_path = Path(path, params['build_path']).resolve()
    data_path = Path(path, params['data_path']).resolve()

    for matrix in unlist_values(params['matrix']):
        option = matrix['option']

        threads = matrix['threads']
        columns = matrix['columns']

        sponge = matrix['sponge']
        rounds = matrix['rounds']
        blocks = matrix['blocks']

        bench = matrix['bench']

        [sponge, sponge_idx] = compose_sponge_name(sponge)

        name = build_path.joinpath(compose_lyra2_name(
            option, threads, columns, sponge, rounds, blocks
        ))

        for data in unlist_values(params['data']):
            pwd = str(data['pwd'])
            salt = str(data['salt'])
            klen = str(data['klen'])
            tcost = str(data['tcost'])
            mcost = str(data['mcost'])

            process = subprocess.run([name, pwd, salt, klen, tcost, mcost])

            print(process)

if __name__ == '__main__':
    import yaml
    from argparse import ArgumentParser

    path = Path(__file__).resolve().parent

    parser = ArgumentParser(description='Friendly lyra2 frontend')

    parser.add_argument(
        '--yaml', default=path.joinpath('lyra2.yml'),
        help='set location of settings file'
    )

    subparsers = parser.add_subparsers(
        dest='cmd', help='available commands/stages'
    )
    subparsers.required = True

    build_parser = subparsers.add_parser(
        'build', help='generate lyra2 executables'
    )

    compute_parser = subparsers.add_parser(
        'compute', help='generate hash values'
    )

    args = parser.parse_args()

    with open(args.yaml, 'r') as config:
        if args.cmd == 'build':
            build_lyra2(yaml.load(config))
        elif args.cmd == 'compute':
            compute_data(yaml.load(config))
        else:
            sys.exit('Unknown args.cmd')
