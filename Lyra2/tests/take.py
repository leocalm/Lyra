#!/usr/bin/env python

if __name__ == "__main__":
    import sys
    import yaml
    import random

    from pathlib import Path
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Take N hashes from data file")

    parser.add_argument(
        "N", default=100, type=int, help="the number of hashes to take"
    )
    parser.add_argument(
        '--seed', default=42, type=int, help='initialize the random generator'
    )
    parser.add_argument(
        "src", help="path to data.yml to take hashes from"
    )

    args = parser.parse_args()

    path = Path(args.src).resolve().parent

    src_fname = Path(args.src).resolve()
    dst_fname = Path(path, "data-" + str(args.N) + ".yml")

    N, entries = args.N, []
    with open(src_fname, "r") as src:
        data = [entry for entry in yaml.load_all(src)]

        if N > len(data):
            print("You've asked for " + N + " hash(es)")
            print("The provided data file only has " + len(data))

            sys.exit("Provided data file does not have enough data")

        random.seed(args.seed)
        entries = random.sample(data, N)

    if entries:
        yaml.dump_all(entries, open(dst_fname, "w"))
    else:
        sys.exit("something went wrong")
