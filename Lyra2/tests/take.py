#!/usr/bin/env python

if __name__ == "__main__":
    import yaml
    from pathlib import Path
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Take N hashes from data file")

    parser.add_argument(
        "N", default=100, type=int, help="the number of hashes to take"
    )
    parser.add_argument(
        "src", help="path to data.yml to take hashes from"
    )

    args = parser.parse_args()

    path = Path(args.src).resolve().parent

    src_fname = Path(args.src).resolve()
    dst_fname = Path(path, "data-" + str(args.N) + ".yml")

    entries = []
    with open(src_fname, "r") as src:
        for i, entry in enumerate(yaml.load_all(src)):
            if i == args.N:
                break

            entries.append(entry)

    yaml.dump_all(entries, open(dst_fname, "w"))
    
