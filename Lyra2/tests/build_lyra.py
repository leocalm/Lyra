import os
import subprocess

from pathlib import Path

def build_lyra2(makefile=None, option=None, bindir=None, binname=None):

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
        binname = bindir.joinpath("lyra2-" + option)

    print(makefile)

    env = os.environ
    env.update({"BINDIR" : str(bindir), "BIN" : str(binname)})

    process = subprocess.run([
        "make", option,
        "BINDIR={}".format(bindir),
        "BIN={}".format(binname),
        "--makefile", makefile,
        "--directory", makefile.parent,
    ])

    print(process.args)


if __name__ == "__main__":
    build_lyra2()
