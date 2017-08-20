## What is harness.py?

This is a script that allows you to:
1. Build several versions of Lyra2
2. Compute hash data for built versions

Afterwards, you can change Lyra2 source, rebuild it and see if the
hash values are still the same or not.

## How to install?

1. Clone the project first:
```
git clone git@github.com:leocalm/Lyra
cd Lyra/Lyra2
```

2. From inside `Lyra/Lyra2` setup a virtual environment with `python3`:

```
virtualenv -p /usr/bin/python3 lyra2-harness-venv3
source lyra2-harness-venv3/bin/activate
pip install -r requirements.txt
```

(to leave the virtual environment, type `deactivate`)

## How to use?

Initially you need to build as many Lyra2 executables as you care
about and then use those executables to compute as many hashes as you
think would be appropriate for testing.

Reasonable building defaults are already supplied in `harness.yml`:
 - 300+ combinations of the lyra executable under `matrix`
 - ~100 hash parameters under `data`

1. Build a few lyra instances (configured in `harness.yml`, see below):

```
./tests/harness.py build
```

2. Use those instances to compute some hashes:

```
./tests/harness.py compute
```

3. Now verify that self-testing succeds:

```
pytest ./test/test_lyra2_data_c.py
```

At this point, you can modify Lyra source code. Once you are done, change `build_path` in `harness.py` to some new value. (Example: if it was `../bin42`, make it `../bin84`), rebuild and run tests:

1. Rebuild lyra instances into new directory:

```
./tests/harness.py build
```

2. Test new instances against old hash values:

```
pytest ./test/test_lyra2_data_c.py
```

## Tips

You can speed things up by telling pytest to run tests in parallel:

```
pytest -n 4
```

You can also build just one new instance of Lyra and quickly see if it
works first. For that, you need to modify `matrix` in `harness.yml` to
look like this (for example):

```
matrix:
  option: generic-x86-64
  threads: 1
  columns:
    - 256
  sponge:
    - Blake2b
  rounds:
    - 1
  blocks:
    - 12
  bench: 0
```