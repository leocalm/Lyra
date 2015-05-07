# Test for the best results obtained on our benchmarks

cd yescryptCUDA/

# benchmarking yescrypt

make PAR=1
# 256 KB
./attackYescryptCUDA 0 5 --multPasswordCUDA 3456 432 8
./attackYescryptCUDA 2 5 --multPasswordCUDA 3520 440 8

./attackYescryptCUDA 0 5 --multPasswordCUDA 3456 108 32
./attackYescryptCUDA 2 5 --multPasswordCUDA 3520 110 32

# 512 KB
./attackYescryptCUDA 0 6 --multPasswordCUDA 3584 448 8
./attackYescryptCUDA 2 6 --multPasswordCUDA 3584 448 8

./attackYescryptCUDA 0 6 --multPasswordCUDA 3584 112 32
./attackYescryptCUDA 2 6 --multPasswordCUDA 3584 112 32

# 1 MB
./attackYescryptCUDA 0 7 --multPasswordCUDA 3520 440 8
./attackYescryptCUDA 2 7 --multPasswordCUDA 3584 448 8

./attackYescryptCUDA 0 7 --multPasswordCUDA 3520 110 32
./attackYescryptCUDA 2 7 --multPasswordCUDA 3584 112 32

# 2 MB
./attackYescryptCUDA 0 8 --multPasswordCUDA 2880 360 8
./attackYescryptCUDA 2 8 --multPasswordCUDA 2912 364 8

./attackYescryptCUDA 0 8 --multPasswordCUDA 2880 90 32
./attackYescryptCUDA 2 8 --multPasswordCUDA 2912 91 32


make PAR=2
# 256 KB
./attackYescryptCUDA 0 5 --multPasswordCUDA 1792 224 8
./attackYescryptCUDA 2 5 --multPasswordCUDA 1760 220 8

./attackYescryptCUDA 0 5 --multPasswordCUDA 1792 56 32
./attackYescryptCUDA 2 5 --multPasswordCUDA 1760 55 32

# 512 KB
./attackYescryptCUDA 0 6 --multPasswordCUDA 1760 220 8
./attackYescryptCUDA 2 6 --multPasswordCUDA 1792 224 8

./attackYescryptCUDA 0 6 --multPasswordCUDA 1760 55 32
./attackYescryptCUDA 2 6 --multPasswordCUDA 1792 56 32

# 1 MB
./attackYescryptCUDA 0 7 --multPasswordCUDA 1760 220 8
./attackYescryptCUDA 2 7 --multPasswordCUDA 1760 220 8

./attackYescryptCUDA 0 7 --multPasswordCUDA 1760 55 32
./attackYescryptCUDA 2 7 --multPasswordCUDA 1760 55 32

# 2 MB
./attackYescryptCUDA 0 8 --multPasswordCUDA 1792 224 8
./attackYescryptCUDA 2 8 --multPasswordCUDA 1760 220 8

./attackYescryptCUDA 0 8 --multPasswordCUDA 1792 56 32
./attackYescryptCUDA 2 8 --multPasswordCUDA 1760 55 32


make PAR=4
# 256 KB
./attackYescryptCUDA 0 5 --multPasswordCUDA 15904 4988 8
./attackYescryptCUDA 2 5 --multPasswordCUDA 896 112 8

./attackYescryptCUDA 0 5 --multPasswordCUDA 15904 497 32
./attackYescryptCUDA 2 5 --multPasswordCUDA 896 28 32

# 512 KB
./attackYescryptCUDA 0 6 --multPasswordCUDA 896 112 8
./attackYescryptCUDA 2 6 --multPasswordCUDA 896 112 8

./attackYescryptCUDA 0 6 --multPasswordCUDA 896 28 32
./attackYescryptCUDA 2 6 --multPasswordCUDA 896 28 32

# 1 MB
./attackYescryptCUDA 0 7 --multPasswordCUDA 896 112 8
./attackYescryptCUDA 2 7 --multPasswordCUDA 896 112 8

./attackYescryptCUDA 0 7 --multPasswordCUDA 896 28 32
./attackYescryptCUDA 2 7 --multPasswordCUDA 896 28 32

# 2 MB
./attackYescryptCUDA 0 8 --multPasswordCUDA 896 112 8 
./attackYescryptCUDA 2 8 --multPasswordCUDA 896 112 8

./attackYescryptCUDA 0 8 --multPasswordCUDA 896 28 32
./attackYescryptCUDA 2 8 --multPasswordCUDA 896 28 32


# benching Lyra2

cd ../../Lyra2/src/

# nTreads=1
# 256 KB (nCols=128)
make linux-x86-64-cuda-attack  nThreads=1 nCols=128
../bin/Lyra2CUDAttack 1 24 --multPasswordCUDA 3456 432 8
../bin/Lyra2CUDAttack 1 24 --multPasswordCUDA 3456 108 32

# 512 KB (nCols=128)
../bin/Lyra2CUDAttack 1 48 --multPasswordCUDA 1792 104 8
../bin/Lyra2CUDAttack 1 48 --multPasswordCUDA 1792 56 32

# 1 MB (nCols=128)
../bin/Lyra2CUDAttack 1 96 --multPasswordCUDA 1312 204 8
../bin/Lyra2CUDAttack 1 96 --multPasswordCUDA 1312 51 32

# 2 MB (nCols=128)
../bin/Lyra2CUDAttack 1 192 --multPasswordCUDA 896 112 8
../bin/Lyra2CUDAttack 1 192 --multPasswordCUDA 896 28 32

# 256 KB (nCols=256)
make linux-x86-64-cuda-attack  nThreads=1 nCols=256
../bin/Lyra2CUDAttack 1 12 --multPasswordCUDA 3328 840 8
../bin/Lyra2CUDAttack 1 12 --multPasswordCUDA 3328 105 32

# 512 KB (nCols=256)
../bin/Lyra2CUDAttack 1 24 --multPasswordCUDA 1024 128 8
../bin/Lyra2CUDAttack 1 24 --multPasswordCUDA 1024 32 32

# 1 MB (nCols=256)
../bin/Lyra2CUDAttack 1 48 --multPasswordCUDA 1760 220 8
../bin/Lyra2CUDAttack 1 48 --multPasswordCUDA 1760 55 32

# 2 MB (nCols=256)
../bin/Lyra2CUDAttack 1 96 --multPasswordCUDA 896 112 8
../bin/Lyra2CUDAttack 1 96 --multPasswordCUDA 896 28 32


# nTreads=2
# 256 KB (nCols=128)
make linux-x86-64-cuda-attack  nThreads=2 nCols=128
../bin/Lyra2CUDAttack 1 24 --multPasswordCUDA 1760 440 8
../bin/Lyra2CUDAttack 1 24 --multPasswordCUDA 1760 110 32

# 512 KB (nCols=128)
../bin/Lyra2CUDAttack 1 48 --multPasswordCUDA 1760 440 8
../bin/Lyra2CUDAttack 1 48 --multPasswordCUDA 1760 110 32

# 1 MB (nCols=128)
../bin/Lyra2CUDAttack 1 96 --multPasswordCUDA 896 224 8
../bin/Lyra2CUDAttack 1 96 --multPasswordCUDA 896 56 32

# 2 MB (nCols=128)
../bin/Lyra2CUDAttack 1 192 --multPasswordCUDA 672 168 8
../bin/Lyra2CUDAttack 1 192 --multPasswordCUDA 672 42 32

# 256 KB (nCols=256)
make linux-x86-64-cuda-attack  nThreads=2 nCols=256
../bin/Lyra2CUDAttack 1 12 --multPasswordCUDA 1792 448 8
../bin/Lyra2CUDAttack 1 12 --multPasswordCUDA 1792 112 32

# 512 KB (nCols=256)
../bin/Lyra2CUDAttack 1 24 --multPasswordCUDA 1760 440 8
../bin/Lyra2CUDAttack 1 24 --multPasswordCUDA 1760 110 32

# 1 MB (nCols=256)
../bin/Lyra2CUDAttack 1 48 --multPasswordCUDA 896 224 8
../bin/Lyra2CUDAttack 1 48 --multPasswordCUDA 896 56 32

# 2 MB (nCols=256)
../bin/Lyra2CUDAttack 1 96 --multPasswordCUDA 896 224 8
../bin/Lyra2CUDAttack 1 96 --multPasswordCUDA 896 56 32


# nTreads=4
# 256 KB (nCols=128)
make linux-x86-64-cuda-attack  nThreads=4 nCols=128
../bin/Lyra2CUDAttack 1 24 --multPasswordCUDA 14432 7216 8
../bin/Lyra2CUDAttack 1 24 --multPasswordCUDA 14432 1804 32

# 512 KB (nCols=128)
../bin/Lyra2CUDAttack 1 48 --multPasswordCUDA 896 448 8
../bin/Lyra2CUDAttack 1 48 --multPasswordCUDA 896 112 32

# 1 MB (nCols=128)
../bin/Lyra2CUDAttack 1 96 --multPasswordCUDA 864 432 8
../bin/Lyra2CUDAttack 1 96 --multPasswordCUDA 864 108 32

# 2 MB (nCols=128)
../bin/Lyra2CUDAttack 1 192 --multPasswordCUDA 448 224 8
../bin/Lyra2CUDAttack 1 192 --multPasswordCUDA 448 56 32

# 512 KB (nCols=256)
make linux-x86-64-cuda-attack  nThreads=4 nCols=256
../bin/Lyra2CUDAttack 1 24 --multPasswordCUDA 1024 512 8
../bin/Lyra2CUDAttack 1 24 --multPasswordCUDA 1024 128 32

# 1 MB (nCols=256)
../bin/Lyra2CUDAttack 1 48 --multPasswordCUDA 896 448 8
../bin/Lyra2CUDAttack 1 48 --multPasswordCUDA 896 112 32

# 2 MB (nCols=256)
../bin/Lyra2CUDAttack 1 96 --multPasswordCUDA 448 224 8
../bin/Lyra2CUDAttack 1 96 --multPasswordCUDA 448 56 32