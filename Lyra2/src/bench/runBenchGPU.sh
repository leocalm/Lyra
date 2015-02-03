#!/bin/bash

#Change this values if you want benchmark Lyra2 with another parameters
#Lyra2 parameters
cols=256
blocksSponge=12
kLen=64
rho=1

echo "Benchmarking Lyra2 (GPU oriented) with nCols = $cols, with T and R variable."
echo "Start time: "
date -u "+%d/%m/%Y %H:%M:%S"
echo " "

cd ..
for sponge in 0 1 2   # 0 = Blake2     1 = BlaMka       2 = half-round BlaMka
do
    for parallelism in 1 2 4
    do
        make clean
        make linux-x86-64-cuda nCols=$cols bSponge=$blocksSponge sponge=$sponge nThreads=$parallelism nRoundsSponge=$rho bench=1
		
        #Due to the driver, first execution is slower.
        #Then must be ignored.
        ../bin/Lyra2CUDA Lyra2Sponge saltsaltsaltsalt 32 1 32
		
        for t in 1 2 3 4 5 6 7
        do
                for r in 64 128 256 512 1024 2048 4096 8192 16384
                do
                        for i in 1 2 3 4 5 6
                        do
                                ../bin/Lyra2CUDA Lyra2Sponge saltsaltsaltsalt $kLen $t $r  
                        done		
                done
        done
    done
done

echo "End time: "
date -u "+%d/%m/%Y %H:%M:%S"
