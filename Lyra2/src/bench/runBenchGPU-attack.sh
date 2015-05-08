#!/bin/bash

#Change this values if you want attack Lyra2 with another parameters
#Lyra2 parameters
parallelism=4
t=1
rows=24
cols=1024
blocksSponge=12
sponge=0
rho=1

#attack parameters
totalPasswords=1024
passwordStep=32
passwords=$passwordStep     #start with
threadsPerBlock=32
sizeINT64=8

echo "Benchmarking Lyra2 (GPU attack)."
echo "Start time: "
date -u "+%d/%m/%Y %H:%M:%S"
echo " "

cd ..

memory=$(($rows * $cols * $blocksSponge * $sizeINT64))

make clean
make linux-x86-64-cuda-attack nCols=$cols bSponge=$blocksSponge sponge=$sponge nThreads=$parallelism nRoundsSponge=$rho bench=1

for i in 1 2 3 4 5 6
do
	while [ $passwords -le $totalPasswords ]
	do
		let totalBlocksToUse=passwords*parallelism/threadsPerBlock
                echo "CODE = T"$t"-COL"$cols"-ROW"$rows"-PAS"$passwords"-BLK"$totalBlocksToUse"-PAR"$parallelism"-TH"$threadsPerBlock"-MEM"$memory
                ../bin/Lyra2CUDAttack $t $rows --multPasswordCUDA $passwords $totalBlocksToUse $threadsPerBlock
		let passwords=passwords+passwordStep
	done
	let passwords=passwordStep
done    

echo "End time: "
date -u "+%d/%m/%Y %H:%M:%S"
