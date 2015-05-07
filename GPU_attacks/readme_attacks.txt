CPU benchmarks:
The CPU benchmarks focused in legitm usage of the kdfs.

To obtain the medium execution time:
- We executed "n" times each derivation;
- With the parameters seted accordingly with parallelism and memory usage desired.

This results were used to compute the GPU/CPU ratio.
We used the PHC code for each algorithm and the fastest version (generally, the vectorized version).


All tests used:
- Intel(R) Xeon(R) CPU E5-2430 0 @ 2.20GHz
- Memory: 48264 MB
- gcc 4.9.2
- O.S.: Ubuntu 14.04.2 LTS

GPU attacks: 
Each attack uses "n" differents passwords to execute "n" parallel instances of the GPU kdf code.
With parallelism (p) inside the kdf code, the GPU will use n*p threads.
The password derivation time is the total test time divided by number of passwords tested.

To obtain the best GPU attack results we proceed in a two step methodology:
1. To get a performance panorama of GPU attack execution:
We executed a test with incremental values of passwords, memory, threads per block (multiples of 32) and paralelism.
The results shows the gpus performance with these parameters.
The best performance was obtained with blocks of 32 threads, what become our standard test size.

2. To check each algorithm performance for specific memory and parallelism usage:
We executed, "n" times, a incremental test:
- With 32 threads per block;
- Varying the number of password derivations until full GPU memory usage.
The result is a graph with total number of passwords tested per derivation medium time.
For each combination of memory and parallelism, the global minimum value was select to be used in the performance graph.


To simplify the job, we used a python program that compiles and execute each test.
The pseudo-code is as follows:

compile attack program with intended test parameters

for (1 to #Repetitions) do
	for (initial#Passwords to final#Passwords) do
            for (totalThreadsPerBlock to numeroThreadsPorBloco) do
                if ( GPU_geometry_is_ok) then
                        execute_attack
		end if
	    end for
    end for
end for

After all, we noted that executing the attack with 8 threads per block (warp), instead of the normal 32, the medium time per password derivation lowers more than 10%.
To the best results of the 32 threads per warp test, we executed again with 8 threads per block and 4 times more blocks.

All tests used:
GPU:
- GeForce GTX TITAN
- CUDA Driver Version / Runtime Version          7.0 / 7.0
- CUDA Capability Major/Minor version number:    3.5
- Total amount of global memory:                 6143 MBytes (6441730048 bytes)
- (14) Multiprocessors, (192) CUDA Cores/MP:     2688 CUDA Cores
CPU base system to GPU:
- Intel(R) Core(TM) i7-3820 CPU @ 3.60GHz
- Memory: 63978 MB 
- O.S.: openSUSE 13.2 "Harlequin"

For yescrypt, we ported both versions, the reference and the optmized.
All tests used the optmized version.
