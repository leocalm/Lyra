#! /usr/bin/env python
#
# This file is part of Lyra2, a password hashing scheme
# Copyright (c) 2013-2015 by Lyra2 Project -- <http://www.lyra2.net/>
#
# Script used only to make the outputs of "runBenchGPU-attack" friendlier.
#
import sys

class measureAttack:
    def __init__ (self):
        self.code = ""
        self.t = 0
        self.r = 0
        self.c = 0
        self.parallelism = 0
        self.sponge = ""
        self.memory = 0
        self.measures = []
        self.average = 0.0
        self.passwords = 0
        self.threads = 0
        self.cudaBlockSize = 0
        self.cudaGridSize = 0
        
    def calcAverage(self):
        self.average = 0.0
        for m in self.measures:
            self.average = self.average + float(m)
        self.average = self.average / len(self.measures)
        
    def toString(self):
        self.calcAverage()
        return ( str(self.t) + '|' + str(self.r) + '|' + str(self.c) + '|' + str(self.parallelism) + '|' + str(self.sponge) + '|' + str(self.memory).split(' ')[1].strip() + '|' + str(round(self.average, 2) ) + '|' + str(self.passwords) + '|' + str(self.threads) + '|' + str(self.cudaBlockSize) + '|' + str(self.cudaGridSize) )
            
def main(argv=None):
    if(len(sys.argv) != 2):
        print('Usage: ./parser.py fileName')
    else:
        f = open(sys.argv[1])
        
    line = f.readline()
    
    mList = []
    
    m = measureAttack()
    print ("T | R | C | Parallelism | Sponge | Memory | Execution Time (us) | passwords | threads | cudaBlockSize | cudaGridSize |")
    while line != '':
            line = f.readline() 
            
            #CODE = T1-COL4-ROW6144-PAS32-BLK2-PAR2-TH64-MEM2359296-O0
            if 'CODE' in line:                      #Data block start
                errorFLAG = False
                code = line.split("=")[1].strip()
                m.code = code
            if 'Total time cost:' in line:          
                errorFLAG = False
                m.t = int(line.split(':')[1])
            if 'Total number of cols:' in line:
                m.c = int(line.split(':')[1])
            if 'Total number of rows:' in line:
                m.r = int(line.split(':')[1])
            if 'Total number of password:' in line:
                m.passwords = int(line.split(':')[1])
            if 'Total number of threads:' in line:
                m.threads = int(line.split(':')[1])
            if 'Memory per password:' in line:
                m.memory = line.split(':')[1]
            if 'Parallelism inside password derivation:' in line:
                m.parallelism = int(line.split(':')[1])
            if 'Synchronism (used just if Parallelism > 1):' in line:
                m.syn = int(line.split('Synchronism (used just if Parallelism > 1): ')[1]) 
            if 'Sponge:' in line:
                 m.sponge = line.split('Sponge: ')[1].rstrip('\n')
            if 'Block Size (threads):' in line:
                m.cudaBlockSize = int(line.split(':')[1])
            if 'Grid Size (blocks):' in line:
                m.cudaGridSize = int(line.split(':')[1].strip() )
            if 'Execution Error!:' in line:
                errorFLAG = True
            if 'Error' in line:
                errorFLAG = True
            if 'Number of rows too small' in line:
                errorFLAG = True

            #Execution Time per password: 1520197.000 us (1520.197 ms, 1.520 seg)
            if 'Execution Time per password:' in line:
                time = line.split(": ")[1].split(" us")[0].strip()
                if (errorFLAG == False):
                    m.measures.append(float(time))

            if "--------------" in line:            #Data block end
                duplicated = False
                if (errorFLAG == False):
                    for temp in mList:
                        if (temp.code ==  m.code):
                            temp.measures.append(float(time))
                            duplicated = True
                  
                    if (duplicated == False):
                        mList.append(m)
                
                errorFLAG = False
                m = measureAttack()

    for a in mList:
        print(a.toString())
    
if __name__ == "__main__":
    main()

