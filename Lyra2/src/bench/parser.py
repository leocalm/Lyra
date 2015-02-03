#! /usr/bin/env python
#
# This file is part of Lyra2, a password hashing scheme
# Copyright (c) 2013-2015 by Lyra2 Project -- <http://www.lyra2.net/>
#
# Script used only to make the outputs of "runBench.sh" and "runBenchGPU.sh" friendlier.
#
import sys

class measure:
    def __init__ (self):
        self.t = 0
        self.r = 0
        self.c = 0
        self.parrallelism = 0
        self.sponge = ""
        self.memory = 0
        self.measures = []
        self.average = 0.0

    def calcAverage(self):
        for m in self.measures:
            self.average = self.average + float(m)
        self.average = self.average / len(self.measures)

    def toString(self):
        return (str(self.t) + "|" + str(self.r) + "|" + str(self.c) + '|' + str(self.parrallelism) + "|" + self.sponge + "|" + str(self.memory) + "|" + str(self.measures) + "|" + str(self.average)).replace("[", "").replace(", ", "|").replace("]", "").replace("L", "")

def main(argv=None):
    if(len(sys.argv) != 2):
        print('Usage: ./parser.py fileName')
    else:
        f = open(sys.argv[1])

        line = f.readline()
        
        m = measure()
        mList = []

        count = 0
        samples = 6		#Change this value if you performe more samples in your benchmark
        
        print ("T | R | C | Parallelism | Sponge | Memory | Execution Time (us)")

        while line != '':
            line = f.readline() 
            if '\tT:' in line:
                m.t = long(line.split('T: ')[1])
            if 'R:' in line:
                m.r = long(line.split('R: ')[1])               
            if 'C:' in line:
                m.c = long(line.split('C: ')[1]) 
            if 'Parallelism:' in line:
                m.parrallelism = long(line.split('Parallelism: ')[1])
            if 'Sponge:' in line:
                m.sponge = line.split('Sponge: ')[1].rstrip('\n')
            if 'Sponge Blocks (bitrate):' in line:
                m.spongBlocks = long(line.split('Sponge Blocks (bitrate): ')[1].split(" =")[0]) 
            if 'Memory:' in line:
                m.memory = long(line.split('Memory: ')[1].split(" bytes")[0]) 
            if 'Execution Time:' in line:
                time = line.split(": ")[1].split(" us")[0]
                m.measures.append(long(time))
                count = count + 1
                if count == samples:
                    m.calcAverage()
                    mList.append(m)
                    m = measure()
                    count = 0

        for a in mList:
            print(a.toString())

if __name__ == "__main__":
    main()

