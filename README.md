# Faster Hardware Fuzzing Framework

## Introduction

This is the source code of our submission *"Faster Hardware Fuzzing in Standard IC Verification Workflow"* for ITC 2024.

![Overview of faster hardware fuzzing framework](overview.png)

Our framework is built upon RTL Fuzz Lab and JQF. We have solved the above speed challenges in hardware fuzzing and achieved a speedup of hundreds of times with RTL Fuzz Lab. 

## Installation

The following dependencies are required to run this software:
* make
* gcc
* g++
* java
* sbt
* verilator
* matplotlib
* scipy

Firstly, our modified chiseltest should be packaged and published locally.
```.sh
cd chiseltest
sbt
publishLocal
exit
```
Secondly, verilator is also modified and need to be compiled.
```.sh
cd verilator
autoconf
export VERILATOR_ROOT=`pwd`
./configure
make
```
Then we can run fast-rtl-fuzz through scripts provided.
```.sh
source env.sh
./run.sh
make
```

