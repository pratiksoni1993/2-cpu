#clang++ -std=c++11 -D __STDC_LIMIT_MACROS -D __STDC_CONSTANT_MACROS -I ../include/ -g -O3 2-cpu.cpp -o toy
 c++ -g -pthread $1.cpp `llvm-config --cxxflags --libs core` `llvm-config --ldflags`  -o $1
