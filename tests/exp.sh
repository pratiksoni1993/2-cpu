set -e
CORE=/home/Desktop

clang -emit-llvm -S $1.c -o $1.ll
llvm-as $1.ll -o $1.bc
llc $1.ll -o $1.S

