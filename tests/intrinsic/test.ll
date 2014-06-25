; ModuleID = 'test.c'
target datalayout = "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:32:64-f32:32:32-f64:32:64-v64:64:64-v128:128:128-a0:0:64-f80:32:32-n8:16:32-S128"
target triple = "i386-pc-linux-gnu"

@.str = private unnamed_addr constant [3 x i8] c"%d\00", align 1

define i32 @main() nounwind {
  %1 = alloca i32, align 4
  %a = alloca i32, align 4
  store i32 0, i32* %1
  store i32 10, i32* %a, align 4
  %2 = load i32* %a, align 4
  %3 = call i32 (i8*, ...)* @printf(i8* getelementptr inbounds ([3 x i8]* @.str, i32 0, i32 0), i32 %2)
  %4 = load i32* %1
  ret i32 %4
}

declare i32 @printf(i8*, ...)
