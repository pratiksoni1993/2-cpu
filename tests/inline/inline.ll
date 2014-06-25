; ModuleID = 'inline.c'
target datalayout = "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:32:64-f32:32:32-f64:32:64-v64:64:64-v128:128:128-a0:0:64-f80:32:32-n8:16:32-S128"
target triple = "i386-pc-linux-gnu"

@format = global [7 x i8] c"%s %s\0A\00", align 1
@hello = global [6 x i8] c"Hello\00", align 1
@world = global [6 x i8] c"world\00", align 1

define i32 @main() nounwind {
  %1 = alloca i32, align 4
  %a = alloca i32, align 4
  %c = alloca i32, align 4
  %d = alloca i32, align 4
  store i32 0, i32* %1
  store i32 10, i32* %a, align 4
  store i32 100, i32* %c, align 4
  %2 = load i32* %a, align 4
  %3 = load i32* %c, align 4
  %4 = add nsw i32 %2, %3
  store i32 %4, i32* %d, align 4
  call void asm sideeffect "addenc %ebx, %eax\0A\09", "~{dirflag},~{fpsr},~{flags}"() nounwind, !srcloc !0
  %5 = load i32* %d, align 4
  ret i32 %5
}

!0 = metadata !{i32 241, i32 261}
