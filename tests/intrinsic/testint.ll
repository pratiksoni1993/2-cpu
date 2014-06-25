; ModuleID = 'test'

define i32 @mul_add(i32 %x, i32 %y, i32 %z) {
entry:
  %tmp = mul i32 %x, %y
  %tmp2 = add i32 %tmp, %z
  %tmp3 = call i32 @llvm.x86.addenc.32(i32 %tmp, i32 %tmp2)
  ret i32 %tmp3
}

declare i32 @llvm.x86.addenc.32(i32, i32) nounwind readnone
