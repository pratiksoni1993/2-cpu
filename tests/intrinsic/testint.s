	.file	"testint.ll"
	.text
	.globl	mul_add
	.align	16, 0x90
	.type	mul_add,@function
mul_add:                                # @mul_add
	.cfi_startproc
# BB#0:                                 # %entry
	movl	4(%esp), %ecx
	imull	8(%esp), %ecx
	movl	12(%esp), %eax
	addl	%ecx, %eax
	addenc 	%eax %ecx 
	ret
.Ltmp0:
	.size	mul_add, .Ltmp0-mul_add
	.cfi_endproc


	.section	".note.GNU-stack","",@progbits
