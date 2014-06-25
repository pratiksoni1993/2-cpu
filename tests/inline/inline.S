	.file	"inline.ll"
	.text
	.globl	main
	.align	16, 0x90
	.type	main,@function
main:                                   # @main
# BB#0:
	subl	$16, %esp
	movl	$0, 12(%esp)
	movl	$10, 8(%esp)
	movl	$100, 4(%esp)
	movl	8(%esp), %eax
	addl	$100, %eax
	movl	%eax, (%esp)
	#APP
	addenc %ebx, %eax
	
	#NO_APP
	movl	(%esp), %eax
	addl	$16, %esp
	ret
.Ltmp0:
	.size	main, .Ltmp0-main

	.type	format,@object          # @format
	.data
	.globl	format
format:
	.asciz	 "%s %s\n"
	.size	format, 7

	.type	hello,@object           # @hello
	.globl	hello
hello:
	.asciz	 "Hello"
	.size	hello, 6

	.type	world,@object           # @world
	.globl	world
world:
	.asciz	 "world"
	.size	world, 6


	.section	".note.GNU-stack","",@progbits
