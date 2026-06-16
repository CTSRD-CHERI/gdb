.if RVY
	.attribute arch, "rv64yfdc"
.else
	.attribute arch, "rv64ifdc"
.endif
	.insn 2, 0x2588
	.insn 2, 0xa1c8
	.insn 2, 0x2522
	.insn 2, 0xa42a
