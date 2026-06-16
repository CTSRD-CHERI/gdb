.if RVY
	.attribute arch, "rv32yfdc"
.else
	.attribute arch, "rv32ifdc"
.endif
	.insn 2, 0x61c8
	.insn 2, 0xe1c8
	.insn 2, 0x6532
	.insn 2, 0xe22a
