        .attribute arch, "rv64ya_zba"

        .text
target:
	# yadd gp, ra, sp
	.insn r 0x7b, 0, 0x03, gp, ra, sp
	# ymv gp, ra
	.insn r 0x7b, 0, 0x03, gp, ra, x0
	# yaddi gp, ra, 1
	.insn i 0x7b, 4, gp, ra, 1
	# ybndswi gp, ra, 1
	.insn i 0x7b, 5, gp, ra, -511
	# ly gp, 0(ra)
	.insn i 0x7b, 1, gp, ra, 0
	# sy gp, 0(ra)
	.insn s 0x7b, 2, gp, 0(ra)
	# amoswap.y gp, ra, (sp)
	.insn r 0x7b, 3, 4, gp, sp, ra
	# amoswap.y.aqrl gp, ra, (sp)
	.insn r 0x7b, 3, 7, gp, sp, ra
	# lr.y gp, (sp)
	.insn r 0x7b, 3, 8, gp, sp, x0
	# lr.y.aq gp, (sp)
	.insn r 0x7b, 3, 10, gp, sp, x0
	# sc.y gp, ra, (sp)
	.insn r 0x7b, 3, 12, gp, sp, ra
	# sc.y.aqrl gp, ra, (sp)
	.insn r 0x7b, 3, 15, gp, sp, ra
	# srliy gp, ra, 64 (yhir gp, ra)
	.insn r 0x7b, 5, 2, gp, ra, x0
	# ysh1add gp, ra, sp
	.insn r 0x7b, 0, 0x05, gp, ra, sp
	# ysh2add gp, ra, sp
	.insn r 0x7b, 0, 0x0d, gp, ra, sp
	# ysh3add gp, ra, sp
	.insn r 0x7b, 0, 0x15, gp, ra, sp
	# ysh4add gp, ra, sp
	.insn r 0x7b, 0, 0x1d, gp, ra, sp
	# ysh1add.uw gp, ra, sp
	.insn r 0x7b, 0, 0x25, gp, ra, sp
	# ysh2add.uw gp, ra, sp
	.insn r 0x7b, 0, 0x2d, gp, ra, sp
	# ysh3add.uw gp, ra, sp
	.insn r 0x7b, 0, 0x35, gp, ra, sp
	# ysh4add.uw gp, ra, sp
	.insn r 0x7b, 0, 0x3d, gp, ra, sp
	# ybndswi gp, ra, 4096
	.insn i 0x7b, 5, gp, ra, -512
	# ybndswi gp, ra, 255
	.insn i 0x7b, 5, gp, ra, -257
	# ybndswi gp, ra, 256
	.insn i 0x7b, 5, gp, ra, -256
	# ybndswi gp, ra, 504
	.insn i 0x7b, 5, gp, ra, -225
	# ybndswi gp, ra, 512
	.insn i 0x7b, 5, gp, ra, -224
	# ybndswi gp, ra, 4080
	.insn i 0x7b, 5, gp, ra, -1
	# srliy gp, ra, 0
	.insn r 0x7b, 5, 0, gp, ra, x0
	# srliy gp, ra, 63
	.insn r 0x7b, 5, 1, gp, ra, x31
	# ymodeswy
	.insn r 0x7b, 0, 0x2b, x0, x0, x0
	# ymodeswi
	.insn r 0x7b, 0, 0x2b, x0, x0, x1
