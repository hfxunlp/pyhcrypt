#encoding: utf-8

import sys
from .crypt import encrypt, decrypt

def handle(cmd, passwd, srcf, rsf):

	func = decrypt if cmd.find("d") >= 0 else encrypt
	if (srcf == rsf) and (srcf != "-"):
		with open(srcf, "rb") as f:
			_tmp = f.read()
		_tmp = func(_tmp, passwd)
		with sys.stdout.buffer if rsf == "-" else open(rsf, "wb") as f:
			f.write(_tmp)
	else:
		with sys.stdin.buffer if srcf == "-" else open(srcf, "rb") as rf, sys.stdout.buffer if rsf == "-" else open(rsf, "wb") as wf:
			for _ in func(rf, passwd):
				wf.write(_)

def cli():
	if len(sys.argv) < 4:
		print("Usage:\n\tpyhcrypt action password input_file output_file\nor\n\tpython -m pyhcrypt action password input_file output_file\nwhere action can be either \"e\" (for encryption) or \"d\" (for decryption), password is the password, input_file and output_file are the corresponding input and output file respectively. \"-\" for standard input/output.")
	else:
		handle(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[-1])

if __name__ == "__main__":
	cli()
