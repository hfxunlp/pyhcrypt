#encoding: utf-8

import sys
from .crypt import encrypt, decrypt

def handle(cmd, passwd, srcf, rsf):

	func = decrypt if cmd.find("d") >= 0 else encrypt
	if srcf == rsf:
		with open(srcf, "rb") as f:
			_tmp = f.read()
		_tmp = func(_tmp, passwd)
		with open(rsf, "wb") as f:
			f.write(_tmp)
	else:
		with open(srcf, "rb") as rf, open(rsf, "wb") as wf:
			for _ in func(rf, passwd):
				wf.write(_)

def cli():
	handle(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[-1])

if __name__ == "__main__":
	cli()
