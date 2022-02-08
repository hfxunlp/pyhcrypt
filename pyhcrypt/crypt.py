#encoding: utf-8

from hashlib import blake2b as hash_blake
from os import urandom

digest_size = 64
use_rand_default = True

h_rand = b"\x04c7:\t\x98\x91\xc8;#\x14\xcb\xa8\xb4CB\xdc\xed\xc4^ru\xdd'\x87\xd0\xb6Q\xdf\xa4\x91\xcfh+N\x18=\xdeij\x1e\x96\xbc5\xe7Z\xa1\xa7\x15P\x8d\xb6\xda\xfb\xd8\xbcGH\x11*\xbf^a\xf4"
t_rand = b'\xe7\xfe\x91\x03\xfc\x8e\xfen\xf3%HL\xb2ZQKs\xbd\xa7\xaf\xe8\xc5\xaf\x98\xeaH\x16i\x03\xe2P\xf3\xfb\xf8mk\xa8Mt\x9a\xe3M\xb4\xa5\x12\xc5b\n\xbf\x1et\xb5\xcb>\x8f_x\x88J\x9d\x16q\x85^'
h_key = b'\xbe#\xd4\x18\xd9:: \x82\xe3Z\xcd\xe0\x80 \x03\x88l\xa8\xab7\xbfvz\xa4\xd3\xc6\x80T\xf0\xa3\xc4\x95\xcc7\x84\x1b\xdcd(\xce\xa1\xcf\x8al\xa1\xbc\x1f\xacE\x7f\xb3\xe8\x94C\x01\x18\x801O1s[\x7f'
t_key = b'or\x80*\xfb\x96\x0c\x9d\xff,w.N\xa7\xe9\xad|\xce\xacFE@\x9c\xd6=\xee\xec\x8a\xe4\xfb\xc8\xbd\xee\xf7\xbfG\xae\xc4\xa8a.\xeb\xdfw\x93Ufn\x89(\x8c*\x87\xd1\x02\xd7\x0e\x96\xd5^\xdf=\xfd\x11'
h_salt = b'\xc5h\x84Kn\xa1\x18\x1b\xf0\xe0qn"D\x95Ovl5R\xda\x97\xec\xbf77:\'\xfdyQ\xf6\xb8\xdbO\'.\x15\xa7\x03\xae\xb3\x01\xcfA\xa5R\xd7\xe3\xca\xd3F|ON\xb3\xea\'\x92\xc2\x8a\x8f\xc1\xe5'
t_salt = b'\x9d`U=%\xa64>\x1b\xf4^\xc2\xbfk\x11B\xda\xbeU\xbc\x85^\x99\x1c\xfc\x14\x82z\xb8\x90\xe3\x8c4\x8f\x0c\xae\xe2\xe9\x14:\x1bL\xe2\xa7\x07\xb4pU\xacB\x92\xde:\x99\xd2\xcd\x9f\x8b\xd6\x90{\x03T\x0b'
h_person = b'M\xf3vAW\x85q\xf6^\xfa\xaeNm\xfbVf\xca\xdbhoG\xf1\x05\xea?@\x18\x84Q\x91\x87y\x12\xa0\xaf\xa7u\x9c\x85\xab\xbcL\x92~W\xb1 \xb5J\x96\xb9\xc2hk\xe2^\xab\x8e\xf5\xfaf\x1ea\xc1'
t_person = b'\xe1\xd3M09\xbe\xd4\xb8\xee\xb0\xe1J`\xf6u\xdd\xd13\x03bD\xcf8\to\xca\xf7\x9a\xba\xde\x18\xbb\xc9\x97^W*\xb3\nm5Y\x95mf\xcc\x15\x85"\x7f\x1dN\x9e\x93/\x16\xd9\x99\xa5\xcf\x85\xf4h\xa1'

MAX_KEY_SIZE, SALT_SIZE, PERSON_SIZE = hash_blake.MAX_KEY_SIZE, hash_blake.SALT_SIZE, hash_blake.PERSON_SIZE

i_from_bytes = int.from_bytes
byteorder = "big"

def xor_bytes(a, b):

	return (i_from_bytes(a, byteorder, signed=False) ^ i_from_bytes(b, byteorder, signed=False)).to_bytes(len(a), byteorder, signed=False)

def get_rand_bytes(l):

	return hash_blake(urandom(l), digest_size=l, key=hash_blake(urandom(MAX_KEY_SIZE), digest_size=MAX_KEY_SIZE).digest(), salt=hash_blake(urandom(SALT_SIZE), digest_size=SALT_SIZE).digest(), person=hash_blake(urandom(PERSON_SIZE), digest_size=PERSON_SIZE).digest()).digest()

def get_hash_key(bytin):

	return hash_blake(h_key + bytin + t_key, digest_size=MAX_KEY_SIZE).digest()

def get_hash_salt(bytin):

	return hash_blake(h_salt + bytin + t_salt, digest_size=SALT_SIZE).digest()

def get_hash_person(bytin):

	return hash_blake(h_person + bytin + t_person, digest_size=PERSON_SIZE).digest()

def prepare_hash(bytin):

	return get_hash_key(bytin), get_hash_salt(bytin), get_hash_person(bytin)

def encrypt_bytes(bytesin, passwd, use_rand=use_rand_default):

	if isinstance(passwd, str):
		passwd = passwd.encode("utf-8")

	hash_key, hash_salt, hash_person = prepare_hash(passwd)
	hasher = hash_blake(passwd, digest_size=digest_size, key=hash_key, salt=hash_salt, person=hash_person)

	_passwd = hasher.digest()
	_content = hash_blake(get_rand_bytes(digest_size), digest_size=digest_size, key=hash_key, salt=hash_salt, person=hash_person).digest() if use_rand else hash_blake(h_rand + passwd + t_rand, digest_size=digest_size, key=hash_key, salt=hash_salt, person=hash_person).digest()

	rs = [xor_bytes(_passwd, _content)] if use_rand else []
	_sind = 0
	_ilen = len(bytesin)
	while _sind < _ilen:
		hasher.update(_content)
		_passwd = hasher.digest()
		_eind = _sind + digest_size
		if _eind <= _ilen:
			_content = bytesin[_sind:_eind]
			_crypt = xor_bytes(_passwd, _content)
		else:
			_content = bytesin[_sind:_ilen]
			_crypt = xor_bytes(_passwd[:_ilen - _sind], _content)
		rs.append(_crypt)
		_sind = _eind

	return b"".join(rs)

def decrypt_bytes(bytesin, passwd, use_rand=use_rand_default):

	if isinstance(passwd, str):
		passwd = passwd.encode("utf-8")

	hash_key, hash_salt, hash_person = prepare_hash(passwd)
	hasher = hash_blake(passwd, digest_size=digest_size, key=hash_key, salt=hash_salt, person=hash_person)

	_passwd = hasher.digest()
	_decrypt = xor_bytes(_passwd, bytesin[:digest_size]) if use_rand else hash_blake(h_rand + passwd + t_rand, digest_size=digest_size, key=hash_key, salt=hash_salt, person=hash_person).digest()

	rs = []
	_sind = digest_size if use_rand else 0
	_ilen = len(bytesin)
	while _sind < _ilen:
		hasher.update(_decrypt)
		_passwd = hasher.digest()
		_eind = _sind + digest_size
		if _eind <= _ilen:
			_content = bytesin[_sind:_eind]
			_decrypt = xor_bytes(_passwd, _content)
		else:
			_content = bytesin[_sind:_ilen]
			_decrypt = xor_bytes(_passwd[:_ilen - _sind], _content)
		rs.append(_decrypt)
		_sind = _eind

	return b"".join(rs)

def encrypt_stream(fin, passwd, use_rand=use_rand_default):

	if isinstance(passwd, str):
		passwd = passwd.encode("utf-8")

	hash_key, hash_salt, hash_person = prepare_hash(passwd)
	hasher = hash_blake(passwd, digest_size=digest_size, key=hash_key, salt=hash_salt, person=hash_person)

	_passwd = hasher.digest()

	if use_rand:
		_content = hash_blake(get_rand_bytes(digest_size), digest_size=digest_size, key=hash_key, salt=hash_salt, person=hash_person).digest()
		yield xor_bytes(_passwd, _content)
	else:
		_content = hash_blake(h_rand + passwd + t_rand, digest_size=digest_size, key=hash_key, salt=hash_salt, person=hash_person).digest()
	hasher.update(_content)
	_content = fin.read(digest_size)
	while _content:
		_passwd = hasher.digest()
		_clen = len(_content)
		if _clen == digest_size:
			yield xor_bytes(_passwd, _content)
		else:
			yield xor_bytes(_passwd[:_clen], _content)
		hasher.update(_content)
		_content = fin.read(digest_size)

def decrypt_stream(fin, passwd, use_rand=use_rand_default):

	if isinstance(passwd, str):
		passwd = passwd.encode("utf-8")

	hash_key, hash_salt, hash_person = prepare_hash(passwd)
	hasher = hash_blake(passwd, digest_size=digest_size, key=hash_key, salt=hash_salt, person=hash_person)

	_passwd = hasher.digest()
	_decrypt = xor_bytes(_passwd, fin.read(digest_size)) if use_rand else hash_blake(h_rand + passwd + t_rand, digest_size=digest_size, key=hash_key, salt=hash_salt, person=hash_person).digest()

	_content = fin.read(digest_size)
	while _content:
		hasher.update(_decrypt)
		_passwd = hasher.digest()
		_clen = len(_content)
		if _clen == digest_size:
			_decrypt = xor_bytes(_passwd, _content)
		else:
			_decrypt = xor_bytes(_passwd[:_clen], _content)
		yield _decrypt
		_content = fin.read(digest_size)

def encrypt(bfin, passwd, use_rand=use_rand_default):

	return encrypt_bytes(bfin, passwd, use_rand=use_rand) if isinstance(bfin, bytes) else encrypt_stream(bfin, passwd, use_rand=use_rand)

def decrypt(bfin, passwd, use_rand=use_rand_default):

	return decrypt_bytes(bfin, passwd, use_rand=use_rand) if isinstance(bfin, bytes) else decrypt_stream(bfin, passwd, use_rand=use_rand)
