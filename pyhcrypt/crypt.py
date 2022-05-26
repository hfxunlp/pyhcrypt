#encoding: utf-8

from hashlib import blake2b as hash_blake
MAX_KEY_SIZE, SALT_SIZE, PERSON_SIZE, MAX_DIGEST_SIZE = hash_blake.MAX_KEY_SIZE, hash_blake.SALT_SIZE, hash_blake.PERSON_SIZE, hash_blake.MAX_DIGEST_SIZE
try:
	from secrets import token_bytes as rand_bytes
except:
	from os import urandom as rand_bytes
from sys import byteorder

use_rand_default = True
use_xrand_default = True

states = {'h_rand': b'Rg\xc7|\x90\x12\xae\x95\xabP\x94mv\x16)]s2\xc7\x880\xd2^\x03\xba\xe3\nZ\xfc\x96\xbb\x19\x81\xf2]\xf8\x9boQ\x99\x88R\xf7\xf9F;$qh\xb0a\xa3M5\xe0\xa0:\x9dS\x8e\xcb;\x87\xff', 't_rand': b"|\xd9\x90\xc5C-\xf5\x88\xeeW\xac\x18\r\xbd\x84\xb7\xb5\x86\r\xb3g\xda=\x12\xb0{\xed\x92\x89\x98H+\x9d\x1dGq\x1dT!\xd97\x95\xfa\x13\\M\xe1\x11\xb5\x8a=\xf3'\xe3\xc5\x8b\x11\xda\x0c\xe7\xaee0\xbb", 'h_key': b"\x905:v\x0b\x95%\x16\xad\xech]\xc2/V\xa2\x9e\x1b\x18\xb4\x91'br\xbc5\xe2x=+\xa8N4Vo\xd3D\x1e\xc5\x92CJ\xf7\x83\x9a\xa1\xac\x8a\xefpBE\xd8\xa8\x063a\x14q\xcc\xa4qN\xa8", 't_key': b"D\xe5\xf3zJ'\x9a\xfe\xd3<\r\x95\xc0^\x0c\xb2\x99(bU\ta-\x82\x1c\x8a\xc0o\x97\xcdK\xd2\xb0-\x8c\xbc\xd0x]\xec\xd8G\x0f\xa3\xbe\xdd\xe3+[A\xd4O\xef+\xcd\xad\x91D\x11\xd3\xa0(\xeaW", 'h_salt': b'\x8d\x8a\x12m:A\xdf\xd4(\xbeM\x859N\xd9IRx\x8a\xe4\xf6\x8e\xc6\x81\xbfD!\xe5\xec\xdf\xacd\xd6\x82\x99\xe0\xd5\n\x0e{%\xa8\xa6-\x18\x16\xc3\xaf\x06\xb5L\xac~\xd1U^7{.v\xe4\xe5F?', 't_salt': b":\xbfo\x13\xa2m\x0e/\x1cXN\xdeX\xa0|\xa0\r\xf8'\xa0VoF\x10\xe5\x84\xb5\x81\xdf\xea\x86>e;\xef\x9b\x94X\x99:%\xb2\xa0Z\xa6\xaf\x94\xb9\x07\xfd\xbd\xec\xde\x067W\xed\xb7R\x89\x82\x8b[$", 'h_person': b"I\x0b\xb1\\\xa7eb\x01J`C!VF\xc4\xf5;\xe5\xc5\xf8\x1c\x18E\xebC\xfa\xafu-r\x1e\xea9RE\x0eq\xf8\xc0\x97:\xd67_\xe7\xb0c'!\xbf2\xff\x8b\r\x04h\xa60A\xbc\xe2\x01b\x87", 't_person': b'\xde\xe0\x07F\xbd\xb0\x18\x1d\xa4\xd3g\x04\xdc\xf9\x11v\x1fr\xdc\xaa\xd6\xe7R\x91\xf7w\xb9F{G\xe6\xad\x9d`qR\xe8\x00\r\x97 V\xf1\x90-\xeby\xdc\xc8\xcbm\x15\x9b\xd2\x0b\x9bY\xde\xc1N\xa608\x05', 'key_key': b'\x18H\xdc\xffp\xc9\xd3\x11\x7fj\xb0\xddZl\xe2\x93\x05fm\x87\x9c)\x1eg\xf7\xf5\xc1h\xc9Q\x86QeJY\x16\xe9\x9b\xbd\x95O~\xc0cu9\x81\xe0\x18\xb5`\xff\x16\x95\r\xd5{\xa0\xe7\xf3M\xd4\xb7\x9c', 'key_salt': b'`\xac\x1a\xcbD\xc0\x0fVKu\x80\xb2I\\\xd9\xca', 'key_person': b'"\xd0\xf3n\xe6\xf8Z\xd8B\xba-\x89`\xb2\xa2E', 'salt_key': b'\x16-\x0fKgU7\x02\xf2beM\x0c\xd1pC\x0b\x10}\xf7\xc9\xa6\x14G`C2\x1d\xdcmg\xe3\ti\xeb\xd8u\x0e\xc9\xb3\xa8\xdfa\xff\xa8p\x0e\x9d\xa9\xf4\xc6;\x18\x03AX\xa2\xa5pC.\xce\x1c\x9e', 'salt_salt': b'\x82e\x8eqSnT\x8f\xeeA\xc3^r\x12\x13\xfb', 'salt_person': b'\xe1\x08\r\xb7\x04\xbff\xb8\x87\xd7?\xae\x93\x02=\xf1', 'person_key': b'\xc6DQ\xf2\\\x1b\xc83\xdc\x0e\xc5\xebz\x84\xfb\xf3\xa1\xd5\xa9I32\\\xec{\xa2\t\x97V\xccw);\xc7\x03\xaer^7\xeb\x86]\xe9\xf4\xd1\x8b\x17:m\xdb\xe5\xc0\x0e\xc5\x87\xfe\xc4A\xb3a\x8b\xb9\xc3}', 'person_salt': b'\xc21\r\xe3\x98V\xd9Z\xfc\xea\xa9\x82\xe0w\xfc\xd6', 'person_person': b'\xcf\xf5B\x86j\xfd\xc2\x13$&wPW\xd8\xd6\xce'}

i_from_bytes = int.from_bytes

def xor_bytes(a, b):

	return (i_from_bytes(a, byteorder, signed=False) ^ i_from_bytes(b, byteorder, signed=False)).to_bytes(len(a), byteorder, signed=False)

def get_rand_bytes_maxhashlen(l, xrand=use_xrand_default):

	_ = hash_blake(rand_bytes(l), digest_size=l, key=hash_blake(rand_bytes(MAX_KEY_SIZE), digest_size=MAX_KEY_SIZE).digest(), salt=hash_blake(rand_bytes(SALT_SIZE), digest_size=SALT_SIZE).digest(), person=hash_blake(rand_bytes(PERSON_SIZE), digest_size=PERSON_SIZE).digest()).digest()

	return xor_bytes(_, rand_bytes(l)) if xrand else _

def get_rand_bytes(l, xrand=use_xrand_default):

	if l <= MAX_DIGEST_SIZE:
		return get_rand_bytes_maxhashlen(l, xrand=xrand)
	else:
		rs = []
		_ = l
		while _ > MAX_DIGEST_SIZE:
			rs.append(get_rand_bytes_maxhashlen(MAX_DIGEST_SIZE, xrand=False))
			_ -= MAX_DIGEST_SIZE
		rs.append(get_rand_bytes_maxhashlen(_, xrand=False))
		rs = b"".join(rs)
		return xor_bytes(rs, rand_bytes(l)) if xrand else rs

def generate_states(xrand=use_xrand_default):

	return {"h_rand": get_rand_bytes_maxhashlen(MAX_DIGEST_SIZE, xrand=xrand), "t_rand": get_rand_bytes_maxhashlen(MAX_DIGEST_SIZE, xrand=xrand), "h_key": get_rand_bytes_maxhashlen(MAX_DIGEST_SIZE, xrand=xrand), "t_key": get_rand_bytes_maxhashlen(MAX_DIGEST_SIZE, xrand=xrand), "h_salt": get_rand_bytes_maxhashlen(MAX_DIGEST_SIZE, xrand=xrand), "t_salt": get_rand_bytes_maxhashlen(MAX_DIGEST_SIZE, xrand=xrand), "h_person": get_rand_bytes_maxhashlen(MAX_DIGEST_SIZE, xrand=xrand), "t_person": get_rand_bytes_maxhashlen(MAX_DIGEST_SIZE, xrand=xrand), "key_key": get_rand_bytes_maxhashlen(MAX_KEY_SIZE, xrand=xrand), "key_salt": get_rand_bytes_maxhashlen(SALT_SIZE, xrand=xrand), "key_person": get_rand_bytes_maxhashlen(PERSON_SIZE, xrand=xrand), "salt_key": get_rand_bytes_maxhashlen(MAX_KEY_SIZE, xrand=xrand), "salt_salt": get_rand_bytes_maxhashlen(SALT_SIZE, xrand=xrand), "salt_person": get_rand_bytes_maxhashlen(PERSON_SIZE, xrand=xrand), "person_key": get_rand_bytes_maxhashlen(MAX_KEY_SIZE, xrand=xrand), "person_salt": get_rand_bytes_maxhashlen(SALT_SIZE, xrand=xrand), "person_person": get_rand_bytes_maxhashlen(PERSON_SIZE, xrand=xrand)}

def get_hash_key(bytin):

	return hash_blake(states["h_key"] + bytin + states["t_key"], digest_size=MAX_KEY_SIZE, key=states["key_key"], salt=states["key_salt"], person=states["key_person"]).digest()

def get_hash_salt(bytin):

	return hash_blake(states["h_salt"] + bytin + states["t_salt"], digest_size=SALT_SIZE, key=states["salt_key"], salt=states["salt_salt"], person=states["salt_person"]).digest()

def get_hash_person(bytin):

	return hash_blake(states["h_person"] + bytin + states["t_person"], digest_size=PERSON_SIZE, key=states["person_key"], salt=states["person_salt"], person=states["person_person"]).digest()

def prepare_hash(bytin):

	return get_hash_key(bytin), get_hash_salt(bytin), get_hash_person(bytin)

def encrypt_bytes(bytesin, passwd, use_rand=use_rand_default, xrand=use_xrand_default):

	if isinstance(passwd, str):
		passwd = passwd.encode("utf-8")

	hash_key, hash_salt, hash_person = prepare_hash(passwd)
	hasher = hash_blake(passwd, digest_size=MAX_DIGEST_SIZE, key=hash_key, salt=hash_salt, person=hash_person)

	_passwd = hasher.digest()
	_content = hash_blake(get_rand_bytes_maxhashlen(MAX_DIGEST_SIZE, xrand=xrand), digest_size=MAX_DIGEST_SIZE, key=hash_key, salt=hash_salt, person=hash_person).digest() if use_rand else hash_blake(states["h_rand"] + passwd + states["t_rand"], digest_size=MAX_DIGEST_SIZE, key=hash_key, salt=hash_salt, person=hash_person).digest()

	rs = [xor_bytes(_passwd, _content)] if use_rand else []
	_sind = 0
	_ilen = len(bytesin)
	while _sind < _ilen:
		hasher.update(_content)
		_passwd = hasher.digest()
		_eind = _sind + MAX_DIGEST_SIZE
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
	hasher = hash_blake(passwd, digest_size=MAX_DIGEST_SIZE, key=hash_key, salt=hash_salt, person=hash_person)

	_passwd = hasher.digest()
	_decrypt = xor_bytes(_passwd, bytesin[:MAX_DIGEST_SIZE]) if use_rand else hash_blake(states["h_rand"] + passwd + states["t_rand"], digest_size=MAX_DIGEST_SIZE, key=hash_key, salt=hash_salt, person=hash_person).digest()

	rs = []
	_sind = MAX_DIGEST_SIZE if use_rand else 0
	_ilen = len(bytesin)
	while _sind < _ilen:
		hasher.update(_decrypt)
		_passwd = hasher.digest()
		_eind = _sind + MAX_DIGEST_SIZE
		if _eind <= _ilen:
			_content = bytesin[_sind:_eind]
			_decrypt = xor_bytes(_passwd, _content)
		else:
			_content = bytesin[_sind:_ilen]
			_decrypt = xor_bytes(_passwd[:_ilen - _sind], _content)
		rs.append(_decrypt)
		_sind = _eind

	return b"".join(rs)

def encrypt_stream(fin, passwd, use_rand=use_rand_default, xrand=use_xrand_default):

	if isinstance(passwd, str):
		passwd = passwd.encode("utf-8")

	hash_key, hash_salt, hash_person = prepare_hash(passwd)
	hasher = hash_blake(passwd, digest_size=MAX_DIGEST_SIZE, key=hash_key, salt=hash_salt, person=hash_person)

	_passwd = hasher.digest()

	if use_rand:
		_content = hash_blake(get_rand_bytes_maxhashlen(MAX_DIGEST_SIZE, xrand=xrand), digest_size=MAX_DIGEST_SIZE, key=hash_key, salt=hash_salt, person=hash_person).digest()
		yield xor_bytes(_passwd, _content)
	else:
		_content = hash_blake(states["h_rand"] + passwd + states["t_rand"], digest_size=MAX_DIGEST_SIZE, key=hash_key, salt=hash_salt, person=hash_person).digest()
	hasher.update(_content)
	_content = fin.read(MAX_DIGEST_SIZE)
	while _content:
		_passwd = hasher.digest()
		_clen = len(_content)
		if _clen == MAX_DIGEST_SIZE:
			yield xor_bytes(_passwd, _content)
		else:
			yield xor_bytes(_passwd[:_clen], _content)
		hasher.update(_content)
		_content = fin.read(MAX_DIGEST_SIZE)

def decrypt_stream(fin, passwd, use_rand=use_rand_default):

	if isinstance(passwd, str):
		passwd = passwd.encode("utf-8")

	hash_key, hash_salt, hash_person = prepare_hash(passwd)
	hasher = hash_blake(passwd, digest_size=MAX_DIGEST_SIZE, key=hash_key, salt=hash_salt, person=hash_person)

	_passwd = hasher.digest()
	_decrypt = xor_bytes(_passwd, fin.read(MAX_DIGEST_SIZE)) if use_rand else hash_blake(states["h_rand"] + passwd + states["t_rand"], digest_size=MAX_DIGEST_SIZE, key=hash_key, salt=hash_salt, person=hash_person).digest()

	_content = fin.read(MAX_DIGEST_SIZE)
	while _content:
		hasher.update(_decrypt)
		_passwd = hasher.digest()
		_clen = len(_content)
		if _clen == MAX_DIGEST_SIZE:
			_decrypt = xor_bytes(_passwd, _content)
		else:
			_decrypt = xor_bytes(_passwd[:_clen], _content)
		yield _decrypt
		_content = fin.read(MAX_DIGEST_SIZE)

def encrypt(bfin, passwd, use_rand=use_rand_default):

	return encrypt_bytes(bfin, passwd, use_rand=use_rand) if isinstance(bfin, bytes) else encrypt_stream(bfin, passwd, use_rand=use_rand)

def decrypt(bfin, passwd, use_rand=use_rand_default):

	return decrypt_bytes(bfin, passwd, use_rand=use_rand) if isinstance(bfin, bytes) else decrypt_stream(bfin, passwd, use_rand=use_rand)
