#encoding: utf-8

from hashlib import blake2b as hash_blake
from cnfg import digest_size, hash_wd

hash_key = hash_blake(hash_wd.encode("utf-8"), digest_size=hash_blake.MAX_KEY_SIZE).digest()
hash_salt = hash_blake(("%s%s%s" % ("sa", hash_wd, "lt",)).encode("utf-8"), digest_size=hash_blake.SALT_SIZE).digest()
PERSON_SIZE = hash_blake.PERSON_SIZE

def hash_func(passwd, usr="", digest_size=digest_size, key=hash_key, salt=hash_salt):

	return hash_blake(passwd.encode("utf-8") if isinstance(passwd, str) else passwd, digest_size=digest_size, key=key, salt=salt, person=hash_blake(usr.encode("utf-8"), digest_size=PERSON_SIZE).digest()).digest()
