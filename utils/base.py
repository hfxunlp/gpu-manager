#encoding: utf-8

from math import log, ceil

def to_int(strin):

	try:
		return int(strin)
	except Exception as e:
		return None

def map_device(lin, mp):

	rs = []
	_mapped = set()
	for lu in lin:
		_mid = mp.get(lu, lu)
		if _mid not in _mapped:
			rs.append(_mid)
			_mapped.add(_mid)

	return rs

def get_duplicate_items(lin):

	_c = {}
	for _ in lin:
		_c[_] = _c.get(_, 0) + 1

	return [_ for _, _v in _c.items() if _v > 1]

def get_exp_p(thres, total, p):

	return 1.0 - (1.0 - p) ** ceil(log(float(thres) / total) / log(1.0 - p))
