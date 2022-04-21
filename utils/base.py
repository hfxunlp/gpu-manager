#encoding: utf-8

from math import log, ceil

def to_int(strin):

	try:
		return int(strin)
	except Exception as e:
		return None

def get_exp_p(thres, total, p):

	return 1.0 - (1.0 - p) ** ceil(log(float(thres) / total) / log(1.0 - p))
