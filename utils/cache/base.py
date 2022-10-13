#encoding: utf-8

from collections import OrderedDict
from time import time, sleep
from threading import Lock
from math import floor

def get_str_bytes(x):

	return x.encode("utf-8") if isinstance(x, str) else x

class Cache:

	def __init__(self, max_caches=None, drop_p=0.1):

		self.data = OrderedDict()
		self.data_lck = Lock()
		self.max_caches = max_caches
		self.drop_p = drop_p

	def get(self, key, value=None):

		with self.data_lck:
			if key in self.data:
				_etime, _value = self.data[key]
				if _etime is None:
					return _value
				else:
					_cur_time = time()
					if _cur_time <= _etime:
						return _value
					else:
						del self.data[key]

		return value

	def set(self, key, value, life_time=None):

		with self.data_lck:
			self.data[key] = ((life_time if life_time is None else (time() + life_time)), value,)
			if (self.max_caches is not None) and (self.drop_p is not None):
				_nd = len(self.data)
				if _nd > self.max_caches:
					_etd = {}
					for _key, (_etime, _,) in self.data.items():
						if _etime is not None:
							if _etime in _etd:
								_etd[_etime].append(_key)
							else:
								_etd[_etime] = [_key]
					_nclean = floor(_nd * self.drop_p)
					for _ in sorted(_etd.keys()):
						_keys = _etd[_]
						_nkeys = len(_keys)
						if _nkeys < _nclean:
							for _key in _keys:
								del self.data[_key]
							_nclean -= _nkeys
						else:
							for _key in _keys[:_nclean]:
								del self.data[_key]
							break

	def __contains__(self, key):

		with self.data_lck:
			if key in self.data:
				_etime = self.data[key][0]
				if _etime is None:
					return True
				else:
					_cur_time = time()
					if _cur_time <= _etime:
						return True
					else:
						del self.data[key]

		return False

	def clear_all_temp(self):

		_c_keys = []
		with self.data_lck:
			for _key, (_etime, _,) in self.data.items():
				if _etime is not None:
					_c_keys.append(_key)
			if _c_keys:
				for _key in _c_keys:
					del self.data[_key]

	def clear(self, *args):

		if args:
			with self.data_lck:
				for _ in args:
					if _ in self.data:
						del self.data[_]
		else:
			with self.data_lck:
				self.data.clear()

	def clear_func(self, func):

		_c_keys = []
		with self.data_lck:
			for _ in self.data.keys():
				if func(_):
					_c_keys.append(_)
			if _c_keys:
				for _ in _c_keys:
					del self.data[_]

	def clear_funcs(self, *funcs, func=any):

		_c_keys = []
		with self.data_lck:
			for _key in self.data.keys():
				if func(_(_key) for _ in funcs):
					_c_keys.append(_key)
			if _c_keys:
				for _key in _c_keys:
					del self.data[_key]

	# with self.data_lck holded when call this function
	def pop_wgz(self, key):

		if key in self.data:
			_ = get_str_bytes(self.data.pop(key)[-1])
			if isinstance(_, bytes):
				_k = ("gzip", _,)
				if _k in self.data:
					del self.data[_k]

	def clear_wgz(self, *args):

		if args:
			with self.data_lck:
				for _ in args:
					self.pop_wgz(_)
		else:
			with self.data_lck:
				self.data.clear()

	def clear_func_wgz(self, func):

		_c_keys = []
		with self.data_lck:
			for _ in self.data.keys():
				if func(_):
					_c_keys.append(_)
			if _c_keys:
				for _ in _c_keys:
					self.pop_wgz(_)

	def clear_funcs_wgz(self, *funcs, func=any):

		_c_keys = []
		with self.data_lck:
			for _key in self.data.keys():
				if func(_(_key) for _ in funcs):
					_c_keys.append(_key)
			if _c_keys:
				for _key in _c_keys:
					self.pop_wgz(_key)

	def clean(self):

		_c_keys = []
		with self.data_lck:
			_cur_time = time()
			for _key, (_etime, _value,) in self.data.items():
				if (_etime is not None) and (_etime < _cur_time):
					_c_keys.append(_key)
			if _c_keys:
				for _key in _c_keys:
					del self.data[_key]

	def clean_wgz(self):

		_c_keys = []
		with self.data_lck:
			_cur_time = time()
			for _key, (_etime, _value,) in self.data.items():
				if (_etime is not None) and (_etime < _cur_time):
					_c_keys.append(_key)
			if _c_keys:
				for _key in _c_keys:
					self.pop_wgz(_key)

	def cleaner_core(self, sleep_time):

		sleep(sleep_time)
		self.clean_wgz()

	def cleaner(self, conditions, func, sleep_time):

		_conditions = tuple(conditions)
		if len(_conditions) > 1:
			while func(_() for _ in conditions):
				self.cleaner_core(sleep_time)
		else:
			_condition = _conditions[0]
			while _condition():
				self.cleaner_core(sleep_time)
		self.clear()

	def items(self):

		with self.data_lck:
			yield from self.data.items()
