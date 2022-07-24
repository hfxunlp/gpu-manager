#encoding: utf-8

from utils.cache.base import Cache as CacheBase

class Cache(CacheBase):

	def clear_gzip_cache(self):

		self.clear_func(lambda x: isinstance(x, tuple) and x[0] == "gzip")

	def clear_status_cache(self):

		self.clear_wgz("/api/status")
		self.clear("/status/tasks")
		self.clear_func_wgz(lambda x: isinstance(x, tuple) and x[0] == "/status")

	def clear_query_cache(self, usrs=None):

		if usrs is None:
			self.clear_func_wgz(lambda x: isinstance(x, tuple) and x[0].endswith("/query"))
		else:
			_us = usrs if isinstance(usrs, (set, dict,)) else set(usrs)
			self.clear_func_wgz(lambda x: isinstance(x, tuple) and x[0].endswith("/query") and (x[1] in _us))

	def clear_query_cache(self, usrs=None):

		if usrs is None:
			self.clear_func_wgz(lambda x: isinstance(x, tuple) and x[0].endswith("/query"))
		else:
			_us = usrs if isinstance(usrs, (set, dict,)) else set(usrs)
			self.clear_func_wgz(lambda x: isinstance(x, tuple) and x[0].endswith("/query") and (x[1] in _us))

	def clear_add_admin_usrtask_cache(self, usrs=None):

		if usrs is None:
			self.clear_func_wgz(lambda x: isinstance(x, tuple) and (x[0] == "/query" or x[0] == "/status"))
		else:
			_us = usrs if isinstance(usrs, (set, dict,)) else set(usrs)
			self.clear_func_wgz(lambda x: isinstance(x, tuple) and (x[0] == "/query" or x[0] == "/status") and (x[-1] in _us))

	def clear_usrtask_cache(self, usrs=None):

		self.clear_wgz("/api/status")
		self.clear("/status/tasks")
		if usrs is None:
			self.clear_func_wgz(lambda x: isinstance(x, tuple) and (x[0] == "/status" or x[0].endswith("/query")))
		else:
			_us = usrs if isinstance(usrs, (set, dict,)) else set(usrs)
			self.clear_func_wgz(lambda x: isinstance(x, tuple) and (x[0] == "/status" or (x[0].endswith("/query") and (x[1] in _us))))

	def clear_userinfo_cache(self):

		self.clear_func_wgz(lambda x: isinstance(x, tuple) and x[0].endswith("/userinfo"))

	def clear_createid_cache(self, task_id):

		self.clear_func_wgz(lambda x: isinstance(x, tuple) and len(x) == 3 and x[0] == "/create" and x[-1] == task_id)

	def clear_usrcreate_cache(self, usrs=None):

		if usrs is None:
			self.clear_func_wgz(lambda x: isinstance(x, tuple) and (x[0] == "/create"))
		else:
			self.clear_wgz(*[("/create", _,) for _ in usrs])

	def clear_usr_cache(self, usrs=None):

		self.clear("/status/tasks")
		if usrs is None:
			self.clear_func_wgz(lambda x: isinstance(x, tuple) or x == "/api/status")
		else:
			_us = usrs if isinstance(usrs, (set, dict,)) else set(usrs)
			self.clear_func_wgz(lambda x: (isinstance(x, tuple) and ((x[1] in _us) or (x[0] == "/status"))) or (x == "/api/status"))

	def clear_all_temp_cache(self):

		self.clear_all_temp()
