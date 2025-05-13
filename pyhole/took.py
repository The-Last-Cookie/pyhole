from datetime import datetime

#unix_timestamp = (datetime.now()) - datetime(1970, 1, 1)).total_seconds()

class Pi:
	def __init__(self):
		self._took = None

		self.component = Component(self)

	def _set_last_response_time(self, took):
		# Document returned object
		# Note that this will be None for endpoints that do not return "took" such as DELETE
		self._took = {
			"time": took,
			"when": get_date
		}

	def get_last_response_time(self):
		return self._took


class Component:
	def __init__(self, pi):
		self._pi = pi

	def endpoint(self):
		json_response = {}

		self._pi._set_last_response_time(json_response["took"])

		return json_response["object"]
