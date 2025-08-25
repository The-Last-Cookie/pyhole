import requests

from .exceptions import *


class Pihole:
	def __init__(self, url: str, cert_bundle: str):
		"""
		Initiates an instance for calling the API

		:params: url: URL to Pi-hole
		:params: cert_bundle: Path to the .crt file of the Pi-hole (not the webserver certificate) for SSL validation. Set this to _False_ if you do not want to use SSL.
		"""

		self.url = url

		self._headers = None
		self._cert_bundle = cert_bundle

		self.metrics = MetricAPI(self)
		self.dns_filter = DnsFilterAPI(self)
		self.groups = GroupAPI(self)
		self.domains = DomainAPI(self)
		self.clients = ClientAPI(self)
		self.lists = ListAPI(self)
		self.ftl = FtlAPI(self)
		self.teleporter = TeleporterAPI(self)
		self.network = NetworkAPI(self)
		self.actions = ActionAPI(self)
		self.padd = PaddAPI(self)
		self.config = ConfigAPI(self)
		self.dhcp = DhcpAPI(self)

	def is_auth_required(self) -> bool:
		"""
		Check if authentication is required.

		If no login is required for the server, this will also return _False_.

		:returns: bool
		"""
		req = requests.get(self.url + "/auth", headers=self._headers, verify=self._cert_bundle)

		if req.status_code == 200:
			return False
		else:
			return True

	def get_current_session(self):
		"""
		Get current session status.

		:returns: JSON object
		:raises: AuthenticationRequiredException
		"""
		req = requests.get(self.url + "/auth", headers=self._headers, verify=self._cert_bundle)

		if req.status_code == 200:
			return req.json()['session']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def authenticate(self, password: str):
		"""
		Creates a session token via a password. This session token is valid for the maximum session time (30 minutes by default). If the session token has not expired yet, the validity of the token will be extended to the maximum session time on any interaction with the API.

		:params: password: Password used for authentication. Can be a user or app password.
		"""
		payload = {"password": password}
		auth_request = requests.post(self.url + "/auth", json=payload, verify=self._cert_bundle)
		session = auth_request.json()['session']

		if auth_request.status_code == 200:
			if session['sid'] is None:
				print("Authentication not required")
				self._headers = None
				return

			self._headers = {
				"X-FTL-SID": session['sid'],
				"X-FTL-CSRF": session['csrf']
			}
			print("Authentication successful")
		elif auth_request.status_code == 400:
			self._headers = None
			raise DataFormatException("Password must be of type 'string'")
		elif auth_request.status_code == 401:
			self._headers = None
			raise AuthenticationRequiredException("Password is not correct")
		elif auth_request.status_code == 429:
			self._headers = None
			raise RateLimitExceededException("Too many requests - " + session['message'])
		else:
			raise ApiError("API request failed due to unknown reasons")

	def delete_current_session(self):
		"""
		Delete the current session.
		"""
		req = requests.delete(self.url + "/auth", headers=self._headers, verify=self._cert_bundle)
		if req.status_code == 204:
			print("Current session deleted")

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		if req.status_code == 404:
			raise ItemNotFoundException("No active session. Authentication not required.")

		raise ApiError("API request failed due to unknown reasons")

	def create_app_password(self):
		"""
		Creates a new password to authenticate against the API instead of the user password.

		This password is only returned once and needs to be saved in order to authenticate again.

		:returns: Application password if successful
		"""
		req = requests.get(self.url + "/auth/app", headers=self._headers, verify=self._cert_bundle)
		if req.status_code == 200:
			application = req.json()["app"]
			password = application["password"]
			hash = application["hash"]

			new_config = {
				"config": {
					"webserver": {
						"api": {
							"app_pwhash": hash
						}
					}
				}
			}

			self.config.patch(new_config)
			print("Password created")
			return password
		elif req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")
		else:
			raise ApiError("API request failed due to unknown reasons")

	def delete_session(self, id: int):
		"""
		Deletes the session with the given id.
		"""
		req = requests.delete(self.url + "/auth/session/" + str(id), headers=self._headers, verify=self._cert_bundle)

		if req.status_code == 204:
			print(f"Session '{str(id)}' deleted")

		if req.status_code == 400:
			raise BadRequestException(req.json()["error"]["message"])

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		if req.status_code == 404:
			raise ItemNotFoundException("Session not found")

		raise ApiError("API request failed due to unknown reasons")

	def get_sessions(self):
		"""
		Get a list of all sessions.

		:returns: JSON object
		"""
		req = requests.get(self.url + "/auth/sessions", headers=self._headers, verify=self._cert_bundle)

		if req.status_code == 200:
			return req.json()['sessions']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def new_totp_credentials(self):
		"""
		Suggest new TOTP credentials for two-factor authentication (2FA).

		_Note: 2FA for authentication is not supported in this library._

		:returns: JSON object
		"""
		req = requests.get(self.url + "/auth/totp", headers=self._headers, verify=self._cert_bundle)

		if req.status_code == 200:
			return req.json()['totp']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")


class MetricAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_history(self):
		"""
		Get activity graph data

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/history", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['history']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_client_history(self, count=5):
		"""
		Get per-client activity graph data over the last 24 hours.

		The last client returned is a special client that contains the total number of queries that were sent by clients that are not in the top N. This client is always present, even if it has 0 queries and can be identified by the special name "other clients" (mind the space in the hostname) and the IP address "0.0.0.0".

		Note that, due to privacy settings, the returned data may also be empty.

		:param: Number of top clients. If set to 0, all clients will be returned.
		:returns: JSON object
		"""
		req = requests.get(self._pi.url + f"/history/clients?N={count}", headers=self._pi._headers, verify=self._pi._cert_bundle)
		req_json = req.json()

		if req.status_code == 200:
			return {
				"clients": req_json['clients'],
				"history": req_json['history']
			}

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_long_term_history(self, start: int, end: int):
		"""
		Get activity graph data (long-term data).

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		req = requests.get(self._pi.url + f"/history/database?from={start}&until={end}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['history']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_long_term_client_history(self, start: int, end: int):
		"""
		Get per-client activity graph data (long-term data).

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		req = requests.get(self._pi.url + f"/history/database/clients?from={start}&until={end}", headers=self._pi._headers, verify=self._pi._cert_bundle)
		req_json = req.json()

		if req.status_code == 200:
			return {
				"clients": req_json['clients'],
				"history": req_json['history']
			}

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_queries(self, filter={}):
		"""
		Request query details.

		By default, this API callback returns the most recent 100 queries. This can be changed using the parameter _length_.

		:param: filter: Filter options. See also Pi-hole API documentation.
		:returns: JSON object

		:param: (optional) from [integer]: Get queries from...
		:param: (optional) until [integer]: Get queries until...
		:param: (optional) length [integer]: Number of results to return
		:param: (optional) start [integer]: Offset from first record
		:param: (optional) cursor [integer]: Database ID of the most recent query to be shown
		:param: (optional) domain [string]: Filter by specific domain (wildcards supported)
		:param: (optional) client_ip [string]: Filter by specific client IP address (wildcards supported)
		:param: (optional) client_name [string]: Filter by specific client hostname (wildcards supported)
		:param: (optional) upstream [string]: Filter by specific upstream (wildcards supported)
		:param: (optional) type [string]: Filter by specific query type (A, AAAA, ...)
		:param: (optional) status [string]: Filter by specific query status (GRAVITY, FORWARDED, ...)
		:param: (optional) reply [string]: Filter by specific reply type (NODATA, NXDOMAIN, ...)
		:param: (optional) dnssec [string]: Filter by specific DNSSEC status (SECURE, INSECURE, ...)
		:param: (optional) disk [bool]: Load queries from on-disk database rather than from in-memory
		"""
		endpoint = "/queries?"

		query_params = ""
		for keyword, value in filter.items():
			query_params = query_params + keyword + "=" + str(value) + "&"

		# Mitigate potential problems with single ampersand at the end
		query_params = query_params.removesuffix("&")

		req = requests.get(self._pi.url + endpoint + query_params, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_suggestions(self):
		"""
		Get query filter suggestions suitable for _get_queries_
		"""
		req = requests.get(self._pi.url + "/queries/suggestions", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['suggestions']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_long_term_query_types(self, start: int, end: int):
		"""
		Get query types (long-term database).

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		req = requests.get(self._pi.url + f"/stats/database/query_types?from={start}&until={end}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['types']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_database_summary(self, start: int, end: int):
		"""
		Get database content details.

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		req = requests.get(self._pi.url + f"/stats/database/summary?from={start}&until={end}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_long_term_top_clients(self, start: int, end: int, **kwargs):
		"""
		Get top clients (long-term database).

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:param: (optional) blocked [bool]: Return information about permitted or blocked queries
		:param: (optional) count [int]: Number of requested items
		:returns: JSON object
		"""
		optional_params = "&"
		for filter, value in kwargs.items():
			optional_params = optional_params + filter + "=" + str(value) + "&"

		# Mitigate potential problems with single ampersand at the end
		optional_params = optional_params.removesuffix("&")

		req = requests.get(self._pi.url + f"/stats/database/top_clients?from={start}&until={end}" + optional_params, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_long_term_top_domains(self, start: int, end: int, **kwargs):
		"""
		Get top domains (long-term database).

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:param: (optional) blocked [bool]: Return information about permitted or blocked queries
		:param: (optional) count [int]: Number of requested items
		:returns: JSON object
		"""
		optional_params = "&"
		for filter, value in kwargs.items():
			optional_params = optional_params + filter + "=" + str(value) + "&"

		# Mitigate potential problems with single ampersand at the end
		optional_params = optional_params.removesuffix("&")

		req = requests.get(self._pi.url + f"/stats/database/top_domains?from={start}&until={end}" + optional_params, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_long_term_upstreams(self, start: int, end: int):
		"""
		Get metrics about Pi-hole's upstream destinations (long-term database).

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		req = requests.get(self._pi.url + f"/stats/database/upstreams?from={start}&until={end}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_query_types(self):
		"""
		Get query types.

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/stats/query_types", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['types']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_recently_blocked(self, count=1):
		"""
		Get most recently blocked domain.

		:param: Number of blocked domains
		:returns: JSON object
		"""
		req = requests.get(self._pi.url + f"/stats/recent_blocked?{count}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_summary(self):
		"""
		Get overview of Pi-hole activity

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/stats/summary", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_top_clients(self, **kwargs):
		"""
		Get top clients.

		:param: (optional) blocked [bool]: Return information about permitted or blocked queries
		:param: (optional) count [int]: Number of requested items
		:returns: JSON object
		"""
		optional_params = ""
		for filter, value in kwargs.items():
			optional_params = optional_params + filter + "=" + str(value) + "&"

		# Mitigate potential problems with single ampersand at the end
		optional_params = optional_params.removesuffix("&")

		req = requests.get(self._pi.url + "/stats/top_clients?" + optional_params, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_top_domains(self, **kwargs):
		"""
		Get top domains.

		:param: (optional) blocked [bool]: Return information about permitted or blocked queries
		:param: (optional) count [int]: Number of requested items
		:returns: JSON object
		"""
		optional_params = ""
		for filter, value in kwargs.items():
			optional_params = optional_params + filter + "=" + str(value) + "&"

		# Mitigate potential problems with single ampersand at the end
		optional_params = optional_params.removesuffix("&")

		req = requests.get(self._pi.url + "/stats/top_domains?" + optional_params, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_upstreams(self):
		"""
		Get metrics about Pi-hole's upstream destinations.

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/stats/upstreams", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")


class DnsFilterAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_state(self):
		"""
		Get current blocking state.

		:returns: JSON object
		"""
		# TODO: Introduce BlockingStateEnum?
		req = requests.get(self._pi.url + "/dns/blocking", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def enable(self, timer: int):
		"""
		Enable blocking for a set amount of seconds. After the timer has ended, the opposite blocking mode will be set.

		Setting _timer_ to 0 causes the blocking mode to be set indefinitely.

		:params: timer: Time in seconds for enabling blocking
		:returns: JSON object
		"""
		# Set timer to indefinite
		if timer == 0:
			timer = None

		payload = {
			"blocking": True,
			"timer": timer
		}

		req = requests.post(self._pi.url + "/dns/blocking", json=payload, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def disable(self, timer: int):
		"""
		Disable blocking for a set amount of seconds. After the timer has ended, the opposite blocking mode will be set.

		Setting _timer_ to 0 causes the blocking mode to be set indefinitely.

		:params: timer: Time in seconds for disabling blocking
		:returns: JSON object
		"""
		# Set timer to indefinite
		if timer == 0:
			timer = None

		payload = {
			"blocking": False,
			"timer": timer
		}

		req = requests.post(self._pi.url + "/dns/blocking", json=payload, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")


class GroupAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_groups(self):
		"""
		Get all groups

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/groups", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['groups']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_group(self, name: str):
		"""
		Get specific group

		:returns: JSON object or None if not found
		"""
		req = requests.get(self._pi.url + f"/groups/{name}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			groups = req.json()['groups']
			if len(groups) == 1:
				return groups[0]

			return None

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def create_group(self, name: str, comment="", enabled=True):
		"""
		Create a new group.

		A "UNIQUE constraint failed" error indicates that a group with the same name already exists.

		:param: name: Name of the group
		:param: comment: Comment describing the group
		:param: enabled: Whether the group is enabled or not
		:returns: JSON object
		"""
		group = {
			"name": name,
			"comment": comment,
			"enabled": enabled
		}

		req = requests.post(self._pi.url + "/groups", json=group, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 201:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 group
				error = json_data['processed']['errors'][0]
				raise ApiError(f"{error['item']} - {error['error']}")

			return json_data['groups'][0]

		if req.status_code == 400:
			# "Invalid request body data (no valid JSON)" is not possible
			# because the body structure is not controllable by the user
			raise UniqueConstraintException(req.json()['error']['message'])

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def rename_group(self, old_name: str, new_name: str):
		"""
		Rename a group.

		:param: old_name: Name the group currently has
		:param: new_name: Name to change to
		:returns: JSON object
		"""
		group = self.get_group(old_name)

		if not group:
			raise ItemNotFoundException(f"Group '{old_name}' not found")

		group["name"] = new_name

		req = requests.put(self._pi.url + f"/groups/{old_name}", json=group, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 group
				error = json_data['processed']['errors'][0]
				raise ApiError(f"{error['item']} - {error['error']}")

			return json_data['groups'][0]

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def update_group_comment(self, name: str, comment: str):
		"""
		Modify the comment of a group

		:param: name: Name of the group
		:param: comment: New comment for the group
		:returns: JSON object
		"""
		group = self.get_group(name)

		if not group:
			raise ItemNotFoundException(f"Group '{name}' not found")

		group["comment"] = comment

		req = requests.put(self._pi.url + f"/groups/{name}", json=group, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 group
				error = json_data['processed']['errors'][0]
				raise ApiError(f"{error['item']} - {error['error']}")

			return json_data['groups'][0]

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def enable_group(self, name: str):
		"""
		Enable group.

		:param: name: Group name
		:returns: JSON object
		"""
		group = self.get_group(name)

		if not group:
			raise ItemNotFoundException(f"Group '{name}' not found")

		group["enabled"] = True

		req = requests.put(self._pi.url + f"/groups/{name}", json=group, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 group
				error = json_data['processed']['errors'][0]
				raise ApiError(f"{error['item']} - {error['error']}")

			return json_data['groups'][0]

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def disable_group(self, name: str):
		"""
		Disable group.

		:param: name: Group name
		:returns: JSON object
		"""
		group = self.get_group(name)

		if not group:
			raise ItemNotFoundException(f"Group '{name}' not found")

		group["enabled"] = False

		req = requests.put(self._pi.url + f"/groups/{name}", json=group, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 group
				error = json_data['processed']['errors'][0]
				raise ApiError(f"{error['item']} - {error['error']}")

			return json_data['groups'][0]

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def delete_groups(self, names: list):
		"""
		Delete groups by name.

		:param: names: Group names
		"""
		groups = []
		for name in names:
			groups.append({"item": name})

		req = requests.post(self._pi.url + "/groups:batchDelete", json=groups, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print("Groups deleted")

		if req.status_code == 400:
			raise BadRequestException("Unexpected request body format.", response=req.json())

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		if req.status_code == 404:
			raise ItemNotFoundException("Groups not found")

		raise ApiError("API request failed due to unknown reasons")

	def delete_group(self, name: str):
		"""
		Delete group by name.

		:param: name: Group name
		"""
		req = requests.delete(self._pi.url + f"/groups/{name}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print(f"Group '{name}' deleted")

		if req.status_code == 401:
			raise AuthenticationRequiredException("Authentication required")

		if req.status_code == 404:
			raise ItemNotFoundException(f"Group '{name}' not found")

		raise ApiError("API request failed due to unknown reasons")


class DomainAPI:
	def __init__(self, pi):
		self._pi = pi

	def delete_domains(self, domains: list):
		"""
		Delete domains from Domain tab.

		Domains: A list of domain objects where each object contains the following data:
		:param: item: Domain name
		:param: type: allow|deny
		:param: kind: exact|regex
		"""
		req = requests.post(self._pi.url + "/domains:batchDelete", json=domains, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print("Domains deleted")

		if req.status_code == 400:
			raise BadRequestException("Unexpected request body format.", response=req.json())

		if req.status_code == 401:
			raise AuthenticationRequiredException("Authentication required")

		if req.status_code == 404:
			raise ItemNotFoundException("Domains not found")

		raise ApiError("API request failed due to unknown reasons")

	def add_domain(self, domain: str, type: str, kind: str, comment="", groups=[0], enabled=True):
		"""
		Add a new domain to the Domain tab.

		A "UNIQUE constraint failed" error indicates that a domain with the same name already exists.

		When adding a regular expression, ensure the request body is properly JSON-escaped.

		:param: domain: Name of the domain
		:param: type: allow|deny
		:param: kind: exact|regex
		:param: comment: Comment for describing the domain
		:param: groups: List of integers describing which groups the domain is assigned to
		:param: enabled: Whether the domain is enabled
		:returns: JSON object
		"""
		payload = {
			"domain": domain,
			"comment": comment,
			"groups": groups,
			"enabled": enabled
		}

		req = requests.post(self._pi.url + f"/domains/{type}/{kind}", json=payload, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 201:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 domain
				error = json_data['processed']['errors'][0]
				raise ApiError(f"{error['item']} - {error['error']}")

			return json_data['domains'][0]

		if req.status_code == 400:
			error = req.json()['error']

			if error['key'] == "bad_request":
				raise DataFormatException(error['message'])

			if error['key'] == "database_error":
				raise UniqueConstraintException(error['message'])

			if error['key'] == "regex_error":
				raise DataFormatException(f"{error['message']} - {error['hint']}")

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def search_domains(self, domain=None, type=None, kind=None):
		"""
		Get domains of a certain characteristic. Set any of the parameter to narrow down the search.

		:param: (optional) domain: Name of the domain
		:param: (optional) type: allow|deny
		:param: (optional) kind: exact|regex
		:returns: JSON object
		"""
		endpoint = "/domains"

		if type == "allow" or type == "deny":
			endpoint = endpoint + f"/{type}"

		if kind == "exact" or kind == "regex":
			endpoint = endpoint + f"/{kind}"

		if domain:
			endpoint = endpoint + f"/{domain}"

		req = requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['domains']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def delete_domain(self, domain: str, type: str, kind: str):
		"""
		Delete domain from Domain tab.

		:param: domain: Name of the domain
		:param: type: allow|deny
		:param: kind: exact|regex
		"""
		req = requests.delete(self._pi.url + f"/domains/{type}/{kind}/{domain}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print(f"Domain '{domain}' deleted")

		if req.status_code == 400:
			raise BadRequestException(req.json()["error"]["message"])

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		if req.status_code == 404:
			raise ItemNotFoundException(f"Domain '{domain}' not found")

		raise ApiError("API request failed due to unknown reasons")

	def update_domain(self, domain: dict, new_values: dict):
		# TODO: This endpoints' description is confusing
		# Separate into update_domain_<parameter> where parameter is type, kind, comment, and groups as well as enable, disable
		"""
		Update values of a domain.

		:param: domain: Current domain object. Be careful of specifying every value, otherwise they will be overwritten. These are the values that should be included:
		:param: domain: Name of the domain
		:param: type: allow|deny
		:param: kind: exact|regex
		:param: comment: Comment for describing the domain
		:param: groups: List of integers describing which groups the domain is assigned to
		:param: enabled: Whether the domain is enabled

		:param: new_values: New values that should be changed. Parameters that are not contained in this object will not be changed.
		:returns: JSON object
		"""
		old_domain = domain["domain"]
		old_type = domain["type"]
		old_kind = domain["kind"]

		for key, value in new_values.items():
			domain[key] = value

		return requests.put(self._pi.url + f"/domains/{old_type}/{old_kind}/{old_domain}", json=domain, headers=self._pi._headers, verify=self._pi._cert_bundle).json()


class ClientAPI:
	def __init__(self, pi):
		self._pi = pi

	def add_client(self, address: str, comment="", groups=[0]):
		"""
		Add a new client.

		A "UNIQUE constraint failed" error indicates that a client with the same address already exists.

		:param: address: IPv4/IPv6 or MAC or hostname or interface (e.g. :eth0)
		:param: comment: Comment for describing the client
		:param: groups: List of integers describing which groups the client is assigned to
		:return: JSON object
		"""
		payload = {
			"client": address,
			"comment": comment,
			"groups": groups
		}

		req = requests.post(self._pi.url + "/clients", json=payload, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 201:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 client
				error = json_data['processed']['errors'][0]

				raise ApiError(f"{error['item']} - {error['error']}") 

			return json_data['clients'][0]

		if req.status_code == 400:
			# "Invalid request body data (no valid JSON)" is not possible
			# because the body structure is not controllable by the user
			raise UniqueConstraintException(req.json()['error']['message'])

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def delete_clients(self, clients: list):
		"""
		Delete clients.

		:param: clients: A list of client names
		"""
		payload = []
		for client in clients:
			payload.append({"item": client})

		req = requests.post(self._pi.url + "/clients:batchDelete", json=payload, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print("Clients deleted")

		if req.status_code == 400:
			raise BadRequestException("Unexpected request body format.", response=req.json())

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		if req.status_code == 404:
			raise ItemNotFoundException("Clients not found")

		raise ApiError("API request failed due to unknown reasons")

	def get_suggestions(self):
		"""
		Get client suggestions of unconfigured clients.

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/clients/_suggestions", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['clients']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_clients(self):
		"""
		Return all clients configured in the Client tab. Clients not added in this tab will not be returned by this endpoint. Refer to Network endpoint.

		:returns: JSON object
		"""
		endpoint = "/clients"
		req = requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['clients']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_client(self, address=None):
		"""
		Get a specific client configured in the Client tab. Clients not added in this tab will not be returned by this endpoint. Refer to Network endpoint.

		:param: address: IPv4/IPv6 or MAC or hostname or interface (e.g. :eth0)
		:returns: JSON object or None if not found
		"""
		endpoint = "/clients"

		if address:
			endpoint = endpoint + f"/{address}"

		req = requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			clients = req.json()['clients']
			if len(clients) == 1:
				return clients[0]

			return None

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def delete_client(self, address: str) -> bool:
		"""
		Delete client from the Client tab.

		:param: address: IPv4/IPv6 or MAC or hostname or interface (e.g. :eth0)
		"""
		req = requests.delete(self._pi.url + f"/clients/{address}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print(f"Client '{address}' deleted")

		if req.status_code == 400:
			raise BadRequestException("Unexpected request body format.", response=req.json())

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		if req.status_code == 404:
			raise ItemNotFoundException(f"Client '{address}' not found")

		raise ApiError("API request failed due to unknown reasons")

	def update_client_comment(self, address: str, comment: str):
		"""
		Update client comment.

		:param: address: IPv4/IPv6 or MAC or hostname or interface (e.g. :eth0)
		:param: comment: New comment
		:returns: JSON object
		"""
		client = self.get_client(address)

		if not client:
			raise ItemNotFoundException(f"Client '{address}' not found")

		client["comment"] = comment

		req = requests.put(self._pi.url + "/clients/" + client["address"], json=client, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 client
				error = json_data['processed']['errors'][0]

				raise ApiError(f"{error['item']} - {error['error']}") 

			return json_data['clients'][0]

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def update_groups(self, address: str, groups: list):
		"""
		Update groups a client is assigned to.

		:param: address: IPv4/IPv6 or MAC or hostname or interface (e.g. :eth0)
		:param: groups: New groups
		:returns: JSON object
		"""
		client = self.get_client(address)

		if not client:
			raise ItemNotFoundException(f"Client '{address}' not found")

		client["groups"] = groups

		req = requests.put(self._pi.url + "/clients/" + client["address"], json=client, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 client
				error = json_data['processed']['errors'][0]

				raise ApiError(f"{error['item']} - {error['error']}") 

			return json_data['clients'][0]

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")


class ListAPI:
	def __init__(self, pi):
		self._pi = pi

	def add_list(self, address: str, type: str, comment="", groups=[0], enabled=True):
		"""
		Add new list.

		A "UNIQUE constraint failed" error indicates that a client with the same address already exists.

		:param: address: Address of the list
		:param: type: allow | block
		:param: comment: Comment for the list
		:param: groups: Groups that the list is assigned to
		:param: enabled: Whether the list is enabled
		:return: JSON object
		"""
		payload = {
			"address": address,
			"type": type,
			"comment": comment,
			"groups": groups,
			"enabled": enabled
		}

		req = requests.post(self._pi.url + "/lists", json=payload, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 201:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 client
				error = json_data['processed']['errors'][0]

				raise ApiError(f"{error['item']} - {error['error']}") 

			return json_data['lists'][0]

		if req.status_code == 400:
			# "Invalid request body data (no valid JSON)" is not possible
			# because the body structure is not controllable by the user
			raise UniqueConstraintException(req.json()['error']['message'])

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def delete_lists(self, lists: list):
		"""
		Delete several lists.

		Each list object has the following keys:
		:param: item: List address
		:param: type: allow | block
		"""
		req = requests.post(self._pi.url + "/lists:batchDelete", json=lists, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print("Lists deleted")

		if req.status_code == 400:
			raise BadRequestException("Unexpected request body format.", response=req.json())

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		if req.status_code == 404:
			raise ItemNotFoundException("Lists not found")

		raise ApiError("API request failed due to unknown reasons")

	def get_lists(self, type=None):
		"""
		Get all lists.

		:param: (optional) type: allow | block
		"""
		endpoint = "/lists/"

		if type == "allow" or type == "block":
			endpoint = endpoint + "?type=" + type

		req = requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['lists']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_list(self, address: str):
		"""
		Get lists. By default, all lists will be returned.

		:param: address: Address of the list

		:returns: JSON object or None if not found
		"""
		endpoint = "/lists/" + address
		req = requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			lists = req.json()['lists']
			if len(lists) == 1:
				return lists[0]

			return None

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def delete_list(self, address: str):
		"""
		Delete a list.

		:param: address: Address of the list
		"""
		req = requests.delete(self._pi.url + f"/lists/{address}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print(f"List '{address}' deleted")

		if req.status_code == 400:
			raise BadRequestException("Unexpected request body format.", response=req.json())

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		if req.status_code == 404:
			raise ItemNotFoundException(f"List '{address}' not found")

		raise ApiError("API request failed due to unknown reasons")

	def search(self, address: str, partial=False, count=20, debug=False):
		"""
		Search lists for domains.

		There is a hard limit set in FTL (default: 10,000) to ensure that the response does not get too large.

		:param: address: Domain to search for
		:param: (optional) partial: Whether partial results should be returned. If activated, ABP results are not returned.
		:param: (optional) count: Number of maximum results to return
		:param: (optional) debug: Add debug information to the response
		"""
		endpoint = f"/search/{address}?partial={partial}&N={count}&debug={debug}"

		req = requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['search']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def update_list_comment(self, address: str, comment: str):
		"""
		Update comment of list

		:param: address: List address
		:param: comment: Comment of the list
		:returns: JSON object
		"""
		list = self.get_lists(address)

		if not list:
			raise ItemNotFoundException(f"List '{address}' not found")

		list["comment"] = comment

		req = requests.put(self._pi.url + "/lists/" + address, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 client
				error = json_data['processed']['errors'][0]

				raise ApiError(f"{error['item']} - {error['error']}") 

			return json_data['lists'][0]

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def update_type_list(self, address: str, type: str):
		"""
		Update type of list

		:param: address: List address
		:param: type: allow | block
		:returns: JSON object
		"""
		list = self.get_lists(address)

		if not list:
			raise ItemNotFoundException(f"List '{address}' not found")

		list["type"] = type

		req = requests.put(self._pi.url + "/lists/" + address, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 client
				error = json_data['processed']['errors'][0]

				raise ApiError(f"{error['item']} - {error['error']}") 

			return json_data['lists'][0]

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def update_groups(self, address: str, groups: list):
		"""
		Update groups assigned to list

		:param: address: List address
		:param: groups: List of integers representing the group IDs
		:returns: JSON object
		"""
		list = self.get_lists(address)

		if not list:
			raise ItemNotFoundException(f"List '{address}' not found")

		list["groups"] = groups

		req = requests.put(self._pi.url + "/lists/" + address, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 client
				error = json_data['processed']['errors'][0]

				raise ApiError(f"{error['item']} - {error['error']}") 

			return json_data['lists'][0]

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def enable(self, address: str):
		"""
		Enable list

		:param: address: List address
		:returns: JSON object
		"""
		list = self.get_lists(address)

		if not list:
			raise ItemNotFoundException(f"List '{address}' not found")

		list["enabled"] = True

		req = requests.put(self._pi.url + "/lists/" + address, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 client
				error = json_data['processed']['errors'][0]

				raise ApiError(f"{error['item']} - {error['error']}") 

			return json_data['lists'][0]

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def disable(self, address: str):
		"""
		Disable list

		:param: address: List address
		:returns: JSON object
		"""
		list = self.get_lists(address)

		if not list:
			raise ItemNotFoundException(f"List '{address}' not found")

		list["enabled"] = False

		req = requests.put(self._pi.url + "/lists/" + address, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			json_data = req.json()

			if json_data['processed']['errors']:
				# Method never handling more than 1 client
				error = json_data['processed']['errors'][0]

				raise ApiError(f"{error['item']} - {error['error']}") 

			return json_data['lists'][0]

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")


class FtlAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_endpoints(self):
		"""
		Get list of available API endpoints

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/endpoints", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['endpoints']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_client_info(self):
		"""
		Get information about requesting client

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/info/client", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_database_info(self):
		"""
		Get information about long-term database

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/info/database", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_ftl_info(self):
		"""
		Get info about various ftl parameters

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/info/ftl", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['ftl']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_host_info(self):
		"""
		Get info about various host parameters

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/info/host", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['host']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_login_info(self):
		"""
		Login page related information

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/info/login", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_messages(self):
		"""
		Get Pi-hole diagnosis messages

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/info/messages", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['messages']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def delete_message(self, message: int):
		"""
		Delete Pi-hole diagnosis messages

		:param: message: Message ID
		"""
		req = requests.delete(self._pi.url + f"/info/messages/{message}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print(f"Message {message} deleted")

		if req.status_code == 400:
			raise BadRequestException("Unexpected request body format.", response=req.json())

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		if req.status_code == 404:
			raise ItemNotFoundException(f"Message {message} not found")

		raise ApiError("API request failed due to unknown reasons")

	def get_message_count(self) -> int:
		"""
		Get count of Pi-hole diagnosis messages
		"""
		req = requests.get(self._pi.url + "/info/messages/count", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['count']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_metrics(self):
		"""
		Get metrics info about the DNS and DHCP metrics

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/info/metrics", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_sensor_info(self):
		"""
		Get info about various sensors

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/info/sensors", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['sensors']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_system_info(self):
		"""
		Get info about various system parameters

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/info/system", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['system']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_version(self):
		"""
		Get Pi-hole version

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/info/version", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['version']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_dnsmasq_log(self, next_id=None):
		"""
		Get DNS log content (dnsmasq)

		:param: (optional) next_id: Every successful request will return a _nextID_. This ID can be used on the next request to only get lines which were added after the last request. This makes periodic polling for new log lines easy as no check for duplicated log lines is necessary. The expected behavior for an immediate re-request of a log line with the same ID is an empty response. As soon as the next message arrived, this will be included in your request and _nextID_ is incremented by one.
		:returns: JSON object
		"""
		endpoint = "/logs/dnsmasq"
		if type(next_id) == int:
			endpoint = endpoint + f"?nextID={next_id}"

		req = requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_ftl_log(self, next_id=None):
		"""
		Get FTL log content

		:param: (optional) next_id: Every successful request will return a _nextID_. This ID can be used on the next request to only get lines which were added after the last request. This makes periodic polling for new log lines easy as no check for duplicated log lines is necessary. The expected behavior for an immediate re-request of a log line with the same ID is an empty response. As soon as the next message arrived, this will be included in your request and _nextID_ is incremented by one.
		:returns: JSON object
		"""
		endpoint = "/logs/ftl"
		if type(next_id) == int:
			endpoint = endpoint + f"?nextID={next_id}"

		req = requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_webserver_log(self, next_id=None):
		"""
		Get webserver log content (CivetWeb HTTP server)

		:param: (optional) next_id: Every successful request will return a _nextID_. This ID can be used on the next request to only get lines which were added after the last request. This makes periodic polling for new log lines easy as no check for duplicated log lines is necessary. The expected behavior for an immediate re-request of a log line with the same ID is an empty response. As soon as the next message arrived, this will be included in your request and _nextID_ is incremented by one.
		:returns: JSON object
		"""
		endpoint = "/logs/webserver"
		if type(next_id) == int:
			endpoint = endpoint + f"?nextID={next_id}"

		req = requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")


class TeleporterAPI:
	def __init__(self, pi):
		self._pi = pi

	def export_settings(self, archive: str, chunk_size=128) -> None:
		"""
		Request an archived copy of your Pi-hole's current configuration as a zip file.

		:param: archive: Path to save the zip file to (e.g. teleporter.zip)
		:param: (optional) chunk_size: Chunk size to write in one iteration
		"""
		req = requests.get(self._pi.url + "/teleporter", stream=True, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		with open(archive, 'wb') as fd:
			for chunk in req.iter_content(chunk_size=chunk_size):
				fd.write(chunk)

		print("Settings successfully exported")

	def import_settings(self, archive: str):
		# FIXME: does api return 403 response when forbidden?
		"""
		Import Pi-hole settings from a zip archive.

		This function requires "webserver.api.app_sudo" to be _True_.

		:param: archive: Path to zip archive
		:returns: JSON object
		"""
		file = open(archive, mode="rb")
		form_data = {"file": ('teleporter.zip', file, 'multipart/form-data')}
		req = requests.post(self._pi.url + "/teleporter", files=form_data, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()
		
		if req.status_code == 400:
			raise BadRequestException("File is not a zip archive")
		
		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")
		
		raise ApiError("API request failed due to unknown reasons")


class NetworkAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_devices(self, max_devices=10, max_addresses=3):
		"""
		Get info about the devices in your local network as seen by your Pi-hole.

		Devices are ordered by when your Pi-hole has received the last query from this device (most recent first).

		:param: (optional) max_devices: Maximum number of devices to show
		:param: (optional) max_addresses: Maximum number of addresses to show per device
		:returns: JSON object
		"""
		endpoint = f"/network/devices?max_devices={max_devices}&max_addresses={max_addresses}"

		req = requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['devices']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def delete_device(self, id: int):
		"""
		Delete a device from the network table

		This will also remove all associated IP addresses and hostnames.

		:param: id: ID of the device
		"""
		req = requests.delete(self._pi.url + f"/network/devices/{id}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print(f"Device {id} deleted")

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		if req.status_code == 404:
			raise ItemNotFoundException(f"Device {id} not found")

		raise ApiError("API request failed due to unknown reasons")

	def get_gateway(self, detailed=False):
		"""
		Get info about the gateway of your Pi-hole

		:param: (optional) detailed: May include detailed information about the individual interfaces and routes depending on the interface type and state
		:returns: JSON object
		"""
		endpoint = f"/network/gateway?detailed={detailed}"

		req = requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['gateway']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_interfaces(self, detailed=False):
		"""
		Get info about the interfaces of your Pi-hole

		:param: (optional) detailed: May include detailed information about the individual interfaces and routes depending on the interface type and state
		:returns: JSON object
		"""
		endpoint = f"/network/interfaces?detailed={detailed}"

		req = requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['interfaces']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def get_routes(self, detailed=False):
		"""
		Get info about the routes of your Pi-hole

		:param: (optional) detailed: May include detailed information about the individual interfaces and routes depending on the interface type and state
		:returns: JSON object
		"""
		endpoint = f"/network/routes?detailed={detailed}"

		req = requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['routes']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")


class ActionAPI:
	def __init__(self, pi):
		self._pi = pi

	def flush_network_table(self):
		"""
		Flush the network table (ARP)

		For this to work, the webserver.api.allow_destructive setting needs to be _True_.

		:returns: JSON object
		"""
		req = requests.post(self._pi.url + "/action/flush/arp", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		if req.status_code == 403:
			raise ForbiddenException("Flushing the network table is not allowed. Check the setting webserver.api.allow_destructive")

		raise ApiError("API request failed due to unknown reasons")

	def flush_dns_logs(self):
		"""
		Flush DNS logs

		:returns: JSON object
		"""
		req = requests.post(self._pi.url + "/action/flush/logs", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def run_gravity(self):
		"""
		Run gravity

		Update Pi-hole's adlists by running pihole -g. The output of the process is streamed with chunked encoding.

		:returns: Streamed chunks (generator) if successful, JSON object otherwise
		"""
		req = requests.post(self._pi.url + "/action/gravity", stream=True, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			for chunk in req.iter_content(chunk_size=128, decode_unicode=True):
				yield chunk
		elif req.status_code == 401:
				raise AuthenticationRequiredException("No valid session token provided")
		else:
			raise ApiError("API request failed due to unknown reasons")

	def restart_dns(self):
		"""
		Restart pihole-FTL

		:returns: JSON object
		"""
		req = requests.post(self._pi.url + "/action/restartdns", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")


class PaddAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_data(self, full=False):
		"""
		Get data for PADD

		:param: (optional) full: Return full data
		:returns: JSON object
		"""
		req = requests.get(self._pi.url + f"/padd?full={full}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")


class ConfigAPI:
	def __init__(self, pi):
		self._pi = pi

	def get(self, element=None, detailed=False):
		"""
		Get entire Pi-hole configuration or one specific element.

		:param: (optional) element: Set to only get one specific element.
		:returns: JSON object
		"""
		endpoint = "/config"

		if element:
			endpoint = endpoint + f"/{element}"

		if detailed:
			endpoint = endpoint + f"?detailed={detailed}"

		req = requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def patch(self, config: dict):
		"""
		Update one or several configurations at once

		:returns: JSON object
		"""
		req = requests.patch(self._pi.url + "/config", json=config, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def set(self, element: str, value: str):
		"""
		Set Pi-hole config

		:returns: None if successful, JSON object otherwise
		"""
		req = requests.put(self._pi.url + f"/config/{element}/{value}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 201:
			print(f"Config '{element}' successfully set")

		if req.status_code == 400:
			raise BadRequestException("Unexpected request body format.", response=req.json())

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def delete(self, element: str, value: str):
		"""
		Delete Pi-hole config
		"""
		req = requests.delete(self._pi.url + f"/config/{element}/{value}", headers=self._pi._headers, verify=self._pi._cert_bundle)
		
		if req.status_code == 204:
			print(f"Config '{element}' deleted")

		if req.status_code == 400:
			raise BadRequestException("Unexpected request body format.", response=req.json())

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		if req.status_code == 404:
			raise ItemNotFoundException(f"Config '{element}' not found")

		raise ApiError("API request failed due to unknown reasons")


class DhcpAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_leases(self):
		"""
		Get currently active DHCP leases

		:returns: JSON object
		"""
		req = requests.get(self._pi.url + "/dhcp/leases", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 200:
			return req.json()['leases']

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		raise ApiError("API request failed due to unknown reasons")

	def delete_lease(self, ip: str):
		"""
		Remove active DHCP lease
		
		Managing DHCP leases is only possible when the DHCP server is enabled.

		:params: ip: IP address of the lease to remove
		"""
		req = requests.delete(self._pi.url + f"/dhcp/leases/{ip}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print(f"Lease for {ip} deleted")

		if req.status_code == 400:
			raise BadRequestException("Unexpected request body format.", response=req.json())

		if req.status_code == 401:
			raise AuthenticationRequiredException("No valid session token provided")

		if req.status_code == 404:
			raise ItemNotFoundException(f"Lease for {ip} not found")

		raise ApiError("API request failed due to unknown reasons")
