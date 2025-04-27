import requests

import utils

CERT_BUNDLE = utils.get_config('cert_bundle')


class Pihole:
	def __init__(self, url: str):
		self.url = url

		self._headers = None

		self.metrics = MetricAPI(self)
		self.dns_filter = DnsFilterAPI(self)
		self.groups = GroupAPI(self)
		self.domains = DomainAPI(self)
		self.clients = ClientAPI(self)

	def is_auth_required(self):
		"""
		Check if authentication is required.

		Returns: JSON object
		"""
		return requests.get(self.url + "/auth", headers=self._headers, verify=CERT_BUNDLE).json()

	def authenticate(self):
		"""
		Creates a session token via the password provided in the config file.

		:returns:
		- None if successful
		- JSON object
		"""
		try:
			password = utils.get_config("password")
		except KeyError:
			print("No password provided in config file")
			return {}

		payload = {"password": password}
		auth_request = requests.post(self.url + "/auth", json=payload, verify=CERT_BUNDLE)

		if auth_request.status_code == 200:
			if auth_request.json()['session']['sid'] is None:
				print("Authentication not required")
				self._headers = None
				return {}

			self._headers = {
				"X-FTL-SID": auth_request.json()['session']['sid'],
				"X-FTL-CSRF": auth_request.json()['session']['csrf']
			}
			print("Authentication successful")
		elif auth_request.status_code == 429:
			self._headers = None
			print("Rate limit exceeded")
			return auth_request.json()
		else:
			self._headers = None
			print("Authentication not successful")
			return auth_request.json()

	def delete_current_session(self) -> bool:
		"""
		Delete the current session.

		:returns: bool
		"""
		req = requests.delete(self.url + "/auth", headers=self._headers, verify=CERT_BUNDLE)
		if req.status_code == 204:
			print("Current session deleted")
			return True

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("No active session")

		return False

	def create_app_password(self):
		"""
		Creates a password to authenticate against the API instead of the user password. Overwrites the password defined in the config file.

		Returns:
		- None if successful
		- JSON object otherwise
		"""
		req = requests.get(self.url + "/auth/app", headers=self._headers, verify=CERT_BUNDLE)
		if req.status_code == 200:
			password = req.json()["app"]["password"]
			hash = req.json()["app"]["hash"]

			utils.set_config("password", password)

			payload = {
				"config": {
					"webserver": {
						"api": {
							"app_pwhash": hash
						}
					}
				}
			}

			requests.patch(self.url + "/config", headers=self._headers, json=payload, verify=CERT_BUNDLE)
			print("Password created")
		else:
			return req.json()

	def delete_session(self, id: int):
		"""
		Deletes the session with the given id.
		"""
		req = requests.delete(self.url + "/auth/session/" + str(id), headers=self._headers, verify=CERT_BUNDLE)
		if req.status_code == 204:
			print("Session deleted")

		if req.status_code == 400:
			print("Bad request")
			return req.json()

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("Session not found")

	def get_sessions(self):
		"""
		Get a list of all sessions.

		Returns: JSON object
		"""
		return requests.get(self.url + "/auth/sessions", headers=self._headers, verify=CERT_BUNDLE).json()

	def new_totp_credentials(self):
		"""
		Suggest new TOTP credentials for two-factor authentication (2FA).

		:returns: JSON object
		"""
		return requests.get(self.url + "/auth/totp", headers=self._headers, verify=CERT_BUNDLE).json()


class MetricAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_history(self):
		"""
		Get activity graph data

		Returns: JSON object
		"""
		return requests.get(self._pi.url + "/history", headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def get_client_history(self, count=5):
		"""
		Get per-client activity graph data over the last 24 hours.

		The last client returned is a special client that contains the total number of queries that were sent by clients that are not in the top N. This client is always present, even if it has 0 queries and can be identified by the special name "other clients" (mind the space in the hostname) and the IP address "0.0.0.0".

		Note that, due to privacy settings, the returned data may also be empty.

		:param: Number of top clients. If set to 0, all clients will be returned.
		:returns: JSON object
		"""
		return requests.get(self._pi.url + f"/history/clients?N={count}", headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def get_long_term_history(self, start: int, end: int):
		"""
		Get activity graph data (long-term data).

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		return requests.get(self._pi.url + f"/history/clients?from={start}&until={end}", headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def get_long_term_client_history(self, start: int, end: int):
		"""
		Get per-client activity graph data (long-term data).

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		return requests.get(self._pi.url + f"/history/database/clients?from={start}&until={end}", headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def get_queries(self, options={}):
		# TODO: It is unclear if "from" and "until" are optional or required parameters
		"""
		Request query details.

		By default, this API callback returns the most recent 100 queries. This can be changed using the parameter _length_.

		:param: options: Filter options. See also Pi-hole API documentation.
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
		endpoint = "/history/database/clients?"

		query_params = ""
		for filter, value in options.items():
			query_params = query_params + filter + "=" + str(value) + "&"

		query_params = query_params.removesuffix("&")

		return requests.get(self._pi.url + endpoint + query_params, headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def get_suggestions(self):
		"""
		Get query filter suggestions suitable for _get\_queries_
		"""
		return requests.get(self._pi.url + "/queries/suggestions", headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def get_long_term_query_types(self, start: int, end: int):
		"""
		Get query types (long-term database).

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		return requests.get(self._pi.url + f"/stats/database/query_types?from={start}&until={end}", headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def get_database_summary(self, start: int, end: int):
		"""
		Get database content details.

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		return requests.get(self._pi.url + f"/stats/database/summary?from={start}&until={end}", headers=self._pi._headers, verify=CERT_BUNDLE).json()

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

		optional_params = optional_params.removesuffix("&")

		return requests.get(self._pi.url + f"/stats/database/top_clients?from={start}&until={end}" + optional_params, headers=self._pi._headers, verify=CERT_BUNDLE).json()

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

		optional_params = optional_params.removesuffix("&")

		return requests.get(self._pi.url + f"/stats/database/top_domains?from={start}&until={end}" + optional_params, headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def get_long_term_upstreams(self, start: int, end: int):
		"""
		Get metrics about Pi-hole's upstream destinations (long-term database).

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		return requests.get(self._pi.url + f"/stats/database/upstreams?from={start}&until={end}", headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def get_query_types(self):
		"""
		Get query types.

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/stats/query_types", headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def get_recently_blocked(self, count=1):
		"""
		Get most recently blocked domain.

		:param: Number of blocked domains
		:returns: JSON object
		"""
		return requests.get(self._pi.url + f"/stats/recent_blocked?{count}", headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def get_summary(self):
		"""
		Get overview of Pi-hole activity

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/stats/summary", headers=self._pi._headers, verify=CERT_BUNDLE).json()

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

		optional_params = optional_params.removesuffix("&")

		return requests.get(self._pi.url + "/stats/top_clients?" + optional_params, headers=self._pi._headers, verify=CERT_BUNDLE).json()

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

		optional_params = optional_params.removesuffix("&")

		return requests.get(self._pi.url + "/stats/top_domains?" + optional_params, headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def get_upstreams(self):
		"""
		Get metrics about Pi-hole's upstream destinations.

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/stats/upstreams", headers=self._pi._headers, verify=CERT_BUNDLE).json()


class DnsFilterAPI:
	def __init__(self, pi):
		self._pi = pi

	def is_active(self):
		"""
		Get current blocking state.

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/dns/blocking", headers=self._pi._headers, verify=CERT_BUNDLE).json()

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

		return requests.post(self._pi.url + "/dns/blocking", json=payload, headers=self._pi._headers, verify=CERT_BUNDLE).json()

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

		return requests.post(self._pi.url + "/dns/blocking", json=payload, headers=self._pi._headers, verify=CERT_BUNDLE).json()


class GroupAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_groups(self):
		return requests.get(self._pi.url + "/groups", headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def get_group(self, name: str):
		return requests.get(self._pi.url + f"/groups/{name}", headers=self._pi._headers, verify=CERT_BUNDLE).json()

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

		return requests.post(self._pi.url + "/groups", json=group, headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def rename_group(self, old_name: str, new_name: str):
		"""
		Rename a group.

		:param: old_name: Name the group currently has
		:param: new_name: Name to change to
		:returns: JSON object
		"""
		try:
			group = self.get_group(old_name)["groups"][0]
		except KeyError:
			print("Group not found")
			return {}

		group["name"] = new_name

		return requests.put(self._pi.url + f"/groups/{old_name}", json=group, headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def update_group_comment(self, name: str, comment: str):
		"""
		Modify the comment of a group

		:param: name: Name of the group
		:param: comment: New comment for the group
		:returns: JSON object
		"""
		try:
			group = self.get_group(name)["groups"][0]
		except KeyError:
			print("Group not found")
			return {}

		group["comment"] = comment

		return requests.put(self._pi.url + f"/groups/{name}", json=group, headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def enable_group(self, name: str):
		"""
		Enable group.

		:param: name: Group name
		:returns: JSON object
		"""
		try:
			group = self.get_group(name)["groups"][0]
		except KeyError:
			print("Group not found")
			return {}

		group["enabled"] = True

		return requests.put(self._pi.url + f"/groups/{name}", json=group, headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def disable_group(self, name: str):
		"""
		Disable group.

		:param: name: Group name
		:returns: JSON object
		"""
		try:
			group = self.get_group(name)["groups"][0]
		except KeyError:
			print("Group not found")
			return {}

		group["enabled"] = False

		return requests.put(self._pi.url + f"/groups/{name}", json=group, headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def delete_groups(self, *names) -> bool:
		"""
		Delete groups by name.

		:param: name: Group names
		:returns: bool
		"""
		groups = []
		for name in names:
			groups.append({"item": name})

		req = requests.post(self._pi.url + "/groups:batchDelete", json=groups, headers=self._pi._headers, verify=CERT_BUNDLE)

		if req.status_code == 204:
			print("Groups deleted")
			return True

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("Groups not found")

		return False

	def delete_group(self, name: str) -> bool:
		"""
		Delete group by name.

		:param: name: Group name
		:returns: bool
		"""
		req = requests.delete(self._pi.url + f"/groups/{name}", headers=self._pi._headers, verify=CERT_BUNDLE)

		if req.status_code == 204:
			print("Group deleted")
			return True

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("Group not found")

		return False


class DomainAPI:
	def __init__(self, pi):
		self._pi = pi

	def delete_domains(self, domains: list) -> bool:
		"""
		Delete domains.

		Domains: A list of domain objects where each object contains the following data:
		:param: item: Domain name
		:param: type: allow|deny
		:param: kind: exact|regex
		:returns: bool
		"""
		req = requests.post(self._pi.url + "/domains:batchDelete", json=domains, headers=self._pi._headers, verify=CERT_BUNDLE)

		if req.status_code == 204:
			print("Domains deleted")
			return True

		if req.status_code == 400:
			print("Bad request. Unexpected request body format.")

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("Domains not found")

		return False

	def add_domain(self, domain: str, type: str, kind: str, comment="", groups=[0], enabled=True):
		"""
		Add a new domain.

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

		return requests.post(self._pi.url + f"/domains/{type}/{kind}", json=payload, headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def search_domains(self, domain=None, type=None, kind=None):
		"""
		Get domains of a certain characteristic. Set any of the parameter to narrow down the search.

		:param: (optional) domain: Name of the domain
		:param: (optional) type: allow|deny
		:param: (optional) kind: exact|regex
		:returns: JSON object
		"""
		endpoint = "/domains"

		if type is not None:
			if type == "allow" or type == "deny":
				endpoint = endpoint + f"/{type}"
			else:
				print("Domain type has an unexpected format")
				return

		if kind is not None:
			if kind == "exact" or kind == "regex":
				endpoint = endpoint + f"{kind}"
			else:
				print("Domain kind has an unexpected format")
			return

		if domain:
			endpoint = endpoint + f"/{domain}"
		return requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def delete_domain(self, domain: str, type: str, kind: str) -> bool:
		"""
		Delete domain

		:param: domain: Name of the domain
		:param: type: allow|deny
		:param: kind: exact|regex
		"""
		req = requests.delete(self._pi.url + f"/domains/{type}/{kind}/{domain}", headers=self._pi._headers, verify=CERT_BUNDLE)

		if req.status_code == 204:
			print("Domain deleted")
			return True

		if req.status_code == 400:
			print("Bad request: " + req.json()["error"]["message"])

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("Domain not found")

		return False

	def update_domain(self, domain: dict, new_values: dict):
		# TODO: This endpoints' description is confusing
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

		return requests.put(self._pi.url + f"/domains/{old_type}/{old_kind}/{old_domain}", json=domain, headers=self._pi._headers, verify=CERT_BUNDLE).json()


class ClientAPI:
	def __init__(self, pi):
		self._pi = pi

	def add_client(self, address: str, comment="", groups=[0]):
		"""
		Add a new client.

		A "UNIQUE constraint failed" error indicates that a client with the same address already exists.

		:param: address: IPv4/IPv6 or MAC or hostname or interface (e.g. :eth0)
		:return: JSON object
		"""
		payload = {
			"client": address,
			"comment": comment,
			"groups": groups
		}

		return requests.post(self._pi.url + "/clients", json=payload, headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def delete_clients(self, clients: list) -> bool:
		"""
		Delete clients.
		:param: clients: A list of client names
		:returns: bool
		"""
		payload = []
		for client in clients:
			payload.append({"item": client})

		req = requests.post(self._pi.url + "/clients:batchDelete", json=payload, headers=self._pi._headers, verify=CERT_BUNDLE)

		if req.status_code == 204:
			print("Clients deleted")
			return True

		if req.status_code == 400:
			print("Bad request. Unexpected request body format.")

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("Clients not found")

		return False

	def get_suggestions(self):
		"""
		Get client suggestions of unconfigured clients.

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/clients/_suggestions", headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def get_client(self, address=None):
		"""
		Get a specific client. By default, this returns all clients.

		:param: address: IPv4/IPv6 or MAC or hostname or interface (e.g. :eth0)
		:returns: JSON object
		"""
		endpoint = "/clients"

		if address is not None:
			endpoint = endpoint + f"/{address}"

		return requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def delete_client(self, address: str) -> bool:
		"""
		Delete client.

		:param: address: IPv4/IPv6 or MAC or hostname or interface (e.g. :eth0)
		"""
		req = requests.delete(self._pi.url + f"/clients/{address}", headers=self._pi._headers, verify=CERT_BUNDLE)

		if req.status_code == 204:
			print("Client deleted")
			return True

		if req.status_code == 400:
			print("Bad request: " + req.json()["error"]["message"])

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("Client not found")

		return False

	def update_client_comment(self, address: str, comment: str):
		"""
		Update client comment.

		:param: address: IPv4/IPv6 or MAC or hostname or interface (e.g. :eth0)
		:param: comment: New comment
		:returns: JSON object
		"""
		try:
			client = self.get_client(address)["clients"][0]
		except KeyError:
			print("Client not found")
			return {}

		client["comment"] = comment

		return requests.put(self._pi.url + "/clients/" + client["address"], json=client, headers=self._pi._headers, verify=CERT_BUNDLE).json()

	def update_groups(self, address: str, groups: list):
		"""
		Update groups a client is assigned to.

		:param: address: IPv4/IPv6 or MAC or hostname or interface (e.g. :eth0)
		:param: groups: New groups
		:returns: JSON object
		"""
		try:
			client = self.get_client(address)["clients"][0]
		except KeyError:
			print("Client not found")
			return {}

		client["groups"] = groups

		return requests.put(self._pi.url + "/clients/" + client["address"], json=client, headers=self._pi._headers, verify=CERT_BUNDLE).json()
