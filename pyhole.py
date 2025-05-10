import requests


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
		"""
		return requests.get(self.url + "/auth", headers=self._headers, verify=self._cert_bundle).json()

	def authenticate(self, password: str):
		"""
		Creates a session token via a password.

		:params: password: Password used for authentication. Can be a user or app password.
		:returns:
		- None if successful
		- JSON object
		"""
		payload = {"password": password}
		auth_request = requests.post(self.url + "/auth", json=payload, verify=self._cert_bundle)

		if auth_request.status_code == 200:
			if auth_request.json()['session']['sid'] is None:
				print("Authentication not required")
				self._headers = None
				return

			self._headers = {
				"X-FTL-SID": auth_request.json()['session']['sid'],
				"X-FTL-CSRF": auth_request.json()['session']['csrf']
			}
			print("Authentication successful")
		elif auth_request.status_code == 429:
			self._headers = None
			raise RateLimitExceededException("Too many requests", response=auth_request.json())
		else:
			self._headers = None
			raise AuthenticationRequiredException("Password is not correct", response=auth_request.json())

	def delete_current_session(self) -> bool:
		"""
		Delete the current session.

		:returns: bool
		"""
		req = requests.delete(self.url + "/auth", headers=self._headers, verify=self._cert_bundle)
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
		Creates a new password to authenticate against the API instead of the user password.

		This password is only returned once and needs to be saved in order to authenticate again.

		Returns:
		- Application password if successful
		- JSON object otherwise
		"""
		req = requests.get(self.url + "/auth/app", headers=self._headers, verify=self._cert_bundle)
		if req.status_code == 200:
			password = req.json()["app"]["password"]
			hash = req.json()["app"]["hash"]

			payload = {
				"config": {
					"webserver": {
						"api": {
							"app_pwhash": hash
						}
					}
				}
			}

			requests.patch(self.url + "/config", headers=self._headers, json=payload, verify=self._cert_bundle)
			print("Password created")

			return password
		else:
			return req.json()

	def delete_session(self, id: int):
		"""
		Deletes the session with the given id.
		"""
		req = requests.delete(self.url + "/auth/session/" + str(id), headers=self._headers, verify=self._cert_bundle)
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
		return requests.get(self.url + "/auth/sessions", headers=self._headers, verify=self._cert_bundle).json()

	def new_totp_credentials(self):
		"""
		Suggest new TOTP credentials for two-factor authentication (2FA).

		:returns: JSON object
		"""
		return requests.get(self.url + "/auth/totp", headers=self._headers, verify=self._cert_bundle).json()


class MetricAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_history(self):
		"""
		Get activity graph data

		Returns: JSON object
		"""
		return requests.get(self._pi.url + "/history", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_client_history(self, count=5):
		"""
		Get per-client activity graph data over the last 24 hours.

		The last client returned is a special client that contains the total number of queries that were sent by clients that are not in the top N. This client is always present, even if it has 0 queries and can be identified by the special name "other clients" (mind the space in the hostname) and the IP address "0.0.0.0".

		Note that, due to privacy settings, the returned data may also be empty.

		:param: Number of top clients. If set to 0, all clients will be returned.
		:returns: JSON object
		"""
		return requests.get(self._pi.url + f"/history/clients?N={count}", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_long_term_history(self, start: int, end: int):
		"""
		Get activity graph data (long-term data).

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		return requests.get(self._pi.url + f"/history/clients?from={start}&until={end}", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_long_term_client_history(self, start: int, end: int):
		"""
		Get per-client activity graph data (long-term data).

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		return requests.get(self._pi.url + f"/history/database/clients?from={start}&until={end}", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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

		return requests.get(self._pi.url + endpoint + query_params, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_suggestions(self):
		"""
		Get query filter suggestions suitable for _get\_queries_
		"""
		return requests.get(self._pi.url + "/queries/suggestions", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_long_term_query_types(self, start: int, end: int):
		"""
		Get query types (long-term database).

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		return requests.get(self._pi.url + f"/stats/database/query_types?from={start}&until={end}", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_database_summary(self, start: int, end: int):
		"""
		Get database content details.

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		return requests.get(self._pi.url + f"/stats/database/summary?from={start}&until={end}", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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

		return requests.get(self._pi.url + f"/stats/database/top_clients?from={start}&until={end}" + optional_params, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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

		return requests.get(self._pi.url + f"/stats/database/top_domains?from={start}&until={end}" + optional_params, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_long_term_upstreams(self, start: int, end: int):
		"""
		Get metrics about Pi-hole's upstream destinations (long-term database).

		:param: Unix timestamp from when the data should be requested
		:param: Unix timestamp from when the data should be requested
		:returns: JSON object
		"""
		return requests.get(self._pi.url + f"/stats/database/upstreams?from={start}&until={end}", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_query_types(self):
		"""
		Get query types.

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/stats/query_types", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_recently_blocked(self, count=1):
		"""
		Get most recently blocked domain.

		:param: Number of blocked domains
		:returns: JSON object
		"""
		return requests.get(self._pi.url + f"/stats/recent_blocked?{count}", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_summary(self):
		"""
		Get overview of Pi-hole activity

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/stats/summary", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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

		return requests.get(self._pi.url + "/stats/top_clients?" + optional_params, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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

		return requests.get(self._pi.url + "/stats/top_domains?" + optional_params, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_upstreams(self):
		"""
		Get metrics about Pi-hole's upstream destinations.

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/stats/upstreams", headers=self._pi._headers, verify=self._pi._cert_bundle).json()


class DnsFilterAPI:
	def __init__(self, pi):
		self._pi = pi

	def is_active(self):
		"""
		Get current blocking state.

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/dns/blocking", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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

		return requests.post(self._pi.url + "/dns/blocking", json=payload, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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

		return requests.post(self._pi.url + "/dns/blocking", json=payload, headers=self._pi._headers, verify=self._pi._cert_bundle).json()


class GroupAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_groups(self):
		return requests.get(self._pi.url + "/groups", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_group(self, name: str):
		return requests.get(self._pi.url + f"/groups/{name}", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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

		return requests.post(self._pi.url + "/groups", json=group, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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

		return requests.put(self._pi.url + f"/groups/{old_name}", json=group, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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

		return requests.put(self._pi.url + f"/groups/{name}", json=group, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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

		return requests.put(self._pi.url + f"/groups/{name}", json=group, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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

		return requests.put(self._pi.url + f"/groups/{name}", json=group, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def delete_groups(self, *names) -> bool:
		"""
		Delete groups by name.

		:param: name: Group names
		:returns: bool
		"""
		groups = []
		for name in names:
			groups.append({"item": name})

		req = requests.post(self._pi.url + "/groups:batchDelete", json=groups, headers=self._pi._headers, verify=self._pi._cert_bundle)

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
		req = requests.delete(self._pi.url + f"/groups/{name}", headers=self._pi._headers, verify=self._pi._cert_bundle)

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
		Delete domains from Domain tab.

		Domains: A list of domain objects where each object contains the following data:
		:param: item: Domain name
		:param: type: allow|deny
		:param: kind: exact|regex
		:returns: bool
		"""
		req = requests.post(self._pi.url + "/domains:batchDelete", json=domains, headers=self._pi._headers, verify=self._pi._cert_bundle)

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

		return requests.post(self._pi.url + f"/domains/{type}/{kind}", json=payload, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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
		return requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def delete_domain(self, domain: str, type: str, kind: str) -> bool:
		"""
		Delete domain from Domain tab.

		:param: domain: Name of the domain
		:param: type: allow|deny
		:param: kind: exact|regex
		"""
		req = requests.delete(self._pi.url + f"/domains/{type}/{kind}/{domain}", headers=self._pi._headers, verify=self._pi._cert_bundle)

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

		return requests.put(self._pi.url + f"/domains/{old_type}/{old_kind}/{old_domain}", json=domain, headers=self._pi._headers, verify=self._pi._cert_bundle).json()


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

		return requests.post(self._pi.url + "/clients", json=payload, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def delete_clients(self, clients: list) -> bool:
		"""
		Delete clients.
		:param: clients: A list of client names
		:returns: bool
		"""
		payload = []
		for client in clients:
			payload.append({"item": client})

		req = requests.post(self._pi.url + "/clients:batchDelete", json=payload, headers=self._pi._headers, verify=self._pi._cert_bundle)

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
		return requests.get(self._pi.url + "/clients/_suggestions", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_client(self, address=None):
		"""
		Get a specific client.
		
		By default, this returns all clients configured in the Client tab. Clients not added in this tab will not be returned by this endpoint. Refer to Network endpoint.

		:param: address: IPv4/IPv6 or MAC or hostname or interface (e.g. :eth0)
		:returns: JSON object
		"""
		endpoint = "/clients"

		if address is not None:
			endpoint = endpoint + f"/{address}"

		return requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def delete_client(self, address: str) -> bool:
		"""
		Delete client from the Client tab.

		:param: address: IPv4/IPv6 or MAC or hostname or interface (e.g. :eth0)
		"""
		req = requests.delete(self._pi.url + f"/clients/{address}", headers=self._pi._headers, verify=self._pi._cert_bundle)

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

		return requests.put(self._pi.url + "/clients/" + client["address"], json=client, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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

		return requests.put(self._pi.url + "/clients/" + client["address"], json=client, headers=self._pi._headers, verify=self._pi._cert_bundle).json()


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

		return requests.post(self._pi.url + "/lists", json=payload, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def delete_lists(self, lists: list) -> bool:
		"""
		Delete several lists.

		Each list object has the following keys:
		:param: item: List address
		:param: type: allow | block
		"""
		req = requests.post(self._pi.url + "/lists:batchDelete", json=lists, headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print("Lists deleted")
			return True

		if req.status_code == 400:
			print("Bad request. Unexpected request body format.")

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("Lists not found")

		return False

	def get_lists(self, address: str, type=None):
		"""
		Get lists. By default, all lists will be returned.

		If _address_ is defined and the list is not present in the database, the returned data is empty.

		:param: address: Address of the list
		:param: (optional) type: allow | block
		"""
		endpoint = "/lists/" + address

		if type == "allow" or type == "block":
			endpoint = endpoint + "?type=" + type

		return requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def delete_list(self, address: str):
		"""
		Delete a list.

		:param: address: Address of the list
		"""
		req = requests.delete(self._pi.url + f"/lists/{address}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print("List deleted")
			return True

		if req.status_code == 400:
			print("Bad request. Unexpected request format.")

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("List not found")

		return False

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

		return requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def update_list_comment(self, address: str, comment: str):
		"""
		Update comment of list

		:param: address: List address
		:param: comment: Comment of the list
		:returns: JSON object
		"""
		try:
			list = self.get_lists(address)["lists"][0]
		except KeyError:
			print("List not found")
			return {}

		list["comment"] = comment

		return requests.put(self._pi.url + "/lists/" + address, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def update_type_list(self, address: str, type: str):
		"""
		Update type of list

		:param: address: List address
		:param: type: allow | block
		:returns: JSON object
		"""
		try:
			list = self.get_lists(address)["lists"][0]
		except KeyError:
			print("List not found")
			return {}

		list["type"] = type

		return requests.put(self._pi.url + "/lists/" + address, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def update_groups(self, address: str, groups: list):
		"""
		Update groups assigned to list

		:param: address: List address
		:param: groups: List of integers representing the group IDs
		:returns: JSON object
		"""
		try:
			list = self.get_lists(address)["lists"][0]
		except KeyError:
			print("List not found")
			return {}

		list["groups"] = groups

		return requests.put(self._pi.url + "/lists/" + address, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def enable(self, address: str):
		"""
		Enable list

		:param: address: List address
		:returns: JSON object
		"""
		try:
			list = self.get_lists(address)["lists"][0]
		except KeyError:
			print("List not found")
			return {}

		list["enabled"] = True

		return requests.put(self._pi.url + "/lists/" + address, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def disable(self, address: str):
		"""
		Disable list

		:param: address: List address
		:returns: JSON object
		"""
		try:
			list = self.get_lists(address)["lists"][0]
		except KeyError:
			print("List not found")
			return {}

		list["enabled"] = False

		return requests.put(self._pi.url + "/lists/" + address, headers=self._pi._headers, verify=self._pi._cert_bundle).json()


class FtlAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_endpoints(self):
		"""
		Get list of available API endpoints

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/endpoints", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_client_info(self):
		"""
		Get information about requesting client

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/info/client", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_database_info(self):
		"""
		Get information about long-term database

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/info/database", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_ftl_info(self):
		"""
		Get info about various ftl parameters

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/info/ftl", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_host_info(self):
		"""
		Get info about various host parameters

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/info/host", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_login_info(self):
		"""
		Login page related information

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/info/login", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_messages(self):
		"""
		Get Pi-hole diagnosis messages

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/info/messages", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def delete_message(self, message: int) -> bool:
		"""
		Delete Pi-hole diagnosis messages

		:param: message: Message ID
		"""
		req = requests.delete(self._pi.url + f"/info/messages/{message}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print("Message deleted")
			return True

		if req.status_code == 400:
			print("Bad request: " + req.json()["error"]["message"])

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("Message not found")

		return False

	def get_message_count(self):
		"""
		Get count of Pi-hole diagnosis messages

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/info/messages/count", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_metrics(self):
		"""
		Get metrics info about the DNS and DHCP metrics

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/info/metrics", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_sensor_info(self):
		"""
		Get info about various sensors

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/info/sensors", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_system_info(self):
		"""
		Get info about various system parameters

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/info/system", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_version(self):
		"""
		Get Pi-hole version

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/info/version", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_dnsmasq_log(self, next_id=None):
		"""
		Get DNS log content (dnsmasq)

		:param: (optional) next_id: Every successful request will return a _nextID_. This ID can be used on the next request to only get lines which were added after the last request. This makes periodic polling for new log lines easy as no check for duplicated log lines is necessary. The expected behavior for an immediate re-request of a log line with the same ID is an empty response. As soon as the next message arrived, this will be included in your request and _nextID_ is incremented by one.
		:returns: JSON object
		"""
		endpoint = "/logs/dnsmasq"
		if type(next_id) == int:
			endpoint = endpoint + f"?nextID={next_id}"

		return requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_ftl_log(self, next_id=None):
		"""
		Get FTL log content

		:param: (optional) next_id: Every successful request will return a _nextID_. This ID can be used on the next request to only get lines which were added after the last request. This makes periodic polling for new log lines easy as no check for duplicated log lines is necessary. The expected behavior for an immediate re-request of a log line with the same ID is an empty response. As soon as the next message arrived, this will be included in your request and _nextID_ is incremented by one.
		:returns: JSON object
		"""
		endpoint = "/logs/ftl"
		if type(next_id) == int:
			endpoint = endpoint + f"?nextID={next_id}"

		return requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_webserver_log(self, next_id=None):
		"""
		Get webserver log content (CivetWeb HTTP server)

		:param: (optional) next_id: Every successful request will return a _nextID_. This ID can be used on the next request to only get lines which were added after the last request. This makes periodic polling for new log lines easy as no check for duplicated log lines is necessary. The expected behavior for an immediate re-request of a log line with the same ID is an empty response. As soon as the next message arrived, this will be included in your request and _nextID_ is incremented by one.
		:returns: JSON object
		"""
		endpoint = "/logs/webserver"
		if type(next_id) == int:
			endpoint = endpoint + f"?nextID={next_id}"

		return requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle).json()


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
			print("Authentication required")
			return

		with open(archive, 'wb') as fd:
			for chunk in req.iter_content(chunk_size=chunk_size):
				fd.write(chunk)

		print("Settings successfully exported")

	def import_settings(self, archive: str):
		"""
		Import Pi-hole settings from a zip archive.

		This function requires "webserver.api.app_sudo" to be _True_.

		:param: archive: Path to zip archive
		:returns: JSON object
		"""
		file = open(archive, mode="rb")
		form_data = {"file": ('teleporter.zip', file, 'multipart/form-data')}
		return requests.post(self._pi.url + "/teleporter", files=form_data, headers=self._pi._headers, verify=self._pi._cert_bundle).json()


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
		return requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def delete_device(self, id: int) -> bool:
		"""
		Delete a device from the network table

		This will also remove all associated IP addresses and hostnames.

		:retuns: bool
		"""
		req = requests.delete(self._pi.url + f"/network/devices/{id}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print("Device deleted")
			return True

		if req.status_code == 400:
			print("Bad request: " + req.json()["error"]["message"])

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("Device not found")

		return False

	def get_gateway(self, detailed=False):
		"""
		Get info about the gateway of your Pi-hole

		:param: (optional) detailed: May include detailed information about the individual interfaces and routes depending on the interface type and state
		:returns: JSON object
		"""
		endpoint = f"/network/gateway?detailed={detailed}"
		return requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_interfaces(self, detailed=False):
		"""
		Get info about the interfaces of your Pi-hole

		:param: (optional) detailed: May include detailed information about the individual interfaces and routes depending on the interface type and state
		:returns: JSON object
		"""
		endpoint = f"/network/interfaces?detailed={detailed}"
		return requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def get_routes(self, detailed=False):
		"""
		Get info about the routes of your Pi-hole

		:param: (optional) detailed: May include detailed information about the individual interfaces and routes depending on the interface type and state
		:returns: JSON object
		"""
		endpoint = f"/network/routes?detailed={detailed}"
		return requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle).json()


class ActionAPI:
	def __init__(self, pi):
		self._pi = pi

	def flush_network_table(self):
		"""
		Flush the network table (ARP)

		For this to work, the webserver.api.allow_destructive setting needs to be true.

		:returns: JSON object
		"""
		return requests.post(self._pi.url + "/action/flush/arp", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def flush_dns_logs(self):
		"""
		Flush DNS logs

		:returns: JSON object
		"""
		return requests.post(self._pi.url + "/action/flush/logs", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

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
		else:
			return req.json()

	def restart_dns(self):
		"""
		Restart pihole-FTL

		:returns: JSON object
		"""
		return requests.post(self._pi.url + "/action/restartdns", headers=self._pi._headers, verify=self._pi._cert_bundle).json()


class PaddAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_data(self, full=False):
		"""
		Get data for PADD

		:param: (optional) full: Return full data
		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/padd", headers=self._pi._headers, verify=self._pi._cert_bundle).json()


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

		return requests.get(self._pi.url + endpoint, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def patch(self, config: dict):
		"""
		Update one or several configurations at once

		:returns: JSON object
		"""
		return requests.patch(self._pi.url + "/config", data=config, headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def set(self, element: str, value: str):
		"""
		Set Pi-hole config

		:returns: None if successful, JSON object otherwise
		"""
		req = requests.put(self._pi.url + f"/config/{element}/{value}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 201:
			print("Config successfully set")
			return

		return req.json()

	def delete(self, element: str, value: str) -> bool:
		"""
		Delete Pi-hole config

		:returns: bool
		"""
		req = requests.delete(self._pi.url + f"/config/{element}/{value}", headers=self._pi._headers, verify=self._pi._cert_bundle)
		
		if req.status_code == 204:
			print("Config deleted")
			return True

		if req.status_code == 400:
			print("Bad request: " + req.json()["error"]["message"])

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("Config not found")

		return False


class DhcpAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_leases(self):
		"""
		Get currently active DHCP leases

		:returns: JSON object
		"""
		return requests.get(self._pi.url + "/dhcp/leases", headers=self._pi._headers, verify=self._pi._cert_bundle).json()

	def delete_lease(self, ip: str):
		"""
		Remove active DHCP lease
		
		Managing DHCP leases is only possible when the DHCP server is enabled.

		:params: ip: IP address of the lease to remove
		:returns: bool
		"""
		req = requests.delete(self._pi.url + f"/dhcp/leases/{ip}", headers=self._pi._headers, verify=self._pi._cert_bundle)

		if req.status_code == 204:
			print("Lease deleted")
			return True

		if req.status_code == 400:
			print("Bad request: " + req.json()["error"]["message"])

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("Lease not found")

		return False
