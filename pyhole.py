import requests

import utils

CERT_BUNDLE = utils.get_config('cert_bundle')


class Pihole:
	def __init__(self, url: str):
		self.url = url

		self.clients = ClientAPI(self)
		self.groups = GroupAPI(self)

		self._headers = None

	def is_auth_required(self):
		"""
		Check if authentication is required.

		Returns: JSON object
		"""
		return requests.get(self.url + "/auth", headers=self._headers, verify=CERT_BUNDLE).json()

	def authenticate(self):
		"""
		Creates a session token via the password provided in the config file.

		Returns:
		- None if successful
		- JSON object otherwise
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
		else:
			self._headers = None
			print("Authentication not successful")
			return auth_request.json()

	def delete_current_session(self) -> None:
		"""
		Delete the current session.

		Returns: None
		"""
		req = requests.delete(self.url + "/auth", headers=self._headers, verify=CERT_BUNDLE)
		if req.status_code == 204:
			print("Current session deleted")

		if req.status_code == 401:
			print("Authentication required")

		if req.status_code == 404:
			print("No active session")

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


class ClientAPI:
	def __init__(self, pi):
		self._pi = pi

	def get_url(self):
		print(self._pi.url)


class GroupAPI:
	def __init__(self, pi):
		self._pi = pi
