class Pihole:
	def __init__(self, url: str):
		self.url = url

		self.clients = ClientAPI(self)
		self.groups = GroupAPI(self)


class ClientAPI:
	def __init__(self, pi):
		self.pi = pi

	def get_url(self):
		print(self.pi.url)


class GroupAPI:
	def __init__(self, pi):
	 	self.pi = pi


pi = Pihole("test")
pi.clients.get_url()
