import json


class ConnectionConfig:
	def __init__(self, path: str):
		self.path = path

	def get(self, config_name: str):
		config = None
		with open(self.path) as file:
			content = file.read()
			config = json.loads(content)

		return config[config_name]

	def save(self, config_name: str, value) -> None:
		config = None

		with open(self.path, mode='r') as file:
			content = file.read()
			config = json.loads(content)
			config[config_name] = value

		with open(self.path, mode='w') as file:
			file.write(json.dumps(config))
