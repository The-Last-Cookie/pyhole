import json

CONFIG_FILE = "config.json"

def get_config(config_name: str):
	config = None
	with open(CONFIG_FILE) as file:
		content = file.read()
		config = json.loads(content)

	return config[config_name]

def set_config(config_name: str, value) -> bool:
	config = None

	with open(CONFIG_FILE, mode='r') as file:
		content = file.read()
		config = json.loads(content)
		config[config_name] = value

	with open(CONFIG_FILE, mode='w') as file:
		file.write(json.dumps(config))
