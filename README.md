# pyhole

![badge](https://badgen.net/badge/ftl/v6.1/blue)
![badge](https://badgen.net/badge/python/v3.10/blue?icon=pypi)

Python library for accessing the Pihole 6 REST API.

This project is **not affiliated** with [Pi-hole](https://github.com/pi-hole).

*Note: This is still in active development, so stuff may break!*

## Installation

### Import

Download the `pyhole.py` file and then import it in Python like so:

```py
from pyhole import Pihole
```

### Secure requests

*Notice: This step is required for the script to work!*

It is recommended that you use SSL for your requests to the API, so you need to copy the root certificate (not the server certificate) from `/etc/pihole/tls_ca.crt` to the device where the script is executed (e.g. `/home/user/pi_certificate.pem`). After that, set the `CERT_BUNDLE` variable e.g. in the `config.json` to the path where you stored the certificate.

If you don't want to use SSL, set the `CERT_BUNDLE` variable to `0`. Keep in mind though that the requests made to the API will be unencrypted in this case and warnings will be displayed on the console.

## Example code

```py
from pyhole import Pihole

# get data from config.json
cert = get_config('cert_bundle')
password = get_config('password')

pi = Pihole("https://pi.hole/api", cert)
pi.authenticate(password)

history = pi.metrics.get_history()
devices = pi.network.get_devices()['devices']
```

## References

- Inspiration for the class structure taken from [How to "namespace" methods in Python class](https://stackoverflow.com/questions/48406389/how-to-namespace-methods-in-python-class).
- [Designing Pythonic library APIs](https://benhoyt.com/writings/python-api-design/)
