# pyhole

![badge](https://badgen.net/badge/ftl/v6.3.3/blue)
![badge](https://badgen.net/badge/python/v3.13/blue?icon=pypi)

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

It is recommended that you use SSL for your requests to the API. Newer versions of the `request` module require the `KeyUsage` and `ExtendedKeyUsage` parameters to be set. By default, Pi-hole creates a certificate without these parameters. In any case, copy the root CA certificate without the private key (**not** the server certificate!) (by default `/etc/pihole/tls_ca.crt`) to the device where the script is executed (e.g. `/home/user/pi_certificate.pem`). After that, set the `CERT_BUNDLE` variable e.g. in the `config.json` to the path where you stored the certificate.

If you don't want to use SSL, set the `CERT_BUNDLE` variable to `0` (integer). Keep in mind though that the requests made to the API will be unencrypted in this case and warnings will be displayed on the console.

## Example code

```py
from pyhole import Pihole

# get data from config.json
cert = "/path/to/cert.pem or crt"
password = "your_password"

pi = Pihole("https://pi.hole/api", cert)
pi.authenticate(password)

history = pi.metrics.get_history()
devices = pi.network.get_devices()
gateway = pi.network.get_gateway()
```

## References

- Inspiration for the class structure taken from [How to "namespace" methods in Python class](https://stackoverflow.com/questions/48406389/how-to-namespace-methods-in-python-class).
- [Designing Pythonic library APIs](https://benhoyt.com/writings/python-api-design/)
