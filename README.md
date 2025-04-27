# pyhole

Python library for accessing the Pihole 6 REST API.

*Note: This is still in active development, so stuff may break!*

## Installation

### Import

Download the `pyhole.py` file and then import it in Python like so:

```py
from pyhole import Pihole
```

### Secure requests

*Notice: This step is required for the script to work!*

It is recommended that you use SSL for your requests to the API, so you need to copy the root certificate (not the server certificate) from `/etc/pihole/tls_ca.crt` to the device where the script is executed (e.g. `/home/user/pi_certificate.pem`). After that, set the `CERT_BUNDLE` variable in the `config.json` to the path where you stored the certificate.

If you don't want to use SSL, set the `CERT_BUNDLE` variable to `0`. Keep in mind though that the requests made to the API will be unencrypted in this case and warnings will be displayed on the console.

## References

- [Pi-hole project](https://github.com/pi-hole)
- Inspiration for the class structure taken from [How to "namespace" methods in Python class](https://stackoverflow.com/questions/48406389/how-to-namespace-methods-in-python-class).
