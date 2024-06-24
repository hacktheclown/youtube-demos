#!/usr/bin/env python3
"""
Be sure to install the module first:

```
pip install pyftpdlib
```
"""

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

authorizer = DummyAuthorizer()
authorizer.add_user("anonymous", "anonymous", "/tmp", perm="elradfmwMT")
handler = FTPHandler

FTPHandler.permit_foreign_addresses = True
FTPHandler.permit_privileged_ports = True

handler.authorizer = authorizer

server = FTPServer(("CHANGEME", 21), handler)
server.serve_forever()
