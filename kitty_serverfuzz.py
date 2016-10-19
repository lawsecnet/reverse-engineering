#
# Server fuzzer concept based on kittyfuzzer framework. More information at
# https://pypi.python.org/pypi/kittyfuzzer/
#

import socket
from kitty.model import *
from kitty.targets.server import ServerTarget


# creating data model template
http_get = Template(name = "HTTP_GET", fields = [
    String('GET', name='method', fuzzable = False),
    Delimiter(' ', name='space1', fuzzable = False),
    String('/index.html', name='path'),
    Delimiter(' ', name='space2'),
    String('HTTP/1.1', name='protocol'),
    Delimiter('\r\n\r\n', name='eom'),
    Dword(1, name = 'major version', encoder = ENC_INT_DEC)
    Delimiter('.', name = 'dot')
    Dword(1, name = 'major version', encoder = ENC_INT_DEC)
    Static('\r\n\r\n', name = 'eom')
])
