#!/opt/cloudmon/virtualenv/bin/python
#
# Usage: push_message.py <server_address> <server_port> <driver_name> <zabbix_hostname> [params]

import sys
import zmq
import pickle

SUCCESS = 0
FAILURE = 1
DEFAULT_TIMEOUT = 3

if len(sys.argv) <= 4:
    print FAILURE
    sys.exit(1)
server_address = sys.argv[1]
server_port = sys.argv[2]
msg = pickle.dumps(sys.argv[3:])
timeout = DEFAULT_TIMEOUT

context = zmq.Context()
socket = context.socket(zmq.PUSH)
socket.setsockopt(zmq.LINGER, 0)
try:
    socket.connect("tcp://%s:%s" % (server_address, server_port))
    tracker = socket.send(msg, copy=False, track=True)
    tracker.wait(timeout)
    print SUCCESS
except:
    print FAILURE
finally:
    socket.close()
