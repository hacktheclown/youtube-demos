#!/usr/bin/env python3

import socket
import threading

LISTEN_IP = 'CHANGEME'
PORTS = [80, 445, 110, 389, 636, 443, 23, 8080, 6000, 5001, 8443, 123]

class MockService:

  def __init__(self, port):

    self.port = port
    self.ip = LISTEN_IP

  def listen(self):

    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind((self.ip, self.port))
    serversocket.listen(5)

    while True:
      (clientsocket, address) = serversocket.accept()
      client_hostname = socket.getfqdn(address[0])
      with clientsocket:
        print(f"Client {address[0]}:{address[1]} ({client_hostname}) connected to {self.port}. Full TCP handshake!")

  def service_thread(self):

    print(f"Listening on port {self.port}")
    server_thread = threading.Thread(target=self.listen)
    server_thread.start()

for port in PORTS:
  service = MockService(port)
  service.service_thread()
