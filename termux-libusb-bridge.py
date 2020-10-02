#!/usr/bin/python

import array
import json
import os
import shlex
import socket
import socketserver
import struct
import subprocess
import sys

socket_name = '\x00green_green_avk.anotherterm.libusb'


# copied directly from https://docs.python.org/3/library/socket.html#socket.socket.sendmsg
def send_fds(sock, msg, fds):
  return sock.sendmsg(
      [msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))])


# copied directly from https://docs.python.org/3/library/socket.html#socket.socket.recvmsg
def recv_fds(sock, msglen, maxfds):
  fds = array.array('i')  # Array of ints
  msg, ancdata, flags, addr = sock.recvmsg(
      msglen, socket.CMSG_LEN(maxfds * fds.itemsize))
  for cmsg_level, cmsg_type, cmsg_data in ancdata:
    if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
      # Append data, ignoring any truncated integers at the end.
      fds.frombytes(cmsg_data[:len(cmsg_data) -
                              (len(cmsg_data) % fds.itemsize)])
  return msg, list(fds)


def get_devices():
  args = ['termux-usb', '-l']
  p = subprocess.run(args, capture_output=True)
  return json.loads(p.stdout)


# inspired by:
# https://github.com/termux/termux-api-package/commit/e19c3ca3fa695e223954f509cf339faeb24c72ad
def open_device(path: os.PathLike):
  s1, s2 = socket.socketpair(socket.AF_UNIX)
  pair_fd = s1.fileno()
  callback = [sys.executable, __file__, str(pair_fd)]
  args = ['termux-usb', '-r', '-e', shlex.join(callback), path]
  p = subprocess.run(args, pass_fds=[pair_fd])
  if p.returncode != 0:
    return None

  s2.settimeout(0.2)
  try:
    msg, [dev_fd] = recv_fds(s2, 1, 1)
  except (ValueError, socket.timeout):
    return None

  return dev_fd


class RequestHandler(socketserver.StreamRequestHandler):

  def read_str(self):
    data = self.rfile.read(2)
    if not data:
      return None
    if len(data) != 2:
      raise OSError('bad read')
    l, = struct.unpack('!H', data)
    if not l:
      return ''
    data = self.rfile.read(l)
    return data.decode('utf8')

  def write_str(self, s):
    data = s.encode('utf8')
    self.wfile.write(struct.pack('!H', len(data)) + data)

  def handle(self):
    # self.client_address, self.request, self.server
    # TODO: check peer credentials uid == myuid
    s = self.read_str()
    if s is None:
      return
    if not s:
      for d in get_devices():
        self.write_str(d)
      self.write_str('')
      return

    fd = open_device(s)
    if fd is None:
      return
    r = send_fds(self.request, b'\x00', [fd])
    os.close(fd)
    self.read_str()  # Wait for closing by the client...


class ThreadingUnixStreamServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
  pass


def main(args):
  if len(args) == 2:
    s = socket.fromfd(int(sys.argv[1]), socket.AF_UNIX, socket.SOCK_STREAM)
    r = send_fds(s, b'@', [int(sys.argv[2])])
    if r != 1:
      return 1
    return 0
  srv = ThreadingUnixStreamServer(socket_name, RequestHandler)
  srv.serve_forever()


if __name__ == '__main__':
  exit(main(sys.argv[1:]))
