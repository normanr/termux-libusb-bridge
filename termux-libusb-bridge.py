#!/usr/bin/python3

import argparse
import array
import dataclasses
import json
import os
import shlex
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import traceback


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


def list_devices():
  args = ['termux-usb', '-l']
  p = subprocess.run(args, capture_output=True)
  return json.loads(p.stdout)


# inspired by:
# https://github.com/termux/termux-api-package/commit/e19c3ca3fa695e223954f509cf339faeb24c72ad
def open_device(path: os.PathLike):
  s1, s2 = socket.socketpair(socket.AF_UNIX)
  pair_fd = s1.fileno()
  callback = [sys.executable, __file__, '--fds', str(pair_fd)]
  args = ['termux-usb', '-r', '-e', shlex.join(callback), os.fspath(path)]
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
    creds = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                    struct.calcsize('3i'))
    pid, uid, gid = struct.unpack('3i', creds)
    if os.getuid() != uid:
      raise OSError('Spoofing detected!')
    s = self.read_str()
    if s is None:
      return
    if not s:
      for d in self.server.get_devices():
        self.write_str(d)
      self.write_str('')
      return

    fd = self.server.get_device(s)
    if fd is None:
      return
    r = send_fds(self.request, b'\x00', [fd])
    try:
      self.read_str()  # Wait for closing by the client...
    except Exception:
      pass


class ThreadingUnixStreamServer(socketserver.ThreadingMixIn,
                                socketserver.UnixStreamServer):
  pass


@dataclasses.dataclass
class FlushingCacheEntry:
  value: ...
  atime: float


class FlushingCache:

  def __init__(self, max_age, expire_callback):
    self.max_age = max_age
    self.expire_callback = expire_callback
    self.lock = threading.Lock()
    self.items = dict()  # type: Dict[str, FlushingCacheEntry]
    self.flush_thread = threading.Thread(target=self.flusher)
    self.flush_thread.start()

  def get(self, key, default):
    with self.lock:
      if key not in self.items:
        return default
      entry = self.items[key]
      # print('get', key, entry)
      entry.atime = time.time()
      return entry.value

  def __setitem__(self, key, value):
    self.items[key] = FlushingCacheEntry(value, time.time())

  def flusher(self):
    while True:
      expired = []
      deadline = time.time() - self.max_age
      # print('check', deadline)
      with self.lock:
        for key, entry in list(self.items.items()):
          if entry.atime < deadline:
            # print('flush', deadline, key, entry)
            del self.items[key]
            expired.append((key, entry.value))
      for key, value in expired:
        try:
          self.expire_callback(key, value)
        except Exception as e:
          traceback.print_exc()
      time.sleep(self.max_age / 5)


class Server(ThreadingUnixStreamServer):

  def __init__(self, server_address):
    super().__init__(server_address, RequestHandler)
    self.device_cache = FlushingCache(3, self.entry_expired)

  def get_devices(self):
    devices = self.device_cache.get(None, None)
    if devices is None:
      devices = list_devices()
    self.device_cache[None] = devices
    return devices

  def get_device(self, path: os.PathLike):
    fspath = os.fspath(path)
    fd = self.device_cache.get(fspath, None)
    if fd is None:
      fd = open_device(path)
      if fd:
        self.device_cache[fspath] = fd
    return fd

  def entry_expired(self, key, value):
    if key:
      os.close(value)


def main(args):
  if args.fds:
    s = socket.fromfd(args.fds[0], socket.AF_UNIX, socket.SOCK_STREAM)
    r = send_fds(s, b'@', [args.fds[1]])
    if r != 1:
      return 1
    return 0
  srv = Server('\x00' + args.socket_name)
  srv.serve_forever()


parser = argparse.ArgumentParser()
parser.add_argument(
    '-s',
    '--socket_name',
    default='green_green_avk.anotherterm.libusb',
    help=('abstract unix socket name of the service to bridge to termux '
          '(default: green_green_avk.anotherterm.libusb)'))
parser.add_argument('--fds', nargs=2, type=int, help=argparse.SUPPRESS)

if __name__ == '__main__':
  exit(main(parser.parse_args()))
