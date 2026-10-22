"""Run only in an isolated Linux network namespace on a disposable CI runner."""
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

if sys.platform != "linux" or os.geteuid() != 0:
    raise SystemExit("requires root inside an isolated Linux network namespace")
if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
    raise SystemExit("refusing to test in the host network namespace")
exe = str(Path(sys.argv[1]).resolve())
fixture = Path(sys.argv[2]).resolve()
def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout
def operation(action, mode=None):
    response = json.loads(command(exe, 'request', str((fixture / mode if mode else fixture) / f'request-{action}.json')))
    if response['error']:
        raise AssertionError(response['error'])
    return response['receipt']
command('ip', 'link', 'set', 'lo', 'up')
for ip in ['223.5.5.5/32', '9.9.9.9/32']:
    command('ip', 'addr', 'add', ip, 'dev', 'lo')
command('ip', '-6', 'addr', 'add', '2001:db8::5/128', 'nodad', 'dev', 'lo')
def udp(address, source, family=socket.AF_INET):
    server = socket.socket(family, socket.SOCK_DGRAM)
    server.bind((address, 0))
    server.settimeout(.5)
    client = socket.socket(family, socket.SOCK_DGRAM)
    client.settimeout(1)
    client.bind((source, 0))
    client.connect(server.getsockname())
    return client, server
def receive(pair, expected=True):
    client, server = pair
    try:
        client.send(b'probe')
    except OSError as error:
        if expected or error.errno not in [errno.EPERM, errno.EACCES, errno.ENETUNREACH]:
            raise
    try:
        data, address = server.recvfrom(200)
    except socket.timeout:
        if expected:
            raise AssertionError('expected packet did not arrive')
        return
    if not expected:
        raise AssertionError('blocked packet arrived')
    assert data == b'probe'
    server.sendto(b'reply', address)
    assert client.recv(200) == b'reply'
local = udp('223.5.5.5', '223.5.5.5')
foreign = udp('9.9.9.9', '223.5.5.5')
v6 = udp('2001:db8::5', '::1', socket.AF_INET6)
listener = socket.socket()
listener.bind(('9.9.9.9', 0))
listener.listen(1)
tcp_client = socket.socket()
tcp_client.settimeout(1)
tcp_client.bind(('223.5.5.5', 0))
tcp_client.connect(listener.getsockname())
tcp_server, _ = listener.accept()
tcp_server.settimeout(.5)
tcp_client.sendall(b'before')
assert tcp_server.recv(100) == b'before'
for pair in [local, foreign, v6]:
    receive(pair)
try:
    receipt = operation('apply')
    assert receipt['configurationActive'] is True, receipt
    assert receipt['enforcementVerified'] is False
    receive(local)
    receive(foreign, False)
    receive(v6, False)
    tcp_client.sendall(b'after')
    try:
        leaked = tcp_server.recv(100)
    except socket.timeout:
        pass
    else:
        raise AssertionError(f'existing TCP connection escaped: {leaked!r}')
    # Packet counter changes must not invalidate exact configuration readback.
    assert operation('status')['configurationActive'] is True
finally:
    receipt = operation('release')
    assert receipt['configurationActive'] is False
receive(foreign)
receive(v6)
print('PASS: CN preserved; foreign UDP/existing TCP/public IPv6 dropped; release restored UDP/IPv6')

loopback = udp('127.0.0.1', '127.0.0.1')
for mode in ['isolation', 'ipv6']:
    try:
        assert operation('apply', mode)['configurationActive']
        receive(loopback)
        receive(local, mode == 'ipv6')
        receive(foreign, mode == 'ipv6')
        receive(v6, False)
        assert operation('status', mode)['configurationActive']
    finally:
        assert not operation('release', mode)['configurationActive']
    receive(foreign)
    receive(v6)
print('PASS: strict isolation has no LAN/DNS bypass; IPv6-only mode preserves IPv4; both restore')
