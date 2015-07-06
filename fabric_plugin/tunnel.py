########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.


from contextlib import contextmanager
import socket
import select

from fabric import api as fabric_api
from fabric.state import connections
from fabric.thread_handling import ThreadHandler

from cloudify import ctx


def documented_contextmanager(func):
    wrapper = contextmanager(func)
    wrapper.undecorated = func
    return wrapper


@documented_contextmanager
def remote(remote_port, show_rtunnel, local_port=None, local_host="localhost",
           remote_bind_address="127.0.0.1"):
    """
    Create a tunnel forwarding a locally-visible port to the remote target.

    * ``remote_port`` (mandatory) is the remote port to listen to.
    * ``local_port`` (optional) is the local port to connect to; the default is
      the same port as the remote one.
    * ``local_host`` (optional) is the locally-reachable computer (DNS name or
      IP address) to connect to; the default is ``localhost`` (that is, the
      same computer Fabric is running on).
    * ``remote_bind_address`` (optional) is the remote IP address to bind to
      for listening, on the current target. It should be an IP address assigned
      to an interface on the target (or a DNS name that resolves to such IP).
      You can use "0.0.0.0" to bind to all interfaces.
    .. note::
        By default, most SSH servers only allow remote tunnels to listen to the
        localhost interface (127.0.0.1). In these cases, `remote_bind_address`
        is ignored by the server, and the tunnel will listen only to 127.0.0.1.
    """
    if local_port is None:
        local_port = remote_port

    sockets = []
    channels = []
    threads = []

    def accept(channel, (src_addr, src_port), (dest_addr, dest_port)):
        channels.append(channel)
        sock = socket.socket()
        sockets.append(sock)

        try:
            sock.connect((local_host, local_port))
        except Exception as e:
            ctx.logger.error(
                '[{0}] rtunnel: cannot connect to {1}:{2} ({3})'.format(
                    fabric_api.env.host_string, local_host,
                    local_port, e.message))
            channel.close()
            return

        # if show_rtunnel:
        print '[{0}] rtunnel: opened reverse tunnel: ' \
              '{1} -> {2} -> {3}'.format(
                  fabric_api.env.host_string,
                  channel.origin_addr,
                  channel.getpeername(),
                  (local_host, local_port))

        th = ThreadHandler('fwd', _forwarder, channel, sock)
        threads.append(th)

    transport = connections[fabric_api.env.host_string].get_transport()
    transport.request_port_forward(
        remote_bind_address, remote_port, handler=accept)

    try:
        yield
    finally:
        for sock, chan, th in zip(sockets, channels, threads):
            sock.close()
            chan.close()
            th.thread.join()
            th.raise_if_needed()
        transport.cancel_port_forward(remote_bind_address, remote_port)


def _forwarder(chan, sock):
    # Bidirectionally forward data between a socket and a Paramiko channel.
    while True:
        r, w, x = select.select([sock, chan], [], [])
        if sock in r:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            chan.send(data)
        if chan in r:
            data = chan.recv(1024)
            if len(data) == 0:
                break
            sock.send(data)
    chan.close()
    sock.close()
