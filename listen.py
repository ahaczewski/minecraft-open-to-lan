#!/usr/bin/env python3
# Multicast client
# Adapted from: http://chaos.weblogs.us/archives/164

import ipaddress
import re
import signal
import socket
import sys

import click
import psutil

CONNECT_TIMEOUT_DEFAULT = 5000
CLIENT_TIMEOUT_DEFAULT = 5000
SERVER_TIMEOUT_DEFAULT = 50000
BASE_PORT_DEFAULT = 25566

ANY = "0.0.0.0"

MCAST_ADDR = "224.0.2.60"
MCAST_PORT = 4445

HAPROXY_TEMPLATE = r"""
# GENERATED CONFIG DON'T EDIT THIS MANUALLY

global
    daemon
    maxconn 256

defaults
    timeout connect {connect_timeout:d}ms
    timeout client  {client_timeout:d}ms
    timeout server  {server_timeout:d}ms
    mode            tcp
"""

HAPROXY_SERVER_TEMPLATE = r"""
frontend front_{name}
    bind            :{frontend_port}
    default_backend back_{name}

backend back_{name}
    server minecraft_{name} {backend_host}:{backend_port}
"""


@click.option("--connect-timeout", default=CONNECT_TIMEOUT_DEFAULT)
@click.option("--client-timeout", default=CLIENT_TIMEOUT_DEFAULT)
@click.option("--server-timeout", default=SERVER_TIMEOUT_DEFAULT)
@click.option("--base-port", default=BASE_PORT_DEFAULT)
@click.command()
def main(connect_timeout, client_timeout, server_timeout, base_port):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # Allow multiple sockets to use the same PORT number
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to the port that we know will receive multicast data
    sock.bind((ANY, MCAST_PORT))

    # Tell the kernel that we want to add ourselves to a multicast group
    # The address for the multicast group is the third param
    status = sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_ADD_MEMBERSHIP,
        socket.inet_aton(MCAST_ADDR) + socket.inet_aton(ANY),
    )

    # setblocking(0) is equiv to settimeout(0.0) which means we poll the socket.
    # But this will raise an error if recv() or send() can't immediately find or send data.
    sock.setblocking(0)

    servers = {}
    config_preamble = HAPROXY_TEMPLATE.format(
        connect_timeout=connect_timeout,
        client_timeout=client_timeout,
        server_timeout=server_timeout,
    )

    while 1:
        try:
            data, addr = sock.recvfrom(1024)
        except socket.error as e:
            pass
        else:
            motd = _parse_motd(data)
            if motd:
                print("Received from {} ---> {}".format(addr, data))
                ip = addr[0]
                player = motd[0]
                port = motd[1]

                if ip in servers:
                    existing_motd = servers[ip]
                    if existing_motd[1] == port:
                        print("Existing server {} omitted".format(player))
                        continue

                print("New server from {} found at {}:{}".format(player, ip, port))
                servers[ip] = motd

                servers_config = _generate_config(servers, base_port)

                with open("minecraftHaProxy.conf", "w") as f:
                    f.write(config_preamble)
                    f.write(servers_config)

                _notify_haproxy()


def _parse_motd(data: bytes):
    if not data.startswith(b"[MOTD]"):
        return None

    # data is a string of the form
    #  [MOTD]Player - Demo World[/MOTD][AD]41504[/AD]
    match = re.search(b"\[MOTD\](.+?) - (.+?)\[/MOTD\]\[AD\](.+?)\[/AD\]", data)

    if match:
        player = match.group(1).decode("utf-8", errors="replace")
        port = match.group(3)
        try:
            return player, int(port)
        except:
            return None
    else:
        return None


def _generate_config(servers, base_port):
    configs = []

    for ip, motd in servers.items():
        address = ipaddress.ip_address(ip)
        port_increment = int(str(address.reverse_pointer).split('.', maxsplit=1)[0])

        name = motd[0].lower().replace(" ", "_")
        backend_port = motd[1]
        frontend_port = base_port + port_increment

        server_config = HAPROXY_SERVER_TEMPLATE.format(
            name=name,
            frontend_port=frontend_port,
            backend_host=ip,
            backend_port=backend_port,
        )

        configs.append(server_config)

    return "\n".join(configs)


def _notify_haproxy():
    haproxy = []
    for proc in psutil.process_iter():
        if "haproxy" in proc.name():
            print("HAproxy process found: {}".format(proc))
            haproxy.append(proc)

    for p in haproxy:
        p.send_signal(signal.SIGHUP)


if __name__ == "__main__":
    sys.exit(main())
