import socket
import sys
import json
from client import TorClient
from nacl.signing import VerifyKey
from tor_protocol import *
from random import sample

request_template = 'GET / HTTP/1.0\r\nHost: {hostname}\r\n\r\n'


def get_request(hostname: str) -> bytes:
    request = request_template.format(hostname=hostname)
    return bytes(request, "utf-8")


def main(argv):
    if len(argv) != 2 and len(argv) != 5:
        print(
            "usage: python3 %s <SERVER IP> [USETOR <DS PUBLIC KEY> <DS IP>]" % argv[0])
        return 1
    hostname = argv[1]
    port = 80
    if len(argv) == 5:
        with open(argv[3], "rb") as ds_keyfile:
            ds_publickey = ds_keyfile.read(32)
    request = get_request(hostname)
    if len(argv) == 2:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4)
        sock.connect((hostname, port))
        print("Successfully connected to %s:%d" % (hostname, port))
        send_all(sock, request)
        response = recv_all(sock, 4096)
    else:
        client = TorClient(argv[4], VerifyKey(ds_publickey))
        all_ip_addrs, all_pks = client.retrieve_onion_routers()
        ip_addrs, pks = zip(*sample(list(zip(all_ip_addrs, all_pks)), 3))
        print('')
        for i in range(3):
            sk = client.create_onion_router(socket.inet_ntoa(ip_addrs[i]))
            client.receive_created(sk, pks[i])
            print('')
        client.begin(hostname, port)
        if (client.receive_connected()):
            print("Successfully connected to %s:%d" % (hostname, port))
        else:
            print("Connection to %s:%d failed" % (hostname, port))
            return 0
        print('')
        client.send_data(request)
        response = client.recv_data()
        client.destroy()
    response = str(response, "utf-8")
    response_begin = response.find("<h1>") + 4
    response_end = response.find("</h1>")
    response = response[response_begin:response_end]
    print('')
    print("Website says:", response)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
