import socket
import sys
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random
import threading
from typing import Tuple
from tor_protocol import *


class DirectoryServer:
    def __init__(self, master_key: SigningKey):
        self.master_key = master_key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.or_ips = []
        self.pks = []

    def serve(self):
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', THOR_PORT))
        self.sock.listen(32)
        while True:
            client_sock, addr = self.sock.accept()
            threading.Thread(target=self.handle_client,
                             args=(client_sock, addr)).start()

    def handle_client(self, client_sock: socket.socket, addr: Tuple[str, int]):
        print("Accepted connection from %s:%d" % (addr[0], addr[1]))
        ip_addr = socket.inet_aton(addr[0])
        cell_header = recv_all(client_sock, CellHeader.TotalSize)
        if len(cell_header) == 0:
            client_sock.close()
            return
        cell_header = CellHeader.deserialize(cell_header)
        if cell_header.type == CellType.DirectoryChallengeInit:
            self.handle_challenge(ip_addr, client_sock, cell_header)
        elif cell_header.type == CellType.DirectoryRetrieveRequest:
            self.handle_retrieve(ip_addr, client_sock, cell_header)
            client_sock.close()

    def handle_challenge(self, ip_addr: bytes, client_sock: socket.socket, cell_header: CellHeader):
        # Receive INIT
        cell_body = DirectoryChallengeInitCellBody.deserialize(
            recv_all(client_sock, cell_header.body_len))
        # Store the initiator's public key and nonce
        init_pk = cell_body.pk
        init_nonce = cell_body.nonce

        # Generate challenge for the initiator (we are the challenger)
        challenger_nonce = random(32)
        # Prove to the initiator that we hold the master key
        challenger_signature = self.master_key.sign(init_nonce).signature
        # Send challenge request
        cell_body = DirectoryChallengeRequestCellBody(
            challenger_nonce, challenger_signature).serialize()
        cell_header = CellHeader(
            THOR_VERSION, CellType.DirectoryChallengeRequest, bytes(16), len(cell_body)).serialize()
        send_all(client_sock, cell_header + cell_body)

        # Recieve the challenge response
        cell_header = CellHeader.deserialize(
            recv_all(client_sock, CellHeader.TotalSize))
        assert cell_header.type == CellType.DirectoryChallengeResponse
        cell_body = DirectoryChallengeResponseCellBody.deserialize(
            recv_all(client_sock, cell_header.body_len))
        # Verify the initiator's signature -- proves that the initiator holds
        # the signing key
        init_signature = cell_body.signature
        try:
            VerifyKey(init_pk).verify(challenger_nonce, init_signature)
            status = 0
        except:
            status = 1

        # Send ACK
        cell_body = DirectoryChallengeAckCellBody(status).serialize()
        cell_header = CellHeader(
            THOR_VERSION, CellType.DirectoryChallengeAck, bytes(16), len(cell_body)).serialize()
        send_all(client_sock, cell_header + cell_body)

        # If challenge successful, add to list and start a heartbeat thread
        if status == 0:
            self.or_ips.append(ip_addr)
            self.pks.append(init_pk)
            print("Approved join from OR at %s" % socket.inet_ntoa(ip_addr))
            threading.Thread(target=self.heartbeat, args=(
                ip_addr, client_sock)).start()
        else:
            print("Refused join from OR at %s" % socket.inet_ntoa(ip_addr))

    def handle_retrieve(self, ip_addr: bytes, client_sock: socket.socket, cell_header: CellHeader):
        # Receive the retrieve request
        cell_body = DirectoryRetrieveRequestCellBody.deserialize(
            recv_all(client_sock, cell_header.body_len))
        # Store the challenger's nonce
        challenger_nonce = cell_body.nonce

        # Prove to the challenger that we hold the master key -- sign the nonce
        # and the message payload
        signature_payload = challenger_nonce
        assert len(self.or_ips) == len(self.pks)
        for i in range(len(self.or_ips)):
            signature_payload += self.or_ips[i]
            signature_payload += self.pks[i]
        challenger_signature = self.master_key.sign(signature_payload).signature

        # Send the response
        cell_body = DirectoryRetrieveResponseCellBody(
            self.or_ips, self.pks, challenger_signature).serialize()
        cell_header = CellHeader(
            THOR_VERSION, CellType.DirectoryRetrieveResponse, bytes(16), len(cell_body)).serialize()
        send_all(client_sock, cell_header + cell_body)
        print("Sent a list of all ORs to %s" % socket.inet_ntoa(ip_addr))

    def heartbeat(self, ip_addr: bytes, sock: socket.socket):
        sock.settimeout(5)
        try:
            while True:
                cell_header = sock.recv(CellHeader.TotalSize)
                if len(cell_header) == 0:
                    print("OR at {} closed the connection, ".format(
                        socket.inet_ntoa(ip_addr)), end='')
                    break
        except socket.timeout:
            print("OR at {} didn't send a heartbeat, ".format(
                socket.inet_ntoa(ip_addr)), end='')
        print("removing from the list")
        sock.close()
        index = self.or_ips.index(ip_addr)
        self.or_ips.pop(index)
        self.pks.pop(index)


def main(argv):
    if len(argv) != 2:
        print("usage: %s <MASTER KEY FILE>" % argv[0])
        return 1
    with open(argv[1], "rb") as keyfile:
        masterkey = keyfile.read(32)
    server = DirectoryServer(SigningKey(masterkey))
    server.serve()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
