import socket
import sys
import threading
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey
from nacl.hash import blake2b
from nacl.encoding import RawEncoder
from nacl.utils import random
from typing import Tuple, Dict, List
from tor_protocol import *

class CircuitState:
    def __init__(self):
        self.ip_addresses: List[bytes] = [None, None]
        self.circuit_ids: List[bytes] = [None, None]
        self.privkey: PrivateKey = None
        self.pubkey: PublicKey = None

    def get_sesskey(self) -> bytes:
        sesskey = None
        if self.privkey is not None and self.pubkey is not None:
            shared_secret = Box(
                self.privkey,
                self.pubkey).shared_key()
            sesskey = blake2b(
                b'',
                digest_size=32,
                key=shared_secret,
                person=b"THOR",
                encoder=RawEncoder)
        return sesskey


class OnionRouter:
    def __init__(self, ip: str, port: int, master_key: SigningKey):
        self.ip = ip
        if port < 0 or port > 65535:
            raise ValueError
        self.port = port
        self.master_key = master_key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Mapping from sockets to IPs
        self.or_sockets: Dict[bytes, socket.socket] = {}
        # Per-circuit ID state
        self.circuits: Dict[bytes, CircuitState] = {}

    def serve(self):
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.ip, self.port))
        self.sock.listen(32)
        while True:
            client_sock, addr = self.sock.accept()
            threading.Thread(target=self.handle_client,
                             args=(client_sock, addr)).start()

    def handle_client(self, client_sock: socket.socket, addr: Tuple[str, int]):
        print("Accepted connection from %s:%d" % (addr[0], addr[1]))
        ip_addr = socket.inet_aton(addr[0])
        # This connection wasn't already open
        assert ip_addr not in self.or_sockets
        self.or_sockets[ip_addr] = client_sock
        while True:
            data = client_sock.recv(CellHeader.TotalSize)
            print(threading.get_ident())
            print(len(data))
            print(data)
            cell_header = CellHeader.deserialize(data)
            if cell_header.type == CellType.Create:
                self.handle_create(ip_addr, client_sock, cell_header)
            elif cell_header.type == CellType.RelayExtend:
                self.handle_relay_extend(ip_addr, client_sock, cell_header)
            elif cell_header.type == CellType.Created:
                self.handle_created(ip_addr, client_sock, cell_header)
            elif cell_header.type == CellType.RelayExtended:
                self.handle_relay_extended(ip_addr, client_sock, cell_header)

    def handle_create(self, ip_addr: bytes,
                      client_sock: socket.socket, cell_header: CellHeader):
        cell_body = CreateCellBody.deserialize(
            client_sock.recv(cell_header.body_len))

        circ_id = cell_header.circ_id
        # This circuit ID doesn't already exist
        assert circ_id not in self.circuits

        circuit_state = CircuitState()
        self.circuits[circ_id] = circuit_state
        # Populate IP address for the incoming part of the circuit
        circuit_state.ip_addresses[0] = ip_addr
        # Populate circuit ID for the incoming part of the circuit
        circuit_state.circuit_ids[0] = circ_id
        # Generate private key for the incoming part of the circuit
        circuit_state.privkey = PrivateKey.generate()
        # Populate public key for the incoming part of the circuit
        circuit_state.pubkey = PublicKey(cell_body.pk)

        # Get session key
        sesskey = circuit_state.get_sesskey()
        # Compute the hash of the session key to send in a response
        sesskey_hash = blake2b(
            sesskey,
            digest_size=32,
            person=b"THOR",
            encoder=RawEncoder)

        # Sign the (pk || hash)
        signature = self.master_key.sign(
            circuit_state.privkey.public_key.encode() +
            sesskey_hash).signature

        # Send response
        response_cell = CreatedCellBody(
            circuit_state.privkey.public_key.encode(),
            sesskey_hash,
            signature)
        response_data = response_cell.serialize()
        hdr = CellHeader(THOR_VERSION, CellType.Created,
                         circ_id, len(response_data)).serialize()
        client_sock.send(hdr + response_data)

    def handle_created(self, ip_addr: bytes, client_sock: socket.socket, cell_header: CellHeader):
        # Circuit ID must already exist
        circ_id = cell_header.circ_id
        assert circ_id in self.circuits

        # Receive the body
        cell_body = CreatedCellBody.deserialize(
            client_sock.recv(cell_header.body_len))

        circuit_state = self.circuits[circ_id]

        # Create body and add an onion layer
        body = RelayExtendedCellBody(
            cell_body.pk, cell_body.hash, cell_body.signature).serialize()
        body = add_onion_layer(body, circuit_state.get_sesskey())

        # Create header
        hdr = CellHeader(THOR_VERSION, CellType.RelayExtended,
                         circuit_state.circuit_ids[0], len(body)).serialize()

        # Send the message
        msg = hdr + body
        sock = self.or_sockets[circuit_state.ip_addresses[0]]
        sock.send(msg)

    def handle_relay_extend(
            self, ip_addr: str, client_sock: socket.socket, cell_header: CellHeader):
        # Circuit ID must already exist
        circ_id = cell_header.circ_id
        assert circ_id in self.circuits

        # Receive the body
        cell_body = client_sock.recv(cell_header.body_len)

        # Peel the onion
        circuit_state = self.circuits[circ_id]
        cell_body = remove_onion_layer(cell_body, circuit_state.get_sesskey())
        if not verify_digest(bytes(cell_body)):
            # The other circuit ID must exist
            assert circuit_state.circuit_ids[1] is not None
            # Create the header
            hdr = CellHeader(THOR_VERSION, CellType.RelayExtend,
                             circuit_state.circuit_ids[1], len(cell_body)).serialize()
            msg = hdr + cell_body
            sock = self.or_sockets[circuit_state.ip_addresses[1]]
            sock.send(msg)
        else:
            # The other circuit ID must not exist
            assert circuit_state.circuit_ids[1] is None
            # Connect to the next OR if not already connected
            # TODO: synchronize
            cell_body = RelayExtendCellBody.deserialize(cell_body)
            print(
                "Address of the next OR:",
                socket.inet_ntoa(
                    cell_body.next_or_ip))
            if cell_body.next_or_ip in self.or_sockets:
                sock = self.or_sockets[cell_body.next_or_ip]
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(
                    (socket.inet_ntoa(cell_body.next_or_ip), THOR_PORT))
                addr = (socket.inet_ntoa(cell_body.next_or_ip), THOR_PORT)
                # Assign a thread to handle this connection
                threading.Thread(target=self.handle_client,
                                 args=(sock, addr)).start()

            circuit_state.ip_addresses[1] = cell_body.next_or_ip
            circuit_state.circuit_ids[1] = random(16)

            # Associate the circuit state with the other circuit ID as well
            self.circuits[circuit_state.circuit_ids[1]] = circuit_state

            body = CreateCellBody(cell_body.pk).serialize()
            hdr = CellHeader(1, CellType.Create,
                             circuit_state.circuit_ids[1], len(body)).serialize()

            msg = hdr + body
            sock.send(msg)

    def handle_relay_extended(self, ip_addr: str, client_sock: socket.socket, cell_header: CellHeader):
        # Circuit ID must already exist
        circ_id = cell_header.circ_id
        assert circ_id in self.circuits

        # Receive the body
        cell_body = client_sock.recv(cell_header.body_len)

        # Add onion layer
        circuit_state = self.circuits[circ_id]
        cell_body = add_onion_layer(cell_body, circuit_state.get_sesskey())

        # Create header
        hdr = CellHeader(THOR_VERSION, CellType.RelayExtended,
                         circuit_state.circuit_ids[0], len(cell_body)).serialize()

        # Send the message
        msg = hdr + cell_body
        sock = self.or_sockets[circuit_state.ip_addresses[0]]
        sock.send(msg)


def main(argv):
    if len(argv) != 4:
        print("usage: %s <IP ADDRESS> <PORT> <SIGNING KEY FILE>" % argv[0])
        return 1
    with open(argv[3], "rb") as keyfile:
        signingkey = keyfile.read(32)
    orouter = OnionRouter(argv[1], int(argv[2]), SigningKey(signingkey))
    orouter.serve()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
