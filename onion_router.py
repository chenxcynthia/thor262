import socket
import ssl
import sys
import threading
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey
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
        self.destination_hostname: str = None
        self.destination_port: int = None
        self.destination_socket: socket.socket = None

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
    def __init__(self, master_key: SigningKey):
        self.master_key = master_key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Mapping from IPs to sockets
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

    def join_directory(self, directory_key: VerifyKey, directory_ip: str) -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((directory_ip, THOR_PORT))

        # Store our public key (we are the initiator)
        init_pk = self.master_key.verify_key.encode()
        # Generate nonce for INIT
        init_nonce = random(32)
        # Send INIT
        cell_body = DirectoryChallengeInitCellBody(
            init_pk, init_nonce).serialize()
        cell_header = CellHeader(
            THOR_VERSION, CellType.DirectoryChallengeInit, bytes(16), len(cell_body)).serialize()
        send_all(sock, cell_header + cell_body)

        # Recieve the challenge request
        cell_header = CellHeader.deserialize(
            recv_all(sock, CellHeader.TotalSize))
        assert cell_header.type == CellType.DirectoryChallengeRequest
        cell_body = DirectoryChallengeRequestCellBody.deserialize(
            recv_all(sock, cell_header.body_len))
        # Verify the challenger's signature
        challenger_signature = cell_body.signature
        try:
            directory_key.verify(init_nonce, challenger_signature)
        except:
            sock.close()
            return -1
        # Prove to the challenger that we hold the signing key
        challenger_nonce = cell_body.nonce
        init_signature = self.master_key.sign(challenger_nonce).signature
        # Send the challenge response
        cell_body = DirectoryChallengeResponseCellBody(
            init_signature).serialize()
        cell_header = CellHeader(
            THOR_VERSION, CellType.DirectoryChallengeResponse, bytes(16), len(cell_body)).serialize()
        send_all(sock, cell_header + cell_body)

        # Receive ACK
        cell_header = CellHeader.deserialize(
            recv_all(sock, CellHeader.TotalSize))
        assert cell_header.type == CellType.DirectoryChallengeAck
        cell_body = DirectoryChallengeAckCellBody.deserialize(
            recv_all(sock, cell_header.body_len))
        return cell_body.status

    def handle_client(self, client_sock: socket.socket, addr: Tuple[str, int]):
        print("Accepted connection from %s:%d" % (addr[0], addr[1]))
        ip_addr = socket.inet_aton(addr[0])
        # This connection wasn't already open
        assert ip_addr not in self.or_sockets
        self.or_sockets[ip_addr] = client_sock
        while True:
            data = recv_all(client_sock, CellHeader.TotalSize)
            print(threading.get_ident())
            print(len(data))
            print(data)
            if len(data) == 0:
                break
            cell_header = CellHeader.deserialize(data)
            if cell_header.type == CellType.Create:
                self.handle_create(ip_addr, client_sock, cell_header)
            elif cell_header.type == CellType.RelayExtend:
                self.handle_relay_extend(ip_addr, client_sock, cell_header)
            elif cell_header.type == CellType.Created:
                self.handle_created(ip_addr, client_sock, cell_header)
            elif cell_header.type == CellType.RelayExtended:
                self.handle_relay_extended(ip_addr, client_sock, cell_header)
            elif cell_header.type == CellType.Destroy:
                self.handle_destroy(ip_addr, client_sock, cell_header)
                if ip_addr not in self.or_sockets:
                    break
            elif cell_header.type == CellType.RelayBegin:
                self.handle_relay_begin(ip_addr, client_sock, cell_header)
            elif cell_header.type == CellType.RelayConnected:
                self.handle_relay_connected(ip_addr, client_sock, cell_header)
            elif cell_header.type == CellType.RelayData:
                self.handle_relay_data(ip_addr, client_sock, cell_header)

    def handle_create(self, ip_addr: bytes,
                      client_sock: socket.socket, cell_header: CellHeader):
        cell_body = CreateCellBody.deserialize(
            recv_all(client_sock, cell_header.body_len))

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
        send_all(client_sock, hdr + response_data)

    def handle_created(self, ip_addr: bytes, client_sock: socket.socket, cell_header: CellHeader):
        # Circuit ID must already exist
        circ_id = cell_header.circ_id
        assert circ_id in self.circuits

        # Receive the body
        cell_body = CreatedCellBody.deserialize(
            recv_all(client_sock, cell_header.body_len))

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
        send_all(sock, msg)

    def handle_destroy(self, ip_addr: bytes, client_sock: socket.socket, cell_header: CellHeader):
        # Circuit ID must exist
        circ_id = cell_header.circ_id
        assert circ_id in self.circuits

        # Receive the body (nop)
        cell_body = DestroyCellBody.deserialize(
            recv_all(client_sock, cell_header.body_len))

        circuit_state = self.circuits[circ_id]

        # Forward the teardown request if there is anyone down the line
        if circuit_state.circuit_ids[1] is not None:
            body = DestroyCellBody().serialize()
            hdr = CellHeader(THOR_VERSION, CellType.Destroy,
                             circuit_state.circuit_ids[1], len(body)).serialize()
            msg = hdr + body
            sock = self.or_sockets[circuit_state.ip_addresses[1]]
            send_all(sock, msg)

        # Close any possible destination connection
        if circuit_state.destination_socket is not None:
            circuit_state.destination_socket.close()

        circ_ids = circuit_state.circuit_ids
        ip_addrs = circuit_state.ip_addresses

        # Remove circuit state
        self.circuits.pop(circ_ids[0])
        if circ_ids[1] is not None:
            self.circuits.pop(circ_ids[1])

        close_incoming = True
        close_outgoing = circ_ids[1] is not None
        for circuit_state in self.circuits.values():
            if close_incoming and ip_addrs[0] == circuit_state.ip_addresses[0]:
                close_incoming = False
            if close_outgoing and ip_addrs[1] == circuit_state.ip_addresses[1]:
                close_outgoing = False
            if not close_incoming and not close_outgoing:
                break
        if close_incoming:
            self.or_sockets[ip_addrs[0]].close()
            self.or_sockets.pop(ip_addrs[0])
        if close_outgoing:
            self.or_sockets[ip_addrs[1]].close()
            self.or_sockets.pop(ip_addrs[1])

    def handle_relay_data(self, ip_addr: str, client_sock: socket.socket, cell_header: CellHeader):
        # Circuit ID must already exist
        circ_id = cell_header.circ_id
        assert circ_id in self.circuits

        # Receive the body
        cell_body = recv_all(client_sock, cell_header.body_len)

        circuit_state = self.circuits[circ_id]

        # If the message is coming from downstream, just pass it along
        if circ_id == circuit_state.circuit_ids[1]:
            # Add onion layer
            circuit_state = self.circuits[circ_id]
            cell_body = add_onion_layer(cell_body, circuit_state.get_sesskey())

            # Create header
            hdr = CellHeader(THOR_VERSION, CellType.RelayData,
                             circuit_state.circuit_ids[0], len(cell_body)).serialize()

            # Send the message
            msg = hdr + cell_body
            sock = self.or_sockets[circuit_state.ip_addresses[0]]
            send_all(sock, msg)
            return

        # Peel off the onion
        cell_body = remove_onion_layer(cell_body, circuit_state.get_sesskey())

        # If the message is not for us, pass it downstream
        if not verify_digest(bytes(cell_body)):
            # The other circuit ID must exist
            assert circuit_state.circuit_ids[1] is not None
            # Create the header
            hdr = CellHeader(THOR_VERSION, CellType.RelayData,
                             circuit_state.circuit_ids[1], len(cell_body)).serialize()
            msg = hdr + cell_body
            sock = self.or_sockets[circuit_state.ip_addresses[1]]
            send_all(sock, msg)
        else:
            # There must be a destination already
            assert circuit_state.destination_socket is not None
            # Send the data to the destination
            cell_body = RelayDataCellBody.deserialize(cell_body)
            send_all(circuit_state.destination_socket, cell_body.data)
            # Receive a response
            response = recv_all(circuit_state.destination_socket, 1073741824)
            # Send it upstream
            cell_body = RelayDataCellBody(response).serialize()
            cell_body = add_onion_layer(cell_body, circuit_state.get_sesskey())
            hdr = CellHeader(THOR_VERSION, CellType.RelayData,
                             circuit_state.circuit_ids[0], len(cell_body)).serialize()
            msg = hdr + cell_body
            sock = self.or_sockets[circuit_state.ip_addresses[0]]
            send_all(sock, msg)

    def handle_relay_begin(self, ip_addr: str, client_sock: socket.socket, cell_header: CellHeader):
        # Circuit ID must already exist
        circ_id = cell_header.circ_id
        assert circ_id in self.circuits

        # Receive the body
        cell_body = recv_all(client_sock, cell_header.body_len)

        # Peel the onion
        circuit_state = self.circuits[circ_id]
        cell_body = remove_onion_layer(cell_body, circuit_state.get_sesskey())

        if not verify_digest(bytes(cell_body)):
            # The other circuit ID must exist
            assert circuit_state.circuit_ids[1] is not None
            # Create the header
            hdr = CellHeader(THOR_VERSION, CellType.RelayBegin,
                             circuit_state.circuit_ids[1], len(cell_body)).serialize()
            msg = hdr + cell_body
            sock = self.or_sockets[circuit_state.ip_addresses[1]]
            send_all(sock, msg)
        else:
            # There must not be a connection already
            assert circuit_state.destination_socket is None
            cell_body = RelayBeginCellBody.deserialize(cell_body)
            new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Special-case for HTTPS
            if cell_body.port == 443:
                new_sock = ssl.create_default_context().wrap_socket(
                    new_sock, server_hostname=cell_body.hostname)
            new_sock.settimeout(2)
            try:
                new_sock.connect((cell_body.hostname, cell_body.port))
                circuit_state.destination_socket = new_sock
                circuit_state.destination_hostname = cell_body.hostname
                circuit_state.destination_port = cell_body.port
                print("Connecting to %s:%d successful" %
                      (cell_body.hostname, cell_body.port))
                status = 0
            except:
                print("Connecting to %s:%d failed" %
                      (cell_body.hostname, cell_body.port))
                status = 1
            cell_body = RelayConnectedCellBody(status).serialize()
            cell_body = add_onion_layer(cell_body, circuit_state.get_sesskey())
            hdr = CellHeader(THOR_VERSION, CellType.RelayConnected,
                             circuit_state.circuit_ids[0], len(cell_body)).serialize()
            msg = hdr + cell_body
            sock = self.or_sockets[circuit_state.ip_addresses[0]]
            send_all(sock, msg)

    def handle_relay_connected(self, ip_addr: str, client_sock: socket.socket, cell_header: CellHeader):
        # Circuit ID must already exist
        circ_id = cell_header.circ_id
        assert circ_id in self.circuits

        # Receive the body
        cell_body = recv_all(client_sock, cell_header.body_len)

        # Add onion layer
        circuit_state = self.circuits[circ_id]
        cell_body = add_onion_layer(cell_body, circuit_state.get_sesskey())

        # Create header
        hdr = CellHeader(THOR_VERSION, CellType.RelayConnected,
                         circuit_state.circuit_ids[0], len(cell_body)).serialize()

        # Send the message
        msg = hdr + cell_body
        sock = self.or_sockets[circuit_state.ip_addresses[0]]
        send_all(sock, msg)

    def handle_relay_extend(
            self, ip_addr: str, client_sock: socket.socket, cell_header: CellHeader):
        # Circuit ID must already exist
        circ_id = cell_header.circ_id
        assert circ_id in self.circuits

        # Receive the body
        cell_body = recv_all(client_sock, cell_header.body_len)

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
            send_all(sock, msg)
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
            send_all(sock, msg)

    def handle_relay_extended(self, ip_addr: str, client_sock: socket.socket, cell_header: CellHeader):
        # Circuit ID must already exist
        circ_id = cell_header.circ_id
        assert circ_id in self.circuits

        # Receive the body
        cell_body = recv_all(client_sock, cell_header.body_len)

        # Add onion layer
        circuit_state = self.circuits[circ_id]
        cell_body = add_onion_layer(cell_body, circuit_state.get_sesskey())

        # Create header
        hdr = CellHeader(THOR_VERSION, CellType.RelayExtended,
                         circuit_state.circuit_ids[0], len(cell_body)).serialize()

        # Send the message
        msg = hdr + cell_body
        sock = self.or_sockets[circuit_state.ip_addresses[0]]
        send_all(sock, msg)


def main(argv):
    if len(argv) != 4:
        print(
            "usage: %s <DIRECTORY SERVER IP ADDRESS> <DIRECTORY SERVER PUBLIC KEY> <PRIVATE KEY FILE>" % argv[0])
        return 1
    with open(argv[2], "rb") as keyfile:
        ds_publickey = keyfile.read(32)
    with open(argv[3], "rb") as keyfile:
        signingkey = keyfile.read(32)
    orouter = OnionRouter(SigningKey(signingkey))
    status = orouter.join_directory(VerifyKey(ds_publickey), argv[1])
    if status == 0:
        print("Successfully joined the DS")
    elif status == -1:
        print("Failed to verify the DS's signature")
    elif status == 1:
        print("DS refused the join")
    # orouter.serve()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
