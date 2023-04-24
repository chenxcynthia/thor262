import socket
from base64 import b64encode
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import VerifyKey
from nacl.encoding import RawEncoder
from nacl.hash import blake2b
from nacl.utils import random
from tor_protocol import *


class TorClient:
    def __init__(self, ds_ip: str, ds_key: VerifyKey):
        self.ds_ip = ds_ip
        self.ds_key = ds_key
        self.circ_id = random(16)
        self.sess_keys = [None, None, None]
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.stage = 0  # which onion router in the circuit the client is making

    def retrieve_onion_routers(self):
        print("Connecting to DS at %s" % self.ds_ip)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.ds_ip, THOR_PORT))

        # Generate nonce for request
        nonce = random(32)
        # Request a list of onion routers
        cell_body = DirectoryRetrieveRequestCellBody(nonce).serialize()
        cell_header = CellHeader(THOR_VERSION, CellType.DirectoryRetrieveRequest, bytes(
            16), len(cell_body)).serialize()
        send_all(sock, cell_header + cell_body)

        # Receive the response
        cell_header = CellHeader.deserialize(
            recv_all(sock, CellHeader.TotalSize))
        assert cell_header.type == CellType.DirectoryRetrieveResponse
        cell_body = DirectoryRetrieveResponseCellBody.deserialize(
            recv_all(sock, cell_header.body_len))
        or_ips = cell_body.or_ips
        or_pks = cell_body.pks
        print("Received OR addresses from DS")
        # Verify the DS's signature
        signature_payload = nonce
        assert len(or_ips) == len(or_pks)
        for i in range(len(or_ips)):
            signature_payload += or_ips[i]
            signature_payload += or_pks[i]
        self.ds_key.verify(signature_payload, cell_body.signature)
        print("DS signature verified")
        return or_ips, or_pks

    def create_onion_router(self, ip):
        sk = PrivateKey.generate()
        pk = sk.public_key

        print("Extending the circuit to OR %d at %s" % (self.stage + 1, ip))

        # making the first onion router
        if self.stage == 0:
            self.socket.connect((ip, 50051))
            cell_type = CellType.Create
            body = CreateCellBody(pk.encode()).serialize()

        # making later onion routers
        else:
            next_or_ip = socket.inet_aton(ip)
            cell_type = CellType.RelayExtend
            body = RelayExtendCellBody(next_or_ip, pk.encode()).serialize()

            # add layers in reverse order
            for j in reversed(range(self.stage)):
                # print('adding layer', j)
                body = add_onion_layer(body, self.sess_keys[j])

        hdr = CellHeader(1, cell_type, self.circ_id, len(body)).serialize()
        self.socket.send(hdr + body)

        return sk

    def receive_created(self, sk, pk):
        cell_header = CellHeader.deserialize(
            recv_all(self.socket, CellHeader.TotalSize))

        cell_body = recv_all(self.socket, cell_header.body_len)
        if self.stage == 0:
            cell_body = CreatedCellBody.deserialize(cell_body)
        else:
            # peel off layers in order
            for j in range(self.stage):
                # print('removing layer ', j)
                # print('sesion key', self.sess_keys[j])
                cell_body = remove_onion_layer(
                    bytes(cell_body), self.sess_keys[j])
            assert len(cell_body) == RelayExtendedCellBody.TotalSize
            assert verify_digest(bytes(cell_body))
            cell_body = RelayExtendedCellBody.deserialize(cell_body)

        shared_secret = Box(sk, PublicKey(cell_body.pk)).shared_key()
        session_key = blake2b(
            b'', digest_size=32, key=shared_secret, person=b"THOR", encoder=RawEncoder)
        self.sess_keys[self.stage] = session_key
        hash_shared_secret = blake2b(
            session_key, digest_size=32, person=b"THOR", encoder=RawEncoder)
        signature_payload = cell_body.pk + cell_body.hash
        VerifyKey(pk).verify(signature_payload, cell_body.signature)
        print("OR signature verified")

        # update "stage" to next one
        self.stage += 1

        if hash_shared_secret == cell_body.hash:
            print("Established a session key with OR %d" % self.stage)
        else:
            raise ValueError("Mismatch between client's and OR's session key")

    def begin(self, hostname, port):
        print("Opening a TCP connection to %s:%d through the circuit" %
              (hostname, port))
        body = RelayBeginCellBody(port, hostname).serialize()
        for j in reversed(range(3)):
            body = add_onion_layer(body, self.sess_keys[j])
        hdr = CellHeader(1, CellType.RelayBegin,
                         self.circ_id, len(body)).serialize()
        self.socket.send(hdr + body)

    def receive_connected(self) -> bool:
        cell_header = CellHeader.deserialize(
            recv_all(self.socket, CellHeader.TotalSize))
        cell_body = recv_all(self.socket, cell_header.body_len)
        for j in range(self.stage):
            cell_body = remove_onion_layer(bytes(cell_body), self.sess_keys[j])
        assert verify_digest(bytes(cell_body))
        cell_body = RelayConnectedCellBody.deserialize(cell_body)
        return cell_body.status == 0

    def send_data(self, data: bytes):
        print("Sending a message through the circuit")
        cell_body = RelayDataCellBody(data).serialize()
        for j in reversed(range(3)):
            cell_body = add_onion_layer(cell_body, self.sess_keys[j])
        cell_header = CellHeader(
            THOR_VERSION, CellType.RelayData, self.circ_id, len(cell_body)).serialize()
        self.socket.send(cell_header + cell_body)

    def recv_data(self) -> bytes:
        print("Receiving a message through the circuit")
        cell_header = CellHeader.deserialize(
            recv_all(self.socket, CellHeader.TotalSize))
        cell_body = recv_all(self.socket, cell_header.body_len)
        for j in range(self.stage):
            cell_body = remove_onion_layer(bytes(cell_body), self.sess_keys[j])
        assert verify_digest(bytes(cell_body))
        cell_body = RelayDataCellBody.deserialize(cell_body)
        return cell_body.data

    def destroy(self):
        print("Destroying the circuit")
        body = DestroyCellBody().serialize()
        hdr = CellHeader(1, CellType.Destroy, self.circ_id,
                         len(body)).serialize()
        self.socket.send(hdr + body)
        self.socket.close()
