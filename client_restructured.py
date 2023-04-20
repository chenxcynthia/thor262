import socket
from base64 import b64encode
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import RawEncoder
from nacl.hash import blake2b
from nacl.utils import random
from tor_protocol import *

class TorClient:
    def __init__(self):
        self.circ_id = random(16)
        self.sess_keys = [None, None, None]
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.stage = 0  # which onion router in the circuit the client is making

    def create_onion_router(self, ip):
        sk = PrivateKey.generate()
        pk = sk.public_key

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

    def receive_created(self, sk):
        cell_header = CellHeader.deserialize(self.socket.recv(CellHeader.TotalSize))
        # assert cell_header.body_len == CreatedCellBody.TotalSize
        
        cell_body = self.socket.recv(cell_header.body_len)
        if self.stage == 0:
            cell_body = CreatedCellBody.deserialize(cell_body)
        else:
            # peel off layers in order
            for j in range(self.stage): 
                # print('removing layer ', j)
                # print('sesion key', self.sess_keys[j])
                cell_body = remove_onion_layer(bytes(cell_body), self.sess_keys[j])
            assert len(cell_body) == RelayExtendedCellBody.TotalSize
            assert verify_digest(bytes(cell_body))
            cell_body = RelayExtendedCellBody.deserialize(cell_body)

        shared_secret = Box(sk, PublicKey(cell_body.pk)).shared_key()
        session_key = blake2b(b'', digest_size=32, key=shared_secret, person=b"THOR", encoder=RawEncoder)
        self.sess_keys[self.stage] = session_key
        hash_shared_secret = blake2b(session_key, digest_size=32, person=b"THOR", encoder=RawEncoder)

        # update "stage" to next one
        self.stage += 1

        print(f"OR {self.stage} public key:", b64encode(cell_body.pk))
        print(f"OR {self.stage} hash of the session key:", b64encode(cell_body.hash))
        print(f"OR {self.stage} signature:", b64encode(cell_body.signature))
        print(f"My hash of OR {self.stage} session key:", b64encode(hash_shared_secret))

        

    def begin(self, hostname, port):
        body = RelayBeginCellBody(port, hostname).serialize()
        for j in reversed(range(3)):
            body = add_onion_layer(body, self.sess_keys[j])
        hdr = CellHeader(1, CellType.RelayBegin, self.circ_id, len(body)).serialize()
        self.socket.send(hdr + body)

    def destroy(self):
        body = DestroyCellBody().serialize()
        hdr = CellHeader(1, CellType.Destroy, self.circ_id, len(body)).serialize()
        self.socket.send(hdr + body)
        self.socket.close()


# TODO: use command line arguments for the 3 IP addresses
ip_addr = ['127.0.0.1', '127.0.0.2', '127.0.0.3']

# Destination website to connect to
hostname = 'www.harvard.edu'
port = 80

client = TorClient()

# Create 3 onion routers
for i in range(3):
    sk = client.create_onion_router(ip_addr[i])
    client.receive_created(sk)

# Send RelayBegin cell to start a TCP connection
client.begin(hostname, port) # Question: does port need to be passed in as a parameter?

# Now tear down the circuit
client.destroy()