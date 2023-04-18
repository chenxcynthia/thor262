from onion_router import CreateCellBody, CreatedCellBody, CellHeader, CellType, RelayExtendCellBody, RelayExtendedCellBody, add_onion_layer, remove_onion_layer, verify_digest
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import RawEncoder
from nacl.hash import blake2b
from nacl.utils import random
from base64 import b64encode
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 50051))

circ_id = random(16)
sess_keys = [None, None, None]

# Send Create cell to create the first circuit hop
sk = PrivateKey.generate()
pk = sk.public_key
body = CreateCellBody(pk.encode()).serialize()
hdr = CellHeader(1, CellType.Create, circ_id, len(body)).serialize()
s.send(hdr + body)

# Receive Created from the first hop
cell_header = CellHeader.deserialize(s.recv(CellHeader.TotalSize))
assert cell_header.body_len == CreatedCellBody.TotalSize
cell_body = s.recv(cell_header.body_len)
cell_body = CreatedCellBody.deserialize(cell_body)
shared_secret = Box(sk, PublicKey(cell_body.pk)).shared_key()
session_key = blake2b(b'', digest_size=32, key=shared_secret, person=b"THOR", encoder=RawEncoder)
sess_keys[0] = session_key
hash_shared_secret = blake2b(session_key, digest_size=32, person=b"THOR", encoder=RawEncoder)
print("OR 1 public key:", b64encode(cell_body.pk))
print("OR 1 hash of the session key:", b64encode(cell_body.hash))
print("OR 1 signature:", b64encode(cell_body.signature))
print("My hash of OR 1 session key:", b64encode(hash_shared_secret))

# Send RelayExtend cell to create the second hop
next_or_ip = socket.inet_aton('127.0.0.2')
sk2 = PrivateKey.generate()
pk2 = sk2.public_key
body = RelayExtendCellBody(next_or_ip, pk2.encode()).serialize()
body = add_onion_layer(body, sess_keys[0])
hdr = CellHeader(1, CellType.RelayExtend, circ_id, len(body)).serialize()
s.send(hdr + body)

# Receive RelayExtended
cell_header = CellHeader.deserialize(s.recv(CellHeader.TotalSize))
cell_body = s.recv(cell_header.body_len)
cell_body = remove_onion_layer(cell_body, sess_keys[0])
assert len(cell_body) == RelayExtendedCellBody.TotalSize
assert verify_digest(bytes(cell_body))
cell_body = RelayExtendedCellBody.deserialize(cell_body)
shared_secret = Box(sk2, PublicKey(cell_body.pk)).shared_key()
session_key = blake2b(b'', digest_size=32, key=shared_secret, person=b"THOR", encoder=RawEncoder)
sess_keys[1] = session_key
hash_shared_secret = blake2b(session_key, digest_size=32, person=b"THOR", encoder=RawEncoder)
print("OR 2 public key:", b64encode(cell_body.pk))
print("OR 2 hash of the session key:", b64encode(cell_body.hash))
print("OR 2 signature:", b64encode(cell_body.signature))
print("My hash of OR 2 session key:", b64encode(hash_shared_secret))


# https://imgur.com/a/B4szw53
next_or_ip = socket.inet_aton('127.0.0.3')
sk3 = PrivateKey.generate()
pk3 = sk3.public_key
body = RelayExtendCellBody(next_or_ip, pk3.encode()).serialize()
body = add_onion_layer(body, sess_keys[1])
body = add_onion_layer(body, sess_keys[0])
hdr = CellHeader(1, CellType.RelayExtend, circ_id, len(body)).serialize()
s.send(hdr + body)

# Receive RelayExtended
cell_header = CellHeader.deserialize(s.recv(CellHeader.TotalSize))
cell_body = s.recv(cell_header.body_len)
cell_body = remove_onion_layer(bytes(cell_body), sess_keys[0])
cell_body = remove_onion_layer(bytes(cell_body), sess_keys[1])
assert len(cell_body) == RelayExtendedCellBody.TotalSize
assert verify_digest(bytes(cell_body))
cell_body = RelayExtendedCellBody.deserialize(cell_body)
shared_secret = Box(sk3, PublicKey(cell_body.pk)).shared_key()
session_key = blake2b(b'', digest_size=32, key=shared_secret, person=b"THOR", encoder=RawEncoder)
sess_keys[2] = session_key
hash_shared_secret = blake2b(session_key, digest_size=32, person=b"THOR", encoder=RawEncoder)
print("OR 3 public key:", b64encode(cell_body.pk))
print("OR 3 hash of the session key:", b64encode(cell_body.hash))
print("OR 3 signature:", b64encode(cell_body.signature))
print("My hash of OR 3 session key:", b64encode(hash_shared_secret))
