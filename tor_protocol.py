from enum import IntEnum
from nacl.secret import SecretBox
from nacl.hash import blake2b
from nacl.encoding import RawEncoder
import socket

THOR_VERSION = 1
THOR_PORT = 50051


def add_onion_layer(data: bytearray, session_key: bytes) -> bytearray:
    return bytearray(SecretBox(session_key).encrypt(data))


def remove_onion_layer(data: bytearray, session_key: bytes) -> bytearray:
    return bytearray(SecretBox(session_key).decrypt(data))


def compute_digest(data: bytes) -> bytes:
    return blake2b(data, digest_size=32, person=b"THOR", encoder=RawEncoder)

# We adopt the convention that the last 32 bytes are the digest


def verify_digest(data: bytes) -> bool:
    assert len(data) >= 32
    return blake2b(data[:-32], digest_size=32, person=b"THOR", encoder=RawEncoder) == data[-32:]


def send_all(sock: socket.socket, data: bytes):
    sent = 0
    while sent < len(data):
        sent = sent + sock.send(data[sent:])


def recv_all(sock: socket.socket, length: int) -> bytes:
    data = b""
    while len(data) < length:
        try:
            chunk = sock.recv(length - len(data))
            if len(chunk) == 0:
                break
        except socket.timeout:
            if len(data) == 0:
                continue
            else:
                break
        data += chunk
    return data


class CellType(IntEnum):
    Create = 0,
    Created = 1,
    Destroy = 2,
    RelayData = 3,
    RelayBegin = 4,
    RelayEnd = 5,
    RelayTeardown = 6,
    RelayConnected = 7,
    RelayExtend = 8,
    RelayExtended = 9
    EndCellType = 10


class CellHeader:
    VersionBegin = 0
    VersionSize = 2
    VersionEnd = 2

    TypeBegin = 2
    TypeSize = 2
    TypeEnd = 4

    CircIdBegin = 4
    CircIdSize = 16
    CircIdEnd = 20

    BodyLenBegin = 20
    BodyLenSize = 4
    BodyLenEnd = 24

    TotalSize = 24

    def __init__(self, version: int, type: CellType, circ_id: bytes, body_len: int):
        if version != THOR_VERSION:
            raise ValueError("Unknown THOR version")
        self.version = version

        if type >= CellType.EndCellType:
            raise ValueError("Invalid cell header type")
        self.type = type

        if len(circ_id) != 16:
            raise ValueError("Invalid circuit ID")
        self.circ_id = circ_id
        self.body_len = body_len

    def serialize(self) -> bytearray:
        data = bytearray(CellHeader.TotalSize)
        data[CellHeader.VersionBegin:CellHeader.VersionEnd] = self.version.to_bytes(
            CellHeader.VersionSize, byteorder='little')
        data[CellHeader.TypeBegin:CellHeader.TypeEnd] = self.type.to_bytes(
            CellHeader.TypeSize, byteorder='little')
        data[CellHeader.CircIdBegin:CellHeader.CircIdEnd] = self.circ_id
        data[CellHeader.BodyLenBegin:CellHeader.BodyLenEnd] = self.body_len.to_bytes(
            CellHeader.BodyLenSize, byteorder='little')
        return data

    @staticmethod
    def deserialize(data: bytearray) -> "CellHeader":
        assert len(data) == CellHeader.TotalSize
        version = int.from_bytes(
            data[CellHeader.VersionBegin:CellHeader.VersionEnd], byteorder='little')
        type = int.from_bytes(
            data[CellHeader.TypeBegin:CellHeader.TypeEnd], byteorder='little')
        circ_id = bytes(data[CellHeader.CircIdBegin:CellHeader.CircIdEnd])
        body_len = int.from_bytes(
            data[CellHeader.BodyLenBegin:CellHeader.BodyLenEnd], byteorder='little')
        return CellHeader(version, type, circ_id, body_len)


class CreateCellBody:
    PublicKeyBegin = 0
    PublicKeySize = 32
    PublicKeyEnd = 32

    TotalSize = 32

    def __init__(self, pk: bytes):
        if len(pk) != 32:
            raise ValueError("Invalid public key length")
        self.pk = pk

    def serialize(self) -> bytearray:
        data = bytearray(CreateCellBody.TotalSize)
        data[CreateCellBody.PublicKeyBegin:CreateCellBody.PublicKeyEnd] = self.pk
        return data

    @staticmethod
    def deserialize(data: bytearray) -> "CreateCellBody":
        assert len(data) == CreateCellBody.TotalSize
        pk = bytes(
            data[CreateCellBody.PublicKeyBegin:CreateCellBody.PublicKeyEnd])
        return CreateCellBody(pk)


class CreatedCellBody:
    PublicKeyBegin = 0
    PublicKeySize = 32
    PublicKeyEnd = 32

    HashBegin = 32
    HashSize = 32
    HashEnd = 64

    SignatureBegin = 64
    SignatureSize = 64
    SignatureEnd = 128

    TotalSize = 128

    def __init__(self, pk: bytes, sharedhash: bytes, signature: bytes):
        if len(pk) != 32:
            raise ValueError("Invalid public key length")
        self.pk = pk
        if len(sharedhash) != 32:
            raise ValueError("Invalid shared secret hash")
        self.hash = sharedhash
        if len(signature) != 64:
            raise ValueError("Invalid signature length")
        self.signature = signature

    def serialize(self) -> bytearray:
        data = bytearray(CreatedCellBody.TotalSize)
        data[CreatedCellBody.PublicKeyBegin:CreatedCellBody.PublicKeyEnd] = self.pk
        data[CreatedCellBody.HashBegin:CreatedCellBody.HashEnd] = self.hash
        data[CreatedCellBody.SignatureBegin:CreatedCellBody.SignatureEnd] = self.signature
        return data

    @staticmethod
    def deserialize(data: bytearray) -> "CreatedCellBody":
        assert len(data) == CreatedCellBody.TotalSize
        pk = bytes(
            data[CreatedCellBody.PublicKeyBegin:CreatedCellBody.PublicKeyEnd])
        sharedhash = bytes(
            data[CreatedCellBody.HashBegin:CreatedCellBody.HashEnd])
        signature = bytes(
            data[CreatedCellBody.SignatureBegin:CreatedCellBody.SignatureEnd])
        return CreatedCellBody(pk, sharedhash, signature)


class DestroyCellBody:
    TotalSize = 0

    def __init__(self):
        pass

    def serialize(self) -> bytearray:
        data = bytearray(DestroyCellBody.TotalSize)
        return data

    @staticmethod
    def deserialize(data: bytearray) -> "DestroyCellBody":
        assert len(data) == DestroyCellBody.TotalSize
        return DestroyCellBody()


class RelayDataCellBody:
    DataBegin = 0

    DigestSize = 32

    def __init__(self, data: bytes):
        self.data = data
        self.digest = compute_digest(self.data)

    def serialize(self) -> bytearray:
        data_size = len(self.data)
        data_end = RelayDataCellBody.DataBegin + data_size
        digest_begin = data_end
        digest_end = digest_begin + RelayDataCellBody.DigestSize
        total_size = data_size + RelayDataCellBody.DigestSize
        data = bytearray(total_size)
        data[RelayDataCellBody.DataBegin:data_end] = self.data
        data[digest_begin:digest_end] = self.digest
        return data

    @staticmethod
    def deserialize(data: bytearray) -> "RelayDataCellBody":
        total_size = len(data)
        assert total_size >= RelayDataCellBody.DigestSize
        data_end = total_size - RelayDataCellBody.DigestSize
        this_data = data[RelayDataCellBody.DataBegin:data_end]
        return RelayDataCellBody(bytes(this_data))


class RelayBeginCellBody:
    PortBegin = 0
    PortSize = 2
    PortEnd = 2

    HostnameBegin = 2

    DigestSize = 32

    def __init__(self, port: int, hostname: str):
        if port < 0 or port > 65535:
            raise ValueError("Invalid port")
        self.port = port
        self.hostname = hostname
        self.digest = compute_digest(self.port.to_bytes(
            RelayBeginCellBody.PortSize, byteorder='little') + bytes(self.hostname, 'utf-8'))

    def serialize(self) -> bytearray:
        hostname_bytes = bytes(self.hostname, 'utf-8')
        hostname_size = len(hostname_bytes)
        hostname_end = RelayBeginCellBody.HostnameBegin + hostname_size
        digest_begin = hostname_end
        digest_end = digest_begin + RelayBeginCellBody.DigestSize
        total_size = RelayBeginCellBody.PortSize + \
            hostname_size + RelayBeginCellBody.DigestSize
        data = bytearray(total_size)
        data[RelayBeginCellBody.PortBegin:RelayBeginCellBody.PortEnd] = self.port.to_bytes(
            RelayBeginCellBody.PortSize, byteorder='little')
        data[RelayBeginCellBody.HostnameBegin:hostname_end] = hostname_bytes
        data[digest_begin:digest_end] = self.digest
        return data

    @staticmethod
    def deserialize(data: bytearray) -> "RelayBeginCellBody":
        total_size = len(data)
        assert total_size >= RelayBeginCellBody.PortSize + RelayBeginCellBody.DigestSize
        hostname_end = total_size - RelayBeginCellBody.DigestSize
        port = int.from_bytes(
            data[RelayBeginCellBody.PortBegin:RelayBeginCellBody.PortEnd], byteorder='little')
        hostname = str(
            data[RelayBeginCellBody.HostnameBegin:hostname_end], 'utf-8')
        return RelayBeginCellBody(port, hostname)


class RelayConnectedCellBody:
    StatusBegin = 0
    StatusSize = 2
    StatusEnd = 2

    DigestBegin = 2
    DigestSize = 32
    DigestEnd = 34

    TotalSize = 34

    def __init__(self, status: int):
        if status < 0 or status > 65535:
            raise ValueError("Invalid status")
        self.status = status
        self.digest = compute_digest(self.status.to_bytes(
            RelayConnectedCellBody.StatusSize, byteorder='little'))

    def serialize(self) -> bytearray:
        data = bytearray(RelayConnectedCellBody.TotalSize)
        data[RelayConnectedCellBody.StatusBegin:RelayConnectedCellBody.StatusEnd] = self.status.to_bytes(
            RelayConnectedCellBody.StatusSize, byteorder='little')
        data[RelayConnectedCellBody.DigestBegin:RelayConnectedCellBody.DigestEnd] = self.digest
        return data

    @staticmethod
    def deserialize(data: bytearray) -> "RelayConnectedCellBody":
        assert len(data) == RelayConnectedCellBody.TotalSize
        status = int.from_bytes(
            data[RelayConnectedCellBody.StatusBegin:RelayConnectedCellBody.StatusEnd], byteorder='little')
        return RelayConnectedCellBody(status)


class RelayExtendCellBody:
    NextOrIpBegin = 0
    NextOrIpEnd = 4
    NextOrIpSize = 4

    PublicKeyBegin = 4
    PublicKeySize = 32
    PublicKeyEnd = 36

    DigestBegin = 36
    DigestSize = 32
    DigestEnd = 68

    TotalSize = 68

    def __init__(self, next_or_ip: bytes, pk: bytes):
        if len(next_or_ip) != 4:
            raise ValueError("Invalid next OR IP address")
        self.next_or_ip = next_or_ip
        if len(pk) != 32:
            raise ValueError("Invalid public key length")
        self.pk = pk
        self.digest = compute_digest(self.next_or_ip + self.pk)

    def serialize(self) -> bytearray:
        data = bytearray(RelayExtendCellBody.TotalSize)
        data[RelayExtendCellBody.NextOrIpBegin:RelayExtendCellBody.NextOrIpEnd] = self.next_or_ip
        data[RelayExtendCellBody.PublicKeyBegin:RelayExtendCellBody.PublicKeyEnd] = self.pk
        data[RelayExtendCellBody.DigestBegin:RelayExtendCellBody.DigestEnd] = self.digest
        return data

    @staticmethod
    def deserialize(data: bytearray) -> "RelayExtendCellBody":
        assert len(data) == RelayExtendCellBody.TotalSize
        next_or_ip = bytes(
            data[RelayExtendCellBody.NextOrIpBegin:RelayExtendCellBody.NextOrIpEnd])
        pk = bytes(
            data[RelayExtendCellBody.PublicKeyBegin:RelayExtendCellBody.PublicKeyEnd])
        return RelayExtendCellBody(next_or_ip, pk)


class RelayExtendedCellBody:
    PublicKeyBegin = 0
    PublicKeySize = 32
    PublicKeyEnd = 32

    HashBegin = 32
    HashSize = 32
    HashEnd = 64

    SignatureBegin = 64
    SignatureSize = 64
    SignatureEnd = 128

    DigestBegin = 128
    DigestSize = 32
    DigestEnd = 160

    TotalSize = 160

    def __init__(self, pk: bytes, sharedhash: bytes, signature: bytes):
        if len(pk) != 32:
            raise ValueError("Invalid public key length")
        self.pk = pk
        if len(sharedhash) != 32:
            raise ValueError("Invalid shared secret hash")
        self.hash = sharedhash
        if len(signature) != 64:
            raise ValueError("Invalid signature length")
        self.signature = signature
        self.digest = compute_digest(self.pk + self.hash + self.signature)

    def serialize(self) -> bytearray:
        data = bytearray(RelayExtendedCellBody.TotalSize)
        data[RelayExtendedCellBody.PublicKeyBegin:RelayExtendedCellBody.PublicKeyEnd] = self.pk
        data[RelayExtendedCellBody.HashBegin:RelayExtendedCellBody.HashEnd] = self.hash
        data[RelayExtendedCellBody.SignatureBegin:RelayExtendedCellBody.SignatureEnd] = self.signature
        data[RelayExtendedCellBody.DigestBegin:RelayExtendedCellBody.DigestEnd] = self.digest
        return data

    def compute_digest(self) -> bytes:
        return blake2b(self.pk + self.hash + self.signature, digest_size=32, person=b"THOR")

    @staticmethod
    def deserialize(data: bytearray) -> "RelayExtendedCellBody":
        assert len(data) == RelayExtendedCellBody.TotalSize
        pk = bytes(
            data[RelayExtendedCellBody.PublicKeyBegin:RelayExtendedCellBody.PublicKeyEnd])
        sharedhash = bytes(
            data[RelayExtendedCellBody.HashBegin:RelayExtendedCellBody.HashEnd])
        signature = bytes(
            data[RelayExtendedCellBody.SignatureBegin:RelayExtendedCellBody.SignatureEnd])
        digest = data[RelayExtendedCellBody.DigestBegin:RelayExtendedCellBody.DigestEnd]
        return RelayExtendedCellBody(pk, sharedhash, signature)
