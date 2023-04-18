from enum import IntEnum
from nacl.secret import SecretBox
from nacl.hash import blake2b
from nacl.encoding import RawEncoder

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
