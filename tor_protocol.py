from enum import IntEnum
from nacl.secret import SecretBox
from nacl.hash import blake2b
from nacl.encoding import RawEncoder
from nacl.utils import random
import socket
from typing import List
import requests  # For geolocating

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


def get_country(ip: str) -> str:
    data = requests.get("https://ipinfo.io/{}/json".format(ip)).json()
    if "country" not in data:
        return None
    else:
        return data["country"]


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
    RelayExtended = 9,
    DirectoryChallengeInit = 10,
    DirectoryChallengeRequest = 11,
    DirectoryChallengeResponse = 12,
    DirectoryChallengeAck = 13,
    DirectoryRetrieveRequest = 14,
    DirectoryRetrieveResponse = 15,
    DirectoryHeartbeat = 16,
    EndCellType = 17


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


class DirectoryChallengeInitCellBody:
    PublicKeyBegin = 0
    PublicKeySize = 32
    PublicKeyEnd = 32

    NonceBegin = 32
    NonceSize = 32
    NonceEnd = 64

    TotalSize = 64

    def __init__(self, pk: bytes, nonce: bytes):
        if len(pk) != 32:
            raise ValueError("Invalid public key length")
        self.pk = pk
        if len(nonce) != 32:
            raise ValueError("Invalid nonce length")
        self.nonce = nonce

    def serialize(self) -> bytearray:
        data = bytearray(DirectoryChallengeInitCellBody.TotalSize)
        data[DirectoryChallengeInitCellBody.PublicKeyBegin:
             DirectoryChallengeInitCellBody.PublicKeyEnd] = self.pk
        data[DirectoryChallengeInitCellBody.NonceBegin:
             DirectoryChallengeInitCellBody.NonceEnd] = self.nonce
        return data

    @staticmethod
    def deserialize(data: bytearray) -> "DirectoryChallengeInitCellBody":
        assert len(data) == DirectoryChallengeInitCellBody.TotalSize
        pk = bytes(
            data[DirectoryChallengeInitCellBody.PublicKeyBegin:DirectoryChallengeInitCellBody.PublicKeyEnd])
        nonce = bytes(
            data[DirectoryChallengeInitCellBody.NonceBegin:DirectoryChallengeInitCellBody.NonceEnd])
        return DirectoryChallengeInitCellBody(pk, nonce)


class DirectoryChallengeRequestCellBody:
    NonceBegin = 0
    NonceSize = 32
    NonceEnd = 32

    SignatureBegin = 32
    SignatureSize = 64
    SignatureEnd = 96

    TotalSize = 96

    def __init__(self, nonce: bytes, signature: bytes):
        if len(nonce) != 32:
            raise ValueError("Invalid signature length")
        self.nonce = nonce
        if len(signature) != 64:
            raise ValueError("Invalid signature length")
        self.signature = signature

    def serialize(self) -> bytearray:
        data = bytearray(DirectoryChallengeRequestCellBody.TotalSize)
        data[DirectoryChallengeRequestCellBody.NonceBegin:
             DirectoryChallengeRequestCellBody.NonceEnd] = self.nonce
        data[DirectoryChallengeRequestCellBody.SignatureBegin:
             DirectoryChallengeRequestCellBody.SignatureEnd] = self.signature
        return data

    @staticmethod
    def deserialize(data: bytearray) -> "DirectoryChallengeRequestCellBody":
        assert len(data) == DirectoryChallengeRequestCellBody.TotalSize
        nonce = bytes(
            data[DirectoryChallengeRequestCellBody.NonceBegin:DirectoryChallengeRequestCellBody.NonceEnd])
        signature = bytes(
            data[DirectoryChallengeRequestCellBody.SignatureBegin:DirectoryChallengeRequestCellBody.SignatureEnd])
        return DirectoryChallengeRequestCellBody(nonce, signature)


class DirectoryChallengeResponseCellBody:
    SignatureBegin = 0
    SignatureSize = 64
    SignatureEnd = 64

    TotalSize = 64

    def __init__(self, signature: bytes):
        if len(signature) != 64:
            raise ValueError("Invalid signature length")
        self.signature = signature

    def serialize(self) -> bytearray:
        data = bytearray(DirectoryChallengeResponseCellBody.TotalSize)
        data[DirectoryChallengeResponseCellBody.SignatureBegin:
             DirectoryChallengeResponseCellBody.SignatureEnd] = self.signature
        return data

    @staticmethod
    def deserialize(data: bytearray) -> "DirectoryChallengeResponseCellBody":
        assert len(data) == DirectoryChallengeResponseCellBody.TotalSize
        signature = bytes(
            data[DirectoryChallengeResponseCellBody.SignatureBegin:DirectoryChallengeResponseCellBody.SignatureEnd])
        return DirectoryChallengeResponseCellBody(signature)


class DirectoryChallengeAckCellBody:
    StatusBegin = 0
    StatusSize = 2
    StatusEnd = 2

    TotalSize = 2

    def __init__(self, status: int):
        if status < 0 or status > 65535:
            raise ValueError("Invalid status")
        self.status = status

    def serialize(self) -> bytearray:
        data = bytearray(DirectoryChallengeAckCellBody.TotalSize)
        data[DirectoryChallengeAckCellBody.StatusBegin:DirectoryChallengeAckCellBody.StatusEnd] = self.status.to_bytes(
            DirectoryChallengeAckCellBody.StatusSize, byteorder='little')
        return data

    @staticmethod
    def deserialize(data: bytearray) -> "DirectoryChallengeAckCellBody":
        assert len(data) == DirectoryChallengeAckCellBody.TotalSize
        status = int.from_bytes(
            data[DirectoryChallengeAckCellBody.StatusBegin:DirectoryChallengeAckCellBody.StatusEnd], byteorder='little')
        return DirectoryChallengeAckCellBody(status)


class DirectoryRetrieveRequestCellBody:
    NonceBegin = 0
    NonceSize = 32
    NonceEnd = 32

    TotalSize = 32

    def __init__(self, nonce: bytes):
        if len(nonce) != 32:
            raise ValueError("Invalid signature length")
        self.nonce = nonce

    def serialize(self) -> bytearray:
        data = bytearray(DirectoryRetrieveRequestCellBody.TotalSize)
        data[DirectoryRetrieveRequestCellBody.NonceBegin:
             DirectoryRetrieveRequestCellBody.NonceEnd] = self.nonce
        return data

    @staticmethod
    def deserialize(data: bytearray) -> "DirectoryRetrieveRequestCellBody":
        assert len(data) == DirectoryRetrieveRequestCellBody.TotalSize
        nonce = bytes(
            data[DirectoryRetrieveRequestCellBody.NonceBegin:DirectoryRetrieveRequestCellBody.NonceEnd])
        return DirectoryRetrieveRequestCellBody(nonce)


class DirectoryRetrieveResponseCellBody:
    ListLenBegin = 0
    ListLenSize = 4
    ListLenEnd = 4

    PairBegin = 4
    OrIpSize = 4
    OrPkSize = 32
    PairSize = OrIpSize + OrPkSize

    SignatureSize = 64

    def __init__(self, or_ips: List[bytes], pks: List[bytes], signature: bytes):
        if len(or_ips) != len(pks):
            raise ValueError("Each OR must have a public key")
        if any([x for x in or_ips if len(x) != 4]):
            raise ValueError("OR IPs must be 4 bytes")
        self.or_ips = or_ips
        if any([x for x in pks if len(x) != 32]):
            raise ValueError("OR public keys must be 32 bytes")
        self.pks = pks
        if len(signature) != 64:
            raise ValueError("Invalid signature length")
        self.signature = signature

    def serialize(self) -> bytearray:
        total_size = DirectoryRetrieveResponseCellBody.ListLenSize + \
            len(self.or_ips) * DirectoryRetrieveResponseCellBody.PairSize
        data = bytearray(total_size)
        data[DirectoryRetrieveResponseCellBody.ListLenBegin:DirectoryRetrieveResponseCellBody.ListLenEnd] = len(
            self.or_ips).to_bytes(DirectoryRetrieveResponseCellBody.ListLenSize, byteorder='little')
        for i in range(len(self.or_ips)):
            ip_begin = DirectoryRetrieveResponseCellBody.PairBegin + \
                i * DirectoryRetrieveResponseCellBody.PairSize
            ip_end = ip_begin + DirectoryRetrieveResponseCellBody.OrIpSize
            pk_begin = ip_end
            pk_end = pk_begin + DirectoryRetrieveResponseCellBody.OrPkSize
            data[ip_begin:ip_end] = self.or_ips[i]
            data[pk_begin:pk_end] = self.pks[i]
        signature_begin = DirectoryRetrieveResponseCellBody.PairBegin + \
            len(self.or_ips) * DirectoryRetrieveResponseCellBody.PairSize
        signature_end = signature_begin + DirectoryRetrieveResponseCellBody.SignatureSize
        data[signature_begin:signature_end] = self.signature
        return data

    @staticmethod
    def deserialize(data: bytearray) -> "DirectoryRetrieveResponseCellBody":
        or_ips: List[bytes] = []
        pks: List[bytes] = []
        assert len(data) >= DirectoryRetrieveResponseCellBody.ListLenSize
        num_pairs = int.from_bytes(
            data[DirectoryRetrieveResponseCellBody.ListLenBegin:DirectoryRetrieveResponseCellBody.ListLenEnd], byteorder='little')
        assert len(data) == DirectoryRetrieveResponseCellBody.ListLenSize + num_pairs * \
            DirectoryRetrieveResponseCellBody.PairSize + \
            DirectoryRetrieveResponseCellBody.SignatureSize
        for i in range(num_pairs):
            ip_begin = DirectoryRetrieveResponseCellBody.PairBegin + \
                i * DirectoryRetrieveResponseCellBody.PairSize
            ip_end = ip_begin + DirectoryRetrieveResponseCellBody.OrIpSize
            pk_begin = ip_end
            pk_end = pk_begin + DirectoryRetrieveResponseCellBody.OrPkSize
            or_ips.append(bytes(data[ip_begin:ip_end]))
            pks.append(bytes(data[pk_begin:pk_end]))
        signature_begin = DirectoryRetrieveResponseCellBody.PairBegin + \
            num_pairs * DirectoryRetrieveResponseCellBody.PairSize
        signature_end = signature_begin + DirectoryRetrieveResponseCellBody.SignatureSize
        signature = data[signature_begin:signature_end]
        return DirectoryRetrieveResponseCellBody(or_ips, pks, signature)


class DirectoryHeartbeatCellBody:
    def __init__(self):
        pass

    def serialize(self) -> bytearray:
        return bytearray(0)

    @staticmethod
    def deserialize(data: bytearray) -> "DirectoryHeartbeatCellBody":
        assert len(data) == 0
        return DirectoryHeartbeatCellBody()
