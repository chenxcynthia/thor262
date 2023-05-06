from tor_protocol import *
from nacl.utils import random
from nacl.hash import blake2b


def PrintPass(test_name: str):
    print('[ \033[92mOK\033[0m ] {}'.format(test_name))


def TestCellHeader():
    # Serialization for all known types should work
    for type in range(0, 17):
        cell_header = CellHeader(THOR_VERSION, type, bytes(16), 0)
        assert cell_header.version == 1
        assert cell_header.type == type
        assert cell_header.circ_id == bytes(16)
        assert cell_header.body_len == 0
        data = cell_header.serialize()
        correct_data = b"\x01\x00" + \
            type.to_bytes(2, byteorder='little') + \
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        assert len(data) == 24
        assert data == correct_data

    # Try for a type out of range
    triggered = False
    try:
        cell_header = CellHeader(THOR_VERSION, 17, bytes(16), 0)
    except ValueError:
        triggered = True
    assert triggered

    # Try for an invalid circuit ID length
    triggered = False
    try:
        cell_header = CellHeader(THOR_VERSION, 0, bytes(15), 0)
    except ValueError:
        triggered = True
    assert triggered

    # Deserialization for all known types should work
    for type in range(0, 17):
        data = b"\x01\x00" + type.to_bytes(2, byteorder='little') + \
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        cell_header = CellHeader.deserialize(data)
        assert cell_header.version == THOR_VERSION
        assert cell_header.type == type
        assert cell_header.circ_id == bytes(16)
        assert cell_header.body_len == 0

    # Try for a wrong length
    data = b"\x00\x00"
    triggered = False
    try:
        cell_header = CellHeader.deserialize(data)
    except AssertionError:
        triggered = True
    assert triggered

    # Try for a wrong version
    data = b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    triggered = False
    try:
        cell_header = CellHeader.deserialize(data)
    except ValueError:
        triggered = True
    assert triggered


def TestCreate():
    # Serialize from valid key
    pk = random(32)
    create_cell = CreateCellBody(pk)
    assert create_cell.pk == pk
    data = create_cell.serialize()
    assert len(data) == 32
    assert data == pk

    # Serialize from invalid key
    pk = random(31)
    triggered = False
    try:
        create_cell = CreateCellBody(pk)
    except ValueError:
        triggered = True
    assert triggered

    # Deserialize from valid key
    data = random(32)
    create_cell = CreateCellBody.deserialize(data)
    assert create_cell.pk == data

    # Deserialize from invalid key
    data = random(33)
    triggered = False
    try:
        create_cell = CreateCellBody.deserialize(data)
    except AssertionError:
        triggered = True
    assert triggered


def TestCreated():
    # Serialize from valid key, hash, and signature
    pk = random(32)
    sharedhash = random(32)
    signature = random(64)
    created_cell = CreatedCellBody(pk, sharedhash, signature)
    assert created_cell.pk == pk
    assert created_cell.hash == sharedhash
    assert created_cell.signature == signature
    data = created_cell.serialize()
    assert len(data) == 128
    assert data == pk + sharedhash + signature

    # Serialize from invalid public key
    pk = random(31)
    sharedhash = random(32)
    signature = random(64)
    triggered = False
    try:
        created_cell = CreatedCellBody(pk, sharedhash, signature)
    except ValueError:
        triggered = True
    assert triggered

    # Serialize from invalid shared hash
    pk = random(32)
    sharedhash = random(31)
    signature = random(64)
    triggered = False
    try:
        created_cell = CreatedCellBody(pk, sharedhash, signature)
    except ValueError:
        triggered = True
    assert triggered

    # Serialize from invalid signature
    pk = random(32)
    sharedhash = random(32)
    signature = random(68)
    triggered = False
    try:
        created_cell = CreatedCellBody(pk, sharedhash, signature)
    except ValueError:
        triggered = True
    assert triggered

    # Deserialize from valid data
    data = random(128)
    created_cell = CreatedCellBody.deserialize(data)
    assert created_cell.pk == data[0:32]
    assert created_cell.hash == data[32:64]
    assert created_cell.signature == data[64:128]

    # Deserialize from invalid data
    data = random(127)
    triggered = False
    try:
        created_cell = CreatedCellBody.deserialize(data)
    except AssertionError:
        triggered = True
    assert triggered


def TestDestroy():
    # Serialize
    destroy_cell = DestroyCellBody().serialize()
    assert len(destroy_cell) == 0

    # Deserialize from valid data
    data = random(0)
    destroy_cell = DestroyCellBody.deserialize(data)

    # Deserialize from invalid data
    data = random(1)
    triggered = False
    try:
        destroy_cell = DestroyCellBody.deserialize(data)
    except AssertionError:
        triggered = True
    assert triggered


def TestComputeDigest():
    for i in range(128):
        data = random(i)
        digest = compute_digest(data)
        assert digest == blake2b(data, digest_size=32,
                                 person=b"THOR", encoder=RawEncoder)


def TestVerifyDigest():
    data = blake2b(b"", digest_size=32, person=b"THOR", encoder=RawEncoder)
    assert verify_digest(data)

    data = bytearray(random(64))
    data[32:64] = blake2b(bytes(data[:32]), digest_size=32,
                          person=b"THOR", encoder=RawEncoder)
    assert verify_digest(bytes(data))


def TestRelayData():
    data = random(128)
    digest = compute_digest(data)
    cell_body = RelayDataCellBody(data)
    assert cell_body.data == data
    assert cell_body.digest == digest
    serial = cell_body.serialize()
    assert serial == data + digest

    data = random(31)
    triggered = False
    try:
        cell_body = RelayDataCellBody.deserialize(data)
    except AssertionError:
        triggered = True
    assert triggered

    data = random(64)
    cell_body = RelayDataCellBody.deserialize(data)
    assert cell_body.data == data[0:32]
    assert cell_body.digest == compute_digest(data[0:32])


def TestRelayBegin():
    port = 50051
    hostname = "hostname"

    cell_body = RelayBeginCellBody(port, hostname)
    assert cell_body.port == port
    assert cell_body.hostname == hostname
    assert cell_body.digest == compute_digest(port.to_bytes(
        2, byteorder='little') + bytes(hostname, 'utf-8'))

    port = 65536
    triggered = False
    try:
        cell_body = RelayBeginCellBody(port, hostname)
    except ValueError:
        triggered = True
    assert triggered

    serial_data = b"\x83\xc3\x68\x6f\x73\x74\x6e\x61\x6d\x65" + \
        compute_digest(b"\x83\xc3\x68\x6f\x73\x74\x6e\x61\x6d\x65")
    cell_body = RelayBeginCellBody.deserialize(serial_data)
    assert cell_body.port == 50051
    assert cell_body.hostname == "hostname"


def TestRelayConnected():
    status = 0

    cell_body = RelayConnectedCellBody(status)
    assert cell_body.status == status
    assert cell_body.digest == compute_digest(status.to_bytes(
        2, byteorder='little'))

    status = 65536
    triggered = False
    try:
        cell_body = RelayConnectedCellBody(status)
    except ValueError:
        triggered = True
    assert triggered

    serial_data = b"\x00\x00" + compute_digest(b"\x00\x00")
    cell_body = RelayConnectedCellBody.deserialize(serial_data)
    assert cell_body.status == 0


def TestRelayExtend():
    next_or_ip = random(4)
    pk = random(32)

    cell_body = RelayExtendCellBody(next_or_ip, pk)
    assert cell_body.next_or_ip == next_or_ip
    assert cell_body.pk == pk
    assert cell_body.digest == compute_digest(next_or_ip + pk)

    next_or_ip = random(5)
    pk = random(32)
    triggered = False
    try:
        cell_body = RelayExtendCellBody(next_or_ip, pk)
    except ValueError:
        triggered = True
    assert triggered

    next_or_ip = random(4)
    pk = random(64)
    triggered = False
    try:
        cell_body = RelayExtendCellBody(next_or_ip, pk)
    except ValueError:
        triggered = True
    assert triggered

    pk = random(32)
    serial_data = b"\x01\x02\x03\x04" + pk + \
        compute_digest(b"\x01\x02\x03\x04" + pk)
    cell_body = RelayExtendCellBody.deserialize(serial_data)
    assert cell_body.next_or_ip == b"\x01\x02\x03\x04"
    assert cell_body.pk == pk


def TestRelayExtended():
    pk = random(32)
    hash = random(32)
    signature = random(64)

    cell_body = RelayExtendedCellBody(pk, hash, signature)
    assert cell_body.pk == pk
    assert cell_body.hash == hash
    assert cell_body.signature == signature
    assert cell_body.digest == compute_digest(pk + hash + signature)

    pk = random(33)
    hash = random(32)
    signature = random(64)
    triggered = False
    try:
        cell_body = RelayExtendedCellBody(pk, hash, signature)
    except ValueError:
        triggered = True
    assert triggered

    pk = random(32)
    hash = random(53)
    signature = random(64)
    triggered = False
    try:
        cell_body = RelayExtendedCellBody(pk, hash, signature)
    except ValueError:
        triggered = True
    assert triggered

    pk = random(32)
    hash = random(32)
    signature = random(1)
    triggered = False
    try:
        cell_body = RelayExtendedCellBody(pk, hash, signature)
    except ValueError:
        triggered = True
    assert triggered

    serial_data = random(160)
    cell_body = RelayExtendedCellBody.deserialize(serial_data)
    assert cell_body.pk == serial_data[0:32]
    assert cell_body.hash == serial_data[32:64]
    assert cell_body.signature == serial_data[64:128]


def TestDirectoryChallengeInit():
    pk = random(32)
    nonce = random(32)

    cell_body = DirectoryChallengeInitCellBody(pk, nonce)
    assert cell_body.pk == pk
    assert cell_body.nonce == nonce

    pk = random(33)
    nonce = random(32)
    triggered = False
    try:
        cell_body = DirectoryChallengeInitCellBody(pk, nonce)
    except ValueError:
        triggered = True
    assert triggered

    pk = random(32)
    nonce = random(256)
    triggered = False
    try:
        cell_body = DirectoryChallengeInitCellBody(pk, nonce)
    except ValueError:
        triggered = True
    assert triggered

    serial_data = random(64)
    cell_body = DirectoryChallengeInitCellBody.deserialize(serial_data)
    assert cell_body.pk == serial_data[0:32]
    assert cell_body.nonce == serial_data[32:64]


def TestDirectoryChallengeRequest():
    nonce = random(32)
    signature = random(64)

    cell_body = DirectoryChallengeRequestCellBody(nonce, signature)
    assert cell_body.nonce == nonce
    assert cell_body.signature == signature

    nonce = random(93)
    signature = random(64)
    triggered = False
    try:
        cell_body = DirectoryChallengeRequestCellBody(nonce, signature)
    except ValueError:
        triggered = True
    assert triggered

    nonce = random(32)
    signature = random(72)
    triggered = False
    try:
        cell_body = DirectoryChallengeRequestCellBody(nonce, signature)
    except ValueError:
        triggered = True
    assert triggered

    serial_data = random(96)
    cell_body = DirectoryChallengeRequestCellBody.deserialize(serial_data)
    assert cell_body.nonce == serial_data[0:32]
    assert cell_body.signature == serial_data[32:96]


def TestDirectoryChallengeResponse():
    signature = random(64)

    cell_body = DirectoryChallengeResponseCellBody(signature)
    assert cell_body.signature == signature

    signature = random(52)
    triggered = False
    try:
        cell_body = DirectoryChallengeResponseCellBody(signature)
    except ValueError:
        triggered = True
    assert triggered

    serial_data = random(64)
    cell_body = DirectoryChallengeResponseCellBody.deserialize(serial_data)
    assert cell_body.signature == serial_data


def TestDirectoryChallengeAck():
    status = 0
    cell_body = DirectoryChallengeAckCellBody(status)
    assert cell_body.status == status

    status = 65536
    triggered = False
    try:
        cell_body = DirectoryChallengeAckCellBody(status)
    except ValueError:
        triggered = True
    assert triggered

    serial_data = b"\x04\x03"
    cell_body = DirectoryChallengeAckCellBody.deserialize(serial_data)
    assert cell_body.status == 772


def main():
    TestCellHeader()
    PrintPass("CellHeader")
    TestCreate()
    PrintPass("CreateCellBody")
    TestCreated()
    PrintPass("CreatedCellBody")
    TestDestroy()
    PrintPass("DestroyCellBody")
    TestComputeDigest()
    PrintPass("ComputeDigest")
    TestVerifyDigest()
    PrintPass("VerifyDigest")
    TestRelayData()
    PrintPass("RelayDataCellBody")
    TestRelayBegin()
    PrintPass("RelayBeginCellBody")
    TestRelayConnected()
    PrintPass("RelayConnectedCellBody")
    TestRelayExtend()
    PrintPass("RelayExtendCellBody")
    TestRelayExtended()
    PrintPass("RelayExtendedCellBody")
    TestDirectoryChallengeInit()
    PrintPass("DirectoryChallengeInit")
    TestDirectoryChallengeRequest()
    PrintPass("DirectoryChallengeRequest")
    TestDirectoryChallengeResponse()
    PrintPass("DirectoryChallengeResponse")
    TestDirectoryChallengeAck()
    PrintPass("DirectoryChallengeAck")


if __name__ == "__main__":
    main()
