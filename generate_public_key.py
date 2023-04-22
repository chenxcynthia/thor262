import sys
from nacl.signing import SigningKey, VerifyKey


def main(argv):
    if len(argv) != 3:
        print("usage: %s <PRIVATE KEY FILE> <OUTPUT FILE>" % argv[0])
        return 1
    with open(argv[1], "rb") as keyfile:
        sk = keyfile.read(32)
    pk = SigningKey(sk).verify_key.encode()
    with open(argv[2], "wb") as outfile:
        outfile.write(pk)
    return 0


if __name__ == "__main__":
    main(sys.argv)
