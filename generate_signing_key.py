from nacl.utils import random
import sys


def generate_signing_key() -> bytes:
    return random(32)


def main(argv):
    if len(argv) != 2:
        print("usage: %s <OUTPUT FILE>" % argv[0])
        return 1
    sk = generate_signing_key()
    with open(argv[1], "wb") as outfile:
        outfile.write(sk)
    return 0


if __name__ == "__main__":
    main(sys.argv)
