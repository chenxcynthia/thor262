# Tor262
Distributed system implementation of Tor

Contributors: @[darkwood101](https://github.com/darkwood101/), @[cynthia9chen](https://github.com/cynthia9chen)

- [1. Background and System Design](#1-background-and-system-design)
- [2. Running Tor262](#2-build)
- [3. Implementation](#3-implementation)
- [4. Real-World Application](#3-application)

## 1. Background and System Design

Tor262 is a distributed systems implementation of The Onion Router, widely known as Tor. We develop a peer-to-peer distributed system to enable encrypted communication between the client and respective onion routers. Our system relies on three onion routers, selected using a directory server, and the client maintains encrypted connection with these onion routers which eventually relay a connection request to a website in an anonymous manner. Finally, we deploy our system for a real-word application: connecting to ChatGPT in Italy, where it is currently banned, by relaying data through a series of onion routers hosted on international AWS instances.  


## 2. Running Tor262 locally
Generate key file:
```console
$ python3 generate_signing_key.py test.key
```

Start up 3 ORs (in 3 terminal windows):
```
$ python3 onion_router.py 127.0.0.1 50051 test.key
$ python3 onion_router.py 127.0.0.2 50051 test.key
$ python3 onion_router.py 127.0.0.3 50051 test.key
```

In the 4th terminal window, start the client:
```
$ python3 client.py
```

Sample client output:
```
OR 1 public key: b'4nX1LOdIt58fArZZW7VzHTwy0oXzzIA+x2TOK1AZ31A='
OR 1 hash of the session key: b'YHFSrnMw5CA2jw3NibhMqq7lcHPSnWQTez7FYcO3OhU='
OR 1 signature: b'V4YHx+nHbtN9Cc28fcM/gsDbiucwGDu451a60uUW95yRu9PU7HVpS2Nga5eczlwJptnYfx0f6uFpscRYPphcDA=='
My hash of OR 1 session key: b'YHFSrnMw5CA2jw3NibhMqq7lcHPSnWQTez7FYcO3OhU='
OR 2 public key: b'l/PFCyaEbQ4qfyLpm0I5kP05lhuUNwfHXF47yYBRtzs='
OR 2 hash of the session key: b'g3UqQqyFXd986OP5kORiL3156FAj1MZXmYDbrKFfwTU='
OR 2 signature: b'bnZyPzSMpnsTYjgnpKUW7+9sTb+IBPgsf6YwHO1SpHv2yfU9NhgpaY3yek6pO+y0bgP1Axi16FtHNmEdhPRLCw=='
My hash of OR 2 session key: b'g3UqQqyFXd986OP5kORiL3156FAj1MZXmYDbrKFfwTU='
OR 3 public key: b'a9XElfCnjltaT2LESYlznyF9/bGHHU0kMq2tZ4i2jUU='
OR 3 hash of the session key: b'Ce7kp0Q1t+xib2SI6932XKwJHMBLDYVt08b2eEt1jM4='
OR 3 signature: b'XSVz/J7OopjH0LODExPfOpll2HWgTiUANxoyU/WbbasxcHr8QE0E9Tc43FOmxvGv+4rJYvOujf+gDsW4zB5GAA=='
My hash of OR 3 session key: b'Ce7kp0Q1t+xib2SI6932XKwJHMBLDYVt08b2eEt1jM4='
```

"OR 1 hash of the session key" must match "My hash of OR 1 session key". Same for OR 2 and OR 3.

## 3. Implementation

## 4. Real-World Application


