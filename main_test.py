
from protocol_tls13_handshake import Handshake, HandshakeType

finished_bytes = bytes.fromhex('140000205f787647e4dcb8dc9f449bcff7a47ecd021b1ad2dcfdbbe92d0b5063f2f8eb9e')
handshake4 = Handshake.from_bytes(finished_bytes)
print(handshake4)
