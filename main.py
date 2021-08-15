
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from protocol_longpacket import LongPacket, PacketType, InitialPacket
from utils import hexdump, bytexor

# Client Inital Packet
recv_msg = bytes.fromhex("""
c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
e221af44860018ab0856972e194cd934
""")

# # Server Inital Packet
# recv_msg = bytes.fromhex("""
# cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a
# 5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3
# dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84
# 022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4
# 2158407dd074ee
# """)


recv_packet = LongPacket.from_bytes(recv_msg)
recv_packet_bytes = bytes(recv_packet)
print(recv_packet)
print(hexdump(recv_packet_bytes))

# client_dst_connection_id = recv_packet.dest_conn_id.byte
client_dst_connection_id = bytes.fromhex('8394c8f03e515708')

# --- 1. 鍵を導出する ---

from protocol_keyschedule import HKDF_extract, HKDF_expand_label
from protocol_packetprotection import initial_salt, get_key_iv_hp
initial_secret = HKDF_extract(initial_salt, client_dst_connection_id)
client_initial_secret = HKDF_expand_label(initial_secret, b'client in', b'', 32)
server_initial_secret = HKDF_expand_label(initial_secret, b'server in', b'', 32)
client_key, client_iv, client_hp = get_key_iv_hp(client_initial_secret)
server_key, server_iv, server_hp = get_key_iv_hp(server_initial_secret)
print('---')
print('initial_secret:')
print(hexdump(initial_secret))
print('client_initial_secret:')
print(hexdump(client_initial_secret))
print('client_key:')
print(hexdump(client_key))
print('client_iv:')
print(hexdump(client_iv))
print('client_hp:')
print(hexdump(client_hp))
print('server_initial_secret:')
print(hexdump(server_initial_secret))
print('server_key:')
print(hexdump(server_key))
print('server_iv:')
print(hexdump(server_iv))
print('server_hp:')
print(hexdump(server_hp))

# --- 2. Header Protectionを解除する ---

def header_protection(long_packet: LongPacket, sc_hp_key) -> bytes:
    recv_packet_bytes = bytes(long_packet)

    def get_np_offset_and_sample_offset(long_packet: LongPacket) -> (int, int):
        assert isinstance(long_packet, LongPacket)
        pn_offset = 7 + len(long_packet.dest_conn_id) + \
                        len(long_packet.src_conn_id) + \
                        len(long_packet.length)
        if PacketType(long_packet.flags.long_packet_type) == PacketType.INITIAL:
            pn_offset += len(bytes(long_packet.token))

        sample_offset = pn_offset + 4

        return pn_offset, sample_offset

    pn_offset, sample_offset = get_np_offset_and_sample_offset(recv_packet)

    sample_length = 16
    sample = recv_packet_bytes[sample_offset:sample_offset+sample_length]
    print('sample:')
    print(hexdump(sample))

    def generate_mask(hp_key, sample) -> bytes:
        cipher = Cipher(algorithms.AES(key=hp_key), modes.ECB())
        encryptor = cipher.encryptor()
        ct = encryptor.update(sample) + encryptor.finalize()
        mask = bytearray(ct)[0:5]
        return mask

    mask = generate_mask(sc_hp_key, sample)
    print('mask:')
    print(hexdump(mask))

    recv_packet_bytes = bytearray(recv_packet_bytes)
    if (recv_packet_bytes[0] & 0x80) == 0x80:
        # Long header: 4 bits masked
        recv_packet_bytes[0] ^= mask[0] & 0x0f
    else:
        # Short header: 5 bits masked
        recv_packet_bytes[0] ^= mask[0] & 0x1f
    
    # ヘッダ保護解除後にパケット番号の長さ取得
    pn_length = (recv_packet_bytes[0] & 0x03) + 1

    # pn_offset is the start of the Packet Number field.
    recv_packet_bytes[pn_offset:pn_offset+pn_length] = \
        bytexor(recv_packet_bytes[pn_offset:pn_offset+pn_length], mask[1:1+pn_length])

    return recv_packet_bytes

recv_packet_bytes = header_protection(recv_packet, client_hp)
# recv_packet_bytes = header_protection(recv_packet, server_hp)

# --- 3. Payloadの暗号文を復号する ---

print('---')
initial_packet = InitialPacket.from_bytes(recv_packet_bytes)
initial_packet_bytes = bytes(initial_packet)
print(initial_packet)
print(hexdump(initial_packet_bytes))

packet_number = initial_packet.get_packet_number_int()
packet_number_bytes = packet_number.to_bytes(len(client_iv), 'big')
print('packet_number:')
print(hexdump(packet_number_bytes))
nonce = bytexor(packet_number_bytes, client_iv)
# nonce = bytexor(packet_number_bytes, server_iv)
print('nonce:')
print(hexdump(nonce))

# Auth Data
aad = initial_packet.get_header_bytes()
print('aad:')
print(hexdump(aad))

data = bytes(initial_packet.packet_payload)
print('data:')
print(hexdump(data))
aesgcm = AESGCM(key=client_key)
# aesgcm = AESGCM(key=server_key)

decrypted = aesgcm.decrypt(nonce, data, aad)
print('decrypted')
print(hexdump(decrypted))

