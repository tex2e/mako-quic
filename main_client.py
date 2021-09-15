
import socket

class ClientConn:
    def __init__(self, host='127.0.0.1', port=443):
        self.server_address = (host, port)
        # ソケット作成
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # メッセージの送信
    def sendto(self, message: bytes):
        return self.sock.sendto(message, self.server_address)

    # メッセージの受信
    def recvfrom(self, buffer_size=1024):
        data, addr = self.sock.recvfrom(buffer_size)
        return data, addr


# conn = ClientConn('127.0.0.1', 4433)
# res = conn.sendto(b'12345')
# print(res)
# res = conn.recvfrom()
# print(res)


from utils import hexdump
from metatype import Uint8, Uint16, Uint32, Opaque, OpaqueUint8, OpaqueUint16, OpaqueLength, VarLenIntEncoding, OpaqueVarLenIntEncoding, List
from protocol_quic import QUICVersions, HeaderForm
from protocol_longpacket import InitialPacket, LongPacket, LongPacketFlags, PacketType
from protocol_packetprotection import get_client_server_key_iv_hp, header_protection, encrypt_payload, decrypt_payload
from protocol_frame import Frame, FrameType, CryptoFrame
from protocol_tls13_handshake import Handshake, HandshakeType
from protocol_tls13_hello import ClientHello
from protocol_tls13_ciphersuite import CipherSuites, CipherSuite
from protocol_tls13_extensions import Extensions, Extension, ExtensionType
from protocol_tls13_ext_version import SupportedVersions, ProtocolVersions, ProtocolVersion
from protocol_tls13_ext_supportedgroups import NamedGroupList, NamedGroups, NamedGroup
from protocol_tls13_ext_signature import SignatureSchemeList, SignatureSchemes, SignatureScheme
from protocol_tls13_ext_keyshare import KeyShareHello, KeyShareEntrys, KeyShareEntry
from protocol_tls13_ext_servername import ServerNameIndications, ServerNameIndication, ServerNameIndicationType


public_key = bytes.fromhex('6923bcdc7b80831a7f0d6fdfddb8e1b5e2f042cb1991cb19fd7ad9bce444fe63')

crypto_frame = Frame(
    frame_type=FrameType.CRYPTO,
    frame_content=CryptoFrame(
        offset=VarLenIntEncoding(Uint8(0)),
        length=VarLenIntEncoding(Uint16(1000)),
        data=Handshake(
            msg_type=HandshakeType.client_hello,
            msg=ClientHello(
                legacy_version=Uint16(0x0303),
                legacy_session_id=OpaqueUint8(b''),
                cipher_suites=CipherSuites([
                    CipherSuite.TLS_AES_128_GCM_SHA256,
                    CipherSuite.TLS_AES_256_GCM_SHA384,
                    CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    # CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                ]),
                extensions=Extensions([
                    Extension(
                        extension_type=ExtensionType.server_name,
                        extension_data=ServerNameIndications([
                            ServerNameIndication(
                                name_type=ServerNameIndicationType.host_name,
                                host_name=OpaqueUint16(b'localhost')
                            )
                        ])
                    ),
                    Extension(
                        extension_type=ExtensionType.supported_versions,
                        extension_data=SupportedVersions(
                            versions=ProtocolVersions([
                                ProtocolVersion.TLS13
                            ])
                        )
                    ),
                    Extension(
                        extension_type=ExtensionType.supported_groups,
                        extension_data=NamedGroupList(
                            named_group_list=NamedGroups([
                                NamedGroup.x25519
                            ])
                        )
                    ),
                    Extension(
                        extension_type=ExtensionType.signature_algorithms,
                        extension_data=SignatureSchemeList(
                            supported_signature_algorithms=SignatureSchemes([
                                SignatureScheme.rsa_pss_rsae_sha256,
                                SignatureScheme.rsa_pss_rsae_sha384,
                                SignatureScheme.rsa_pss_rsae_sha512,
                            ])
                        )
                    ),
                    Extension(
                        extension_type=ExtensionType.key_share,
                        extension_data=KeyShareHello(
                            shares=KeyShareEntrys([
                                KeyShareEntry(
                                    group=NamedGroup.x25519,
                                    key_exchange=OpaqueUint16(public_key)
                                )
                            ])
                        )
                    )
                ]),
            )
        )
    )
)
crypto_frame_len = len(bytes(crypto_frame))
# TODO: バイト列にしたときにCRYPTO FrameのLengthが不一致のため、要修正

client_dst_connection_id = bytes.fromhex('1a26dc5bd9625e2bcd0efd3a329ce83136a32295')

packet_number = 1
initial_packet = InitialPacket(
    flags=LongPacketFlags(header_form=HeaderForm.LONG, fixed_bit=1,
                          long_packet_type=PacketType.INITIAL, type_specific_bits=0b0011),
    version=QUICVersions.QUICv1,
    dest_conn_id=OpaqueUint8(client_dst_connection_id),
    src_conn_id=OpaqueUint8(bytes.fromhex('c6b336557f9128bef8a099a10d320c26e9c8d1ab')),
    token=OpaqueVarLenIntEncoding(b''),
    length=None,
    packet_number=Uint32(packet_number),
    packet_payload=None
)

packet_number_len = (initial_packet.flags.type_specific_bits & 0x03) + 1  # バケット番号長
aead_tag_len = 16
length_len = Uint16.size

# Clientが送信するInitial Packetを含むUDPペイロードは1200バイト以上にしないといけない (MUST)
padding_frame_len = 1200 - 5 - len(bytes(initial_packet.dest_conn_id)) - len(bytes(initial_packet.src_conn_id)) - len(bytes(initial_packet.token)) - length_len - packet_number_len - crypto_frame_len - aead_tag_len
print('[+] padding_frame_len:', padding_frame_len)

# 1200バイト以上になるようにパディング追加
padding_frame = Frame(
    frame_type=FrameType.PADDING,
    frame_content=b'\x00' * padding_frame_len
)
Frames = List(size_t=lambda x: None, elem_t=Frame)
frames = Frames([
    crypto_frame,
    padding_frame,
])
plaintext_payload_bytes = bytes(frames)
initial_packet.packet_payload = plaintext_payload_bytes
initial_packet.length = VarLenIntEncoding(Uint16(len(plaintext_payload_bytes) + packet_number_len + aead_tag_len))
initial_packet.update()
print('=== send packed ===')
print(initial_packet)

client_key, client_iv, client_hp, server_key, server_iv, server_hp = \
    get_client_server_key_iv_hp(client_dst_connection_id)
cs_key = client_key
cs_iv = client_iv
cs_hp = client_hp
# print('cs_key:')
# print(hexdump(cs_key))
# print('cs_iv:')
# print(hexdump(cs_iv))
# print('cs_hp:')
# print(hexdump(cs_hp))

print('>>>')
print(initial_packet.token)
print(bytes(initial_packet.token))
aad = initial_packet.get_header_bytes()
print('aad:')
print(hexdump(aad))

ciphertext_payload_bytes = encrypt_payload(plaintext_payload_bytes, cs_key, cs_iv, aad, packet_number)

print('encrypted:')
print(hexdump(ciphertext_payload_bytes))

initial_packet.length = VarLenIntEncoding(Uint16(len(ciphertext_payload_bytes) + packet_number_len))
initial_packet.packet_payload = OpaqueLength(ciphertext_payload_bytes)
initial_packet.update()
print(initial_packet)

send_packet = LongPacket.from_bytes(bytes(initial_packet))
send_packet_bytes = header_protection(send_packet, cs_hp, mode='encrypt', debug=True)
print('encrypted packet:')
print(hexdump(send_packet_bytes))
print('[+] len(send_packet_bytes):', len(send_packet_bytes))

conn = ClientConn('127.0.0.1', 4433)
res = conn.sendto(send_packet_bytes)
print(res)
res = conn.recvfrom()
print(res)
recv_msg, addr = res

# Retry Packet
recv_packet = LongPacket.from_bytes(recv_msg)
recv_packet_bytes = bytes(recv_packet)
print('=== recv packed ===')
print(recv_packet)
print(hexdump(recv_packet_bytes))

# import sys
# sys.exit()

# --- 2回目 ---------------------------------------------------------------------

# 受信したRetryパケットからtokenを取り出して、ClientHelloを含むQUICパケットを作って送る

print('---')
retry_token = recv_packet.payload.retry_token
client_dst_connection_id = recv_packet.src_conn_id.byte
print('[+] server conn id:')
print(hexdump(recv_packet.src_conn_id.byte))
print('[+] retry_token:', retry_token)

# Send InitailPacket after Retry

packet_number = 2
initial_packet = InitialPacket(
    flags=LongPacketFlags(header_form=HeaderForm.LONG, fixed_bit=1,
                        long_packet_type=PacketType.INITIAL, type_specific_bits=0b0011),
    version=QUICVersions.QUICv1,
    dest_conn_id=OpaqueUint8(client_dst_connection_id),
    src_conn_id=OpaqueUint8(bytes.fromhex('c6b336557f9128bef8a099a10d320c26e9c8d1ab')),
    token=OpaqueVarLenIntEncoding(retry_token),
    length=VarLenIntEncoding(Uint16(len(plaintext_payload_bytes) + packet_number_len + aead_tag_len)),
    packet_number=Uint32(packet_number),
    packet_payload=plaintext_payload_bytes
)
print('=== send packed ===')
print(initial_packet)

# client_dst_connection_id = bytes.fromhex('1a26dc5bd9625e2bcd0efd3a329ce83136a32295')
client_key, client_iv, client_hp, server_key, server_iv, server_hp = \
    get_client_server_key_iv_hp(client_dst_connection_id)
cs_key = client_key
cs_iv = client_iv
cs_hp = client_hp
print('cs_key:')
print(hexdump(cs_key))
print('cs_iv:')
print(hexdump(cs_iv))
print('cs_hp:')
print(hexdump(cs_hp))

aad = initial_packet.get_header_bytes()
print('aad:')
print(hexdump(aad))

ciphertext_payload_bytes = encrypt_payload(plaintext_payload_bytes, cs_key, cs_iv, aad, packet_number)

print('encrypted:')
print(hexdump(ciphertext_payload_bytes))

initial_packet.length = VarLenIntEncoding(Uint16(len(ciphertext_payload_bytes) + packet_number_len))
initial_packet.packet_payload = OpaqueLength(ciphertext_payload_bytes)
initial_packet.update()
print(initial_packet)

send_packet = LongPacket.from_bytes(bytes(initial_packet))
# print('before encrypted packet:')
# print(hexdump(bytes(send_packet)))
send_packet_bytes = header_protection(send_packet, cs_hp, mode='encrypt', debug=True)
print('encrypted packet:')
print(hexdump(send_packet_bytes))
print('[+] len(send_packet_bytes):', len(send_packet_bytes))

conn = ClientConn('127.0.0.1', 4433)
res = conn.sendto(send_packet_bytes)
print(res)
res = conn.recvfrom()
print(res)
recv_msg, addr = res
