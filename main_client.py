
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


# TODO: 暗号化の手順が間違っているのでmain_enc.pyを参考に後で修正する

from utils import hexdump
from metatype import Uint8, Uint16, Opaque, OpaqueUint8, OpaqueUint16, OpaqueLength, VarLenIntEncoding, OpaqueVarLenIntEncoding, List
from protocol_quic import QUICVersions
from protocol_longpacket import InitialPacket, LongPacketFlags, PacketType
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
padding_frame_len = 1200 - crypto_frame_len
padding_frame = Frame(
    frame_type=FrameType.PADDING,
    frame_content=b'\x00' * padding_frame_len
)

Frames = List(size_t=lambda x: None, elem_t=Frame)
frames = Frames([
    crypto_frame,
    # padding_frame,
])
print(frames)
print('[+] crypto_frame_len: ', crypto_frame_len)

frames_bytes = bytes(frames)

initial_packet = InitialPacket(
    flags=LongPacketFlags(header_form=1, fixed_bit=1,
                          long_packet_type=PacketType.INITIAL, type_specific_bits=0),
    version=QUICVersions.QUICv1,
    dest_conn_id=OpaqueUint8(bytes.fromhex('1a26dc5bd9625e2bcd0efd3a329ce83136a32295')),
    src_conn_id=OpaqueUint8(bytes.fromhex('c6b336557f9128bef8a099a10d320c26e9c8d1ab')),
    token=OpaqueVarLenIntEncoding(b''),
    length=VarLenIntEncoding(Uint16(len(frames_bytes))),
    # length=VarLenIntEncoding(Uint16(crypto_frame_len)),
    packet_number=Uint8(1),
    packet_payload=OpaqueLength(frames_bytes)
)
print('=== send packed ===')
print(initial_packet)

###
from protocol_packetprotection import get_client_server_key_iv_hp, header_protection, encrypt_payload, decrypt_payload
## 切り替えて使うこと!!
msg_sender = 'client'
# msg_sender = 'server'
client_dst_connection_id = bytes.fromhex('1a26dc5bd9625e2bcd0efd3a329ce83136a32295')
client_key, client_iv, client_hp, server_key, server_iv, server_hp = \
    get_client_server_key_iv_hp(client_dst_connection_id)
if msg_sender == 'client':
    cs_key = client_key
    cs_iv = client_iv
else:
    cs_key = server_key
    cs_iv = server_iv
aad = initial_packet.get_header_bytes()
packet_number = initial_packet.get_packet_number_int()
encrypted_frames_bytes = encrypt_payload(frames_bytes, cs_key, cs_iv, aad, packet_number)
initial_packet.packet_payload = OpaqueLength(encrypted_frames_bytes)
initial_packet.length = VarLenIntEncoding(Uint16(len(encrypted_frames_bytes)))
print('>>>', len(encrypted_frames_bytes), len(frames_bytes))
###


# InitialPacketを暗号化＆ヘッダ保護してから送信する

from protocol_longpacket import LongPacket
conn = ClientConn('127.0.0.1', 4433)
res = conn.sendto(bytes(initial_packet))
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

# TODO: 受信したRetryパケットからtokenを取り出して、ClientHelloを含むQUICパケットを作って送る

print('---')
print(recv_packet.payload.retry_token)
retry_token = recv_packet.payload.retry_token


# Send InitailPacket after Retry

initial_packet = InitialPacket(
    flags=LongPacketFlags(header_form=1, fixed_bit=1,
                          long_packet_type=PacketType.INITIAL, type_specific_bits=0),
    version=QUICVersions.QUICv1,
    dest_conn_id=OpaqueUint8(bytes.fromhex('1a26dc5bd9625e2bcd0efd3a329ce83136a32295')),
    src_conn_id=OpaqueUint8(bytes.fromhex('c6b336557f9128bef8a099a10d320c26e9c8d1ab')),
    token=OpaqueVarLenIntEncoding(retry_token),
    length=VarLenIntEncoding(Uint16(len(frames_bytes))),
    packet_number=Uint8(2),
    packet_payload=OpaqueLength(frames_bytes)
)
print('=== send packed ===')
print(initial_packet)

###
from protocol_packetprotection import get_client_server_key_iv_hp, header_protection, encrypt_payload, decrypt_payload
## 切り替えて使うこと!!
msg_sender = 'client'
# msg_sender = 'server'
client_dst_connection_id = bytes.fromhex('1a26dc5bd9625e2bcd0efd3a329ce83136a32295')
client_key, client_iv, client_hp, server_key, server_iv, server_hp = \
    get_client_server_key_iv_hp(client_dst_connection_id)
if msg_sender == 'client':
    cs_key = client_key
    cs_iv = client_iv
else:
    cs_key = server_key
    cs_iv = server_iv
aad = initial_packet.get_header_bytes()
packet_number = initial_packet.get_packet_number_int()
encrypted_frames_bytes = encrypt_payload(frames_bytes, cs_key, cs_iv, aad, packet_number)
initial_packet.packet_payload = OpaqueLength(encrypted_frames_bytes)
initial_packet.length = VarLenIntEncoding(Uint16(len(encrypted_frames_bytes)))
print('>>>', len(encrypted_frames_bytes), len(frames_bytes))
###

res = conn.sendto(bytes(initial_packet))
print(res)
res = conn.recvfrom()
print(res)
recv_msg, addr = res
