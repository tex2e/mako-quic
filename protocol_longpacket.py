
from metatype import Uint8, Uint32, Uint64, Opaque, OpaqueUint8, VarLenIntEncoding, Type, Enum, List
import metastruct as meta
from utils import hexdump

class PacketType(Enum):
    INITIAL   = 0x00
    _0RTT     = 0x01
    HANDSHAKE = 0x02
    RETRY     = 0x03

# Long Header Packet {
#   Header Form (1) = 1,
#   Fixed Bit (1) = 1,
#   Long Packet Type (2),
#   Type-Specific Bits (4),

class LongPacketFlags(Type):
    def __init__(self, header_form, fixed_bit,
                       long_packet_type, type_specific_bits):
        self.header_form = header_form
        self.fixed_bit = fixed_bit
        self.long_packet_type = long_packet_type
        self.type_specific_bits = type_specific_bits
        self.type_specific_bits_msb2bit = (type_specific_bits & 0b1100) >> 2
        self.type_specific_bits_lsb2bit = (type_specific_bits & 0b0011) >> 0

    @classmethod
    def from_stream(cls, fs, parent=None):
        flags = fs.read(1)
        header_form        = (ord(flags) & 0b10000000) >> 7
        fixed_bit          = (ord(flags) & 0b01000000) >> 6
        long_packet_type   = (ord(flags) & 0b00110000) >> 4
        type_specific_bits = (ord(flags) & 0b00001111) >> 0
        return LongPacketFlags(header_form, fixed_bit,
                               long_packet_type, type_specific_bits)

    def __bytes__(self):
        res = 0
        res |= self.header_form        << 7
        res |= self.fixed_bit          << 6
        res |= self.long_packet_type   << 4
        res |= self.type_specific_bits << 0
        return bytes([res])

    def __repr__(self):
        res = ""
        res += "header_form={0:1b}({1}), ".format(self.header_form,
                LongPacketFlags.get_name_of_header_form(self.header_form))
        res += "fixed_bit={0:1b}, ".format(self.fixed_bit)
        res += "long_packet_type={0:02b}({1}), ".format(self.long_packet_type,
                LongPacketFlags.get_name_of_packet_type(self.long_packet_type))
        res += "type_specific_bits={0:04b}".format(self.type_specific_bits)
        return res

    @staticmethod
    def get_name_of_header_form(value):
        if value == 0: return "Short"
        if value == 1: return "Long"

    @staticmethod
    def get_name_of_packet_type(value):
        if value == 0x00: return "Initial"
        if value == 0x01: return "0-RTT"
        if value == 0x02: return "Handshake"
        if value == 0x03: return "Retry"


# Initial Packet {
#   Header Form (1) = 1,
#   Fixed Bit (1) = 1,
#   Long Packet Type (2) = 0,
#   Reserved Bits (2),         # Protected
#   Packet Number Length (2),  # Protected
#   Version (32),
#   DCID Len (8),
#   Destination Connection ID (0..160),
#   SCID Len (8),
#   Source Connection ID (0..160),
#   Token Length (i),
#   Token (..),
#   Length (i),
#   Packet Number (8..32),     # Protected
#   Protected Payload (0..24), # Skipped Part
#   Protected Payload (128),   # Sampled Part
#   Protected Payload (..)     # Remainder
# }

@meta.struct
class LongPacket(meta.MetaStruct):
    flags: LongPacketFlags # Protected
    version: Uint32
    dest_conn_id: OpaqueUint8
    src_conn_id: OpaqueUint8
    token: Opaque(VarLenIntEncoding)
    length: VarLenIntEncoding
    protected_payload: Opaque(lambda self: self.length) # Protected

@meta.struct
class InitialPacket(meta.MetaStruct):
    flags: LongPacketFlags
    version: Uint32
    dest_conn_id: OpaqueUint8
    src_conn_id: OpaqueUint8
    token: Opaque(VarLenIntEncoding)
    length: VarLenIntEncoding
    packet_number: Opaque(lambda self: self.flags.type_specific_bits_lsb2bit + 1)
    packet_payload: Opaque(lambda self: int(self.length) - self.packet_number.get_size())

    def get_header_bytes(self):
        # AEAD Auth Data
        return bytes(self.flags) + bytes(self.version) + bytes(self.dest_conn_id) + \
               bytes(self.src_conn_id) + bytes(self.token) + bytes(self.length) + \
               bytes(self.packet_number)

    def get_packet_number_int(self):
        return int.from_bytes(bytes(self.packet_number), 'big')






from protocol_tls13_handshake import Handshake

class FrameType(Enum):
    elem_t = VarLenIntEncoding

    PADDING = VarLenIntEncoding(Uint8(0x00))
    ACK = VarLenIntEncoding(Uint8(0x02))
    CRYPTO = VarLenIntEncoding(Uint8(0x06))

# PADDING Frame {
#   Type (i) = 0x00,
# }
class Padding(Type):
    def __init__(self, padding: bytes):
        self.padding = padding

    @classmethod
    def from_stream(cls, fs, parent=None):
        padding = bytearray()
        while True:
            data = fs.read(1)
            if len(data) <= 0:
                break
            if data == b'\x00':
                padding.append(ord(data))
            else:
                fs.seek(-1, 1) # seek -1 from current position (1)
        return Padding(padding)

    def __bytes__(self):
        return self.padding

    def __repr__(self):
        return 'Padding[%d]' % (len(self.padding) + 1)

# ACK Frame {
#   Type (i) = 0x02..0x03,
#   Largest Acknowledged (i),
#   ACK Delay (i),
#   ACK Range Count (i),
#   First ACK Range (i),
#   ACK Range (..) ...,
#   [ECN Counts (..)],           <= only exists when type is 0x03
# }
@meta.struct
class AckRange(meta.MetaStruct):
    gap: VarLenIntEncoding
    ack_range_length: VarLenIntEncoding

@meta.struct
class AckFrame(meta.MetaStruct):
    largest_acknowledged: VarLenIntEncoding
    ack_delay: VarLenIntEncoding
    ack_range_count: VarLenIntEncoding   # ここは0しか入らないとして、ACK Rangesのことは考えない
    first_ack_range: VarLenIntEncoding
    # ack_range: AckRange

# CRYPTO Frame {
#   Type (i) = 0x06,
#   Offset (i),
#   Length (i),
#   Crypto Data (..),
# }
@meta.struct
class CryptoFrame(meta.MetaStruct):
    offset: VarLenIntEncoding
    length: VarLenIntEncoding
    data: Handshake

@meta.struct
class Frame(meta.MetaStruct):
    frame_type: FrameType
    frame_content: meta.Select('frame_type', cases={
        FrameType.PADDING: Padding,
        FrameType.ACK: AckFrame,
        FrameType.CRYPTO: CryptoFrame,
    })



