
from metatype import Uint8, Uint32, Uint64, Opaque, OpaqueUint8, VarLenIntEncoding, Type, Enum, List
import metastruct as meta
from utils import hexdump
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
        return bytes(self.padding)

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


