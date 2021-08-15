
from protocol_keyschedule import HKDF_expand_label

initial_salt = bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a')

def get_key_iv_hp(cs_initial_secret):
    cs_key = HKDF_expand_label(cs_initial_secret, b'quic key', b'', 16)
    cs_iv = HKDF_expand_label(cs_initial_secret, b'quic iv', b'', 12)
    cs_hp = HKDF_expand_label(cs_initial_secret, b'quic hp', b'', 16)
    return cs_key, cs_iv, cs_hp
