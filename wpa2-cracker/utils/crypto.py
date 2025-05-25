import hmac
from hashlib import pbkdf2_hmac, sha1

def get_pmk(psk: bytes,
            ssid: bytes) -> bytes:
    """
    Generates a 32-byte PMK by using PBKDF2-HMAC-SHA1 against the PSK (wifi
    password) and SSID.
    """
    pmk = pbkdf2_hmac('sha1', psk, ssid, 4096, dklen=32)

    return pmk

def __ptk_prf(pmk: bytes,
              label: str,
              data: bytes) -> bytes:
    """
    Custom PRF based on HMAC-SHA1 that generates the 64 bytes PTK.
    """
    blen = 64  # in bytes
    i = 0
    r = b''
    while len(r) < blen:
        hmacsha1 = hmac.new(pmk, label.encode() + bytes([0x00]) + data + bytes([i]), sha1)
        r += hmacsha1.digest()
        i += 1

    return r[:blen]

def get_ptk(pmk: bytes,
            anonce: bytes,
            snonce: bytes,
            amac: bytes,
            smac: bytes) -> bytes:
    """
    Gets the 64-bytes PTK by performing custom PRF against the supplicant/access
    point nonces/mac addresses and PMK.
    """
    mac1, mac2 = sorted([amac, smac])
    nonce1, nonce2 = sorted([anonce, snonce])
    data = mac1 + mac2 + nonce1 + nonce2
    label = "Pairwise key expansion"
    ptk = __ptk_prf(pmk, label, data)

    return ptk

def get_kck(ptk: bytes) -> bytes:
    """
    Extracts the 16-byte KCK from PTK
    """
    return ptk[0:16]

def get_mic(kck: bytes,
            data: bytes) -> bytes:
    """
    This is the MIC which is derived by getting the HMAC-SHA1 of KCK and eapol
    frame (with MIC value zeroed out). HMAC-SHA1 digest is 20 bytes but MIC
    should only be 16 bytes so we will truncate it before returning to the
    caller.
    """
    hmacsha1 = hmac.new(kck, data, sha1)

    return hmacsha1.digest()[:16]
