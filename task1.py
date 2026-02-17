import os
import time
from typing import Optional, Tuple

from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import pad, unpad


PLAINTEXT = b"this is the wireless security lab"

# "key is 128-bit 1s" -> 16 bytes of 0xFF
AES_KEY_128_ONES = b"\xFF" * 16

# "key is 40-bit 1s" -> 5 bytes of 0xFF
RC4_KEY_40_ONES = b"\xFF" * 5


# -----------------------
# Encryption
# -----------------------

def aes_encrypt_cbc(plaintext: bytes, key: bytes) -> bytes:
    """
    AES-CBC with PKCS#7 padding and random IV.
    Output format: IV || CIPHERTEXT
    """
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ct


def aes_decrypt_cbc(iv_and_ct: bytes, key: bytes) -> bytes:
    iv = iv_and_ct[:16]
    ct = iv_and_ct[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt_padded = cipher.decrypt(ct)
    return unpad(pt_padded, AES.block_size)


def rc4_encrypt(plaintext: bytes, key: bytes) -> bytes:
    cipher = ARC4.new(key)
    return cipher.encrypt(plaintext)


def rc4_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = ARC4.new(key)
    return cipher.decrypt(ciphertext)


# -----------------------
# "Cracking" attempts
# -----------------------

# This function came from ChatGPT 5.2
def is_likely_english_ascii(b: bytes) -> bool:
    """
    Very simple heuristic: mostly printable ASCII and spaces.
    (Used when you *don't* assume the plaintext is known.)
    """
    if not b:
        return False
    printable = 0
    for x in b:
        if x in (9, 10, 13) or 32 <= x <= 126:
            printable += 1
    return printable / len(b) > 0.95


def brute_force_rc4_40bit(ciphertext: bytes, known_plaintext: Optional[bytes] = None, start: int = 0, end: int = (1 << 40), report_every: int = 1_000_000) -> Tuple[Optional[bytes], Optional[bytes]]:
    
    t0 = time.time()
    for i in range(start, end):
        key = i.to_bytes(5, "big")  # 40-bit key -> 5 bytes
        pt = rc4_decrypt(ciphertext, key)

        if known_plaintext is not None:
            if pt == known_plaintext:
                return key, pt
        else:
            if is_likely_english_ascii(pt):
                # may be false positive)
                return key, pt

        if report_every and (i - start) % report_every == 0 and i != start:
            elapsed = time.time() - t0
            rate = (i - start) / max(elapsed, 1e-9)
            print(f"[RC4 brute] tried {i-start:,} keys | ~{rate:,.0f} keys/s")

    return None, None



def main() -> None:
    print("Plaintext:", PLAINTEXT)

    # Encrypt with AES-CBC (random IV each run)
    aes_ct = aes_encrypt_cbc(PLAINTEXT, AES_KEY_128_ONES)

    # Encrypt with RC4
    rc4_ct = rc4_encrypt(PLAINTEXT, RC4_KEY_40_ONES)

    print("\nEncrypted results (as Bytes): \n")
    print("AES-CBC ciphertext (IV||CT):", aes_ct)
    print("RC4 ciphertext:", rc4_ct)

    # Show successful decrypt (for your own verification)
    print("\nVerification decrypt: \n")
    print("AES decrypted:", aes_decrypt_cbc(aes_ct, AES_KEY_128_ONES))
    print("RC4 decrypted:", rc4_decrypt(rc4_ct, RC4_KEY_40_ONES))


    print("\nCracking: \n")


    # Here we do a *targeted demonstration*:
    # We'll search a small window around the real key value 0xFFFFFFFFFF,
    # so you can see the brute-forcer succeed quickly.
    real_key_int = int.from_bytes(RC4_KEY_40_ONES, "big")
    window = 1E7  # 10 million keys to test (out of 1 trillion total possible)
    window = int(window)
    start = max(0, real_key_int - window)
    end = min((1 << 40), real_key_int + 1)

    print(f"RC4 brute-force demo range: [{start:#x}, {end:#x}) (size {end-start:,})")
    
    #start timer
    t0 = time.time()
    found_key, found_pt = brute_force_rc4_40bit( rc4_ct, known_plaintext=PLAINTEXT, start=start, end=end, report_every=1_000_000)
    elapsed = time.time() - t0
    print(f"RC4 brute-force demo took {elapsed:.2f} seconds")

    if found_key is not None:
        print("\n[RC4 crack demo SUCCESS]")
        print("Found key bytes:", found_key)
        print("Recovered plaintext:", found_pt)
    else:
        print("\n[RC4 crack demo FAILED]")



if __name__ == "__main__":
    main()
