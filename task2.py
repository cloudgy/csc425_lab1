from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

aes_key = b"Lab1Task2_AESKey"  # 16 bytes (AES-128)
block_size = 16


def split_into_blocks(data_bytes, size=16):
    return [data_bytes[i:i+size] for i in range(0, len(data_bytes), size)]


def create_repeated_plaintext():
    block_A = b"A" * block_size
    block_B = b"B" * block_size
    # Repeated pattern to reveal ECB behavior
    return (block_A * 4) + (block_B * 4) + (block_A * 4)


def encrypt_with_aes(mode_name, plaintext_bytes):
    if mode_name == "ECB":
        cipher = AES.new(aes_key, AES.MODE_ECB)
        return cipher.encrypt(plaintext_bytes), {}

    if mode_name == "CBC":
        iv = get_random_bytes(block_size)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        return cipher.encrypt(plaintext_bytes), {"iv": iv}

    if mode_name == "CFB":
        iv = get_random_bytes(block_size)
        cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv, segment_size=128)
        return cipher.encrypt(plaintext_bytes), {"iv": iv}

    if mode_name == "OFB":
        iv = get_random_bytes(block_size)
        cipher = AES.new(aes_key, AES.MODE_OFB, iv=iv)
        return cipher.encrypt(plaintext_bytes), {"iv": iv}

    if mode_name == "CTR":
        nonce_value = get_random_bytes(8)
        cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce_value)
        return cipher.encrypt(plaintext_bytes), {"nonce": nonce_value}

    raise ValueError("Unsupported mode")


def decrypt_with_aes(mode_name, ciphertext_bytes, parameters):
    if mode_name == "ECB":
        cipher = AES.new(aes_key, AES.MODE_ECB)
        return cipher.decrypt(ciphertext_bytes)

    if mode_name == "CBC":
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=parameters["iv"])
        return cipher.decrypt(ciphertext_bytes)

    if mode_name == "CFB":
        cipher = AES.new(aes_key, AES.MODE_CFB, iv=parameters["iv"], segment_size=128)
        return cipher.decrypt(ciphertext_bytes)

    if mode_name == "OFB":
        cipher = AES.new(aes_key, AES.MODE_OFB, iv=parameters["iv"])
        return cipher.decrypt(ciphertext_bytes)

    if mode_name == "CTR":
        cipher = AES.new(aes_key, AES.MODE_CTR, nonce=parameters["nonce"])
        return cipher.decrypt(ciphertext_bytes)

    raise ValueError("Unsupported mode")


def check_pattern_preservation(plaintext_bytes, ciphertext_bytes):
    plaintext_blocks = split_into_blocks(plaintext_bytes, block_size)
    ciphertext_blocks = split_into_blocks(ciphertext_bytes, block_size)

    plaintext_to_cipher_map = {}

    for index in range(len(plaintext_blocks)):
        current_plain_block = plaintext_blocks[index]
        current_cipher_block = ciphertext_blocks[index]

        if current_plain_block in plaintext_to_cipher_map:
            if plaintext_to_cipher_map[current_plain_block] != current_cipher_block:
                return False
        else:
            plaintext_to_cipher_map[current_plain_block] = current_cipher_block

    # Ensure repeated plaintext actually produced repeated ciphertext
    for plain_block in set(plaintext_blocks):
        if plaintext_blocks.count(plain_block) > 1:
            corresponding_cipher = plaintext_to_cipher_map[plain_block]
            if ciphertext_blocks.count(corresponding_cipher) > 1:
                return True

    return False


def check_error_propagation(original_plaintext, mode_name, original_ciphertext, parameters):
    modified_ciphertext = bytearray(original_ciphertext)

    byte_position_to_flip = (3 * block_size) + 5
    if byte_position_to_flip >= len(modified_ciphertext):
        byte_position_to_flip = len(modified_ciphertext) - 1

    modified_ciphertext[byte_position_to_flip] ^= 1  # flip one bit

    decrypted_modified_plaintext = decrypt_with_aes(
        mode_name,
        bytes(modified_ciphertext),
        parameters
    )

    original_blocks = split_into_blocks(original_plaintext, block_size)
    modified_blocks = split_into_blocks(decrypted_modified_plaintext, block_size)

    flipped_block_index = byte_position_to_flip // block_size

    for block_index in range(flipped_block_index + 1, len(original_blocks)):
        if original_blocks[block_index] != modified_blocks[block_index]:
            return True

    return False


def yes_or_no(value):
    return "Yes" if value else "No"


if __name__ == "__main__":
    plaintext = create_repeated_plaintext()

    for aes_mode in ["ECB", "CBC", "CFB", "OFB", "CTR"]:
        ciphertext, encryption_parameters = encrypt_with_aes(aes_mode, plaintext)

        pattern_result = check_pattern_preservation(plaintext, ciphertext)
        error_result = check_error_propagation(
            plaintext,
            aes_mode,
            ciphertext,
            encryption_parameters
        )

        print(
            f"{aes_mode} | "
            f"Pattern preservation: {yes_or_no(pattern_result)} | "
            f"Error propagation: {yes_or_no(error_result)}"
        )
