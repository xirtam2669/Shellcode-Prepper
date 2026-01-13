#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import sys
import argparse


def main():
    parser = argparse.ArgumentParser(
        description="Generate + encrypt shellcode"
    )

    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Path to raw shellcode file"
    )

    parser.add_argument(
        "--alg",
        required=True,
        help="Select an algorithm. Options are 'rc4' or 'aes'."
    )

    parser.add_argument(
        "--key",
        help="Specify encryption key. Default is hardcoded testing key."
    )

    parser.add_argument(
        "--iv",
        help="Specify IV key for AES. Default is hardcoded testing IV."
    )

    parser.add_argument(
        "--outfile",
        help="Output file name for encrypted shellcode (default: test_implant.bin)",
    )

    args = parser.parse_args()

    # Input file handling
    match args.file:
        case "" | None:
            print("[!] No input file specified.")
            sys.exit(1)
        case _:
            input_file = args.file

    # Algorithm selection
    match args.alg:
        case "rc4":
            alg = args.alg
        case "aes":
            alg = args.alg
            iv = args.iv.encode() if args.iv else b'1234567890123456'
        case _:
            print("[!] Invalid algorithm specified. Use 'rc4' or 'aes'.")
            sys.exit(1)

    # Output file handling
    match args.outfile:
        case "" | None:
            output_file = "cipher.bin"
        case _:
            output_file = args.outfile

    # Key handling
    match args.key:
        case "" | None:
            key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
        case _:
            key = args.key.encode()


    # -------------------------------------------------------
    # 1. Ecrypt shellcode
    # -------------------------------------------------------
    print("[+] Loading raw shellcode from disk...")
    try:
        with open(input_file, "rb") as f:
            shellcode = f.read()

        if alg == "rc4":
            ciphertext = rc4(key, shellcode)
            plaintext = rc4(key, ciphertext)
            if plaintext != shellcode:
                print("Round trip test failed")
        if alg == "aes":
            ciphertext = aes(key, iv, shellcode)

        with open(output_file, "wb") as f:
            f.write(ciphertext)
        print(f"[+] {alg.upper()} encryption complete. Ciphertext written to {output_file}")


    except Exception as e:
        print(f"[!] Failed to read raw shellcode: {e}")
        sys.exit(1)

def rc4(key: bytes, data: bytes) -> bytes:
    """Encrypts or decrypts data using the RC4 algorithm.
    Args:
        key (bytes): The encryption/decryption key.
        data (bytes): The data to be encrypted or decrypted.
    Returns:
        bytes: The resulting encrypted or decrypted data.
    """

    S = list(range(256))
    j = 0

    # Key scheduling algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-random generation algorithm (PRGA)
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        out.append(byte ^ k)

    return bytes(out)

def rc4_debug_verify(key: bytes, original: bytes) -> bool:
    """
    Encrypts then decrypts data and verifies byte-for-byte equality.
    Returns True if identical, False otherwise.
    """
    encrypted = rc4_crypt(key, original)
    decrypted = rc4_crypt(key, encrypted)

    if decrypted != original:
        for i, (a, b) in enumerate(zip(original, decrypted)):
            if a != b:
                print(f"[!] RC4 mismatch at offset {i}: {a:#02x} != {b:#02x}")
                break
        return False

    print("[+] RC4 debug OK: decrypted data matches original")
    return True

def aes(key, iv, shellcode):
    """Encrypts shellcode using AES encryption in CBC mode.
    Args:
        key (bytes): The AES encryption key.
        iv (bytes): The initialization vector.
        shellcode (bytes): The shellcode to be encrypted.
    Returns:
        bytes: The encrypted shellcode.
    """

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(shellcode, AES.block_size)
    encrypted = cipher.encrypt(padded)

    return encrypted

if __name__ == "__main__":
    main()
