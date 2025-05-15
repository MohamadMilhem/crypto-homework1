#!/usr/bin/env python3
import importlib.util
import pickle
import os
from pathlib import Path
from tqdm import tqdm
#from Crypto.Cipher import DES
from task3_client import query_server

# Define the path to the module
module_path = Path(__file__).resolve().parent.parent / "Task2" / "task2_des.py"

# Load the module
spec = importlib.util.spec_from_file_location("des", module_path)
des = importlib.util.module_from_spec(spec)
spec.loader.exec_module(des)

# Replace with your student ID
STUDENT_ID = "1211053"

# Checkpoint file
CHECKPOINT_FILE = "mitm_checkpoint.pkl"


def bytes_to_hex(b):
    """Convert bytes to hex string"""
    return b.hex().upper()


def hex_to_bytes(h):
    """Convert hex string to bytes"""
    return bytes.fromhex(h)


def key_to_bytes(key_int):
    """Convert a 56-bit integer key to bytes with parity bits"""
    # Convert to 56-bit binary
    key_bin = format(key_int, '056b')

    # Insert parity bits
    result = ""
    for i in range(0, 56, 7):
        # Take 7 bits
        chunk = key_bin[i:i + 7]
        # Count 1s
        ones_count = chunk.count('1')
        # Add parity bit for odd parity
        parity_bit = '0' if ones_count % 2 == 1 else '1'
        result += chunk + parity_bit

    # Convert to bytes
    result_int = int(result, 2)
    result_bytes = result_int.to_bytes(8, byteorder='big')
    return result_bytes


def key_to_hex_with_parity(key_int):
    """Convert a key integer to a hex string with parity bits"""
    key_bytes = key_to_bytes(key_int)
    return bytes_to_hex(key_bytes)


def key_to_hex_without_parity(key_int):
    """Convert a key integer to a 56-bit hex string (no parity)"""
    return format(key_int, '014X')


def des_encrypt(key_int, plain_hex):
    """Encrypt a plaintext using DES"""
    key = bytes_to_hex(key_to_bytes(key_int))
    plaintext = plain_hex
    cipher = des.des_encrypt(plaintext, key)
    return cipher


def des_decrypt(key_int, cipher_hex):
    """Decrypt a ciphertext using DES"""
    key = bytes_to_hex(key_to_bytes(key_int))
    ciphertext = cipher_hex
    reconstructed_plaintext = des.des_decrypt(ciphertext, key)
    return reconstructed_plaintext


def generate_12bit_keys():
    """Generate all possible 12-bit keys"""
    for i in range(0x1000):  # 2^12 = 4096 possibilities
        yield i  # Just return the integer value


def mitm_attack():
    """Perform Meet-in-the-Middle attack on 3DES"""
    # Choose a plaintext to send to server
    chosen_plaintext = "0123456789ABCDEF"

    # Get corresponding ciphertext from the server
    ciphertext = query_server(STUDENT_ID, chosen_plaintext)
    print(f"Plaintext: {chosen_plaintext}")
    print(f"Ciphertext from server: {ciphertext}")

    # Load checkpoint if exists
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, 'rb') as f:
            lookup_table, tested_keys = pickle.load(f)
        print(f"Loaded checkpoint: {len(lookup_table)} entries in lookup table, {len(tested_keys)} keys tested")
    else:
        # Step 1: Build lookup table for first encryption stage
        lookup_table = {}
        tested_keys = set()
        print("Building lookup table...")

    # Continue building lookup table if needed
    if len(lookup_table) < 4096:  # 2^12 keys
        for k1 in tqdm(generate_12bit_keys(), total=4096, initial=len(lookup_table)):
            if k1 in lookup_table:
                continue

            # Calculate first encryption: E_k1(P)
            middle1 = des_encrypt(k1, chosen_plaintext)
            lookup_table[k1] = middle1

            # Save checkpoint periodically
            if len(lookup_table) % 100 == 0:
                with open(CHECKPOINT_FILE, 'wb') as f:
                    pickle.dump((lookup_table, tested_keys), f)

        print(f"\nLookup table complete with {len(lookup_table)} entries")
        # Save final lookup table
        with open(CHECKPOINT_FILE, 'wb') as f:
            pickle.dump((lookup_table, tested_keys), f)

    # Step 2: Try all possible K2 values and look for matches
    print("Searching for matching keys...")
    found_keys = []

    for k2 in tqdm(generate_12bit_keys(), total=4096, initial=len(tested_keys)):
        if k2 in tested_keys:
            continue

        # For all possible K1 values
        for k1, middle1 in lookup_table.items():
            # Calculate backwards: Dec_k1(C)
            temp = des_decrypt(k1, ciphertext)

            # Calculate what should be the output of the middle operation: Dec_k2(Enc_k1(P))
            # For the correct key, Enc_k2(Dec_k1(C)) should equal middle1
            if des_encrypt(k2, temp) == middle1:
                print(
                    f"\nPotential key pair found: K1={key_to_hex_without_parity(k1)}, K2={key_to_hex_without_parity(k2)}")

                # Verify by encrypting a different plaintext
                verify_plain = "FEDCBA9876543210"
                verify_cipher = query_server(STUDENT_ID, verify_plain)

                # Manual 3DES encryption to verify
                step1 = des_encrypt(k1, verify_plain)
                step2 = des_decrypt(k2, step1)
                step3 = des_encrypt(k1, step2)

                if step3 == verify_cipher:
                    print(f"\nKey pair verified: K1={key_to_hex_without_parity(k1)}, K2={key_to_hex_without_parity(k2)}")
                    found_keys.append((k1, k2))

        tested_keys.add(k2)

        # Save checkpoint periodically
        if len(tested_keys) % 100 == 0:
            with open(CHECKPOINT_FILE, 'wb') as f:
                pickle.dump((lookup_table, tested_keys), f)

    # Display results
    if found_keys:
        print("\nRecovered Keys:")
        for k1, k2 in found_keys:
            print(f"K1 (without parity): {key_to_hex_without_parity(k1)}")
            print(f"K2 (without parity): {key_to_hex_without_parity(k2)}")
            print(f"K1 (with parity): {key_to_hex_with_parity(k1)}")
            print(f"K2 (with parity): {key_to_hex_with_parity(k2)}")
    else:
        print("No valid key pairs found.")

    # Statistics
    print("\nAttack Statistics:")
    print(f"Server queries: 2")  # Initial + verification
    print(f"DES encryptions performed: {len(lookup_table) + len(found_keys) * 2}")
    print(f"DES decryptions performed: {len(tested_keys) * len(lookup_table) + len(found_keys)}")

    return found_keys


if __name__ == "__main__":
    print("Starting Meet-in-the-Middle attack on 3DES...")
    mitm_attack()