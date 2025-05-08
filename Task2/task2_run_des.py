"""
Interactive DES Console Program
This program allows users to encrypt or decrypt messages using the DES algorithm.
"""

import task2_des as des
import re


def is_valid_hex(hex_str, expected_length=None):
    """
    Validate if the input is a valid hexadecimal string of the expected length.

    Args:
        hex_str (str): The hexadecimal string to validate
        expected_length (int, optional): Expected length in hexadecimal characters

    Returns:
        bool: True if valid, False otherwise
    """
    # Check if the string contains only hexadecimal characters
    if not re.match(r'^[0-9a-fA-F]+$', hex_str):
        return False

    # Check length if specified
    if expected_length is not None and len(hex_str) != expected_length:
        return False

    return True


def ascii_to_hex(ascii_str):
    """Convert ASCII string to hexadecimal."""
    return ''.join(f'{ord(c):02x}' for c in ascii_str)


def hex_to_ascii(hex_str):
    """Convert hexadecimal to ASCII string."""
    ascii_str = ""
    for i in range(0, len(hex_str), 2):
        char_code = int(hex_str[i:i + 2], 16)
        # Filter out non-printable characters for display
        if 32 <= char_code <= 126:  # Printable ASCII range
            ascii_str += chr(char_code)
        else:
            ascii_str += '.'  # Replace non-printable with dot
    return ascii_str


def pad_text(text, block_size=8):
    """Pad text to ensure it's a multiple of block_size bytes."""
    padding_length = block_size - (len(text) % block_size)
    if padding_length == block_size:
        return text  # No padding needed
    return text + ' ' * padding_length  # Pad with spaces


def main():
    """Main function for the interactive DES console program."""
    print("\n=== DES Encryption/Decryption Tool ===\n")

    # Prompt for operation
    while True:
        operation = input("Select operation - Encrypt (E) or Decrypt (D): ").strip().upper()
        if operation in ['E', 'D']:
            break
        print("Invalid selection! Please enter 'E' for Encryption or 'D' for Decryption.")

    # Prompt for input format
    while True:
        input_format = input("Select input format - Hexadecimal (H) or ASCII (A): ").strip().upper()
        if input_format in ['H', 'A']:
            break
        print("Invalid selection! Please enter 'H' for Hexadecimal or 'A' for ASCII.")

    # Prompt for output format
    while True:
        output_format = input("Select output format - Hexadecimal (H) or ASCII (A): ").strip().upper()
        if output_format in ['H', 'A']:
            break
        print("Invalid selection! Please enter 'H' for Hexadecimal or 'A' for ASCII.")

    # Prompt for input text (plaintext or ciphertext)
    if input_format == 'H':
        # Hex input
        while True:
            if operation == 'E':
                input_text = input("Enter 64-bit plaintext in hexadecimal (16 characters): ").strip().lower()
            else:
                input_text = input("Enter 64-bit ciphertext in hexadecimal (16 characters): ").strip().lower()

            if is_valid_hex(input_text, 16):
                break
            print("Invalid input! Please enter a valid 16-character hexadecimal string.")
    else:
        # ASCII input
        if operation == 'E':
            input_ascii = input("Enter plaintext (up to 8 ASCII characters): ").strip()
            # Pad to 8 characters if needed
            input_ascii = pad_text(input_ascii)
            # Limit to 8 characters (64 bits)
            input_ascii = input_ascii[:8]
            # Convert to hex
            input_text = ascii_to_hex(input_ascii)
            print(f"ASCII input converted to hex: {input_text}")
        else:
            while True:
                input_text = input("Enter ciphertext in hexadecimal (16 characters): ").strip().lower()
                if is_valid_hex(input_text, 16):
                    break
                print("Invalid input! Please enter a valid 16-character hexadecimal string.")

    # Prompt for key
    if input_format == 'H':
        # Hex key
        while True:
            key = input("Enter 56-bit DES key in hexadecimal (14 characters): ").strip().lower()
            if is_valid_hex(key, 14):
                break
            print("Invalid key! Please enter a valid 14-character hexadecimal string.")
    else:
        # ASCII key
        key_ascii = input("Enter key as ASCII text (up to 7 characters): ").strip()
        # Pad to 7 characters (56 bits) if needed
        key_ascii = pad_text(key_ascii, 7)
        # Limit to 7 characters
        key_ascii = key_ascii[:7]
        # Convert to hex
        key = ascii_to_hex(key_ascii)
        print(f"ASCII key converted to hex: {key}")

    # Process
    if operation == 'E':
        print("\nPerforming DES Encryption...")
        result_hex = des.des_encrypt(input_text, key)

        if output_format == 'H':
            print(f"Plaintext (hex): {input_text}")
            print(f"Key (hex): {key}")
            print(f"Ciphertext (hex): {result_hex}")
        else:
            # Convert input and key to ASCII for display if they were entered as ASCII
            if input_format == 'A':
                input_display = hex_to_ascii(input_text)
                key_display = hex_to_ascii(key)
            else:
                input_display = hex_to_ascii(input_text)
                key_display = hex_to_ascii(key)

            result_ascii = hex_to_ascii(result_hex)
            print(f"Plaintext (ASCII): {input_display}")
            print(f"Key (ASCII): {key_display}")
            print(f"Ciphertext (ASCII): {result_ascii}")
            print(f"Ciphertext (hex): {result_hex}")
    else:
        print("\nPerforming DES Decryption...")
        result_hex = des.des_decrypt(input_text, key)

        if output_format == 'H':
            print(f"Ciphertext (hex): {input_text}")
            print(f"Key (hex): {key}")
            print(f"Plaintext (hex): {result_hex}")
        else:
            # Convert input and key to ASCII for display if they were entered as ASCII
            if input_format == 'A':
                input_display = hex_to_ascii(input_text)
                key_display = hex_to_ascii(key)
            else:
                input_display = hex_to_ascii(input_text)
                key_display = hex_to_ascii(key)

            result_ascii = hex_to_ascii(result_hex)
            print(f"Ciphertext (ASCII): {input_display}")
            print(f"Key (ASCII): {key_display}")
            print(f"Plaintext (ASCII): {result_ascii}")
            print(f"Plaintext (hex): {result_hex}")


if __name__ == "__main__":
    main()
