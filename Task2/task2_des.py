"""
Data Encryption Standard (DES) Implementation
This module contains all core DES encryption and decryption functions.
"""

# DES Tables and Constants
# Initial Permutation (IP)
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final Permutation (IP^-1)
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Expansion Permutation (E)
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# P-Box Permutation
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# S-Boxes
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# PC-1 (Permuted Choice 1) - Used for key schedule
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# PC-2 (Permuted Choice 2) - Used for key schedule
PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
       15, 6, 21, 10, 23, 19, 12, 4,
       26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]

# Left shifts for key schedule
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def hex_to_bin(hex_str):
    """Convert hexadecimal string to binary string."""
    bin_str = ""
    for char in hex_str:
        bin_str += bin(int(char, 16))[2:].zfill(4)
    return bin_str


def bin_to_hex(bin_str):
    """Convert binary string to hexadecimal string."""
    hex_str = ""
    for i in range(0, len(bin_str), 4):
        hex_str += format(int(bin_str[i:i + 4], 2), 'x')
    return hex_str


def permute(input_block, permutation_table):
    """Permute the input block according to the permutation table."""
    output = ""
    for pos in permutation_table:
        output += input_block[pos - 1]  # -1 because permutation tables use 1-based indexing
    return output


def initial_permutation(plain_text):
    """Apply initial permutation to the plain text."""
    return permute(plain_text, IP)


def final_permutation(block):
    """Apply final permutation to the block."""
    return permute(block, FP)


def expand(right_half):
    """Apply expansion permutation to the right half."""
    return permute(right_half, E)


def s_box_substitution(expanded_right):
    """Apply S-Box substitution."""
    output = ""
    for i in range(8):  # 8 S-boxes
        chunk = expanded_right[i * 6:(i + 1) * 6]
        row = int(chunk[0] + chunk[5], 2)  # First and last bit determine row
        col = int(chunk[1:5], 2)  # Middle 4 bits determine column
        s_value = S_BOXES[i][row][col]
        output += format(s_value, '04b')  # Convert to 4-bit binary
    return output


def p_box_permutation(s_box_output):
    """Apply P-Box permutation."""
    return permute(s_box_output, P)


def generate_subkeys(key):
    """Generate all 16 subkeys for DES from the given key."""
    # Convert 56-bit key from hex to binary
    key_bin = hex_to_bin(key)

    # Apply PC-1 permutation to get 56-bit key
    key_56 = key_bin   # permute(key_bin, PC1)

    # Split into left and right halves
    left = key_56[:28]
    right = key_56[28:]

    subkeys = []
    for i in range(16):
        # Left circular shift on both halves
        left = left[SHIFTS[i]:] + left[:SHIFTS[i]]
        right = right[SHIFTS[i]:] + right[:SHIFTS[i]]

        # Combine halves and apply PC-2 to get 48-bit subkey
        combined = left + right
        subkey = permute(combined, PC2)

        subkeys.append(subkey)

    return subkeys


def round_function(right_half, subkey):
    """Apply the round function (f-function) to the right half using the subkey."""
    # Step 1: Expand right half from 32 to 48 bits
    expanded = expand(right_half)

    # Step 2: XOR with the subkey
    xor_result = ''.join('1' if expanded[i] != subkey[i] else '0' for i in range(len(expanded)))

    # Step 3: S-Box substitution
    s_box_output = s_box_substitution(xor_result)

    # Step 4: P-Box permutation
    return p_box_permutation(s_box_output)


def des_encrypt(plain_text_hex, key_hex):
    """
    Encrypt a 64-bit plain text with a 56-bit key using DES.

    Args:
        plain_text_hex (str): 64-bit plain text in hexadecimal format
        key_hex (str): 56-bit key in hexadecimal format

    Returns:
        str: Encrypted cipher text in hexadecimal format
    """
    # Convert plaintext from hex to binary
    plain_text = hex_to_bin(plain_text_hex)

    # Generate 16 subkeys
    subkeys = generate_subkeys(key_hex)

    # Apply initial permutation
    ip_output = initial_permutation(plain_text)

    # Split into left and right halves
    left = ip_output[:32]
    right = ip_output[32:]

    # 16 rounds of encryption
    for i in range(16):
        # Keep a copy of the right half (will become new left half)
        old_right = right

        # Apply round function to right half with the current subkey
        f_output = round_function(right, subkeys[i])

        # XOR the f-function output with the left half to get new right half
        right = ''.join('1' if left[j] != f_output[j] else '0' for j in range(32))

        # The old right half becomes the new left half
        left = old_right

    # Swap left and right halves for the final step
    combined = right + left

    # Apply final permutation
    cipher_text = final_permutation(combined)

    # Convert binary cipher text to hexadecimal
    return bin_to_hex(cipher_text)


def des_decrypt(cipher_text_hex, key_hex):
    """
    Decrypt a 64-bit cipher text with a 56-bit key using DES.

    Args:
        cipher_text_hex (str): 64-bit cipher text in hexadecimal format
        key_hex (str): 56-bit key in hexadecimal format

    Returns:
        str: Decrypted plain text in hexadecimal format
    """
    # Convert ciphertext from hex to binary
    cipher_text = hex_to_bin(cipher_text_hex)

    # Generate 16 subkeys
    subkeys = generate_subkeys(key_hex)

    # Apply initial permutation
    ip_output = initial_permutation(cipher_text)

    # Split into left and right halves
    left = ip_output[:32]
    right = ip_output[32:]

    # 16 rounds of decryption (using subkeys in reverse order)
    for i in range(15, -1, -1):
        # Keep a copy of the right half (will become new left half)
        old_right = right

        # Apply round function to right half with the current subkey
        f_output = round_function(right, subkeys[i])

        # XOR the f-function output with the left half to get new right half
        right = ''.join('1' if left[j] != f_output[j] else '0' for j in range(32))

        # The old right half becomes the new left half
        left = old_right

    # Swap left and right halves for the final step
    combined = right + left

    # Apply final permutation
    plain_text = final_permutation(combined)

    # Convert binary plain text to hexadecimal
    return bin_to_hex(plain_text)