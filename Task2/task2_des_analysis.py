"""
DES Avalanche Effect Analysis
This script analyzes the avalanche effect in DES by measuring the bit changes
in ciphertext when a single bit is flipped in either plaintext or key.
"""

import task2_des as des
import random
import sys


def generate_random_hex(length):
    """Generate a random hexadecimal string of specified length."""
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))


def flip_random_bit(hex_string):
    """Flip a random bit in the hexadecimal string."""
    # Convert hex to binary
    bin_string = des.hex_to_bin(hex_string)

    # Choose a random position to flip
    position = random.randint(0, len(bin_string) - 1)

    # Flip the bit
    flipped_bin = bin_string[:position] + ('1' if bin_string[position] == '0' else '0') + bin_string[position + 1:]

    # Convert back to hex
    return des.bin_to_hex(flipped_bin)


def count_differing_bits(hex1, hex2):
    """Count the number of bits that differ between two hexadecimal strings."""
    bin1 = des.hex_to_bin(hex1)
    bin2 = des.hex_to_bin(hex2)

    # Count differing bits
    diff_count = sum(1 for a, b in zip(bin1, bin2) if a != b)
    return diff_count


def run_avalanche_analysis(iterations=10):
    """Run the avalanche effect analysis for specified number of iterations."""
    results = {
        'plaintext_change': [],
        'key_change': []
    }

    print(f"\n=== DES Avalanche Effect Analysis ({iterations} iterations) ===\n")
    print("For each iteration:")
    print("1. A random plaintext and key are generated")
    print("2. The plaintext is encrypted with the key to get ciphertext C1")
    print("3. A single bit is flipped in either plaintext or key")
    print("4. The modified input is encrypted to get ciphertext C2")
    print("5. The number of differing bits between C1 and C2 is counted\n")

    for i in range(iterations):
        print(f"Iteration {i + 1}:")

        # Generate random plaintext and key
        plaintext = generate_random_hex(16)  # 64 bits = 16 hex characters
        key = generate_random_hex(14)  # 56 bits = 14 hex characters

        # Calculate original ciphertext
        c1 = des.des_encrypt(plaintext, key)

        # Test 1: Flip a bit in the plaintext
        plaintext_mod = flip_random_bit(plaintext)
        c2_plaintext = des.des_encrypt(plaintext_mod, key)
        diff_plaintext = count_differing_bits(c1, c2_plaintext)
        results['plaintext_change'].append(diff_plaintext)

        print(f"  Plaintext change: {diff_plaintext} bits differ in ciphertext")

        # Test 2: Flip a bit in the key
        key_mod = flip_random_bit(key)
        c2_key = des.des_encrypt(plaintext, key_mod)
        diff_key = count_differing_bits(c1, c2_key)
        results['key_change'].append(diff_key)

        print(f"  Key change: {diff_key} bits differ in ciphertext")
        print()

    # Compute and display statistics
    print("\n=== Avalanche Effect Analysis Results ===")
    print("\nPlaintext Bit Flip Results:")
    print(f"  Individual results: {results['plaintext_change']}")
    print(f"  Average bits changed: {sum(results['plaintext_change']) / iterations:.2f} out of 64 bits")
    print(f"  Average percentage changed: {(sum(results['plaintext_change']) / iterations / 64) * 100:.2f}%")

    print("\nKey Bit Flip Results:")
    print(f"  Individual results: {results['key_change']}")
    print(f"  Average bits changed: {sum(results['key_change']) / iterations:.2f} out of 64 bits")
    print(f"  Average percentage changed: {(sum(results['key_change']) / iterations / 64) * 100:.2f}%")

    print("\n=== Interpretation ===")
    print("The avalanche effect is considered strong when a single bit change in input")
    print("causes approximately 50% of output bits to change (about 32 bits for DES).")

    # Interpret results
    pt_avg = sum(results['plaintext_change']) / iterations
    key_avg = sum(results['key_change']) / iterations

    print("\nConclusion:")
    if 28 <= pt_avg <= 36:
        print("- Plaintext avalanche effect is excellent (close to the ideal 50%)")
    elif 20 <= pt_avg < 28 or 36 < pt_avg <= 44:
        print("- Plaintext avalanche effect is good but not ideal")
    else:
        print("- Plaintext avalanche effect is weaker than expected")

    if 28 <= key_avg <= 36:
        print("- Key avalanche effect is excellent (close to the ideal 50%)")
    elif 20 <= key_avg < 28 or 36 < key_avg <= 44:
        print("- Key avalanche effect is good but not ideal")
    else:
        print("- Key avalanche effect is weaker than expected")


if __name__ == "__main__":
    # Default to 10 iterations or accept command line argument
    iterations = 10
    if len(sys.argv) > 1:
        try:
            iterations = int(sys.argv[1])
        except ValueError:
            print("Invalid number of iterations. Using default (10).")

    run_avalanche_analysis(iterations)