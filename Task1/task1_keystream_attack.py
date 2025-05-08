def hex_to_bytes(hex_str):
    """
    Convert a hexadecimal string to a list of bytes.
    Example: "1a2b" -> [26, 43]
    """
    return [int(hex_str[i:i + 2], 16) for i in range(0, len(hex_str), 2)]


def bytes_to_hex(byte_list):
    """
    Convert a list of bytes to a hexadecimal string.
    Example: [26, 43] -> "1a2b"
    """
    return ''.join(f'{b:02x}' for b in byte_list)


def xor_bytes(b1, b2):
    """
    XOR two byte arrays element by element.
    If lengths differ, uses the length of the shorter one.
    Example: [1, 2, 3] XOR [5, 6, 7] = [4, 4, 4]
    """
    return [x ^ y for x, y in zip(b1, b2)]


def is_printable_ascii(byte):
    """
    Check if a byte represents a printable ASCII character.
    ASCII 32-126 are printable (space through ~).
    """
    return 32 <= byte <= 126


def is_letter(byte):
    """
    Check if a byte represents an ASCII letter (A-Z, a-z).
    ASCII 65-90 are uppercase letters, 97-122 are lowercase.
    """
    return (65 <= byte <= 90) or (97 <= byte <= 122)


def read_ciphertexts(filename):
    """
    Read multiple ciphertexts from the given file.
    Each ciphertext should start with "Ciphertext #" on its own line.
    Falls back to hardcoded values if file reading fails.
    """
    ciphertexts = []

    try:
        with open(filename, 'r') as file:
            content = file.read()

            # Parse the file content to extract ciphertexts
            lines = content.split('\n')
            current_ciphertext = None

            for line in lines:
                line = line.strip()
                if line.startswith("Ciphertext #"):
                    # We found the start of a new ciphertext
                    if current_ciphertext is not None:
                        ciphertexts.append(current_ciphertext)
                    current_ciphertext = ""
                elif line and current_ciphertext is not None:
                    # Add this line to the current ciphertext
                    current_ciphertext += line

            # Don't forget to add the last ciphertext if it exists
            if current_ciphertext:
                ciphertexts.append(current_ciphertext)
    except Exception as e:
        print(f"Error reading ciphertexts: {e}")
        # If file reading fails, use these hardcoded values instead
        ciphertexts = [
            "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
            "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
            "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
            "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
            "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
            "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
            "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
            "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
            "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
            "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83"
        ]

    # Convert all hex strings to byte arrays
    return [hex_to_bytes(ct) for ct in ciphertexts]


def read_target_ciphertext(filename):
    """
    Read the target ciphertext (the one we want to decrypt) from the given file.
    Falls back to a hardcoded value if file reading fails.
    """
    try:
        with open(filename, 'r') as file:
            content = file.read()

            # Look for the target ciphertext line
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith("Target Ciphertext:"):
                    # The target ciphertext should be on the next line
                    continue
                elif line:
                    return hex_to_bytes(line)
    except Exception as e:
        print(f"Error reading target ciphertext: {e}")
        # Fall back to hardcoded value if file reading fails
        return hex_to_bytes(
            "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904")


def score_possible_space(byte_val, idx, ciphertexts):
    """
    Score a byte position for being a possible space character in the plaintext.
    A higher score indicates a higher likelihood of the position being a space.

    When a space (0x20) is XORed with a letter, the result
    is another letter in the ASCII range. This is because spaces flip the 6th bit
    of letters, converting between uppercase and lowercase in ASCII.
    """
    score = 0
    total = 0

    # Check each ciphertext at this position
    for ct_idx, ct in enumerate(ciphertexts):
        if idx < len(ct):
            # XOR the ciphertext byte with our potential key byte
            byte = ct[idx] ^ byte_val

            # If we get a letter or common punctuation, that's good evidence
            if is_letter(byte) or byte in [ord('.'), ord(','), ord(';'), ord(':'), ord('?'), ord('!')]:
                score += 1
            # If we get something unprintable, that's evidence against
            elif not is_printable_ascii(byte):
                score -= 0.5
            total += 1

    # Return normalized score (0 to 1)
    return score / total if total > 0 else 0


def recover_key(ciphertexts):
    """
    Attempt to recover the keystream by analyzing ciphertexts encrypted with the same key.

    when a space (0x20) is XORed with a letter in the plaintext,
    the result is still a letter (due to bit flipping properties of XOR).
    By identifying likely spaces, we can recover bytes of the key.
    """
    # Find the maximum length among all ciphertexts
    max_length = max(len(ct) for ct in ciphertexts)

    # Initialize the keystream with None values (unknown bytes)
    keystream = [None] * max_length

    # Calculate all pairwise XORs of ciphertexts
    # This helps identify positions where characters differ
    xor_pairs = []
    for i in range(len(ciphertexts)):
        for j in range(i + 1, len(ciphertexts)):
            xor_result = xor_bytes(ciphertexts[i], ciphertexts[j])
            xor_pairs.append((i, j, xor_result))

    # For each position in the ciphertexts, try to determine if a space exists
    for idx in range(max_length):
        best_space_score = 0
        best_ct_idx = -1

        # Try each ciphertext and see if assuming a space at position idx
        # makes sense for the other ciphertexts
        for ct_idx, ct in enumerate(ciphertexts):
            if idx < len(ct):
                # Assume this position contains a space (0x20) in the plaintext
                # Then the key byte would be: ciphertext_byte XOR 0x20
                space_key = ct[idx] ^ 0x20

                # Check if this assumption creates sensible characters in other ciphertexts
                score = score_possible_space(space_key, idx, ciphertexts)

                # Keep track of the best score
                if score > best_space_score:
                    best_space_score = score
                    best_ct_idx = ct_idx

        # If we have a good confidence score (experimentally determined threshold)
        # assume we found a space and recover the key byte
        if best_space_score > 0.7 and best_ct_idx != -1:
            keystream[idx] = ciphertexts[best_ct_idx][idx] ^ 0x20

    return keystream


def decrypt_with_key(ciphertext, keystream):
    """
    Decrypt a ciphertext using the recovered keystream.
    For positions where the key is unknown (None), the result will also be None.
    """
    plaintext_bytes = []

    for i, byte in enumerate(ciphertext):
        if i < len(keystream) and keystream[i] is not None:
            # If we know the key byte, we can decrypt
            plaintext_bytes.append(byte ^ keystream[i])
        else:
            # Otherwise, mark as unknown
            plaintext_bytes.append(None)

    return plaintext_bytes


def bytes_to_readable(byte_list):
    """
    Convert a list of bytes to a readable string.
    - Printable ASCII characters are shown as themselves
    - None values (unknown bytes) are shown as underscore '_'
    - Non-printable characters are shown as question mark '?'
    """
    result = ""
    for b in byte_list:
        if b is None:
            result += "_"  # Placeholder for unknown bytes
        elif is_printable_ascii(b):
            result += chr(b)  # Convert byte to character
        else:
            result += "?"  # Non-printable character
    return result


def find_candidate_plaintexts(ciphertexts, keystream):
    """
    Find candidate partial plaintexts for all ciphertexts using the recovered keystream.
    This helps us see the partial decryption results and potentially identify patterns.
    """
    candidates = []

    for ct in ciphertexts:
        plaintext_bytes = decrypt_with_key(ct, keystream)
        readable = bytes_to_readable(plaintext_bytes)
        candidates.append(readable)

    return candidates


def main():
    # Step 1: Read the ciphertexts and target ciphertext from files
    # The target is the one we ultimately want to decrypt
    ciphertexts = read_ciphertexts("Task1/given_ciphertext.txt")
    target_ciphertext = read_target_ciphertext("Task1/target_ciphertext.txt")

    # Step 2: Attempt to recover the keystream using statistical analysis
    # This is the core of the many-time pad vulnerability attack
    keystream = recover_key(ciphertexts)

    # Step 3: Print the partially recovered keystream (for debugging)
    # Replace None values with 0 for display purposes
    print("Partially recovered keystream (hex):")
    print(bytes_to_hex([k if k is not None else 0 for k in keystream]))
    print()

    # Step 4: Find candidate plaintexts for all ciphertexts
    # This helps us verify our approach and possibly extract more information
    candidates = find_candidate_plaintexts(ciphertexts, keystream)
    print("Candidate partial plaintexts:")
    for i, candidate in enumerate(candidates):
        print(f"Ciphertext {i + 1}:")
        print(candidate)
        print()

    # Step 5: Decrypt the target ciphertext with our partial keystream
    # This is our initial attempt at decryption
    target_plaintext_bytes = decrypt_with_key(target_ciphertext, keystream)
    target_plaintext = bytes_to_readable(target_plaintext_bytes)

    print("Partial decryption of target ciphertext:")
    print(target_plaintext)

    print("\n--- Manual refinement ---")

    # Step 6: Manual refinement using educated guesses
    # Based on examining the partial plaintexts, we can make educated guesses
    # about certain fragments of the plaintexts to improve our key recovery

    # Format: (position, ciphertext_index, known_fragment)
    known_fragments = [
        (17, 8, "encryption"),
        (0, 6, "There are two types"),
        (38, 9, "defines crypto as the"),
        (80, 6, "force to break the code"),
        (104, 3, "encryption algorithm"),
        (122, 5, "secrets"),
        (128, 8, "a procedure for decrypting"),
        (149, 6, "brute force to break you")
    ]

    # Fragments we're guessing from the partially decrypted target
    known_fragments_from_target = [
        (23, "When using a stream cipher, "),
        (61, "the key more than once"),
    ]

    # Step 7: Refine the keystream using our guesses from other ciphertexts
    for pos, ct_idx, fragment in known_fragments:
        # Convert the fragment to bytes
        plaintext_bytes = [ord(c) for c in fragment]
        for i, p_byte in enumerate(plaintext_bytes):
            # Make sure we're within bounds
            if pos + i < len(keystream) and pos + i < len(ciphertexts[ct_idx]):
                # Recover key byte: ciphertext XOR plaintext = key
                keystream[pos + i] = ciphertexts[ct_idx][pos + i] ^ p_byte

    # Step 8: Refine the keystream using our guesses from the target
    for pos, fragment in known_fragments_from_target:
        plaintext_bytes = [ord(c) for c in fragment]
        for i, p_byte in enumerate(plaintext_bytes):
            if pos + i < len(keystream) and pos + i < len(target_ciphertext):
                keystream[pos + i] = target_ciphertext[pos + i] ^ p_byte

    # Step 9: Try again with the refined keystream
    candidates = find_candidate_plaintexts(ciphertexts, keystream)
    print("Candidate partial plaintexts:")
    for i, candidate in enumerate(candidates):
        print(f"Ciphertext {i + 1}:")
        print(candidate)
        print()

    # Print the refined keystream (for debugging)
    print("Refined keystream (hex):")
    print(bytes_to_hex([k if k is not None else 0 for k in keystream]))

    # Step 10: Final decryption attempt with the refined keystream
    refined_target_bytes = decrypt_with_key(target_ciphertext, keystream)
    refined_target = bytes_to_readable(refined_target_bytes)

    print("\nRefined decryption of target:")
    print(refined_target)


if __name__ == "__main__":
    main()

