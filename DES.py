# Simplified DES implementation in Python (with encryption and decryption)

# Initial Permutation Table (IP)
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Inverse Initial Permutation Table (IP_INV)
IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

# Expansion Table (E)
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# S-boxes (only S-box 1 shown for brevity)
# Full S-boxes for DES
S_BOXES = [
    [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
    ],
    [
        [15,1,8,14,6,11,3,4,13,12,7,5,10,9,0,2],
        [1,15,13,8,10,3,7,4,12,5,6,11,9,0,14,2],
        [7,11,4,1,9,12,14,2,13,15,0,8,10,3,5,6],
        [9,14,15,5,0,12,7,11,10,3,13,8,6,1,2,4]
    ],
    [
        [10,0,9,14,6,3,15,5,1,13,12,7,11,8,2,4],
        [13,7,0,9,3,4,6,10,2,8,5,15,14,12,11,1],
        [13,6,4,9,8,15,14,12,0,1,7,3,10,2,5,11],
        [3,15,0,8,13,12,11,9,10,7,4,5,6,1,14,2]
    ],
    [
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,15,4],
        [13,8,11,5,6,15,0,3,10,1,2,14,7,12,9,4],
        [10,1,9,3,15,12,6,8,13,14,0,11,7,4,5,2],
        [3,15,10,5,1,12,6,11,8,0,14,9,7,4,13,2]
    ],
    [
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
        [14,11,2,12,4,7,13,1,5,8,15,10,3,9,6,0],
        [11,13,5,6,7,14,9,3,15,0,8,10,1,2,12,4],
        [3,15,10,1,13,8,9,4,5,0,14,7,11,2,12,6]
    ],
    [
        [12,1,10,15,9,2,6,8,0,13,3,14,5,11,7,4],
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
        [9,14,15,5,0,11,8,12,7,4,2,13,1,3,10,6],
        [4,3,2,12,9,5,15,10,11,14,8,1,7,6,0,13]
    ],
    [
        [4,11,2,14,15,0,8,13,3,12,7,5,10,6,9,1],
        [13,0,11,7,4,9,1,10,14,3,5,12,15,2,8,6],
        [1,15,13,8,10,3,7,4,12,5,6,11,9,0,14,2],
        [7,12,3,11,14,13,8,1,15,10,6,9,4,5,2,0]
    ],
    [
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
        [1,15,13,8,10,3,7,4,12,5,6,11,9,0,14,2],
        [7,11,4,13,1,9,0,15,5,14,10,3,12,8,2,6],
        [9,12,14,15,1,10,7,4,5,8,6,3,11,13,2,0]
    ]
]

# Permutation (P-box)
P = [16, 7, 20, 21,
     29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2, 8, 24, 14,
     32, 27, 3, 9,
     19, 13, 30, 6,
     22, 11, 4, 25]

# Key permutation tables (for simplicity, will use static 56-bit key here)
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       28, 20, 12, 4, 62, 54, 46,
       38, 30, 22, 14, 6, 61, 53,
       45, 37, 29, 21, 13, 5, 63, 55,
       47, 39, 31, 23, 15, 7]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6,
       21, 10, 23, 19, 12, 4, 26, 8, 16, 7,
       27, 20, 13, 2, 41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]

SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 1, 2,
                  2, 2, 2, 2, 1, 2, 2, 1]

def permute(block, table):
    return [block[i - 1] for i in table]

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def sbox_substitution(bits):
    output = []
    for i in range(8):  # 8 S-boxes
        block = bits[i*6:(i+1)*6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        val = S_BOXES[i][row][col]
        output += [(val >> i) & 1 for i in reversed(range(4))]
    return output

def feistel(right, subkey):
    expanded = permute(right, E)
    xored = xor(expanded, subkey)
    substituted = sbox_substitution(xored)
    return permute(substituted, P)

def generate_keys(key):
    key = permute(key, PC1)
    left, right = key[:28], key[28:]
    subkeys = []

    for i in range(16):
        left = left[SHIFT_SCHEDULE[i]:] + left[:SHIFT_SCHEDULE[i]]
        right = right[SHIFT_SCHEDULE[i]:] + right[:SHIFT_SCHEDULE[i]]
        combined = left + right
        subkeys.append(permute(combined, PC2))

    return subkeys

def des_encrypt(block, key):
    block = permute(block, IP)
    left, right = block[:32], block[32:]
    subkeys = generate_keys(key)

    for i in range(16):
        new_right = xor(left, feistel(right, subkeys[i]))
        left, right = right, new_right

    return permute(right + left, IP_INV)

def des_decrypt(block, key):
    block = permute(block, IP)
    left, right = block[:32], block[32:]
    subkeys = generate_keys(key)[::-1]

    for i in range(16):
        new_right = xor(left, feistel(right, subkeys[i]))
        left, right = right, new_right

    return permute(right + left, IP_INV)

# Helper functions to convert text and hex to binary (for I/O)

def text_to_bin(text):
    # Pad text to make it 64-bit if needed
    bin_str = ''.join(format(ord(char), '08b') for char in text)
    return [int(bit) for bit in bin_str.ljust(64, '0')]

def bin_to_text(binary):
    # Convert binary to text
    bin_str = ''.join(str(b) for b in binary)
    return ''.join(chr(int(bin_str[i:i+8], 2)) for i in range(0, len(bin_str), 8))

def hex_to_bin(hex_str):
    # Convert hex to binary
    return [int(bit) for char in bytes.fromhex(hex_str) for bit in format(char, '08b')]

def text_to_hex(text):
    return ''.join(f'{ord(i):02x}'for i in text)

def bin_to_hex(binary):
    # Convert binary to hex
    return ''.join(format(int(''.join(map(str, binary[i:i+8])), 2), '02x') for i in range(0, len(binary), 8))

# function to split the messege each 64 bit or each 8 letter becase the each letter is 1 byte 
def split_and_pad_message(message):
    message_bytes = message
    if len(message_bytes) % 8 == 0:
        return [message_bytes]
    chunks = [message_bytes[i:i+8] for i in range(0, len(message_bytes), 8)]
    return chunks

key = text_to_bin('abdelmkf')  # 64-bit key (56 effective bits + parity)
plaintext = 'hello abdelrahman nice to meet you please meet me at 7 pm i want talk with you about something '

# Encrypt
blocks = split_and_pad_message(plaintext)
cipher = []
for block in blocks:
    cipher_bin = des_encrypt(text_to_bin(block), key)
    cipher.append(bin_to_hex(cipher_bin))
cipher_text = ''.join(cipher)
print("Encrypted:", cipher_text)

# Decrypt
decrypted = []
for hex_block in cipher:
    bin_block = hex_to_bin(hex_block)
    plain_bin = des_decrypt(bin_block, key)
    decrypted.append(bin_to_text(plain_bin))
plain_text = ''.join(decrypted).rstrip()  # remove padding
print("Decrypted:", plain_text)