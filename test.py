import operator as op
from sympy import isprime, gcd
import DES 
import AES
def encrypt_RC4(message, seed):
    s = []
    T = []
    cipher =[]
    key=[]
    # Convert seed to digit list
    seed = [int(i) for i in str(seed)]
    message = [ord(i) for i in str(message)]
    print(message)
    # Key Scheduling Algorithm (KSA)
    for i in range(256):
        s.append(i)
        T.append(seed[i % len(seed)])
    
    j = 0
    for i in range(256):
        j = (j + s[i] + T[i]) % 256
        s[i], s[j] = s[j], s[i]  # swap

    # Pseudo-Random Generation Algorithm (PRGA)
    i = 0
    j = 0
    for k in range(len(message)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]  # swap
        t = (s[i] + s[j]) % 256
        k_stream = s[t]
        key.append(s[t])
        cipher.append(op.xor(message[k], k_stream))
        
    return cipher , key


def decrypt_RC4(cipher , key):
    plaintxt=""
    for i in range(len(cipher)):
        plaintxt+=str(chr(op.xor(cipher[i] , key[i])))

    return plaintxt


def extended_gcd(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        gcd, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return (gcd, x, y)

def mod_inverse(a, m):
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise Exception("No modular inverse exists")
    else:
        return x % m
    
#=================================================================================================================================
#=========================================================RSA========================================================================

# RSA
def encrypt_RSA(p, q, messege):
    # Step 1: Convert string to list of ASCII values
    if isinstance(messege, str):
        messege = [ord(c) for c in messege]

    # Step 2: Compute RSA parameters
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Step 3: Choose e
    e = None
    for i in range(4, phi_n):
        if isprime(i) and gcd(i, phi_n) == 1:
            e = i
            break

    if e is None:
        raise ValueError("No suitable public exponent found.")

    # Step 4: Compute private exponent d
    d = mod_inverse(e, phi_n)

    # Step 5: Encrypt the message
    encrypted = [(char ** e) % n for char in messege]
    #encrypted = [chr(i) for i in encrypted]
    public_key = [e, n]
    private_key = [d, n]
    return encrypted, public_key, private_key

# decrypt RSA
def decrypt_RSA(cipher , key):
    plaintext=[]
    #cipher  = [ord(i) for  i in cipher]
    cipher  = [(i**key[0])%key[1] for  i in cipher]
    plaintext = "".join([chr(i) for i in cipher]) # takes all items in an iterable and joins them into one string. 
    return plaintext


#=================================================================================================================================
#============================================================AES=====================================================================

""" very importent In ASCII (basic English letters and symbols) 1 letter = 1 byte 
    but In UTF-8 (most common encoding today) English letters → 1 byte
    Other characters (e.g., Arabic, Chinese, emojis) → 2 to 4 bytes

    'in this project we use the ASCII it mean the 1 letter = 1 byte '
"""
def split_and_pad_message(message , type_of_encode):
    message_bytes = message.encode(type_of_encode)
    if len(message_bytes) % 56 == 0:
        return [message_bytes]
    chunks = [message_bytes[i:i+56] for i in range(0, len(message_bytes), 56)]
    last_chunk = chunks[-1]
    remainder = len(last_chunk) % 16
    if remainder != 0:
        padding_length = 56 - remainder
        last_chunk += b'\0' * (padding_length - 1) + bytes([padding_length])
        chunks[-1] = last_chunk
    return chunks

#=================================================================================================================================
#============================================================test=====================================================================
# Test input for the full encryption/decryption system

# RC4 Test
message_rc4 = "hello "
seed_rc4 = 987654321
cipher_rc4, key_rc4 = encrypt_RC4(message_rc4, seed_rc4)
decrypted_rc4 = decrypt_RC4(cipher_rc4, key_rc4)
print("RC4 Cipher:", cipher_rc4)
print("RC4 Decrypted:", decrypted_rc4)

# RSA Test
p = 61
q = 53
message_rsa = "Hello"
cipher_rsa, public_key_rsa, private_key_rsa = encrypt_RSA(p, q, message_rsa)
decrypted_rsa = decrypt_RSA(cipher_rsa, private_key_rsa)
print("RSA Cipher:", cipher_rsa)
print("RSA Decrypted:", decrypted_rsa)

# DES Test
key = DES.text_to_bin('abdelmkf')  # 64-bit key (56 effective bits + parity)
plaintext = 'hello abdelrahman nice to meet you please meet me at 7 pm i want talk with you about something '

# Encrypt
blocks = DES.split_and_pad_message(plaintext)
cipher = []
for block in blocks:
    cipher_bin = DES.des_encrypt(DES.text_to_bin(block), key)
    cipher.append(DES.bin_to_hex(cipher_bin))
cipher_text = ''.join(cipher)
print("Encrypted:", cipher_text)

# Decrypt
decrypted = []
for hex_block in cipher:
    bin_block = DES.hex_to_bin(hex_block)
    plain_bin = DES.des_decrypt(bin_block, key)
    decrypted.append(DES.bin_to_text(plain_bin))
plain_text = ''.join(decrypted).rstrip()  # remove padding
print("Decrypted:", plain_text)

# AES Test
key = b'ThisIsA32ByteLongSecretKeyFAES!!'
plaintext = b"hello abdelrahman nice to meet you please meet me at 7 pm i want talk with you about something !"
print("Plaintext:", plaintext)

ciphertext = AES.aes_256_encrypt_ecb(plaintext, key)
print("Encrypted (hex):", ciphertext.hex())

decrypted = AES.aes_256_decrypt_ecb(ciphertext, key)
print("Decrypted:", decrypted)