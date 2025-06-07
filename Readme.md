# Multi-Algorithm Encryption and Hashing Project

## Overview

This project implements a set of cryptographic algorithms **from scratch** for educational purposes.  
Users can encrypt or hash messages using a selection of algorithms:

- **Symmetric Encryption:** AES, DES, RC4  
- **Asymmetric Encryption:** RSA  
- **Hash Functions:** MD5, SHA-1, SHA-2, SHA-3

> **Note:**  
> This project is for learning and demonstration only.  
> Do **NOT** use these implementations in production or real security applications.

---

## Features

- Encrypt messages using AES, DES, or RC4 symmetric algorithms  
- Encrypt and decrypt messages using RSA asymmetric algorithm  
- Generate cryptographic hashes using MD5, SHA-1, SHA-2, SHA-3  
- User selects algorithm and inputs message via console or UI  
- All algorithms implemented from the ground up (no external crypto libraries)

---

## Algorithms Implemented

| Algorithm | Type              | Description                         |
|-----------|-------------------|-----------------------------------|
| AES       | Symmetric cipher  | Advanced Encryption Standard       |
| DES       | Symmetric cipher  | Data Encryption Standard           |
| RC4       | Symmetric cipher  | Stream cipher                      |
| RSA       | Asymmetric cipher | Public-key cryptosystem            |
| MD5       | Hash function     | Message Digest 5                   |
| SHA-1     | Hash function     | Secure Hash Algorithm 1            |
| SHA-2     | Hash function     | Secure Hash Algorithm 2 (SHA-256) |
| SHA-3     | Hash function     | Keccak-based hash                  |

---

## Usage

1. Run the program (e.g., `python main.py` or your compiled executable)  
2. Select the desired encryption or hashing algorithm from the menu  
3. Enter the message you want to encrypt or hash  
4. Provide any necessary keys (for symmetric/asymmetric encryption)  
5. View the output (encrypted text or hash digest)  

---

## Example

```plaintext
Choose algorithm:
1. AES
2. DES
3. RSA
4. RC4
5. Hash (MD5, SHA-1, SHA-2, SHA-3)

Enter choice: 1
Enter your message: Hello World
Enter key: mysecretkey12345
Encrypted message: 5f4dcc3b5aa765d61d8327deb882cf99
