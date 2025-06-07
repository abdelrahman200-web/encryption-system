# SHA-256 Constants
# 4hashing 
H=[
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]
#all Kay
K=[
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]
#funcation all codee righ_rooootate 
def right_rotate(n,d):
    return ((n>>d)|(n<<(32-d)))&0xFFFFFFFF
def to_bytes(n,length):
    return [(n>>(8*i))&0xFF for i in reversed(range(length))]
def from_bytes(b):
    return sum((byte<<(8*(len(b)-1-i))) for i,byte in enumerate(b))
def pad_message(message):
    message_bytes=[ord(c) for c in message]
    bit_len=len(message_bytes)*8
    message_bytes.append(0x80)
    while (len(message_bytes) * 8)%512!=448:
        message_bytes.append(0x00)
    bit_len_bytes=to_bytes(bit_len,8)
    message_bytes.extend(bit_len_bytes)
    return message_bytes
def split_blocks(message_bytes):
    return [message_bytes[i:i+64]for i in range(0,len(message_bytes),64)]
def sha256(message):
    message_bytes=pad_message(message)
    blocks=split_blocks(message_bytes)
    h=H[:]
    for block in blocks:
        w=[]
        for i in range(16):
            start=i*4
            w.append(from_bytes(block[start:start+4]))
        for i in range(16,64):
            s0=right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1=right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            S1=right_rotate(e, 6)^right_rotate(e, 11) ^ right_rotate(e, 25)
            ch=(e & f)^((~e) & g)
            temp1=(hh+S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
            S0=right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj=(a & b)^(a & c)^(b & c)
            temp2=(S0+maj)&0xFFFFFFFF
            hh=g
            g=f
            f=e
            e=(d+temp1)&0xFFFFFFFF
            d=c
            c=b
            b=a
            a=(temp1+temp2)&0xFFFFFFFF
        h=[(x+y)&0xFFFFFFFF for x, y in zip(h,[a,b,c,d,e,f,g,hh])]
