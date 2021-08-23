import textwrap
wsize = 32
# some functions
def ROTR(x, n):
    return ((x << (wsize - n)) & (2 ** wsize - 1)) | (x >> n)

def CH(x,y,z):
    return (x & y) ^ (~x & z)

def MAJ(x,y,z):
    return (x & y) ^ (x & z) ^ (y & z)

def BSIG0(x):
    return ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22)

def BSIG1(x):
    return ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25)

def SSIG0(x):
    return ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3)

def SSIG1(x):
    return ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10)

# K Constants
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def sha_224(data):
    H = [
        0xc1059ed8,
        0x367cd507,
        0x3070dd17,
        0xf70e5939,
        0xffc00b31,
        0x68581511,
        0x64f98fa7,
        0xbefa4fa4
    ]

    raw_msg = "".join(f'{msg:0>8b}' for msg in data)
    
    # Appended "1" to message
    full_msg = raw_msg + '1'
    L = len(full_msg)

    # Find K0s
    K0s = L % 512
    if K0s <= 448:
        K0s = 448 - K0s
    else:
        K0s = 512 - K0s + 448
    # Append K "0" to msg
    full_msg = full_msg + "0"*K0s
    L = len(raw_msg)
    full_msg = full_msg + '{:064b}'.format(L)
    
    for chunk in textwrap.wrap(full_msg, 512):
        # Split msg to 512-bit
        w = []
        wsize = 32
        for t in range(16):
            x = chunk[t*wsize:(t+1)*wsize]
            w.append(int(x, 2))
        
        for t in range(16, 64):
            w.append((SSIG1(w[t-2]) + w[t-7] + SSIG0(w[t-15]) + w[t-16]) % 2**wsize)
        
        
        # init working vars
        a,b,c,d,e,f,g,h = H

        # hash computation        
        for t in range(64):
            T1 = (h + BSIG1(e) + CH(e,f,g) + K[t] + w[t]) % 2**wsize # keep in 32-bits
            T2 = (BSIG0(a) + MAJ(a,b,c)) % 2**wsize
            h = g
            g = f
            f = e
            e = (d + T1) % 2**wsize 
            d = c
            c = b
            b = a
            a = (T1 + T2) % 2**wsize

        # recompute intermediate hash value
        H[0] = (H[0] + a) % 2**wsize
        H[1] = (H[1] + b) % 2**wsize
        H[2] = (H[2] + c) % 2**wsize
        H[3] = (H[3] + d) % 2**wsize
        H[4] = (H[4] + e) % 2**wsize
        H[5] = (H[5] + f) % 2**wsize
        H[6] = (H[6] + g) % 2**wsize
        H[7] = (H[7] + h) % 2**wsize
    
    return bytes.fromhex("".join(f'{h:08x}' for h in H[:7]))

print('====== SHA-224 ======')
msg = input("Enter message to encrypted: ")
print('Implemented SHA-224 result: ', sha_224(msg.encode('utf-8')).hex())
import hashlib
print('Referenced hashlib.SHA-224: ', hashlib.sha224(msg.encode('utf-8')).digest().hex())

########################################################################
def hmac_sha224(key, msg):
    # generate k0
    B = 64
    # check and hash if K is longer than B
    if len(key) > B:
        key = sha_224(key)
    
    # padding if K is less than B
    key = key + b'\x00'*(B - len(key))
    
    # step 4, 7
    
    ipad = bytes((x ^ 0x36) for x in key)
    opad = bytes((x ^ 0x5c) for x in key)
    # step 5,6
    ipad_msg = sha_224(ipad + msg)
    # step 8, 9
    return sha_224(opad + ipad_msg)

print('====== HMAC (SHA-224) ======')
key = input("Enter key: ")
msg = input("Enter message to encrypted: ")
print('Implemented HMAC result: ', hmac_sha224(key=key.encode('utf-8'), msg=msg.encode('utf-8')).hex())
import hmac
print('Referenced hmac/SHA-224: ', hmac.new(key=key.encode('utf-8'), msg=msg.encode('utf-8'), digestmod=hashlib.sha224).digest().hex())

########################################################################
from math import ceil
def hkdf_extract(ikm, salt = b''):
    # return: prk
    hash_length = 28 # Hashlength SHA-224
    if len(salt) == 0:
        salt = bytes(0x0 * hash_length)
    return hmac_sha224(
        key=salt,
        msg=ikm,
    )

def hkdf_expand(prk, L, info = b''):
    hash_length = 28 # Hashlength SHA-224
    if (L > 255*hash_length):
        raise Exception('Error: L <= 255*hash_length')
    n = ceil(L/hash_length)
    t = b""
    okm = b""
    
    for i in range(n):
        t = hmac_sha224(
            key=prk,
            msg=(t + info + bytes([1+i]))
        )

        okm += t
    return okm[:L]

print('====== HKDF (HMAC/SHA-224) ======')
ikm = input("Enter IKM: ")
salt = input("Enter SALT: ")

prk = hkdf_extract(ikm.encode('utf-8'), salt.encode('utf-8'))
print('PRK: ', prk.hex())

info = input("Enter Info: ")
L = int(input("Enter L = "))

okm = hkdf_expand(prk, L, info.encode('utf-8'))
print('OKM =', okm.hex())


print('Done!')