# Common Crypto Patterns in Binaries

Quick-reference for identifying and recovering data protected by common cryptographic patterns found in malware, packed binaries, and license-validation schemes.

## XOR — Single Byte

**Identification:**
- Disassembly: `xor reg, imm8` in a loop over a buffer
- Ciphertext: one byte value dominates (it's `key ^ 0x00` from null padding)
- FLOSS often catches this automatically

**Recovery:**
```python
def xor_single(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)
```

**Key recovery (known-plaintext):**
```python
# If you know any plaintext byte at position i:
key = ciphertext[i] ^ known_plaintext[i]
```

## XOR — Multi-Byte (Repeating Key)

**Identification:**
- Loop with `mod` or `and` computing `i % key_len`
- Pattern: `xor [buf+i], [key + (i % N)]`
- Key often visible in `.data` or `.rdata` section, or pushed to stack

**Recovery:**
```python
def xor_multi(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
```

## XOR + ADD/SUB Layered

**Identification:**
- Multiple sequential loops over the same buffer
- Different operations per loop (XOR then ADD, or SUB then XOR)
- Each loop uses a different key/constant

**Recovery — apply inverse operations in reverse order:**
```python
# If encryption was: XOR(key1) → ADD(key2) → XOR(key3)
# Decryption is:     XOR(key3) → SUB(key2) → XOR(key1)
def layered_decrypt(data: bytes, key1: bytes, key2: bytes, key3: bytes) -> bytes:
    buf = bytearray(data)
    for i in range(len(buf)):
        buf[i] ^= key3[i % len(key3)]
    for i in range(len(buf)):
        buf[i] = (buf[i] - key2[i % len(key2)]) % 256
    for i in range(len(buf)):
        buf[i] ^= key1[i % len(key1)]
    return bytes(buf)
```

## RC4 (ARC4)

**Identification:**
- KSA: 256-iteration loop initializing S-box (`for i in 0..255: S[i] = i`), then swap loop
- PRGA: stream generation with `i = (i+1) % 256; j = (j+S[i]) % 256; swap`
- Key usually 5–32 bytes, often in `.data` or derived from a string
- capa tag: `encrypt data using RC4`

**Recovery:**
```python
from Crypto.Cipher import ARC4

def rc4_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    return ARC4.new(key).decrypt(ciphertext)
```

## AES (ECB / CBC)

**Identification:**
- S-box constants: `0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5...` (first row of AES S-box)
- Round constant table: `0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36`
- Key schedule with 10 rounds (AES-128), 12 (AES-192), or 14 (AES-256)
- capa tag: `encrypt data using AES`

**Recovery:**
```python
from Crypto.Cipher import AES

# ECB mode (no IV)
def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(ciphertext)

# CBC mode (needs IV — often first 16 bytes of ciphertext, or hardcoded)
def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
```

## Base64

**Identification:**
- Custom alphabet table in `.rdata` (64 chars + padding `=`)
- 3-byte-to-4-byte expansion pattern in loop
- Standard alphabet: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`

**Recovery:**
```python
import base64

# Standard
plaintext = base64.b64decode(encoded)

# Custom alphabet — translate to standard first
import string
custom = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"  # example
standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
plaintext = base64.b64decode(encoded.translate(str.maketrans(custom, standard)))
```

## Custom Substitution / Lookup Table

**Identification:**
- 256-byte (or smaller) table in `.data` / `.rdata`
- Loop: `output[i] = table[input[i]]`
- No mathematical relationship between input and output bytes

**Recovery — invert the table:**
```python
def invert_substitution(table: bytes, ciphertext: bytes) -> bytes:
    inverse = [0] * 256
    for i, v in enumerate(table):
        inverse[v] = i
    return bytes(inverse[b] for b in ciphertext)
```

## TEA / XTEA / XXTEA

**Identification:**
- Magic constant `0x9E3779B9` (golden ratio derivative)
- 32 or 64 rounds of Feistel-like operations
- Operates on 32-bit blocks

**Recovery:**
```python
import struct

def xtea_decrypt(key: bytes, block: bytes, rounds: int = 32) -> bytes:
    v0, v1 = struct.unpack('<II', block)
    k = struct.unpack('<4I', key)
    delta = 0x9E3779B9
    total = (delta * rounds) & 0xFFFFFFFF
    for _ in range(rounds):
        v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (total + k[(total >> 11) & 3]))) & 0xFFFFFFFF
        total = (total - delta) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (total + k[total & 3]))) & 0xFFFFFFFF
    return struct.pack('<II', v0, v1)
```

## Hashing (non-reversible — for identification only)

Common hash constants that identify the algorithm:
| Constant | Algorithm |
|----------|-----------|
| `0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476` | MD5 init |
| `0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0` | SHA-1 init |
| `0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A` | SHA-256 init |
| `0x00, 0x07, 0x0E, 0x15...` (CRC table) | CRC32 |

Use hash identification to understand validation logic, not to "reverse" the hash.
