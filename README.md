# DEAs — Data Encryption Algorithms

A clean, from-scratch implementation of classic and modern encryption algorithms in C. Built without external libraries — every algorithm is implemented directly from the official specifications.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![C](https://img.shields.io/badge/language-C-00599C?logo=c)
---

## Algorithms

| Algorithm | Status | Key Sizes | Modes |
|-----------|--------|-----------|-------|
| DES | ✅ Complete | 64-bit | ECB, CBC, CTR |
| AES | ✅ Complete | 128 / 192 / 256-bit | ECB, CBC, CTR |
| RSA | Planned | — | — |
| AES-NI | Planned | — | Hardware-accelerated showcase |

---

## Project Structure

```
DEAs/
├── src/
│   ├── aes_core.c
│   ├── aes_core.h
│   ├── des_core.c
│   ├── des_core.h
├── utils/
│   ├── utils.c
│   └── utils.h
├── demos/
│   ├── aes_demo.c
│   └── des_demo.c
├── Makefile
└── README.md
```

---

## Building

Requires `gcc` and `make`.

```bash
# Build both demos
make

# Build only AES demo
make aes

# Build only DES demo
make des

# Clean build artifacts
make clean
```

---

## Usage

### AES

Include `aes_core.h` and initialize a context once per key. The same context can then be reused to encrypt as many 16-byte blocks as needed.

```c
#include "aes_core.h"

// 1. Define your key as raw bytes
uint8_t key[32] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

// 2. Initialize context
AES_Ctx ctx;
aes_init(&ctx, key, AES_256);   // AES_128, AES_192, or AES_256

// 3. Encrypt a 16-byte block
uint8_t message[16]  = { /* ... */ };
uint8_t cipher[16];
uint8_t decrypted[16];

aes_encrypt(message, cipher, &ctx);
aes_decrypt(cipher, decrypted, &ctx);
```

**Key size options:**

| Enum | Key length |
|------|-----------|
| `AES_128` | 16 bytes |
| `AES_192` | 24 bytes |
| `AES_256` | 32 bytes |

> **Note:** The state array is column-major, matching the AES spec (FIPS 197). 

---

### DES

Include `des_core.h`. DES operates on 64-bit blocks and supports three modes of operation.

```c
#include "des_core.h"

uint64_t key     = 0x133457799BBCDFF1;
uint64_t iv      = 0xDEADBEEFCAFEBABE;   // for CBC
uint64_t nonce   = 0xFEDCBA9876543210;   // for CTR

uint64_t message[3]    = { 0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xAABBCCDDEEFF0011 };
uint64_t ciphertext[3] = {0};
uint64_t decrypted[3]  = {0};

// ECB
des_ecb_encrypt(message, ciphertext, 3, key);
des_ecb_decrypt(ciphertext, decrypted, 3, key);

// CBC
des_cbc_encrypt(message, ciphertext, 3, key, iv);
des_cbc_decrypt(ciphertext, decrypted, 3, key, iv);

// CTR
des_ctr_encrypt(message, ciphertext, 3, key, nonce);
des_ctr_decrypt(ciphertext, decrypted, 3, key, nonce);
```

### Mode overview

| Mode | IV / Nonce required | Notes |
|------|-------------------|-------|
| ECB | No | Each block encrypted independently — not recommended for most use cases |
| CBC | IV (64-bit) | Each block XORed with previous ciphertext before encryption |
| CTR | Nonce (64-bit) | Turns DES into a stream cipher; encrypt and decrypt use the same function |

---

## References

- [FIPS 197 — AES Specification](https://csrc.nist.gov/publications/detail/fips/197/final)
- [FIPS 46-3 — DES Specification](https://csrc.nist.gov/pubs/fips/46-3/final)

---

## License

MIT
