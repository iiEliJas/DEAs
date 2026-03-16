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
| RSA | Planned | / | / |
| AES-NI | Planned | / | Hardware-accelerated showcase |

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

// 1. Define your key and message as raw bytes
uint8_t key[32] = { /* ... */ };
uint8_t message[48]  = { /* ... */ };    // you can have multiple blocks of 16 bytes
uint8_t iv[16] = { /* ... */ };
uint8_t nonce[16] = { /* ... */ };


// 2. Initialize context
AES_Ctx ctx;
aes_init(&ctx, key, AES_256);   // AES_128, AES_192, or AES_256

// 3. Encrypt a 16-byte block
uint8_t cipher[16];
uint8_t decrypted[16];

// ECB
aes_ecb_encrypt(message, cipher, 3, &ctx);
aes_ecb_decrypt(cipher, decrypted, 3, &ctx);

// CBC
aes_cbc_encrypt(message, cipher, 3, &ctx, iv);
aes_cbc_decrypt(cipher, decrypted, 3, &ctx, iv);

// CTR
aes_ctr_encrypt(message, cipher, 3, &ctx, nonce);
aes_ctr_decrypt(cipher, decrypted, 3, &ctx, nonce);

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

uint64_t key     = /* ... */ ;
uint64_t iv      = /* ... */ ;    // for CBC
uint64_t nonce   = /* ... */ ;    // for CTR

uint64_t message[3]    = { /* ... */ };
uint64_t cipher[3];
uint64_t decrypted[3];

// ECB
des_ecb_encrypt(message, cipher, 3, key);
des_ecb_decrypt(cipher, decrypted, 3, key);

// CBC
des_cbc_encrypt(message, cipher, 3, key, iv);
des_cbc_decrypt(cipher, decrypted, 3, key, iv);

// CTR
des_ctr_encrypt(message, cipher, 3, key, nonce);
des_ctr_decrypt(cipher, decrypted, 3, key, nonce);
```

### Mode overview

| Mode | IV / Nonce required | Notes |
|------|-------------------|-------|
| ECB | No | Each block encrypted independently; not recommended for most use cases |
| CBC | IV (64-bit) | Each block XORed with previous ciphertext before encryption |
| CTR | Nonce (64-bit) | Turns DES into a stream cipher; encrypt and decrypt use the same function |

---

## References

- [FIPS 197 — AES Specification](https://csrc.nist.gov/publications/detail/fips/197/final)
- [FIPS 46-3 — DES Specification](https://csrc.nist.gov/pubs/fips/46-3/final)

---

## License

MIT
