# DEAs - Data Encryption Algorithms

A clean, from-scratch implementation of classic and modern encryption algorithms in C. Built without external libraries - every algorithm is implemented directly from the official specifications.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![C](https://img.shields.io/badge/language-C-00599C?logo=c)
[![CI](https://github.com/iiEliJas/DEAs/actions/workflows/ci.yml/badge.svg)](https://github.com/iiEliJas/DEAs/actions/workflows/ci.yml)
---

## Algorithms

| Algorithm | Key Sizes | Modes |
|-----------|-----------|-------|
| DES | 64-bit | ECB, CBC, CTR |
| AES | 128 / 192 / 256-bit | ECB, CBC, CTR |
| AES-NI | 128 / 256-bit | ECB, CBC, CTR |
| AES256GCM | 256-bit | GCM |

---

## References

- [FIPS 197 — AES Specification](https://csrc.nist.gov/publications/detail/fips/197/final)
- [Intel AES-NI WhitePaper](https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf)
- [NIST SP 800-38D - GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [FIPS 46-3 — DES Specification](https://csrc.nist.gov/pubs/fips/46-3/final)
  
---

## Building

Requires `gcc` and `make`.

```bash
make           # Build all demos

make aes       # Build AES demo

make aesni     # Build AESNI demo

make aesgcm    # Build AES256GCM demo

make des       # Build DES demo

make clean     # Clean build
```

---

## Usage

### AES
> **The software AES implementation is for educational purposes only.** 
> The lookup tables are vulnerable to cache-timing attacks. An attacker with access to cache timing information can
> potentially recover the key. Do not use this implementation to encrypt sensitive data. Use AES-NI instead.

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
 
### AES-NI
 
A hardware-accelerated AES implementation using Intel AES-NI instructions. The encryption and decryption are performed directly in hardware, making it both significantly faster than the software implementation and immune to cache-timing attacks. 
 
**Requirements:** An x86-64 CPU with AES-NI support.  
 
The API is similar to the software AES so the two can be swapped without changing much.
 
```c
#include "aesni_core.h"
 
// 1. Define your key and message as raw bytes
uint8_t key[32]     = { /* ... */ };
uint8_t message[48] = { /* ... */ };    // multiples of 16 bytes
uint8_t iv[16]      = { /* ... */ };
uint8_t nonce[16]   = { /* ... */ };
 
// 2. Initialize context
AESNI_Ctx ctx;
aesni_init(key, AESNI_256, &ctx);   // AESNI_128 or AESNI_256
 
// 3. Encrypt / decrypt
uint8_t cipher[48];
uint8_t decrypted[48];
 
// ECB
aesni_ecb_encrypt(message, cipher, 3, &ctx);
aesni_ecb_decrypt(cipher, decrypted, 3, &ctx);
 
// CBC
aesni_cbc_encrypt(message, cipher, 3, &ctx, iv);
aesni_cbc_decrypt(cipher, decrypted, 3, &ctx, iv);
 
// CTR
aesni_ctr_encrypt(message, cipher, 3, &ctx, nonce);
aesni_ctr_decrypt(cipher, decrypted, 3, &ctx, nonce);
```

---

### AES256-GCM

An implementation of the Galois Counter Mode (GCM), providing both high-speed encryption and data authenticity (AEAD)
 
**Requirements:** An x86-64 CPU with AES-NI support.  
 
```c
#include "aesni_core.h"
#include <string.h>
 
// Define your key and message as raw bytes
uint8_t key[32]     = { /* ... */ };
uint8_t message[48] = { /* ... */ };
uint8_t iv[12]      = { /* ... */ };
const char *aad = "...";
 
uint8_t cipher[48];
uint8_t tag[16];
uint8_t decrypted[48];

// 2. Encrypt and generate tag
aes256gcm_encrypt(message, 48, (uint8_t*)aad, strlen(aad), key, iv, cipher, tag);

// 3. Decrypt and verify tag
// Returns 0 on success, non-zero if the tag doesn't match
int result = aes256gcm_decrypt(cipher, 48, (uint8_t*)aad, strlen(aad), key, iv, tag, decrypted);
```

---

### DES

> **DES can be broken.** It is provided here for educational purposes only. 
> Do not use it to protect sensitive data.

Include `des_core.h`. DES operates on 64-bit blocks and supports three modes of operation.

```c
#include "des_core.h"

uint64_t key   = /* ... */ ;
uint64_t iv    = /* ... */ ;    // for CBC
uint64_t nonce = /* ... */ ;    // for CTR

uint64_t message[3] = { /* ... */ };
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

## Testing
 
Tests are built and compared with the official NIST known-answer test vectors (KAT).
 
```bash
make test        # run all tests
make test-aes    # run AES tests 
make test-aesni  # run AESNI tests 
make test-aesgcm # run AES256GCM tests
make test-des    # run DES tests 
```

---

## License

MIT
