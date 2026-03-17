# VFP-AES256-Native

> Modern AES-256 encryption for Visual FoxPro — no DLLs, no ActiveX, no external dependencies.

---

## Why this exists

Until now, the only serious encryption options for VFP were:

| Solution | Problem |
|---|---|
| [Chilkat ActiveX](https://www.chilkatsoft.com/) | Requires COM registration, external ActiveX |
| [MarshallSoft AES4FP](https://www.marshallsoft.com/aes4fp.htm) | Costs $139, requires external DLL |
| VFPEncryption FLL (2005) | No PBKDF2, no HMAC, outdated |

**This function fills that gap.** Pure VFP code calling the native Windows CNG API (`bcrypt.dll`) directly — nothing external needed.

---

## Security features

| Feature | Detail |
|---|---|
| **Algorithm** | AES-256-CBC |
| **IV** | Random 16 bytes per encryption (BCryptGenRandom) |
| **Key derivation** | PBKDF2-SHA256, 100,000 iterations |
| **Salt** | Random 16 bytes per encryption |
| **Integrity** | Encrypt-then-MAC with HMAC-SHA256 |
| **Keys** | Separate encryption and MAC keys derived independently |
| **Timing attacks** | Constant-time HMAC comparison |
| **Memory** | Sensitive key material wiped in FINALLY block |
| **Dependencies** | bcrypt.dll only (built into Windows Vista+) |

---

## Requirements

- Visual FoxPro 9.0 or later
- Windows Vista or later (bcrypt.dll)
- No external libraries, DLLs, or ActiveX components

---

## Usage

```foxpro
* Encrypt
lcEncrypted = Cifrado_AES("myPassword", "sensitive data", .F.)

* Decrypt
lcOriginal = Cifrado_AES("myPassword", lcEncrypted, .T.)

Parameters
Parameter	Type	Description
tcPassword	String	Encryption password
tcData	String	Data to encrypt or decrypt
tlDecrypt	Boolean	.F. = encrypt, .T. = decrypt
Return value
Encrypt: Base64 string containing salt + IV + ciphertext + HMAC
Decrypt: Original plaintext string, or empty string on failure
How it works
Password + Salt (16 bytes random)
        │
        ▼
PBKDF2-SHA256 (100,000 iterations)
        │
        ├──► Encryption Key (32 bytes)
        └──► MAC Key (32 bytes)
                │
Plaintext ──► AES-256-CBC (IV random) ──► Ciphertext
                                               │
                              HMAC-SHA256 ─────┘
                                               │
                    Base64(Salt + IV + Ciphertext + HMAC)
Comparison
Feature	This function	Chilkat	MarshallSoft	VFPEncryption FLL
AES-256	✅	✅	✅	✅
PBKDF2 100k iters	✅	✅	❌	❌
HMAC integrity	✅	✅	❌	❌
Encrypt-then-MAC	✅	❌	❌	❌
No external DLL	✅	❌	❌	❌
No ActiveX	✅	❌	✅	✅
Free	✅	❌	❌	✅
Pure VFP source	✅	❌	❌	❌
License
MIT License — free for personal and commercial use. See LICENSE.

Author
Sebastián Cabrera (@SebaXAvenger)
Security review assistance: AI (Claude / Abacus.AI)
