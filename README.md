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
