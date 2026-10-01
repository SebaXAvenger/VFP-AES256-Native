# VFP-AES256-Native

AES-256-CBC with encrypt-then-MAC authentication for **32-bit Visual FoxPro 9 SP2 / VFPA**. The PRG calls Windows CNG in the system `bcrypt.dll`; it does not implement AES itself or require a third-party DLL or ActiveX. This is not a certified cryptographic library.

## Requirements

- VFP 9 SP2, or a compatible VFPA **x86** runtime. Native 64-bit VFPA is not supported by these INTEGER handle declarations.
- Windows **7 or later** for BCryptDeriveKeyPBKDF2 and CNG-managed hash/key objects. This is an API minimum, not a recommendation to use an unsupported operating system.
- No Python dependency for the application. Python is used only for the independent development reference.

## Usage

From the folder containing the PRG:

```foxpro
SET PROCEDURE TO Cifrado_AES.prg ADDITIVE
lcEncrypted = Cifrado_AES("myPassword", "sensitive data", .F.)
IF NOT EMPTY(m.lcEncrypted)
    lcOriginal = Cifrado_AES("myPassword", m.lcEncrypted, .T.)
ENDIF
```

The password and data must be character strings; mode must be logical. Invalid input, wrong password, invalid authentication or an API failure returns `""`. This preserves the original return contract; the caller must check it and must never overwrite a stored ciphertext after failed encryption. Empty or whitespace-only inputs remain rejected by the existing EMPTY policy. The function processes bytes: applications must define and preserve password/text encoding themselves.

## Wire format

The result is **hexadecimal**, not Base64. Both uppercase and lowercase hexadecimal inputs are accepted. Whitespace and non-hex characters are rejected.

| Raw offset (zero-based) | Length | Content |
|---|---:|---|
| 0 | 4 | Iterations, little-endian |
| 4 | 16 | Random salt |
| 20 | 16 | Original random IV |
| 36 | 32 | HMAC-SHA256 |
| 68 | Multiple of 16 | AES-CBC ciphertext with block padding |

PBKDF2-HMAC-SHA256 derives **one 64-byte output**, split into the first 32 bytes for AES and the next 32 for HMAC. These are distinct key bytes, not two independent PBKDF2 calls. HMAC authenticates `iterations || salt || IV || ciphertext`, excluding the tag itself; authentication is checked before decryption.

New encryption retains **100,000 iterations** and the existing field layout. Decryption accepts 100,000 through 1,000,000 iterations and rejects other counts **before** key derivation. Plaintext is limited to **1 MiB**; raw messages to 1,048,660 bytes and hex input to 2,097,320 characters. These limits are deliberate resource bounds, not cipher limits. Older valid messages within those limits retain the same interpretation. Larger legacy data now fails closed: assess actual stored sizes before deployment. This change does not repair ciphertext already produced incorrectly or recover missing secrets. The format has no magic/version field; a future protocol change needs an explicit migration strategy.

## Hardening in 1.0.1

- Check salt/IV RNG status and all HMAC creation/update/finalization results.
- Reject malformed hex, truncated/non-block-aligned ciphertext, unsupported iteration counts and excessive sizes.
- Place parsing in the error handler; validate mode type.
- Use a fresh working IV for each size/encrypt/decrypt call; preserve the original IV for authentication and serialization.
- Validate CNG output sizes against allocated capacity.
- Check normal handle destruction; attempt cleanup without leaking cleanup exceptions.
- Reduce remaining key/plaintext references including the imported-key blob.

The HMAC comparison scans all 32 bytes without an early mismatch return. This is **not a proven constant-time guarantee** for the VFP runtime. Assigning zero strings is **not guaranteed secure erasure** of heap storage or runtime copies; caller passwords and returned plaintext also remain under caller/runtime control.

## Validation

Performed in the development environment:
- Static source/API review, including IV mutation and API platform requirements.
- Independent Python AES-CBC/PBKDF2/HMAC reference round trip and six authenticated-field tampering cases.

**Not performed:** VFP compilation, Windows CNG execution, DLL calling-convention validation in VFP/VFPA, failure injection, timing or memory-erasure verification. The independent reference does not prove that VFP marshals CNG calls correctly.

`tests/test_aes.prg` includes the independent deterministic decrypt vector, byte-level tampering, wrong passwords, invalid inputs, block boundaries, randomization and size bounds. From an isolated source folder in your target x86 VFP environment:

```foxpro
DO tests\test_aes.prg
```

The test stops on a failure. Run it before replacing the function in production, and separately verify decrypting representative existing ciphertexts. RNG/HMAC failure injection and handle-leak testing remain manual/native-harness work.

## Recovery

Keep the previous PRG and representative ciphertext samples. Roll back the source if target-runtime checks fail. Do not silently re-encrypt data during rollout; a source rollback does not undo stored-data changes. No operational data is modified by this PR.

## References

- [BCryptDeriveKeyPBKDF2](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekeypbkdf2)
- [BCryptGenRandom](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom)
- [BCryptEncrypt: mutable IV](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt)
- [BCryptCreateHash: automatic object allocation](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash)
- [BCryptImportKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkey)
- [VFP STRCONV](https://www.vfphelp.com/help/_5wn12psg4.htm)
- [VFP structured error handling](https://www.vfphelp.com/vfp9/html/220ead6b-fd59-49d7-94e3-6270a91e6807.htm)

MIT License. Author: Sebastian Cabrera.
