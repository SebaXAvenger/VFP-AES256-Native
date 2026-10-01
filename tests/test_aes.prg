* Run from repository root in VFP 9 SP2 / VFPA x86:
* DO tests\test_aes.prg
* No operational tables or files are accessed.
SET PROCEDURE TO Cifrado_AES.prg ADDITIVE
LOCAL lcPassword, lcPlain, lcCipher, lcSecond, lcVector, lcBad, lnPosition, lnLength
lcPassword = "ReferencePassword2026!"
lcPlain = STRCONV("496E646570656E64656E7420414553207265666572656E636500FF", 16)
lcVector = "A0860100000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F29DE99A5548AE6528B40E9A7D87E793D1B3573E69118722EE84C81D27D168DCAF0487EAB1709D8B924B56F1D6D905263E30949952B51E2441F9406F1A01F29B8"
DO CheckAES WITH Cifrado_AES(m.lcPassword, m.lcVector, .T.) == m.lcPlain, "Independent vector"
DO CheckAES WITH Cifrado_AES(m.lcPassword, LOWER(m.lcVector), .T.) == m.lcPlain, "Lowercase hex"
FOR lnLength = 1 TO 33
  lcPlain = REPLICATE("x", m.lnLength) + CHR(0) + CHR(255)
  lcCipher = Cifrado_AES(m.lcPassword, m.lcPlain, .F.)
  DO CheckAES WITH NOT EMPTY(m.lcCipher), "Encryption"
  DO CheckAES WITH Cifrado_AES(m.lcPassword, m.lcCipher, .T.) == m.lcPlain, "Round trip"
ENDFOR
lcSecond = Cifrado_AES(m.lcPassword, m.lcPlain, .F.)
DO CheckAES WITH NOT EMPTY(m.lcSecond) AND NOT (m.lcSecond == m.lcCipher), "Randomized encryption"
DO CheckAES WITH Cifrado_AES("wrong", m.lcVector, .T.) == "", "Wrong password"
FOR lnPosition = 1 TO LEN(m.lcVector) STEP 2
  lcBad = STUFF(m.lcVector, m.lnPosition, 2, ;
    IIF(SUBSTR(m.lcVector, m.lnPosition, 2) == "00", "01", "00"))
  DO CheckAES WITH Cifrado_AES(m.lcPassword, m.lcBad, .T.) == "", "Tampering"
ENDFOR
DO CheckAES WITH Cifrado_AES(m.lcPassword, "Z" + SUBSTR(m.lcVector, 2), .T.) == "", "Non-hex"
DO CheckAES WITH Cifrado_AES(m.lcPassword, SUBSTR(m.lcVector, 2), .T.) == "", "Odd length"
DO CheckAES WITH Cifrado_AES(m.lcPassword, LEFT(m.lcVector, 166), .T.) == "", "Truncated"
DO CheckAES WITH Cifrado_AES(m.lcPassword, "FFFFFFFF" + SUBSTR(m.lcVector, 9), .T.) == "", "Iteration overflow"
DO CheckAES WITH Cifrado_AES(m.lcPassword, "00000000" + SUBSTR(m.lcVector, 9), .T.) == "", "Zero iterations"
DO CheckAES WITH Cifrado_AES(m.lcPassword, m.lcPlain, "yes") == "", "Invalid mode"
DO CheckAES WITH Cifrado_AES(.NULL., m.lcPlain, .F.) == "", "NULL password"
DO CheckAES WITH Cifrado_AES(m.lcPassword, .NULL., .F.) == "", "NULL data"
DO CheckAES WITH Cifrado_AES(m.lcPassword, "", .F.) == "", "Empty data"
DO CheckAES WITH Cifrado_AES(m.lcPassword, REPLICATE("x", 1048577), .F.) == "", "Oversized plaintext"
lcPlain = REPLICATE("x", 1048576)
lcCipher = Cifrado_AES(m.lcPassword, m.lcPlain, .F.)
DO CheckAES WITH NOT EMPTY(m.lcCipher), "Maximum size encryption"
DO CheckAES WITH Cifrado_AES(m.lcPassword, m.lcCipher, .T.) == m.lcPlain, "Maximum size round trip"
? "All AES tests passed in this VFP runtime."
RETURN

PROCEDURE CheckAES
LPARAMETERS tlCondition, tcLabel
IF NOT m.tlCondition
  ERROR ("AES test failed: " + m.tcLabel)
ENDIF
ENDPROC
