*===============================================================
* TEST_CIFRADO_AES.PRG
* Pruebas completas para la función Cifrado_AES
*===============================================================

SET PROCEDURE TO cifrado_aes.prg ADDITIVE

LOCAL lcPASS, lcTexto, lcEncriptado, lcDesencriptado
LOCAL lnPruebas, lnOK, lnFail, lcSep

lcSep     = REPLICATE("=", 55)
lnPruebas = 0
lnOK      = 0
lnFail    = 0

?
? lcSep
? "   TEST SUITE — Cifrado_AES"
? lcSep

?
? "--- PRUEBA 1: Cifrado y descifrado básico ---"
lcPASS          = "MiPassword123"
lcTexto         = "Hola mundo VFP!"
lcEncriptado    = Cifrado_AES(lcPASS, lcTexto,      .F.)
lcDesencriptado = Cifrado_AES(lcPASS, lcEncriptado, .T.)

= Evaluar("Encripta y devuelve no-vacío",          !EMPTY(lcEncriptado),       @lnPruebas, @lnOK, @lnFail)
= Evaluar("Desencripta igual al original",         lcDesencriptado == lcTexto, @lnPruebas, @lnOK, @lnFail)
= Evaluar("El cifrado NO es igual al texto plano", lcEncriptado <> lcTexto,    @lnPruebas, @lnOK, @lnFail)

?
? "--- PRUEBA 2: Salida en formato HEX ---"
LOCAL lcSoloHex
lcSoloHex = EMPTY(CHRTRAN(UPPER(lcEncriptado), "0123456789ABCDEF", ""))
= Evaluar("Salida hex solo tiene chars válidos", lcSoloHex, @lnPruebas, @lnOK, @lnFail)

?
? "--- PRUEBA 3: IV/Salt aleatorio (cada cifrado es distinto) ---"
LOCAL lcEnc1, lcEnc2, lcDec1, lcDec2
lcEnc1 = Cifrado_AES("pass", "mismo texto", .F.)
lcEnc2 = Cifrado_AES("pass", "mismo texto", .F.)
= Evaluar("Dos cifrados del mismo texto son distintos", lcEnc1 <> lcEnc2, @lnPruebas, @lnOK, @lnFail)

lcDec1 = Cifrado_AES("pass", lcEnc1, .T.)
lcDec2 = Cifrado_AES("pass", lcEnc2, .T.)
= Evaluar("Ambos descifran al mismo texto original", lcDec1 == lcDec2, @lnPruebas, @lnOK, @lnFail)

?
? "--- PRUEBA 4: Password incorrecto devuelve vacío ---"
LOCAL lcEncCorrecto, lcDecMal
lcEncCorrecto = Cifrado_AES("passwordCorrecto",   "dato secreto", .F.)
lcDecMal      = Cifrado_AES("passwordIncorrecto", lcEncCorrecto,  .T.)
= Evaluar("Password incorrecto devuelve vacío", EMPTY(lcDecMal), @lnPruebas, @lnOK, @lnFail)

?
? "--- PRUEBA 5: Datos corruptos devuelven vacío ---"
LOCAL lcEncOrig, lcCorrupto, lcDecCorrupto, lnMid
lcEncOrig  = Cifrado_AES("pass123", "dato original", .F.)
lnMid      = INT(LEN(lcEncOrig) / 2)
lcCorrupto = STUFF(lcEncOrig, lnMid, 1, IIF(SUBSTR(lcEncOrig, lnMid, 1) == "A", "B", "A"))
lcDecCorrupto = Cifrado_AES("pass123", lcCorrupto, .T.)
= Evaluar("Dato alterado devuelve vacío (HMAC detecta)", EMPTY(lcDecCorrupto), @lnPruebas, @lnOK, @lnFail)

?
? "--- PRUEBA 6: Casos borde ---"
LOCAL lcVacio, lcNulo
lcVacio = Cifrado_AES("pass", "",  .F.)
lcNulo  = Cifrado_AES("",    "x", .F.)
= Evaluar("Texto vacío devuelve vacío",    EMPTY(lcVacio), @lnPruebas, @lnOK, @lnFail)
= Evaluar("Password vacío devuelve vacío", EMPTY(lcNulo),  @lnPruebas, @lnOK, @lnFail)

?
? "--- PRUEBA 7: Texto largo (>1 bloque AES) ---"
LOCAL lcTextoLargo, lcEncLargo, lcDecLargo
lcTextoLargo = REPLICATE("ABCDabcd1234!@#$", 100)
lcEncLargo   = Cifrado_AES("claveSegura!", lcTextoLargo, .F.)
lcDecLargo   = Cifrado_AES("claveSegura!", lcEncLargo,   .T.)
= Evaluar("Texto largo encripta OK",           !EMPTY(lcEncLargo),          @lnPruebas, @lnOK, @lnFail)
= Evaluar("Texto largo desencripta correcto",  lcDecLargo == lcTextoLargo,  @lnPruebas, @lnOK, @lnFail)

?
? "--- PRUEBA 8: Caracteres especiales ---"
LOCAL lcEspecial, lcEncEsp, lcDecEsp
lcEspecial = "Ñoño üñíçödé €$@#%"
lcEncEsp   = Cifrado_AES("clave#$%", lcEspecial, .F.)
lcDecEsp   = Cifrado_AES("clave#$%", lcEncEsp,   .T.)
= Evaluar("Caracteres especiales encriptan OK",           !EMPTY(lcEncEsp),        @lnPruebas, @lnOK, @lnFail)
= Evaluar("Caracteres especiales desencriptan correcto",  lcDecEsp == lcEspecial,  @lnPruebas, @lnOK, @lnFail)

?
? "--- PRUEBA 9: Password con caracteres especiales ---"
LOCAL lcPassEsp, lcEncPassEsp, lcDecPassEsp
lcPassEsp    = "P@$$w0rd!#%"
lcEncPassEsp = Cifrado_AES(lcPassEsp, "texto de prueba", .F.)
lcDecPassEsp = Cifrado_AES(lcPassEsp, lcEncPassEsp, .T.)
= Evaluar("Password con caracteres especiales funciona", lcDecPassEsp == "texto de prueba", @lnPruebas, @lnOK, @lnFail)

?
? "--- PRUEBA 10: Tamaño mínimo del blob (>= 168 hex chars) ---"
LOCAL lcEncMin
lcEncMin = Cifrado_AES("p", "x", .F.)
= Evaluar("Blob mínimo tiene largo correcto", LEN(lcEncMin) >= 168, @lnPruebas, @lnOK, @lnFail)

*---------------------------------------------------------------
* RESUMEN
*---------------------------------------------------------------
?
? lcSep
? SPACE(10) + "RESULTADO FINAL"
? lcSep
? "  Total pruebas   : " + TRANSFORM(lnPruebas)
? "  Pasaron [OK]    : " + TRANSFORM(lnOK)
? "  Fallaron [FAIL] : " + TRANSFORM(lnFail)
?
IF lnFail == 0
  ? "  *** TODAS LAS PRUEBAS PASARON ***"
ELSE
  ? "  *** ATENCIÓN: " + TRANSFORM(lnFail) + " prueba(s) fallaron ***"
ENDIF
? lcSep
?

RELEASE PROCEDURE cifrado_aes.prg
RETURN

*===============================================================
FUNCTION Evaluar(tcNombre, tlCondicion, tnPruebas, tnOK, tnFail)
*===============================================================
  tnPruebas = tnPruebas + 1
  IF tlCondicion
    tnOK = tnOK + 1
    ? "  [OK]   " + tcNombre
  ELSE
    tnFail = tnFail + 1
    ? "  [FAIL] " + tcNombre
  ENDIF
  RETURN tlCondicion
ENDFUNC
