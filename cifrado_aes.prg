*==============================================================================
* LICENCIA MIT
*==============================================================================
* Copyright (c) 2026 Sebastián Cabrera
*
* Se concede permiso, de forma gratuita, a cualquier persona que obtenga una
* copia de este software y los archivos de documentación asociados, para usar,
* copiar, modificar, fusionar, publicar, distribuir, sublicenciar y/o vender
* copias del software, sin restricciones, sujeto a las siguientes condiciones:
*
* El aviso de copyright anterior y este aviso de permiso se incluirán en todas
* las copias o partes sustanciales del software.
*
* EL SOFTWARE SE PROPORCIONA "TAL CUAL", SIN GARANTÍA DE NINGÚN TIPO.
*==============================================================================

*==============================================================================
* FUNCIÓN : Cifrado_AES
* ARCHIVO  : cifrado_aes.prg
* VERSIÓN  : 1.0.0
* FECHA    : 02/2026
*==============================================================================
*
* DESCRIPCIÓN
*   Cifra o descifra una cadena de texto usando AES-256-CBC con autenticación
*   HMAC-SHA256 (esquema Encrypt-then-MAC). Utiliza exclusivamente la API
*   criptográfica nativa de Windows (CNG / bcrypt.dll), sin dependencias
*   externas ni ActiveX.
*
* REQUISITOS
*   - Visual FoxPro 9.0 SP2 o superior
*   - Windows Vista o superior  (bcrypt.dll disponible desde Windows Vista)
*   - No requiere librerías externas ni componentes COM/ActiveX
*
* PARÁMETROS
*   tcPassword  (C)  Contraseña en texto plano. No puede estar vacía.
*                    La fortaleza del cifrado depende de esta contraseña.
*
*   tcData      (C)  - Al CIFRAR   : texto plano (cualquier string VFP).
*                    - Al DESCIFRAR: blob hexadecimal producido por esta función.
*
*   tlDecrypt   (L)  .F. = cifrar  |  .T. = descifrar
*
* RETORNO    (C)
*   - Al CIFRAR   : string hexadecimal (mayúsculas) listo para almacenar o
*                   transmitir. Formato interno del blob:
*                     [Iters 4B][Salt 16B][IV 16B][HMAC 32B][CipherText NB]
*                   Todo codificado en HEX ? longitud siempre par.
*
*   - Al DESCIFRAR: texto plano original.
*
*   - En caso de ERROR o HMAC inválido: retorna "" (cadena vacía).
*                   NUNCA lanza una excepción al llamador.
*
* NOTAS DE SEGURIDAD
*   - Clave de cifrado  (AES-256) y clave MAC (HMAC-SHA256) se derivan
*     por separado mediante PBKDF2-SHA256 con 100.000 iteraciones.
*   - Salt (16 bytes) e IV (16 bytes) son aleatorios por cada cifrado
*     (BCryptGenRandom con flag BCRYPT_USE_SYSTEM_PREFERRED_RNG).
*   - La verificación del HMAC se realiza en TIEMPO CONSTANTE para evitar
*     ataques de temporización (timing attacks).
*   - Las variables con material de clave son sobreescritas con ceros en
*     el bloque FINALLY antes de liberarse.
*
* CRÉDITOS
*   Autor    : Sebastián Cabrera
*   Basado en: Documentación oficial de Windows CNG API (Microsoft Docs)
*              https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/
*   Asistencia de diseño y revisión de seguridad: IA (Claude, Abacus.AI)
*
* EJEMPLO DE USO
*   lcTexto     = "Hola Mundo - Dato secreto 123"
*   lcPassword  = "MiContraseñaSegura!2026"
*
*   lcCifrado   = Cifrado_AES(lcPassword, lcTexto,   .F.)
*   lcOriginal  = Cifrado_AES(lcPassword, lcCifrado, .T.)
*
*   ? "Texto original : " + lcTexto
*   ? "Texto cifrado  : " + lcCifrado
*   ? "Texto recuperado: " + lcOriginal
*   ? "Coincide: " + IIF(lcTexto == lcOriginal, "SI", "NO")
*==============================================================================
FUNCTION Cifrado_AES(tcPassword, tcData, tlDecrypt)

  *-- Tamaños fijos del protocolo
  #DEFINE ITERS_SIZE   4    && Bytes para almacenar el número de iteraciones
  #DEFINE SALT_SIZE    16   && Bytes de Salt aleatorio
  #DEFINE IV_SIZE      16   && Bytes de IV aleatorio
  #DEFINE KEY_SIZE     32   && Bytes de clave AES-256
  #DEFINE HMAC_SIZE    32   && Bytes de HMAC-SHA256
  #DEFINE HEADER_SIZE  68   && Iters(4) + Salt(16) + IV(16) + HMAC(32)
  #DEFINE MIN_BLOB     84   && HEADER_SIZE + mínimo 1 bloque AES (16 bytes)
  #DEFINE KDF_SIZE     64   && PBKDF2 produce 64 bytes: 32 enc + 32 mac

  *-- Configuración de seguridad
  #DEFINE DEFAULT_ITERS 100000

  *-- Constantes CNG
  #DEFINE STATUS_SUCCESS        0
  #DEFINE BCRYPT_HMAC_FLAG      8
  #DEFINE BCRYPT_BLOCK_PADDING  1

  *-- Handles de CNG
  LOCAL lhAesAlg, lhHmacAlg, lhAesKey, lhHmacHash
  lhAesAlg   = 0
  lhHmacAlg  = 0
  lhAesKey   = 0
  lhHmacHash = 0

  *-- Variables de trabajo
  LOCAL lcSalt, lcIV, lcKeyMaterial, lcKeyEnc, lcKeyMac
  LOCAL lcCipherText, lcHmacCalc, lcHmacStored, lcResult
  LOCAL lnStatus, lnIdx, lnDiff
  LOCAL lcBlobHeader, lcKeyBlob, lcRawData
  LOCAL lcIterLo, lnIters
  LOCAL lnOutSize, lcCipher, lnPlainSize, lcPlain
  LOCAL loEx, lcPropName, lcPropValue

  *-- Inicializar variables CRÍTICAS antes del TRY
  lcKeyEnc      = SPACE(0)
  lcKeyMac      = SPACE(0)
  lcKeyMaterial = SPACE(0)
  lcResult      = ""

  *-- Validaciones básicas de entrada
  IF VARTYPE(tcPassword) <> "C" OR EMPTY(tcPassword)
    RETURN ""
  ENDIF
  IF VARTYPE(tcData) <> "C" OR EMPTY(tcData)
    RETURN ""
  ENDIF

  *-- Preparación de los datos
  IF tlDecrypt
    lcRawData = STRCONV(tcData, 16)
    IF EMPTY(lcRawData) OR LEN(lcRawData) < MIN_BLOB
      RETURN ""
    ENDIF
  ELSE
    lcRawData = tcData
  ENDIF

  TRY
    *=========================================================
    * 1. DECLARACIONES DLL – Windows CNG (bcrypt.dll)
    *=========================================================
    DECLARE INTEGER BCryptOpenAlgorithmProvider IN bcrypt.dll ;
      INTEGER @ phAlgorithm, STRING pszAlgId, ;
      STRING pszImplementation, INTEGER dwFlags

    DECLARE INTEGER BCryptSetProperty IN bcrypt.dll ;
      INTEGER hAlgorithm, STRING pszProperty, ;
      STRING pbInput, INTEGER cbInput, INTEGER dwFlags

    DECLARE INTEGER BCryptCloseAlgorithmProvider IN bcrypt.dll ;
      INTEGER hAlgorithm, INTEGER dwFlags

    DECLARE INTEGER BCryptGenRandom IN bcrypt.dll ;
      INTEGER hAlgorithm, STRING @ pbBuffer, ;
      INTEGER cbBuffer, INTEGER dwFlags

    *-- cIterationsLo y cIterationsHi DEBEN ser INTEGER.
    *-- Si se pasan como STRING, VFP envía punteros a memoria (corrompiendo la llamada).
    DECLARE INTEGER BCryptDeriveKeyPBKDF2 IN bcrypt.dll ;
      INTEGER hPrf, STRING pbPassword, INTEGER cbPassword, ;
      STRING pbSalt, INTEGER cbSalt, ;
      INTEGER cIterationsLo, INTEGER cIterationsHi, ;
      STRING @ pbDerivedKey, INTEGER cbDerivedKey, INTEGER dwFlags

    DECLARE INTEGER BCryptImportKey IN bcrypt.dll ;
      INTEGER hAlgorithm, INTEGER hImportKey, ;
      STRING pszBlobType, INTEGER @ phKey, ;
      INTEGER pbKeyObject, INTEGER cbKeyObject, ;
      STRING pbInput, INTEGER cbInput, INTEGER dwFlags

    DECLARE INTEGER BCryptDestroyKey IN bcrypt.dll ;
      INTEGER hKey

    DECLARE INTEGER BCryptEncrypt IN bcrypt.dll ;
      INTEGER hKey, STRING pbInput, INTEGER cbInput, ;
      INTEGER pPaddingInfo, STRING pbIV, INTEGER cbIV, ;
      STRING @ pbOutput, INTEGER cbOutput, ;
      INTEGER @ pcbResult, INTEGER dwFlags

    DECLARE INTEGER BCryptEncrypt IN bcrypt.dll ;
      AS BCryptEncryptGetSize ;
      INTEGER hKey, STRING pbInput, INTEGER cbInput, ;
      INTEGER pPaddingInfo, STRING pbIV, INTEGER cbIV, ;
      INTEGER pbOutput, INTEGER cbOutput, ;
      INTEGER @ pcbResult, INTEGER dwFlags

    DECLARE INTEGER BCryptDecrypt IN bcrypt.dll ;
      INTEGER hKey, STRING pbInput, INTEGER cbInput, ;
      INTEGER pPaddingInfo, STRING pbIV, INTEGER cbIV, ;
      STRING @ pbOutput, INTEGER cbOutput, ;
      INTEGER @ pcbResult, INTEGER dwFlags

    DECLARE INTEGER BCryptDecrypt IN bcrypt.dll ;
      AS BCryptDecryptGetSize ;
      INTEGER hKey, STRING pbInput, INTEGER cbInput, ;
      INTEGER pPaddingInfo, STRING pbIV, INTEGER cbIV, ;
      INTEGER pbOutput, INTEGER cbOutput, ;
      INTEGER @ pcbResult, INTEGER dwFlags

    DECLARE INTEGER BCryptCreateHash IN bcrypt.dll ;
      INTEGER hAlgorithm, INTEGER @ phHash, ;
      INTEGER pbHashObject, INTEGER cbHashObject, ;
      STRING pbSecret, INTEGER cbSecret, INTEGER dwFlags

    DECLARE INTEGER BCryptHashData IN bcrypt.dll ;
      INTEGER hHash, STRING pbInput, INTEGER cbInput, INTEGER dwFlags

    DECLARE INTEGER BCryptFinishHash IN bcrypt.dll ;
      INTEGER hHash, STRING @ pbOutput, INTEGER cbOutput, INTEGER dwFlags

    DECLARE INTEGER BCryptDestroyHash IN bcrypt.dll ;
      INTEGER hHash

    *=========================================================
    * 2. ABRIR PROVEEDORES Y FORZAR MODO CBC
    *=========================================================
    *-- CNG requiere UTF-16 obligatoriamente para cadenas LPCWSTR
    lnStatus = BCryptOpenAlgorithmProvider(@lhAesAlg, STRCONV("AES" + CHR(0), 5), 0, 0)
    IF lnStatus <> STATUS_SUCCESS
      ERROR "BCryptOpenAlgorithmProvider(AES) falló."
    ENDIF

    lcPropName  = STRCONV("ChainingMode" + CHR(0), 5)
    lcPropValue = STRCONV("ChainingModeCBC" + CHR(0), 5)
    lnStatus = BCryptSetProperty(lhAesAlg, lcPropName, lcPropValue, LEN(lcPropValue), 0)
    IF lnStatus <> STATUS_SUCCESS
      ERROR "BCryptSetProperty(ChainingModeCBC) falló."
    ENDIF

    lnStatus = BCryptOpenAlgorithmProvider(@lhHmacAlg, STRCONV("SHA256" + CHR(0), 5), 0, BCRYPT_HMAC_FLAG)
    IF lnStatus <> STATUS_SUCCESS
      ERROR "BCryptOpenAlgorithmProvider(SHA256) falló."
    ENDIF

    *=========================================================
    * 3. EXTRACCIÓN/GENERACIÓN DE HEADER
    *=========================================================
    IF tlDecrypt
      lcIterLo     = SUBSTR(lcRawData, 1,  ITERS_SIZE)
      lcSalt       = SUBSTR(lcRawData, 5,  SALT_SIZE)
      lcIV         = SUBSTR(lcRawData, 21, IV_SIZE)
      lcHmacStored = SUBSTR(lcRawData, 37, HMAC_SIZE)
      lcCipherText = SUBSTR(lcRawData, 69)
      lnIters      = CTOBIN(lcIterLo, "4RS")
    ELSE
      lcSalt   = REPLICATE(CHR(0), SALT_SIZE)
      lcIV     = REPLICATE(CHR(0), IV_SIZE)
      BCryptGenRandom(0, @lcSalt, SALT_SIZE, 2)
      BCryptGenRandom(0, @lcIV,   IV_SIZE,   2)
      lnIters  = DEFAULT_ITERS
      lcIterLo = BINTOC(lnIters, "4RS")
    ENDIF

    *=========================================================
    * 4. DERIVAR CLAVE CON PBKDF2-SHA256
    *=========================================================
    lcKeyMaterial = REPLICATE(CHR(0), KDF_SIZE)

    *-- Se pasa lnIters (parte baja) y 0 (parte alta) para el ULONGLONG
    lnStatus = BCryptDeriveKeyPBKDF2( ;
      lhHmacAlg, tcPassword, LEN(tcPassword), ;
      lcSalt, SALT_SIZE, lnIters, 0, ;
      @lcKeyMaterial, KDF_SIZE, 0)

    IF lnStatus <> STATUS_SUCCESS
      ERROR "BCryptDeriveKeyPBKDF2 falló."
    ENDIF

    lcKeyEnc = SUBSTR(lcKeyMaterial, 1,            KEY_SIZE)
    lcKeyMac = SUBSTR(lcKeyMaterial, KEY_SIZE + 1, KEY_SIZE)
    lcKeyMaterial = REPLICATE(CHR(0), KDF_SIZE)

    *=========================================================
    * 5. IMPORTAR CLAVE AES
    *=========================================================
    lcBlobHeader = BINTOC(0x4d42444b, "4RS") + ;
                   BINTOC(1,          "4RS") + ;
                   BINTOC(KEY_SIZE,   "4RS")

    lcKeyBlob = lcBlobHeader + lcKeyEnc

    *-- KeyDataBlob debe pasarse como UTF-16
    lnStatus = BCryptImportKey(lhAesAlg, 0, STRCONV("KeyDataBlob" + CHR(0), 5), @lhAesKey, ;
                               0, 0, lcKeyBlob, LEN(lcKeyBlob), 0)
    IF lnStatus <> STATUS_SUCCESS
      ERROR "BCryptImportKey falló."
    ENDIF

    lcKeyEnc = REPLICATE(CHR(0), KEY_SIZE)

    *=========================================================
    * 6. CIFRAR O DESCIFRAR
    *=========================================================
    IF NOT tlDecrypt
      *------------------------------------------------------
      * CIFRAR
      *------------------------------------------------------
      lnOutSize = 0
      lnStatus = BCryptEncryptGetSize(lhAesKey, lcRawData, LEN(lcRawData), ;
                                      0, lcIV, IV_SIZE, ;
                                      0, 0, @lnOutSize, BCRYPT_BLOCK_PADDING)
      IF lnStatus <> STATUS_SUCCESS
        ERROR "BCryptEncryptGetSize falló."
      ENDIF

      lcCipher = REPLICATE(CHR(0), lnOutSize)
      lnStatus = BCryptEncrypt(lhAesKey, lcRawData, LEN(lcRawData), ;
                               0, lcIV, IV_SIZE, ;
                               @lcCipher, lnOutSize, @lnOutSize, BCRYPT_BLOCK_PADDING)
      IF lnStatus <> STATUS_SUCCESS
        ERROR "BCryptEncrypt falló."
      ENDIF

      lcCipherText = LEFT(lcCipher, lnOutSize)

      *-- HMAC sobre Iters + Salt + IV + CipherText
      lcHmacCalc = REPLICATE(CHR(0), HMAC_SIZE)
      lnStatus = BCryptCreateHash(lhHmacAlg, @lhHmacHash, 0, 0, lcKeyMac, KEY_SIZE, 0)

      BCryptHashData(lhHmacHash, lcIterLo,     ITERS_SIZE,        0)
      BCryptHashData(lhHmacHash, lcSalt,       SALT_SIZE,         0)
      BCryptHashData(lhHmacHash, lcIV,         IV_SIZE,           0)
      BCryptHashData(lhHmacHash, lcCipherText, LEN(lcCipherText), 0)

      lnStatus = BCryptFinishHash(lhHmacHash, @lcHmacCalc, HMAC_SIZE, 0)
      BCryptDestroyHash(lhHmacHash)
      lhHmacHash = 0

      *-- Ensamblar blob final y convertir a Hexadecimal (15 = Mayúsculas)
      lcResult = STRCONV(lcIterLo + lcSalt + lcIV + lcHmacCalc + lcCipherText, 15)

    ELSE
      *------------------------------------------------------
      * DESCIFRAR
      *------------------------------------------------------
      lcHmacCalc = REPLICATE(CHR(0), HMAC_SIZE)
      lnStatus = BCryptCreateHash(lhHmacAlg, @lhHmacHash, 0, 0, lcKeyMac, KEY_SIZE, 0)

      BCryptHashData(lhHmacHash, lcIterLo,     ITERS_SIZE,        0)
      BCryptHashData(lhHmacHash, lcSalt,       SALT_SIZE,         0)
      BCryptHashData(lhHmacHash, lcIV,         IV_SIZE,           0)
      BCryptHashData(lhHmacHash, lcCipherText, LEN(lcCipherText), 0)

      lnStatus = BCryptFinishHash(lhHmacHash, @lcHmacCalc, HMAC_SIZE, 0)
      BCryptDestroyHash(lhHmacHash)
      lhHmacHash = 0

      *-- Comparación HMAC en tiempo constante (evita timing attacks)
      lnDiff = 0
      FOR lnIdx = 1 TO HMAC_SIZE
        lnDiff = BITOR(lnDiff, BITXOR(ASC(SUBSTR(lcHmacCalc,   lnIdx, 1)), ;
                                      ASC(SUBSTR(lcHmacStored, lnIdx, 1))))
      ENDFOR

      IF lnDiff <> 0
        ERROR "HMAC inválido."
      ENDIF

      lnPlainSize = 0
      lnStatus = BCryptDecryptGetSize(lhAesKey, lcCipherText, LEN(lcCipherText), ;
                                      0, lcIV, IV_SIZE, ;
                                      0, 0, @lnPlainSize, BCRYPT_BLOCK_PADDING)
      IF lnStatus <> STATUS_SUCCESS
        ERROR "BCryptDecryptGetSize falló."
      ENDIF

      lcPlain  = REPLICATE(CHR(0), lnPlainSize)
      lnStatus = BCryptDecrypt(lhAesKey, lcCipherText, LEN(lcCipherText), ;
                               0, lcIV, IV_SIZE, ;
                               @lcPlain, lnPlainSize, @lnPlainSize, BCRYPT_BLOCK_PADDING)
      IF lnStatus <> STATUS_SUCCESS
        ERROR "BCryptDecrypt falló."
      ENDIF

      lcResult = LEFT(lcPlain, lnPlainSize)
    ENDIF

  CATCH TO loEx
    lcResult = ""
    *-- Descomenta si necesitas ver exactamente dónde falla:
    * MESSAGEBOX("Causa: " + loEx.Message + CHR(13) + "Línea: " + TRANSFORM(loEx.Lineno), 16, "Error")

  FINALLY
    IF lhHmacHash <> 0
      BCryptDestroyHash(lhHmacHash)
    ENDIF
    IF lhAesKey <> 0
      BCryptDestroyKey(lhAesKey)
    ENDIF
    IF lhAesAlg <> 0
      BCryptCloseAlgorithmProvider(lhAesAlg, 0)
    ENDIF
    IF lhHmacAlg <> 0
      BCryptCloseAlgorithmProvider(lhHmacAlg, 0)
    ENDIF

    *-- Limpiar material de clave de memoria
    lcKeyEnc      = REPLICATE(CHR(0), KEY_SIZE)
    lcKeyMac      = REPLICATE(CHR(0), KEY_SIZE)
    lcKeyMaterial = REPLICATE(CHR(0), KDF_SIZE)
  ENDTRY

  RETURN lcResult
ENDFUNC

*==============================================================================
* EJEMPLO MÍNIMO DE USO
* Podés ejecutar este bloque directamente desde el Command Window de VFP:
*   DO cifrado_aes.prg
*==============================================================================
PROCEDURE EjemploCifradoAES

  LOCAL lcTexto, lcPassword, lcCifrado, lcDescifrado

  lcTexto    = "Hola Mundo - Dato secreto 123!@#"
  lcPassword = "MiContraseñaSegura!2026"

  *-- Cifrar
  lcCifrado = Cifrado_AES(lcPassword, lcTexto, .F.)

  *-- Descifrar
  lcDescifrado = Cifrado_AES(lcPassword, lcCifrado, .T.)

  *-- Mostrar resultados
  ? REPLICATE("-", 60)
  ? "EJEMPLO DE USO - Cifrado_AES"
  ? REPLICATE("-", 60)
  ? "Texto original  : " + lcTexto
  ? "Cifrado (HEX)   : " + LEFT(lcCifrado, 40) + "..."
  ? "Descifrado      : " + lcDescifrado
  ? "Verificación    : " + IIF(lcTexto == lcDescifrado, "OK - Coincide", "ERROR - No coincide")
  ? REPLICATE("-", 60)

ENDPROC