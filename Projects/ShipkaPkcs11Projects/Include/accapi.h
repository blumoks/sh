#ifndef ACCAPI_H
#define ACCAPI_H
#ifdef  __cplusplus
extern "C" {
#endif

/*Имя криптопровайдера*/
#define ACCSP_NAME  "Shipka Base Cryptographic Provider"
#define ACCSP_GOST2001_NAME  "Shipka Base Cryptographic Provider GOST2001"

/*Тип криптопровайдера ГОСТ*/
#define PROV_GOST_2001_DH 75

/* Имя контейнера по умолчанию*/
#define SHIPKA_DEFCONT_NAME "DefaultKeys"
/* Дополнительные атрибуты для ключей */
#define KP_USER_NAME    42
#define KP_USER_POST    43
#define KP_SHIP_NAME    44


#define CRYPT_NOTEXPORT 0x0200  // делает ключ неэкспортируемым


/* Параметр, который может задаваться в качестве dwParam в функции CryptGetProvParam,
/* при этом этом на выходе получаем:
                             /* pdwDataLen - длина серийного номера ШИПКИ,
                             /* pbData - серийный номер ШИПКИ.*/
#define PP_SHIPKA_SER_NUM       41

// dwFlags для CryptAcquireContext, если пользователь хочет работать только с Аккордом
#define CRYPT_ACCORD            0x00000200
// dwFlags для CryptAcquireContext, если пользователь хочет работать только с ШИПКОЙ
#define CRYPT_SHIPKA            0x00000400

/* Описатели пользовательских ключей */
/* Algorithm types */
#define ALG_TYPE_GR3410				(7 << 9)
/* GR3411 sub-id */
#define ALG_SID_GR3411				30
/* G28147 sub_id */
#define ALG_SID_G28147				30

/* Export Key sub_id */
#define ALG_SID_PRO_EXP				31
#define ALG_SID_SIMPLE_EXP			32
//Для прошивки ранее 44.57
#define ALG_SID_PRO_EXP_OBSOLETE	       	33
#define ALG_SID_SIMPLE_EXP_OBSOLETE		34

/* Hash sub ids */
#define ALG_SID_G28147_MAC			31
#define ALG_SID_GR3410EL			35
/* GOST_DH sub ids */
#define ALG_SID_GR3410EL			35
#define ALG_SID_DH_EL_SF			36
#define ALG_SID_DH_EL_EPHEM			37
/* G28147_VD sub_id (для ООО "Валидата") */
#define ALG_SID_G28147_VD       		38

#define CALG_GR3411 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411)

#define CALG_G28147_MAC (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_G28147_MAC)

#define CALG_G28147_IMIT   CALG_G28147_MAC

#define CALG_DH_EL_EPHEM (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EL_EPHEM)

#define CALG_GR3410EL (ALG_CLASS_SIGNATURE | ALG_TYPE_GR3410 | ALG_SID_GR3410EL)

#define CALG_DH_EL_SF (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EL_SF)

#define CALG_G28147 (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_G28147)

#define CALG_PRO_EXPORT (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRO_EXP)

#define CALG_SIMPLE_EXPORT (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SIMPLE_EXP)

//Дополнительные алгоритмы, которые использовались с прошивкой ранее 44.57
#define CALG_PRO_EXPORT_OBSOLETE (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRO_EXP_OBSOLETE)

#define CALG_SIMPLE_EXPORT_OBSOLETE (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SIMPLE_EXP_OBSOLETE)


#define CRYPT_ALG_PARAM_OID_GROUP_ID            20       \

//алгоритм генерации симметричного ключа шифрования по ГОСТ 28147-89 для ООО "Валидата"
#define CALG_G28147_VD (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_G28147_VD)

//блоб для экспорта/импорта ключа шифрования по ГОСТ 28147-89 для ООО "Валидата"
#define SIMPLEBLOB_VD                           0x2

/* Константы и структуры для схем цифровой подписи и */
/* открытого распределения ключей */

/* Признак ключей ГОСТ Р 34.10-2001 */
#define GR3410_1_MAGIC			        0x3147414D
/* Признак ключей ГОСТ 28147-89 */
#define G28147_MAGIC			        0x374a51fd

#define SECRET_KEY_LEN 				32
#define G28147_KEYLEN 				SECRET_KEY_LEN
#define SEANCE_VECTOR_LEN			8

/* Макимальная длина OID */
#define OID_MAX_LEN                             18

/* Режим шифрования "гаммирование" по ГОСТ 28147-89.*/
#define CRYPT_MODE_CNT          CRYPT_MODE_OFB

/* Дополнительные параметры криптопровайдера */
#define PP_LAST_ERROR 90
#define PP_ENUMOIDS_EX 91
#define PP_HASHOID 92
#define PP_CIPHEROID 93
#define PP_SIGNATUREOID 94
#define PP_DHOID 95

#define PP_ST_GEN_VD 96 //для установки/получения параметров генерации ключа шифрования по ГОСТ 28147-89 для ООО "Валидата"
#define PP_ST_IMP_VD 98 //для импорта ключа шифрования по ГОСТ 28147-89 для ООО "Валидата"

#define PP_ENUM_HASHOID 103
#define PP_ENUM_CIPHEROID 104
#define PP_ENUM_SIGNATUREOID 105
#define PP_ENUM_DHOID	106

/* Дополнительные параметры объекта хеша */
#define HP_HASHSTARTVECT        0x0008
#define HP_HASHCOPYVAL	        0x0009
#define HP_OID                  0x000a
#define HP_OPEN                 0x000B
#define HP_OPAQUEBLOB           0x000C

/* Дополнительные параметры ключа */
#define KP_OID                  102
#define KP_HASHOID              103
#define KP_CIPHEROID            104
#define KP_SIGNATUREOID         105
#define KP_DHOID                106
#define KP_CKA_ID               107

#define KP_ST_EXP_VD 97 //для экспорта ключа шифрования по ГОСТ 28147-89 для ООО "Валидата"

/* CRYPT_PRIVATE_KEYS_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_PRIVATE_KEYS_V1 "1.2.643.2.2.37.1"
#define szOID_CP_GOST_PRIVATE_KEYS_V2 "1.2.643.2.2.37.2"
#define szOID_CP_GOST_PRIVATE_KEYS_V2_FULL "1.2.643.2.2.37.2.1"
#define szOID_CP_GOST_PRIVATE_KEYS_V2_PARTOF "1.2.643.2.2.37.2.2"

/* CRYPT_HASH_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3411 "1.2.643.2.2.9"

/* CRYPT_ENCRYPT_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_28147 "1.2.643.2.2.21"

/* CRYPT_PUBKEY_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3410EL "1.2.643.2.2.19"
#define szOID_CP_DH_EL "1.2.643.2.2.98"

/* CRYPT_SIGN_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3411_R3410EL "1.2.643.2.2.3"

/* CRYPT_ENHKEY_USAGE_OID_GROUP_ID */
#define szOID_KP_TLS_PROXY "1.2.643.2.2.34.1"
#define szOID_KP_RA_CLIENT_AUTH "1.2.643.2.2.34.2"
#define szOID_KP_WEB_CONTENT_SIGNING "1.2.643.2.2.34.3"
#define szOID_KP_RA_ADMINISTRATOR "1.2.643.2.2.34.4"
#define szOID_KP_RA_OPERATOR "1.2.643.2.2.34.5"


/* OID for HASH */
#define OID_HashTest "1.2.643.2.2.30.0"
#define OID_HashVerbaO "1.2.643.2.2.30.1"	/* ГОСТ Р 34.11-94, параметры по умолчанию */
#define OID_HashVar_1 "1.2.643.2.2.30.2"
#define OID_HashVar_2 "1.2.643.2.2.30.3"
#define OID_HashVar_3 "1.2.643.2.2.30.4"
#define OID_HashVar_Default OID_HashVerbaO


/* OID for Crypt */
#define OID_CryptTest "1.2.643.2.2.31.0"
#define OID_CipherVerbaO "1.2.643.2.2.31.1"	/* ГОСТ 28147-89, параметры по умолчанию */
#define OID_CipherVar_1 "1.2.643.2.2.31.2"	/* ГОСТ 28147-89, параметры шифрования 1 */
#define OID_CipherVar_2 "1.2.643.2.2.31.3" 	/* ГОСТ 28147-89, параметры шифрования 2 */
#define OID_CipherVar_3 "1.2.643.2.2.31.4"	/* ГОСТ 28147-89, параметры шифрования 3 */
#define OID_CipherVar_Default OID_CipherVerbaO
#define OID_CipherOSCAR "1.2.643.2.2.31.5"	/* ГОСТ 28147-89, параметры Оскар 1.1 */
#define OID_CipherTestHash "1.2.643.2.2.31.6"	/* ГОСТ 28147-89, параметры Оскар 1.0 */
#define OID_CipherRIC1 "1.2.643.2.2.31.7"	/* ГОСТ 28147-89, параметры РИК 1 */


/* OID для подписи по ГОСТ 2001*/
#define OID_EC_A "1.2.643.2.2.35.1"
#define OID_EC_B "1.2.643.2.2.35.2"
#define OID_EC_C "1.2.643.2.2.35.3"

/* OID for DH 1024*/
#define OID_DH128Var_1   "1.2.643.2.2.33.1"
#define OID_DH128Var_2   "1.2.643.2.2.33.2"
#define OID_DH128Var_3   "1.2.643.2.2.33.3"

/*Длина в байтах имитовставки при импорте/экспорте*/
#define EXPORT_IMIT_SIZE		4

/* Определения для структуры SIMPLEBLOB */
typedef struct CRYPT_SIMPLEBLOB_HEADER_ {
    BLOBHEADER BlobHeader;
                    /* Общий заголовок ключевого блоба. Определяет алгоритм ключа
                     * находящегося в ключевом блобе. См. PUBLICKEYSTRUC.
                     */
    DWORD Magic;    /*Признак ключей по ГОСТ 28147-89, устанавливается в G28147_MAGIC.
                     */
    ALG_ID EncryptKeyAlgId;
                    /*Определяет алгоритм экспорта ключа. Этот алгоритм является
                     * параметром ключа экспорта. См. CPGetKeyParam.
                     */
} CRYPT_SIMPLEBLOB_HEADER;

typedef struct CRYPT_SIMPLEBLOB_ {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
                    /*Общий заголовок ключевого блоба типа SIMPLEBLOB.
                     */
    BYTE    bSV[SEANCE_VECTOR_LEN];
                    /*Сеансовый вектор. Участвует в вычислении имитовставки при
					/*использовании алгоритма CALG_PRO_EXPORT.
                     */
    BYTE    bEncryptedKey[1/*псевдомассив*/];
                    /* Зашифрованный ключ ГОСТ 28147-89.
                    /* Длинна массива G28147_KEYLEN
                     */
    BYTE    bMacKey[EXPORT_IMIT_SIZE];
	            /* Имитовставка
	            */
    BYTE    bEncryptionParamSet[1/*псевдомассив*/];
	            /* Параметры алгоритама шифрования ГОСТ 28147-89
		    */
}   CRYPT_SIMPLEBLOB, *PCRYPT_SIMPLEBLOB;


/* Определения для структуры CRYPT_PUBKEYPARAM:
   Структура CRYPT_PUBKEYPARAM содержит признак ключей
   по ГОСТ Р 34.10-2001.
*/
typedef struct _CRYPT_PUBKEYPARAM_ {
    DWORD Magic;    /*Признак ключей по ГОСТ Р 34.10-2001
                     * устанавливается в GR3410_1_MAGIC.
                     */
    DWORD BitLen;   /*Длина открытого ключа в битах.
                     */
} CRYPT_PUBKEYPARAM, *LPCRYPT_PUBKEYPARAM;

/* Определения для структуры CRYPT_PUBKEY_INFO_HEADER:
*/
typedef struct CRYPT_PUBKEY_INFO_HEADER_ {
    BLOBHEADER BlobHeader;
                    /*!< Общий заголовок ключевого блоба. Определяет его тип и алгоритм ключа
                     * находящегося в ключевом блобе. Для открытых ключей алгоритм 
                     * ключа всегда CALG_GR3410EL. Для ключевых 
                     * пар алгоритм отражает её назначение. См. \ref _PUBLICKEYSTRUC.
                     */
    CRYPT_PUBKEYPARAM KeyParam;
                    /*!< Основной признак и длинна ключей ГОСТ Р 34.10-2001.
                     */
} CRYPT_PUBKEY_INFO_HEADER;

/* Определения для структуры CRYPT_PUBLICKEYBLOB:
  Псевдоструктура CRYPT_PUBLICKEYBLOB полностью описывает ключевой блоб
  типа PUBLICKEYBLOB. Все поля этой псевдоструктуры  выравнены по границе байта
  и находятся в сетевом порядке байт (ASN1 DER). Сетевой порядок байт означает,
  что число 0x12345678 будет записано в виде 0x12 0x34 0x56 0x78 в отличии от
  Intell порядка  байт в памяти: 0x78 0x56 0x34 0x12.
*/
typedef struct CRYPT_PUBLICKEYBLOB_ {
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
                    /*!< Общий заголовок ключевого блоба типа PUBLICKEYBLOB.
                     */
    BYTE    bASN1GostR3410_94_PublicKeyParameters[16/*псевдомассив*/];
                    /*!< Содержит структуру, определяющую 
                     * параметры открытого ключа:
                     * \code
                     *      GostR3410-94-PublicKeyParameters ::=
                     *           SEQUENCE {
                     *              publicKeyParamSet
                     *                  OBJECT IDENTIFIER (
                     *                      id-GostR3410-94-TestParamSet |      -- Only for tests use
                     *                      id-GostR3410-94-CryptoPro-A-ParamSet |
                     *                      id-GostR3410-94-CryptoPro-B-ParamSet |
                     *                      id-GostR3410-94-CryptoPro-C-ParamSet |
                     *                      id-GostR3410-94-CryptoPro-D-ParamSet |
                     *                      id-GostR3410-94-CryptoPro-XchA-ParamSet |
                     *                      id-GostR3410-94-CryptoPro-XchB-ParamSet |
                     *                      id-GostR3410-94-CryptoPro-XchC-ParamSet
                     *                  ),
                     *              digestParamSet
                     *                  OBJECT IDENTIFIER (
                     *                      id-GostR3411-94-TestParamSet |      -- Only for tests use
                     *                      id-GostR3411-94-CryptoProParamSet
                     *                  ),
                     *              encryptionParamSet
                     *                  OBJECT IDENTIFIER (
                     *                      id-Gost28147-89-TestParamSet |      -- Only for tests use
                     *                      id-Gost28147-89-CryptoPro-A-ParamSet |
                     *                      id-Gost28147-89-CryptoPro-B-ParamSet |
                     *                      id-Gost28147-89-CryptoPro-C-ParamSet |
                     *                      id-Gost28147-89-CryptoPro-D-ParamSet |
                     *                      id-Gost28147-89-CryptoPro-Simple-A-ParamSet |
                     *                      id-Gost28147-89-CryptoPro-Simple-B-ParamSet |
                     *                      id-Gost28147-89-CryptoPro-Simple-C-ParamSet |
                     *                      id-Gost28147-89-CryptoPro-Simple-D-ParamSet
                     *                  ) OPTIONAL
                     *          }
                     * \endcode
                     */
    BYTE    bPublicKey[64/*псевдомассив*/];
                    /*!< Содержит открытый ключ в сетевом представлении (ASN1 DER). 
                     * Длина массива равна tPublicKeyParam.KeyParam.BitLen/8.
                     */
}   CRYPT_PUBLICKEYBLOB, *PCRYPT_PUBLICKEYBLOB;

/* Определение для структуры CRYPT_PUBLICKEYBLOB:
   Псевдоструктура CRYPT_PRIVATEKEYBLOB полностью описывает ключевой блоб
   типа PRIVATEKEYBLOB. Все поля этой псевдоструктуры выравнены по границе байта
   и находятся в сетевом порядке байт (ASN1 DER). Сетевой порядок байт означает,
   что число 0x12345678 будет записано в виде 0x12 0x34 0x56 0x78 в отличии от
   Intell порядка байт в памяти: 0x78 0x56 0x34 0x12.
 */
typedef struct _CRYPT_PRIVATEKEYBLOB {
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
                    /*!< Общий заголовок ключевого блоба типа PRIVATEKEYBLOB.
                     */
    BYTE    bExportedKeys[1/* Псевдо массив.*/];
	/*
	KeyTransferContent ::=
	SEQUENCE {
	    encryptedPrivateKey  GostR3410EncryptedKey,
	    privateKeyParameters PrivateKeyParameters,
	}
	KeyTransfer ::=
	SEQUENCE {
	    keyTransferContent       KeyTransferContent,
	    hmacKeyTransferContent   Gost28147HMAC
	}
	*/
}   CRYPT_PRIVATEKEYBLOB, *PCRYPT_PRIVATEKEYBLOB;


#pragma pack(push, 1)
//Структура, необходимая для генерации ключа шифрования по ГОСТ 28147-89 для ООО "Валидата"
typedef struct _VD_GEN_SYM_KEY
{
            unsigned char  publ[64]; // открытый ключ получателя
            int ver1;                // версия структуры зашифрованного ключа:если серии
                                     //открытого ключа получателя и отправителя
                                     //совпадают, то ver1 = 1(структура VD_CRYPT_48v1),
                                     //иначе ver1= 0(структура VD_CRYPT_48v2)
            char NumRecv[4];         //номер ключа получателя
            char SerRecv[6];         //серия ключа получателя
            char NumSend[4];         //номер ключа отправителя
            char SerSend[6];         //серия ключа отправителя
} VD_GEN_SYM_KEY, *PVD_GEN_SYM_KEY;

//Структура, необходимая для экспорта ключа шифрования по ГОСТ 28147-89 для ООО "Валидата"
typedef struct _VD_EXP_SYM_KEY
{
            unsigned char  publ[64]; // открытый ключ получателя
            int ver1;                // версия структуры зашифрованного ключа:если серии
                                     //открытого ключа получателя и отправителя
                                     //совпадают, то ver1 = 1(структура VD_CRYPT_48v1),
                                     //иначе ver1= 0(структура VD_CRYPT_48v2)
            char NumRecv[4];         //номер ключа получателя
            char SerRecv[6];         //серия ключа получателя
} VD_EXP_SYM_KEY, *PVD_EXP_SYM_KEY;

//Структура, необходимая для импорта ключа шифрования по ГОСТ 28147-89 для ООО "Валидата"
typedef struct _VD_IMP_SYM_KEY
{
            unsigned char  publ[64]; // открытый ключ отправителя
            int            ver1;     // версия структуры зашифрованного ключа:если серии
                                     //открытого ключа получателя и отправителя
                                     //совпадают, то ver1 = 1(структура VD_CRYPT_48v1),
                                     //иначе ver1= 0(структура VD_CRYPT_48v2)
            unsigned char  S2[8];    //дополнительная синхропосылка №2
            char SerSend[6];         //серия ключа отправителя

} VD_IMP_SYM_KEY, *PVD_IMP_SYM_KEY;


#pragma pack(pop)

#ifdef  __cplusplus
}
#endif
#endif
 