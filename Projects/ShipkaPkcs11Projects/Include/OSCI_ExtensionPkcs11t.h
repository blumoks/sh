
#ifndef _OSCI_EXTENSION_PKCS11T_H_
#define _OSCI_EXTENSION_PKCS11T_H_ 1

#include "pkcs11t.h"
#include "pkcs11_cpalgs.h"

#define SHEX_MAX_SO_PASSWORD_LEN	32

// флаги для работы с подсистемой I\A устройства
#define SHEX_IA_INIT_FLAG			0x80600001
#define SHEX_IA_DEFAULT_PIN_FLAG	0x80600002
#define SHEX_IA_PUK_MODE_FLAG		0x80600004
#define SHEX_IA_PUK_EXIST_FLAG		0x80600008

// флаги идентификаторов наборов алфавита для PIN
#define SHEX_PIN_SET_NUMBERS_FLAG	0x80600001
#define SHEX_PIN_SET_UP_CASE_FLAG	0x80600002
#define SHEX_PIN_SET_LOW_CASE_FLAG	0x80600004
#define SHEX_PIN_SET_SPECIAL_FLAG	0x80600008

// дополнительные классы объектов
#define SHEX_CKO_LOG_FILE					0x80005401

// дополнительные идентификаторы механизмов
#define SH_CKM_PKCS1_SIMPLE_BLOB_WRAP_KEY	0x4003
#define SHEX_CKM_GR3410EL_WRAP				0x8060C105

// дополнительные атрибуты
#define SH_CKA_G28147_KEY_MESHING		    0x4304
// этот атрибут вводится для обеспечения совместимости с криптопровайдером,
// когда необходимо через PKCS #11 получить имя ключевого контейнера для работы
// в Windows через Crypto API
#define CKA_SH_CONTAINER					0x80005417
// атрибуты объекта типа CKO_LOG_FILE, определяет позицию метки конца файла журнала
#define SHEX_CKA_EOF_POSITION				0x80005418

// параметры для механизма SHEX_CKM_GR3410EL_WRAP
typedef struct _SHEX_CK_GR3410EL_WRAP_PARAMS
{	CK_CP_G28147_WRAP_TYPE		wa; // Может быть CKD_CP_G28147_WRAP_SIMPLE или CKD_CP_G28147_WRAP_PRO.
	CK_GR3410_VKO_DERIVE_PARAMS	VKO;
}SHEX_CK_GR3410EL_WRAP_PARAMS, *SHEX_CK_GR3410EL_WRAP_PARAMS_PTR;

// структура для получения максимального количества объектов, которое можно создать в OSCI-устройстве
typedef struct _SHEX_DEVICE_PROPERTY
{	CK_ULONG	ulObjectCount;
	CK_ULONG	ulCertX509Count;
	CK_ULONG	ulSecretKeyCount;
	CK_ULONG	ulKeyPairCount;
} SHEX_EX_DEVICE_PROPERTY, CK_PTR SHEX_EX_DEVICE_PROPERTY_PTR;

// структура для получения дополнительной информации о типе и прошивке устройства
typedef struct _SHEX_DEVICE_FIRMWARE_INFO
{	CK_UTF8CHAR	model[16];			// модель устройства
	CK_VERSION	firmwareVersion;	// версия прошивки
	CK_VERSION	xilinxVersion;		// версия xilinx (только для Аккорда)
} SHEX_DEVICE_FIRMWARE_INFO, CK_PTR SHEX_DEVICE_FIRMWARE_INFO_PTR;

// параметры PIN устройства
typedef struct _SHEX_DEVICE_PIN_PARAMS
{	CK_ULONG	ulStructVersion;				// версия структуры
	CK_ULONG	ulPinMinLen;
	CK_ULONG	ulPinMaxLen;
	CK_ULONG	ulPinAlphabetSet;
	CK_ULONG	ulPinMaxWrongAttemps;
} SHEX_DEVICE_PIN_PARAMS, CK_PTR SHEX_DEVICE_PIN_PARAMS_PTR;

// параметры PUK устройства
typedef struct _SHEX_DEVICE_PUK_PARAMS
{	CK_ULONG	ulStructVersion;				// версия структуры
	CK_ULONG	ulPukLen;
	CK_ULONG	ulPukMaxWrongAttemps;
} SHEX_DEVICE_PUK_PARAMS, CK_PTR SHEX_DEVICE_PUK_PARAMS_PTR;

// параметры авторизации устройства
typedef struct _SHEX_DEVICE_IA_PARAMETERS
{	CK_ULONG	ulStructVersion;				// версия структуры
	CK_ULONG	ulRemainInvalidPinAttempts;
	CK_BBOOL	blPukMode;						// TRUE, если устройство инициализировано в режиме работы с PUK
	CK_BBOOL	blNeedCreatePuk;				// TRUE, если необходимо отформатировать устройство для генерации PUK
} SHEX_DEVICE_IA_PARAMETERS, CK_PTR SHEX_DEVICE_IA_PARAMETERS_PTR;

// пароль администратора
typedef struct _SHEX_SO_PASSWORD
{	char		pcPswValue[SHEX_MAX_SO_PASSWORD_LEN];
	CK_ULONG	ulPswLength;
} SHEX_SO_PASSWORD, CK_PTR SHEX_SO_PASSWORD_PTR;

// параметры инициализации подсистемы I\A
typedef struct _SHEX_IA_PARAMS
{	SHEX_DEVICE_PIN_PARAMS	PINParams;
	SHEX_DEVICE_PUK_PARAMS	PUKParams;
	SHEX_SO_PASSWORD		SOPassword;
	CK_BBOOL				blLockParams;
	CK_ULONG				ulFlags;
} SHEX_IA_PARAMS, CK_PTR PSHEX_IA_PARAMS_PTR;

// определяем переменную для получения списка функций расширения
typedef struct _CK_SHEX_FUNCTION_LIST CK_SHEX_FUNCTION_LIST;
typedef CK_SHEX_FUNCTION_LIST CK_PTR CK_SHEX_FUNCTION_LIST_PTR;
typedef CK_SHEX_FUNCTION_LIST_PTR CK_PTR CK_SHEX_FUNCTION_LIST_PTR_PTR;

/*OID for HASH*/
#define OID_Hash_Prefix		"1.2.643.2.2.30"
#define OID_HashTest		"1.2.643.2.2.30.0"
#define OID_HASH_TEST		"1.2.643.2.2.30.0"
#define OID_HashVerbaO		"1.2.643.2.2.30.1"	/* ГОСТ Р 34.11-94, параметры по умолчанию */
#define OID_HASH_A			"1.2.643.2.2.30.1"
#define OID_HashVar_1		"1.2.643.2.2.30.2"
#define OID_HASH_B			"1.2.643.2.2.30.2"
#define OID_HashVar_2		"1.2.643.2.2.30.3"
#define OID_HASH_C			"1.2.643.2.2.30.3"
#define OID_HashVar_3		"1.2.643.2.2.30.4"
#define OID_HASH_D			"1.2.643.2.2.30.4"
#define OID_HashVar_Default	OID_HashVerbaO

/* OID for Crypt */
#define OID_Crypt_Prefix	"1.2.643.2.2.31"
#define OID_CryptTest		"1.2.643.2.2.31.0"
#define OID_CRYPT_TEST		"1.2.643.2.2.31.0"
#define OID_CipherVerbaO	"1.2.643.2.2.31.1"	/* ГОСТ 28147-89, параметры по умолчанию */
#define OID_CRYPT_A			"1.2.643.2.2.31.1"
#define OID_CipherVar_1		"1.2.643.2.2.31.2"	/* ГОСТ 28147-89, параметры шифрования 1 */
#define OID_CRYPT_B			"1.2.643.2.2.31.2"
#define OID_CipherVar_2		"1.2.643.2.2.31.3" 	/* ГОСТ 28147-89, параметры шифрования 2 */
#define OID_CRYPT_C			"1.2.643.2.2.31.3"
#define OID_CipherVar_3		"1.2.643.2.2.31.4"	/* ГОСТ 28147-89, параметры шифрования 3 */
#define OID_CRYPT_D			"1.2.643.2.2.31.4"
#define OID_CipherVar_Default OID_CipherVerbaO
#define OID_CipherOSCAR		"1.2.643.2.2.31.5"	/* ГОСТ 28147-89, параметры Оскар 1.1 */
#define OID_CRYPT_OSCAR_1_1	"1.2.643.2.2.31.5"
#define OID_CipherTestHash	"1.2.643.2.2.31.6"	/* ГОСТ 28147-89, параметры Оскар 1.0 */
#define OID_CRYPT_OSCAR_1_0	"1.2.643.2.2.31.6"
#define OID_CipherRIC1		"1.2.643.2.2.31.7"	/* ГОСТ 28147-89, параметры РИК 1 */
#define OID_CRYPT_RIC_1		"1.2.643.2.2.31.7"

/* OID for Signature 1024*/
#define OID_EDS_TEST		"1.2.643.2.2.32.0"
#define OID_SignDH128VerbaO	"1.2.643.2.2.32.2" 	/*VerbaO*/
#define OID_EDS_A			"1.2.643.2.2.32.2"
#define OID_Sign128Var_1	"1.2.643.2.2.32.3"
#define OID_EDS_B			"1.2.643.2.2.32.3"
#define OID_Sign128Var_2	"1.2.643.2.2.32.4"
#define OID_EDS_C			"1.2.643.2.2.32.4"
#define OID_Sign128Var_3	"1.2.643.2.2.32.5"
#define OID_EDS_D			"1.2.643.2.2.32.5"

/* OID for DH 1024*/
#define OID_DH128Var_1		"1.2.643.2.2.33.1"
#define OID_DH128Var_2		"1.2.643.2.2.33.2"
#define OID_DH128Var_3		"1.2.643.2.2.33.3"

#ifndef OID_ECCTest3410
  #define OID_ECCTest3410	"1.2.643.2.2.35.0"      /* ГОСТ Р 34.10-2001, тестовые параметры */
  #define OID_EC_Test		"1.2.643.2.2.35.0"      /*В RFC 4357 этот OID описан как test.*/
#endif

#ifndef OID_ECCSignDHPRO
  #define OID_ECCSignDHPRO	"1.2.643.2.2.35.1"	/* ГОСТ Р 34.10-2001, параметры по умолчанию */
  #define OID_EC_A			"1.2.643.2.2.35.1"	/*В RFC 4357 этот OID описан как параметр A.*/
#endif

#ifndef OID_ECCSignDHOSCAR
  #define OID_ECCSignDHOSCAR	"1.2.643.2.2.35.2"	/* ГОСТ Р 34.10-2001, параметры Оскар 2.x */
  #define OID_EC_B				"1.2.643.2.2.35.2"	/*В RFC 4357 этот OID описан как параметр B.*/
#endif

#ifndef OID_ECCSignDHVar_1
  #define OID_ECCSignDHVar_1	"1.2.643.2.2.35.3"	/* ГОСТ Р 34.10-2001, параметры подписи 1 */
  #define OID_EC_C				"1.2.643.2.2.35.3"	/*В RFC 4357 этот OID описан как параметр C.*/
#endif

#endif