
#ifndef _OSCI_EXTENSION_PKCS11T_H_
#define _OSCI_EXTENSION_PKCS11T_H_ 1

#include "pkcs11t.h"
#include "pkcs11_cpalgs.h"

#define SHEX_MAX_SO_PASSWORD_LEN	32

// ����� ��� ������ � ����������� I\A ����������
#define SHEX_IA_INIT_FLAG			0x80600001
#define SHEX_IA_DEFAULT_PIN_FLAG	0x80600002
#define SHEX_IA_PUK_MODE_FLAG		0x80600004
#define SHEX_IA_PUK_EXIST_FLAG		0x80600008

// ����� ��������������� ������� �������� ��� PIN
#define SHEX_PIN_SET_NUMBERS_FLAG	0x80600001
#define SHEX_PIN_SET_UP_CASE_FLAG	0x80600002
#define SHEX_PIN_SET_LOW_CASE_FLAG	0x80600004
#define SHEX_PIN_SET_SPECIAL_FLAG	0x80600008

// �������������� ������ ��������
#define SHEX_CKO_LOG_FILE					0x80005401

// �������������� �������������� ����������
#define SH_CKM_PKCS1_SIMPLE_BLOB_WRAP_KEY	0x4003
#define SHEX_CKM_GR3410EL_WRAP				0x8060C105

// �������������� ��������
#define SH_CKA_G28147_KEY_MESHING		    0x4304
// ���� ������� �������� ��� ����������� ������������� � �����������������,
// ����� ���������� ����� PKCS #11 �������� ��� ��������� ���������� ��� ������
// � Windows ����� Crypto API
#define CKA_SH_CONTAINER					0x80005417
// �������� ������� ���� CKO_LOG_FILE, ���������� ������� ����� ����� ����� �������
#define SHEX_CKA_EOF_POSITION				0x80005418

// ��������� ��� ��������� SHEX_CKM_GR3410EL_WRAP
typedef struct _SHEX_CK_GR3410EL_WRAP_PARAMS
{	CK_CP_G28147_WRAP_TYPE		wa; // ����� ���� CKD_CP_G28147_WRAP_SIMPLE ��� CKD_CP_G28147_WRAP_PRO.
	CK_GR3410_VKO_DERIVE_PARAMS	VKO;
}SHEX_CK_GR3410EL_WRAP_PARAMS, *SHEX_CK_GR3410EL_WRAP_PARAMS_PTR;

// ��������� ��� ��������� ������������� ���������� ��������, ������� ����� ������� � OSCI-����������
typedef struct _SHEX_DEVICE_PROPERTY
{	CK_ULONG	ulObjectCount;
	CK_ULONG	ulCertX509Count;
	CK_ULONG	ulSecretKeyCount;
	CK_ULONG	ulKeyPairCount;
} SHEX_EX_DEVICE_PROPERTY, CK_PTR SHEX_EX_DEVICE_PROPERTY_PTR;

// ��������� ��� ��������� �������������� ���������� � ���� � �������� ����������
typedef struct _SHEX_DEVICE_FIRMWARE_INFO
{	CK_UTF8CHAR	model[16];			// ������ ����������
	CK_VERSION	firmwareVersion;	// ������ ��������
	CK_VERSION	xilinxVersion;		// ������ xilinx (������ ��� �������)
} SHEX_DEVICE_FIRMWARE_INFO, CK_PTR SHEX_DEVICE_FIRMWARE_INFO_PTR;

// ��������� PIN ����������
typedef struct _SHEX_DEVICE_PIN_PARAMS
{	CK_ULONG	ulStructVersion;				// ������ ���������
	CK_ULONG	ulPinMinLen;
	CK_ULONG	ulPinMaxLen;
	CK_ULONG	ulPinAlphabetSet;
	CK_ULONG	ulPinMaxWrongAttemps;
} SHEX_DEVICE_PIN_PARAMS, CK_PTR SHEX_DEVICE_PIN_PARAMS_PTR;

// ��������� PUK ����������
typedef struct _SHEX_DEVICE_PUK_PARAMS
{	CK_ULONG	ulStructVersion;				// ������ ���������
	CK_ULONG	ulPukLen;
	CK_ULONG	ulPukMaxWrongAttemps;
} SHEX_DEVICE_PUK_PARAMS, CK_PTR SHEX_DEVICE_PUK_PARAMS_PTR;

// ��������� ����������� ����������
typedef struct _SHEX_DEVICE_IA_PARAMETERS
{	CK_ULONG	ulStructVersion;				// ������ ���������
	CK_ULONG	ulRemainInvalidPinAttempts;
	CK_BBOOL	blPukMode;						// TRUE, ���� ���������� ���������������� � ������ ������ � PUK
	CK_BBOOL	blNeedCreatePuk;				// TRUE, ���� ���������� ��������������� ���������� ��� ��������� PUK
} SHEX_DEVICE_IA_PARAMETERS, CK_PTR SHEX_DEVICE_IA_PARAMETERS_PTR;

// ������ ��������������
typedef struct _SHEX_SO_PASSWORD
{	char		pcPswValue[SHEX_MAX_SO_PASSWORD_LEN];
	CK_ULONG	ulPswLength;
} SHEX_SO_PASSWORD, CK_PTR SHEX_SO_PASSWORD_PTR;

// ��������� ������������� ���������� I\A
typedef struct _SHEX_IA_PARAMS
{	SHEX_DEVICE_PIN_PARAMS	PINParams;
	SHEX_DEVICE_PUK_PARAMS	PUKParams;
	SHEX_SO_PASSWORD		SOPassword;
	CK_BBOOL				blLockParams;
	CK_ULONG				ulFlags;
} SHEX_IA_PARAMS, CK_PTR PSHEX_IA_PARAMS_PTR;

// ���������� ���������� ��� ��������� ������ ������� ����������
typedef struct _CK_SHEX_FUNCTION_LIST CK_SHEX_FUNCTION_LIST;
typedef CK_SHEX_FUNCTION_LIST CK_PTR CK_SHEX_FUNCTION_LIST_PTR;
typedef CK_SHEX_FUNCTION_LIST_PTR CK_PTR CK_SHEX_FUNCTION_LIST_PTR_PTR;

/*OID for HASH*/
#define OID_Hash_Prefix		"1.2.643.2.2.30"
#define OID_HashTest		"1.2.643.2.2.30.0"
#define OID_HASH_TEST		"1.2.643.2.2.30.0"
#define OID_HashVerbaO		"1.2.643.2.2.30.1"	/* ���� � 34.11-94, ��������� �� ��������� */
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
#define OID_CipherVerbaO	"1.2.643.2.2.31.1"	/* ���� 28147-89, ��������� �� ��������� */
#define OID_CRYPT_A			"1.2.643.2.2.31.1"
#define OID_CipherVar_1		"1.2.643.2.2.31.2"	/* ���� 28147-89, ��������� ���������� 1 */
#define OID_CRYPT_B			"1.2.643.2.2.31.2"
#define OID_CipherVar_2		"1.2.643.2.2.31.3" 	/* ���� 28147-89, ��������� ���������� 2 */
#define OID_CRYPT_C			"1.2.643.2.2.31.3"
#define OID_CipherVar_3		"1.2.643.2.2.31.4"	/* ���� 28147-89, ��������� ���������� 3 */
#define OID_CRYPT_D			"1.2.643.2.2.31.4"
#define OID_CipherVar_Default OID_CipherVerbaO
#define OID_CipherOSCAR		"1.2.643.2.2.31.5"	/* ���� 28147-89, ��������� ����� 1.1 */
#define OID_CRYPT_OSCAR_1_1	"1.2.643.2.2.31.5"
#define OID_CipherTestHash	"1.2.643.2.2.31.6"	/* ���� 28147-89, ��������� ����� 1.0 */
#define OID_CRYPT_OSCAR_1_0	"1.2.643.2.2.31.6"
#define OID_CipherRIC1		"1.2.643.2.2.31.7"	/* ���� 28147-89, ��������� ��� 1 */
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
  #define OID_ECCTest3410	"1.2.643.2.2.35.0"      /* ���� � 34.10-2001, �������� ��������� */
  #define OID_EC_Test		"1.2.643.2.2.35.0"      /*� RFC 4357 ���� OID ������ ��� test.*/
#endif

#ifndef OID_ECCSignDHPRO
  #define OID_ECCSignDHPRO	"1.2.643.2.2.35.1"	/* ���� � 34.10-2001, ��������� �� ��������� */
  #define OID_EC_A			"1.2.643.2.2.35.1"	/*� RFC 4357 ���� OID ������ ��� �������� A.*/
#endif

#ifndef OID_ECCSignDHOSCAR
  #define OID_ECCSignDHOSCAR	"1.2.643.2.2.35.2"	/* ���� � 34.10-2001, ��������� ����� 2.x */
  #define OID_EC_B				"1.2.643.2.2.35.2"	/*� RFC 4357 ���� OID ������ ��� �������� B.*/
#endif

#ifndef OID_ECCSignDHVar_1
  #define OID_ECCSignDHVar_1	"1.2.643.2.2.35.3"	/* ���� � 34.10-2001, ��������� ������� 1 */
  #define OID_EC_C				"1.2.643.2.2.35.3"	/*� RFC 4357 ���� OID ������ ��� �������� C.*/
#endif

#endif