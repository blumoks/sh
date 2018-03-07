#ifndef DEFINES_AND_CONSTANTS_H
#define DEFINES_AND_CONSTANTS_H

#include "platform.h"
#include "Cryptoki.h"
#include "OSCI_ExtensionPkcs11.h"

#define DLL_USAGE __declspec(dllexport)

typedef struct _MY_DEVICE_INFO {
	CK_CHAR				cDeviceID [10];	//8 numbers+'\0'
	CK_ULONG			ulFlags;
	CK_UTF8CHAR			cDeviceType [16];
	CK_ULONG            ulMaxPinLen;           
	CK_ULONG            ulMinPinLen;
}MY_DEVICE_INFO,*MY_DEVICE_INFO_PTR;

typedef struct _MY_PIN_PARAMS {
	CK_CHAR				pcPinValue [32];
	CK_ULONG			ulPinLength;
}MY_PIN_PARAMS, *MY_PIN_PARAMS_PTR;

typedef struct _MY_KEY_TEMPLATE_INFO {
	CK_ULONG			ulNumOfParams;
	CK_ATTRIBUTE_PTR	psKeyParams;
} MY_KEY_TEMPLATE_INFO, *MY_KEY_TEMPLATE_INFO_PTR;

typedef struct _MY_KEY_INFO {
	_MY_KEY_INFO(){};
	CK_BYTE				pbKeyId[32];		//cka_id
	CK_ULONG			ulKeyIdLen;			//cka_id_len
	CK_KEY_TYPE			ulKeyType;			//rc2/des/3des/gost/rsa
	CK_ULONG			ulKeyTypeLen;	
	CK_OBJECT_CLASS		ulKeyClass;			//secret/public/private
	CK_ULONG			ulKeyClassLen;	
	CK_ULONG			ulKeyLen;			//key len
	CK_ULONG			ulKeyLenLen;	
	CK_BBOOL			bExportable;
	CK_ULONG			ulExportableLen;	
	CK_BYTE 			pbLabel[128];
	CK_ULONG			ulLabelLen;			//label_len
} MY_KEY_INFO, *MY_KEY_INFO_PTR;


#define DEVICE_NOT_INITIALIZED	(0x00000001)
#define DEVICE_NOT_FORMATED		(0x00000002)
#define PIN_NOT_SETTED			(0x00000004)
#define PUK_NOT_SETTED			(0x00000008)
#define PUK_NOT_REQUIRED		(0x00000010)
#define PIN_BLOCKED				(0x00000020)
#define PUK_BLOCKED				(0x00000040)

#define SHIPKA_1_6				("SHIPKA-1.6")
#define SHIPKA_2_0				("SHIPKA-2.0")
#define SHIPKA_LITE				("SHIPKA-lite")
#define ACCORD_U				("ACCORD")

#define DEVICE_ID_LEN			(8)

#define CKA_WRAPPED_KEY			(0x80000001)
#define CKA_ENCRYPTED_DATA		(0x80000002)
#define CKA_SIGNATURE			(0x80000003)

#define NOT_ENOUGH_MEMORY		(0x80000300)
#define PUK_INVALID_LENGTH		(0x80000301)
#define PUK_INVALID_VALUE		(0x80000302)
#define CKR_PUK_NOT_SETTED		(0x80000303)
#define CKR_DEVICE_BLOCKED		(0x80000304)
#define CKR_DEVICE_NOT_BLOCKED	(0x80000305)
#define AUTH_PARAMS_NOT_SETTED	(0x80000306)
#define DIFFERENT_PINS			(0x80000307)
#define PIN_NOT_ENTERED			(0x80000308)
#define MEMORY_NOT_ALLOCATED	(0x80000309)
#define CKR_KEYS_NOT_FOUND		(0x80000310)
#define CKR_TOO_MANY_KEYS_FOUND	(0x80000311)
#define CKR_ATTRIBUTE_NOT_FOUND	(0x80000312)
#define CKR_FILE_ERROR			(0x80000313)
#define CKR_CLASS_WASNT_INITED	(0x80000314)
#define CKR_CLASS_WASNT_CLEARED	(0x80000315)
#define CKR_DEVICE_WASNT_INITED	(0x80000316)
#define CKR_WRONG_INPUT			(0x80000317)
#define CKR_SHIPKA_NOT_SUPPORTED (0x80000318)

#define SHIPKA_LITE_DEFAULT_PIN	((CK_UTF8CHAR_PTR)"OKBSAPR_")

#define CHANGE_DEVICE_PIN		("ChangePIN")
#define UNBLOCK_DEVICE			("Unblock")
#define FORMAT_DEVICE			("Format")
#define GET_DEVICE_INFO			("GetDeviceInfo")
#define GET_DEVICE_LIST			("GetDeviceList")
#define CHANGE_LANGUAGE			("ChangeLanguage")
#define GEN_SEC_KEY				("GenerateKey")
#define GEN_KEY_PAIR			("GeneratePair")
#define DELETE_KEYS				("DeleteKeys")
#define GET_KEYS_LIST			("GetKeysList")
#define EXPORT_PUBLIC_KEY		("ExportPubKey")
#define EXPORT_SEC_PRI_KEY		("ExportKey")
#define EXPORT_PUBKEY_TO_FILE	("ExportPubKeyToFile")
#define EXPORT_KEY_TO_FILE		("ExportKeyToFile")
#define IMPORT_PUBKEY_FROM_FILE	("ImportPubKeyFromFile")
#define IMPORT_KEY_FROM_FILE	("ImportKeyFromFile")

#define READABLE_INFO			("-more")

#define SECRET_KEY				("SecretKey")
#define PUBLIC_KEY				("PublicKey")
#define PRIVATE_KEY				("PrivateKey")
#define TRUE_ATTR				("True")
#define FALSE_ATTR				("False")
#define RSA						("Rsa")
#define GR3410EL				("ShipkaGostPair")
#define G28147					("ShipkaGostSecret")
#define GOST28147				("Gost28147")
#define GOST3410				("Gost3410")
#define DES3					("Des3")
#define RC2						("Rc2")
#define KEY_TYPE_PARAM			("Type=")
#define KEY_CLASS_PARAM			("Class=")
#define CKA_ID_PARAM			("CkaId=")
#define NOT_EXPORTABLE_PARAM	("Ext=")
#define LEN_PARAM				("Len=")
#define LABEL_PARAM				("Label=")


#define DEF_KEY_ATTRS_NUM		(0x06)
const PCHAR DEF_KEY_ATTRS[DEF_KEY_ATTRS_NUM] =		{KEY_TYPE_PARAM,	KEY_CLASS_PARAM,	CKA_ID_PARAM,	NOT_EXPORTABLE_PARAM,	LEN_PARAM,			LABEL_PARAM};
const CK_ULONG DEF_ATTR_VALUES[DEF_KEY_ATTRS_NUM] = {CKA_KEY_TYPE,		CKA_CLASS,			CKA_ID,			CKA_EXTRACTABLE,		CKA_MODULUS_BITS,	CKA_LABEL};

#define DEF_NUM_OF_ALGS			(0x07)
const PCHAR DEF_ALG_TYPES_NAMES[DEF_NUM_OF_ALGS] =	{RSA,		GR3410EL,		G28147,		DES3,		RC2,		GOST28147,		GOST3410};
const CK_ULONG DEF_ALG_TYPES[DEF_NUM_OF_ALGS] =		{CKK_RSA,	CKK_GR3410EL,	CKK_G28147,	CKK_DES3,	CKK_RC2,	CKK_GOST28147,	CKK_GOSTR3410};

#define DEF_NUM_OF_CLASSES		(0x03)
const PCHAR DEF_CLASS_NAME[DEF_NUM_OF_CLASSES] =	 {SECRET_KEY,		PUBLIC_KEY,		PRIVATE_KEY};
const CK_ULONG DEF_CLASS_VALUE[DEF_NUM_OF_CLASSES] = {CKO_SECRET_KEY,	CKO_PUBLIC_KEY,	CKO_PRIVATE_KEY};

#endif