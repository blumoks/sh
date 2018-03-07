#ifndef _PKCS11_CPALGS_H_
#define _PKCS11_CPALGS_H_

#pragma pack(push, pkcs11_cpalgs, 1)

/* Новые типы объектов Этот раздел содержит дополнения к разделу 9.4 [3] */
/* Дополнительно определяются следующие типы ключей: */
#define CKK_GR3410EL                           0x80504301 
#define CKK_G28147                             0x80504302 

/* Дополнительно определяются следующие типы атрибутов: */
#define CKA_GR3410_PARAMETER_OID               0x80504300 
#define CKA_GR3410_CHECK                       0x80504301 
#define CKA_G28147_PARAMETER_OID               0x80504303 
#define CKA_G28147_KEY_MESHING                 0x80504304
/* Дополнительные атрибуты для Валидаты */
#define CKA_VD_S2								0x4503
#define CKA_VD_SERSEND							0x4505

/* Новые типы данных для механизмов 
   Этот раздел содержит дополнения к разделу 9.5 [3]. 
   Дополнительно определяются следующие типы механизмов: */ 
#define CKM_GR3410EL_KEY_PAIR_GEN              0x80504300 
#define CKM_GR3410EL                           0x80504301 
#define CKM_GR3410EL_GR3411                    0x80504302 
#define CKM_GR3410EL_DERIVE                    0x80504303 
#define CKM_GR3411                             0x80504308 
#define CKM_GR3411_HMAC                        0x80504309 
#define CKM_GR3411_HMAC_GENERAL                0x80504310 
#define CKM_GR3411_KEY_DERIVATION              0x80504311 
#define CKM_G28147_KEY_GEN                     0x80504312 
#define CKM_G28147_ECB                         0x80504313 
#define CKM_G28147_CNT                         0x80504314 
#define CKM_G28147_CFB                         0x80504315 
#define CKM_G28147_MAC                         0x80504316 
#define CKM_G28147_MAC_GENERAL                 0x80504317 
#define CKM_CP_G28147_WRAP                     0x80504318 
#define CKM_CP_G28147_CBC                      0x80504319 
#define CKM_CP_G28147_CBC_PAD                  0x80504320 
#define CKM_CP_G28147_DERIVE                   0x80504321 
#define CKM_CPTLS_PRE_MASTER_KEY_GEN           0x80504322 
#define CKM_CPTLS_MASTER_KEY_DERIVE            0x80504323 
#define CKM_CPTLS_KEY_AND_MAC_DERIVE           0x80504324 
#define CKM_CPTLS_PRF                          0x80504325
// механизмы Вербы 
#define CKM_VD_WRAP								0x4518
#define CKM_VD									0x4502 //шифрование
#define CKM_VD_DERIVE							0x4503

/* Дополнительно определяются следующие типы данных: */
typedef CK_ULONG CK_CP_IV_TYPE;
typedef CK_CP_IV_TYPE CK_PTR CK_CP_IV_TYPE_PTR; 

/* #define CKD_NULL                        0x00000001 */     
#define CKD_CP_IV_RANDOM                   0x00504312     
#define CKD_CP_IV_PARAMS                   0x00504313

typedef CK_ULONG CK_GR3410_VKO_TYPE; 
typedef CK_GR3410_VKO_TYPE CK_PTR CK_GR3410_VKO_TYPE_PTR;

/* #define CKD_NULL                        0x00000001 */     
#define CKD_GR3410EL_VKO                   0x00504322 

typedef struct CK_GR3410_VKO_PARAMS {   
  CK_GR3410_VKO_TYPE kdf;   
  CK_CP_IV_TYPE ivSrc;   
  CK_BYTE iv[8];   
  CK_BYTE_PTR pHashOID;   
  CK_ULONG ulHashOIDLen;   
  CK_BYTE_PTR pPublicData;   
  CK_ULONG ulPublicDataLen; 
} CK_GR3410_VKO_DERIVE_PARAMS, CK_PTR CK_GR3410_VKO_DERIVE_PARAMS_PTR;
typedef CK_GR3410_VKO_PARAMS CK_PTR CK_GR3410_VKO_PARAMS_PTR;


typedef CK_ULONG CK_GR3411_H0_TYPE;
typedef CK_GR3411_H0_TYPE CK_PTR CK_GR3411_H0_TYPE_PTR;     

#define CKD_GR3411_H0_OID                  0x00504331     
#define CKD_GR3411_H0_DIGEST               0x00504332     
#define CKD_GR3411_H0_PARAMS               0x00504333 

typedef struct CK_GR3411_PARAMS {   
  CK_GR3411_H0_TYPE h0Type;   
  CK_BYTE_PTR       pH0;   
  CK_BYTE_PTR       pHashOID;   
  CK_ULONG          ulHashOIDLen; 
} CK_GR3411_PARAMS;
typedef CK_GR3411_PARAMS CK_PTR CK_GR3411_PARAMS_PTR;

typedef struct CK_GR3411_HMAC_PARAMS {   
  CK_MAC_GENERAL_PARAMS mac_General_Params;   
  CK_GR3411_PARAMS gr3411_Params; 
} CK_GR3411_HMAC_PARAMS; 
typedef CK_GR3411_HMAC_PARAMS CK_PTR CK_GR3411_HMAC_PARAMS_PTR;
 
typedef struct CK_G28147_PARAMS {   
  CK_CP_IV_TYPE ivSrc;   
  CK_BYTE iv[8]; 
} CK_G28147_PARAMS; 
typedef CK_G28147_PARAMS CK_PTR CK_G28147_PARAMS_PTR;

typedef struct CK_G28147_MAC_PARAMS {   
  CK_G28147_PARAMS g28147_Params;   
  CK_MAC_GENERAL_PARAMS mac_General_Params; 
} CK_G28147_MAC_PARAMS; 
typedef CK_G28147_MAC_PARAMS CK_PTR CK_G28147_MAC_PARAMS_PTR;

typedef CK_ULONG CK_CP_G28147_WRAP_TYPE;
typedef CK_CP_G28147_WRAP_TYPE CK_PTR CK_CP_G28147_WRAP_TYPE_PTR;

#define CKD_CP_G28147_WRAP_PRO             0x00504341     
#define CKD_CP_G28147_WRAP_SIMPLE          0x00504342 

// идентификаторы режима импорта/экспорта для того, чтобы можно было использовать устаревший
// механизм импорта/экспорта (прошивки до 44.62, не включая 44.62) на устройствах с прошивками
// от 44.62 включительно.
#define CKD_CP_G28147_WRAP_PRO_OBSOLETE             0x00504343     
#define CKD_CP_G28147_WRAP_SIMPLE_OBSOLETE          0x00504344 

typedef CK_ULONG CK_CP_G28147_MASK_TYPE;
typedef CK_CP_G28147_MASK_TYPE CK_PTR CK_CP_G28147_MASK_TYPE_PTR;

/* #define CKD_NULL                        0x00000001 */     
#define CKD_CP_G28147_MULTIPLE             0x00504352 
typedef struct CK_CP_G28147_WRAP_PARAMS {   
  CK_CP_G28147_WRAP_TYPE wa;   
  CK_CP_G28147_MASK_TYPE mt;   
  CK_G28147_PARAMS g28147_Params; 
} CK_CP_G28147_WRAP_PARAMS; 
typedef CK_CP_G28147_WRAP_PARAMS CK_PTR CK_CP_G28147_WRAP_PARAMS_PTR;

typedef CK_ULONG CK_CP_G28147_DERIVE_TYPE; 
typedef CK_CP_G28147_DERIVE_TYPE CK_PTR CK_CP_G28147_DERIVE_TYPE_PTR;

#define CKD_CP_G28147_DERIVE               0x00504361     
#define CKD_CP_G28147_DERIVE_OSCAR         0x00504362     
#define CKD_CP_G28147_DERIVE_GR3411_XI     0x00504363 

typedef struct CK_CP_G28147_DERIVE_PARAMS {   
  CK_CP_G28147_DERIVE_TYPE da;   
  CK_BYTE_PTR pData;   
  CK_ULONG ulLen; 
} CK_CP_G28147_DERIVE_PARAMS; 
typedef CK_CP_G28147_DERIVE_PARAMS CK_PTR CK_CP_G28147_DERIVE_PARAMS_PTR;

typedef struct CK_CPTLS_PRF_PARAMS {   
  CK_BYTE_PTR  pSeed;   
  CK_ULONG     ulSeedLen;   
  CK_BYTE_PTR  pLabel;   
  CK_ULONG     ulLabelLen;   
  CK_BYTE_PTR  pOutput;   
  CK_ULONG_PTR pulOutputLen;   
  CK_BYTE_PTR  pHashOID;   
  CK_ULONG     ulHashOIDLen; 
} CK_CPTLS_PRF_PARAMS;
typedef CK_CPTLS_PRF_PARAMS CK_PTR CK_CPTLS_PRF_PARAMS_PTR;

typedef struct CK_CPTLS_MASTER_KEY_DERIVE_PARAMS {   
  CK_SSL3_RANDOM_DATA RandomInfo;   
  CK_VERSION_PTR      pVersion;   
  CK_BYTE_PTR         pHashOID;   
  CK_ULONG            ulHashOIDLen; 
} CK_CPTLS_MASTER_KEY_DERIVE_PARAMS;
typedef CK_CPTLS_MASTER_KEY_DERIVE_PARAMS CK_PTR CK_CPTLS_MASTER_KEY_DERIVE_PARAMS_PTR;

typedef struct CK_CPTLS_KEY_MAT_PARAMS {   
  CK_ULONG                ulMacSizeInBits;   
  CK_ULONG                ulKeySizeInBits;   
  CK_ULONG                ulIVSizeInBits;   
  CK_BYTE_PTR             pHashOID;   
  CK_ULONG                ulHashOIDLen;   
  CK_SSL3_RANDOM_DATA     RandomInfo;   
  CK_SSL3_KEY_MAT_OUT_PTR pReturnedKeyMaterial; 
} CK_CPTLS_KEY_MAT_PARAMS; 
typedef CK_CPTLS_KEY_MAT_PARAMS CK_PTR CK_CPTLS_KEY_MAT_PARAMS_PTR;

//////////////// параметры механизмов Вербы /////////////////////////
typedef struct _VD_GEN_SYM_KEY
{
	unsigned char  publ[64]; // открытый ключ получателя
	int ver1;                // версия структуры зашифрованного ключа:если серии 
                             // открытого ключа получателя и отправителя совпадают, то 
                             //ver1 = 1(структура VD_CRYPT_48v1), иначе ver1= 0
                             //(структура VD_CRYPT_48v2)
	char NumResv[4];         //номер ключа получателя     
    char SerResv[6];         //серия ключа получателя
    char NumSend[4];         //номер ключа отправителя     
    char SerSend[6];         //серия ключа отправителя
} VD_GEN_SYM_KEY, *PVD_GEN_SYM_KEY;

typedef struct _VD_EXP_SYM_KEY
{
	unsigned char  publ[64];// открытый ключ получателя
	int ver1;				// версия структуры зашифрованного ключа:если серии 
							// открытого ключа получателя и отправителя совпадают, то 
							//ver1 = 1(структура VD_CRYPT_48v1), иначе ver1= 0
							//(структура VD_CRYPT_48v2)
	char NumResv[4];		//номер ключа получателя     
	char SerResv[6];		//серия ключа получателя
} VD_EXP_SYM_KEY, *PVD_EXP_SYM_KEY;

typedef struct _VD_IMP_SYM_KEY
{
	unsigned char  pub_key[64];	// открытый ключ отправителя
	int ver1;					// версия структуры зашифрованного ключа:если серии 
								// открытого ключа получателя и отправителя совпадают, то 
								//ver1 = 1(структура VD_CRYPT_48v1), иначе ver1= 0
								//(структура VD_CRYPT_48v2)
   unsigned char  S2[8];		// Дополнительная синхропосылка №2         
} VD_IMP_SYM_KEY, *PVD_IMP_SYM_KEY;


#pragma pack(pop, pkcs11_cpalgs)

#endif
