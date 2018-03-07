#ifndef ACCAPI_H
#define ACCAPI_H
#ifdef  __cplusplus
extern "C" {
#endif

/*��� ����������������*/
#define ACCSP_NAME  "Shipka Base Cryptographic Provider"
#define ACCSP_GOST2001_NAME  "Shipka Base Cryptographic Provider GOST2001"

/*��� ���������������� ����*/
#define PROV_GOST_2001_DH 75

/* ��� ���������� �� ���������*/
#define SHIPKA_DEFCONT_NAME "DefaultKeys"
/* �������������� �������� ��� ������ */
#define KP_USER_NAME    42
#define KP_USER_POST    43
#define KP_SHIP_NAME    44


#define CRYPT_NOTEXPORT 0x0200  // ������ ���� ����������������


/* ��������, ������� ����� ���������� � �������� dwParam � ������� CryptGetProvParam,
/* ��� ���� ���� �� ������ ��������:
                             /* pdwDataLen - ����� ��������� ������ �����,
                             /* pbData - �������� ����� �����.*/
#define PP_SHIPKA_SER_NUM       41

// dwFlags ��� CryptAcquireContext, ���� ������������ ����� �������� ������ � ��������
#define CRYPT_ACCORD            0x00000200
// dwFlags ��� CryptAcquireContext, ���� ������������ ����� �������� ������ � ������
#define CRYPT_SHIPKA            0x00000400

/* ��������� ���������������� ������ */
/* Algorithm types */
#define ALG_TYPE_GR3410				(7 << 9)
/* GR3411 sub-id */
#define ALG_SID_GR3411				30
/* G28147 sub_id */
#define ALG_SID_G28147				30

/* Export Key sub_id */
#define ALG_SID_PRO_EXP				31
#define ALG_SID_SIMPLE_EXP			32
//��� �������� ����� 44.57
#define ALG_SID_PRO_EXP_OBSOLETE	       	33
#define ALG_SID_SIMPLE_EXP_OBSOLETE		34

/* Hash sub ids */
#define ALG_SID_G28147_MAC			31
#define ALG_SID_GR3410EL			35
/* GOST_DH sub ids */
#define ALG_SID_GR3410EL			35
#define ALG_SID_DH_EL_SF			36
#define ALG_SID_DH_EL_EPHEM			37
/* G28147_VD sub_id (��� ��� "��������") */
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

//�������������� ���������, ������� �������������� � ��������� ����� 44.57
#define CALG_PRO_EXPORT_OBSOLETE (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRO_EXP_OBSOLETE)

#define CALG_SIMPLE_EXPORT_OBSOLETE (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SIMPLE_EXP_OBSOLETE)


#define CRYPT_ALG_PARAM_OID_GROUP_ID            20       \

//�������� ��������� ������������� ����� ���������� �� ���� 28147-89 ��� ��� "��������"
#define CALG_G28147_VD (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_G28147_VD)

//���� ��� ��������/������� ����� ���������� �� ���� 28147-89 ��� ��� "��������"
#define SIMPLEBLOB_VD                           0x2

/* ��������� � ��������� ��� ���� �������� ������� � */
/* ��������� ������������� ������ */

/* ������� ������ ���� � 34.10-2001 */
#define GR3410_1_MAGIC			        0x3147414D
/* ������� ������ ���� 28147-89 */
#define G28147_MAGIC			        0x374a51fd

#define SECRET_KEY_LEN 				32
#define G28147_KEYLEN 				SECRET_KEY_LEN
#define SEANCE_VECTOR_LEN			8

/* ����������� ����� OID */
#define OID_MAX_LEN                             18

/* ����� ���������� "������������" �� ���� 28147-89.*/
#define CRYPT_MODE_CNT          CRYPT_MODE_OFB

/* �������������� ��������� ���������������� */
#define PP_LAST_ERROR 90
#define PP_ENUMOIDS_EX 91
#define PP_HASHOID 92
#define PP_CIPHEROID 93
#define PP_SIGNATUREOID 94
#define PP_DHOID 95

#define PP_ST_GEN_VD 96 //��� ���������/��������� ���������� ��������� ����� ���������� �� ���� 28147-89 ��� ��� "��������"
#define PP_ST_IMP_VD 98 //��� ������� ����� ���������� �� ���� 28147-89 ��� ��� "��������"

#define PP_ENUM_HASHOID 103
#define PP_ENUM_CIPHEROID 104
#define PP_ENUM_SIGNATUREOID 105
#define PP_ENUM_DHOID	106

/* �������������� ��������� ������� ���� */
#define HP_HASHSTARTVECT        0x0008
#define HP_HASHCOPYVAL	        0x0009
#define HP_OID                  0x000a
#define HP_OPEN                 0x000B
#define HP_OPAQUEBLOB           0x000C

/* �������������� ��������� ����� */
#define KP_OID                  102
#define KP_HASHOID              103
#define KP_CIPHEROID            104
#define KP_SIGNATUREOID         105
#define KP_DHOID                106
#define KP_CKA_ID               107

#define KP_ST_EXP_VD 97 //��� �������� ����� ���������� �� ���� 28147-89 ��� ��� "��������"

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
#define OID_HashVerbaO "1.2.643.2.2.30.1"	/* ���� � 34.11-94, ��������� �� ��������� */
#define OID_HashVar_1 "1.2.643.2.2.30.2"
#define OID_HashVar_2 "1.2.643.2.2.30.3"
#define OID_HashVar_3 "1.2.643.2.2.30.4"
#define OID_HashVar_Default OID_HashVerbaO


/* OID for Crypt */
#define OID_CryptTest "1.2.643.2.2.31.0"
#define OID_CipherVerbaO "1.2.643.2.2.31.1"	/* ���� 28147-89, ��������� �� ��������� */
#define OID_CipherVar_1 "1.2.643.2.2.31.2"	/* ���� 28147-89, ��������� ���������� 1 */
#define OID_CipherVar_2 "1.2.643.2.2.31.3" 	/* ���� 28147-89, ��������� ���������� 2 */
#define OID_CipherVar_3 "1.2.643.2.2.31.4"	/* ���� 28147-89, ��������� ���������� 3 */
#define OID_CipherVar_Default OID_CipherVerbaO
#define OID_CipherOSCAR "1.2.643.2.2.31.5"	/* ���� 28147-89, ��������� ����� 1.1 */
#define OID_CipherTestHash "1.2.643.2.2.31.6"	/* ���� 28147-89, ��������� ����� 1.0 */
#define OID_CipherRIC1 "1.2.643.2.2.31.7"	/* ���� 28147-89, ��������� ��� 1 */


/* OID ��� ������� �� ���� 2001*/
#define OID_EC_A "1.2.643.2.2.35.1"
#define OID_EC_B "1.2.643.2.2.35.2"
#define OID_EC_C "1.2.643.2.2.35.3"

/* OID for DH 1024*/
#define OID_DH128Var_1   "1.2.643.2.2.33.1"
#define OID_DH128Var_2   "1.2.643.2.2.33.2"
#define OID_DH128Var_3   "1.2.643.2.2.33.3"

/*����� � ������ ������������ ��� �������/��������*/
#define EXPORT_IMIT_SIZE		4

/* ����������� ��� ��������� SIMPLEBLOB */
typedef struct CRYPT_SIMPLEBLOB_HEADER_ {
    BLOBHEADER BlobHeader;
                    /* ����� ��������� ��������� �����. ���������� �������� �����
                     * ������������ � �������� �����. ��. PUBLICKEYSTRUC.
                     */
    DWORD Magic;    /*������� ������ �� ���� 28147-89, ��������������� � G28147_MAGIC.
                     */
    ALG_ID EncryptKeyAlgId;
                    /*���������� �������� �������� �����. ���� �������� ��������
                     * ���������� ����� ��������. ��. CPGetKeyParam.
                     */
} CRYPT_SIMPLEBLOB_HEADER;

typedef struct CRYPT_SIMPLEBLOB_ {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
                    /*����� ��������� ��������� ����� ���� SIMPLEBLOB.
                     */
    BYTE    bSV[SEANCE_VECTOR_LEN];
                    /*��������� ������. ��������� � ���������� ������������ ���
					/*������������� ��������� CALG_PRO_EXPORT.
                     */
    BYTE    bEncryptedKey[1/*������������*/];
                    /* ������������� ���� ���� 28147-89.
                    /* ������ ������� G28147_KEYLEN
                     */
    BYTE    bMacKey[EXPORT_IMIT_SIZE];
	            /* ������������
	            */
    BYTE    bEncryptionParamSet[1/*������������*/];
	            /* ��������� ���������� ���������� ���� 28147-89
		    */
}   CRYPT_SIMPLEBLOB, *PCRYPT_SIMPLEBLOB;


/* ����������� ��� ��������� CRYPT_PUBKEYPARAM:
   ��������� CRYPT_PUBKEYPARAM �������� ������� ������
   �� ���� � 34.10-2001.
*/
typedef struct _CRYPT_PUBKEYPARAM_ {
    DWORD Magic;    /*������� ������ �� ���� � 34.10-2001
                     * ��������������� � GR3410_1_MAGIC.
                     */
    DWORD BitLen;   /*����� ��������� ����� � �����.
                     */
} CRYPT_PUBKEYPARAM, *LPCRYPT_PUBKEYPARAM;

/* ����������� ��� ��������� CRYPT_PUBKEY_INFO_HEADER:
*/
typedef struct CRYPT_PUBKEY_INFO_HEADER_ {
    BLOBHEADER BlobHeader;
                    /*!< ����� ��������� ��������� �����. ���������� ��� ��� � �������� �����
                     * ������������ � �������� �����. ��� �������� ������ �������� 
                     * ����� ������ CALG_GR3410EL. ��� �������� 
                     * ��� �������� �������� � ����������. ��. \ref _PUBLICKEYSTRUC.
                     */
    CRYPT_PUBKEYPARAM KeyParam;
                    /*!< �������� ������� � ������ ������ ���� � 34.10-2001.
                     */
} CRYPT_PUBKEY_INFO_HEADER;

/* ����������� ��� ��������� CRYPT_PUBLICKEYBLOB:
  ��������������� CRYPT_PUBLICKEYBLOB ��������� ��������� �������� ����
  ���� PUBLICKEYBLOB. ��� ���� ���� ���������������  ��������� �� ������� �����
  � ��������� � ������� ������� ���� (ASN1 DER). ������� ������� ���� ��������,
  ��� ����� 0x12345678 ����� �������� � ���� 0x12 0x34 0x56 0x78 � ������� ��
  Intell �������  ���� � ������: 0x78 0x56 0x34 0x12.
*/
typedef struct CRYPT_PUBLICKEYBLOB_ {
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
                    /*!< ����� ��������� ��������� ����� ���� PUBLICKEYBLOB.
                     */
    BYTE    bASN1GostR3410_94_PublicKeyParameters[16/*������������*/];
                    /*!< �������� ���������, ������������ 
                     * ��������� ��������� �����:
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
    BYTE    bPublicKey[64/*������������*/];
                    /*!< �������� �������� ���� � ������� ������������� (ASN1 DER). 
                     * ����� ������� ����� tPublicKeyParam.KeyParam.BitLen/8.
                     */
}   CRYPT_PUBLICKEYBLOB, *PCRYPT_PUBLICKEYBLOB;

/* ����������� ��� ��������� CRYPT_PUBLICKEYBLOB:
   ��������������� CRYPT_PRIVATEKEYBLOB ��������� ��������� �������� ����
   ���� PRIVATEKEYBLOB. ��� ���� ���� ��������������� ��������� �� ������� �����
   � ��������� � ������� ������� ���� (ASN1 DER). ������� ������� ���� ��������,
   ��� ����� 0x12345678 ����� �������� � ���� 0x12 0x34 0x56 0x78 � ������� ��
   Intell ������� ���� � ������: 0x78 0x56 0x34 0x12.
 */
typedef struct _CRYPT_PRIVATEKEYBLOB {
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
                    /*!< ����� ��������� ��������� ����� ���� PRIVATEKEYBLOB.
                     */
    BYTE    bExportedKeys[1/* ������ ������.*/];
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
//���������, ����������� ��� ��������� ����� ���������� �� ���� 28147-89 ��� ��� "��������"
typedef struct _VD_GEN_SYM_KEY
{
            unsigned char  publ[64]; // �������� ���� ����������
            int ver1;                // ������ ��������� �������������� �����:���� �����
                                     //��������� ����� ���������� � �����������
                                     //���������, �� ver1 = 1(��������� VD_CRYPT_48v1),
                                     //����� ver1= 0(��������� VD_CRYPT_48v2)
            char NumRecv[4];         //����� ����� ����������
            char SerRecv[6];         //����� ����� ����������
            char NumSend[4];         //����� ����� �����������
            char SerSend[6];         //����� ����� �����������
} VD_GEN_SYM_KEY, *PVD_GEN_SYM_KEY;

//���������, ����������� ��� �������� ����� ���������� �� ���� 28147-89 ��� ��� "��������"
typedef struct _VD_EXP_SYM_KEY
{
            unsigned char  publ[64]; // �������� ���� ����������
            int ver1;                // ������ ��������� �������������� �����:���� �����
                                     //��������� ����� ���������� � �����������
                                     //���������, �� ver1 = 1(��������� VD_CRYPT_48v1),
                                     //����� ver1= 0(��������� VD_CRYPT_48v2)
            char NumRecv[4];         //����� ����� ����������
            char SerRecv[6];         //����� ����� ����������
} VD_EXP_SYM_KEY, *PVD_EXP_SYM_KEY;

//���������, ����������� ��� ������� ����� ���������� �� ���� 28147-89 ��� ��� "��������"
typedef struct _VD_IMP_SYM_KEY
{
            unsigned char  publ[64]; // �������� ���� �����������
            int            ver1;     // ������ ��������� �������������� �����:���� �����
                                     //��������� ����� ���������� � �����������
                                     //���������, �� ver1 = 1(��������� VD_CRYPT_48v1),
                                     //����� ver1= 0(��������� VD_CRYPT_48v2)
            unsigned char  S2[8];    //�������������� ������������� �2
            char SerSend[6];         //����� ����� �����������

} VD_IMP_SYM_KEY, *PVD_IMP_SYM_KEY;


#pragma pack(pop)

#ifdef  __cplusplus
}
#endif
#endif
 