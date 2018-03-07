#include "KeyManagment.h"
/**
@page KeyManagment
*/

/**
@brief KeyManagmentClass constructor
*/
KeyManagmentClass::KeyManagmentClass():WorkWithKeysClass()
{
	pbLastExported = NULL;
	ulLastExpLen = 0;
	pbInputParsedData = NULL;
	ulInputParsedDataLen = 0;
};
/**
@brief KeyManagmentClass parametrized constructor
@param pcDeviceID(in) - ID of device we are working with as string
@param sPinParams(in) - parameters of PIN to this device: PIN and its length;
*/
KeyManagmentClass::KeyManagmentClass(char *pcDeviceID, MY_PIN_PARAMS sPinParams):WorkWithKeysClass(pcDeviceID, sPinParams)
{
	pbLastExported = NULL;
	ulLastExpLen = 0;
	pbInputParsedData = NULL;
	ulInputParsedDataLen = 0;
};
/**
@brief KeyManagmentClass destructor
*/
KeyManagmentClass::~KeyManagmentClass()
{
	if (pbLastExported) free (pbLastExported);
	pbLastExported = NULL;
	if (pbInputParsedData) free (pbInputParsedData);
	pbInputParsedData = NULL;
};
//==================================================================================================================
/**
@brief Function to generate secret key
@param sKeyTemplateInfo(in) - Attributes of key to be generated; some attributes will be added automatically;
@param pMechanism(in) - Mechanism of key generation; if NULL then default mechanism for type of key defined in sKeyTemplateInfo will be used;
*/
void KeyManagmentClass::GenerateSecKey(MY_KEY_TEMPLATE_INFO sKeyTemplateInfo, CK_MECHANISM_PTR pMechanism)
{
	MY_KEY_TEMPLATE_INFO	sTempKeyInfo;
	CK_MECHANISM			ckTempMechanism;
	CK_ULONG				ulAttrCounter;

	const CK_BYTE params_oid[] = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01};
	CK_BYTE	pbRandomId [4];
	//Default attributes to be setted:			iCounter:
	//CKA_KEY_TYPE - SettedByUser				0
	//CKA_CLASS = CKO_SECRET_KEY				1
	//CKA_EXTRACTABLE = CK_TRUE					2
	//CKA_MODIFIABLE = CK_FALSE					3
	//CKA_ENCRYPT = CK_TRUE						4
	//CKA_DECRYPT = CK_TRUE						5
	//CKA_TOKEN = CK_TRUE						6
	//CKA_ID = RANDOM							7
	//for RC2: CKA_VALUE_LEN = 40				8
	//for GOST_OKB: CKA_OBJECT_ID = CKK_G28147; 9
	//SH_CKA_G28147_KEY_MESHING = CK_TRUE		10
	//for GOST_2: CKA_GOST28147_PARAMS			11
	const CK_ULONG ulNumOfDefAttrs = 12;
	const CK_ULONG ulG28147AttrsNum = ulNumOfDefAttrs-2;
	const CK_ULONG ulGost28147AttrsNum = ulNumOfDefAttrs-3;
	const CK_ULONG ulRc2AttrsNum = ulNumOfDefAttrs-3;
	const CK_ULONG ulOtherAttrsNum = ulNumOfDefAttrs-4;
	CK_ULONG iDefaultAttrCounters [ulNumOfDefAttrs];		//have 9 default attributes
	int iNumOfDefParams = 0;
	memset(iDefaultAttrCounters,0,ulNumOfDefAttrs * sizeof(CK_ULONG));
 
	//check, if sKeyTemplateInfo is OK and find all values of default arguments setted by user:
#pragma region GetiingUserAttrs
	CK_ULONG i = 0;
	for(i; i<sKeyTemplateInfo.ulNumOfParams; i++)
	{
		ulAttrCounter = 0;
		if (sKeyTemplateInfo.psKeyParams[i].type == CKA_KEY_TYPE)
		{
			if (iDefaultAttrCounters[ulAttrCounter]) break;
			else iDefaultAttrCounters[ulAttrCounter] = i+1;
			iNumOfDefParams++;
		}
		ulAttrCounter++;
		if (sKeyTemplateInfo.psKeyParams[i].type == CKA_CLASS)
		{
			if (*((CK_OBJECT_CLASS_PTR)sKeyTemplateInfo.psKeyParams[i].pValue) == ulClass_SecKey) 
			{
				if (iDefaultAttrCounters[ulAttrCounter]) break;
				else iDefaultAttrCounters[ulAttrCounter] = i+1;
				iNumOfDefParams++;
			}
			else break;
		}
		ulAttrCounter++;
		if (sKeyTemplateInfo.psKeyParams[i].type == CKA_EXTRACTABLE)
		{
			if (iDefaultAttrCounters[ulAttrCounter]) break;
			else iDefaultAttrCounters[ulAttrCounter] = i+1;
			iNumOfDefParams++;
		}
		ulAttrCounter++;
		if (sKeyTemplateInfo.psKeyParams[i].type == CKA_MODIFIABLE)
		{
			if (iDefaultAttrCounters[ulAttrCounter]) break;
			else iDefaultAttrCounters[ulAttrCounter] = i+1;
			iNumOfDefParams++;
		}
		ulAttrCounter++;
		if (sKeyTemplateInfo.psKeyParams[i].type == CKA_ENCRYPT)
		{
			if (iDefaultAttrCounters[ulAttrCounter]) break;
			else iDefaultAttrCounters[ulAttrCounter] = i+1;
			iNumOfDefParams++;
		}
		ulAttrCounter++;
		if (sKeyTemplateInfo.psKeyParams[i].type == CKA_DECRYPT)
		{
			if (iDefaultAttrCounters[ulAttrCounter]) break;
			else iDefaultAttrCounters[ulAttrCounter] = i+1;
			iNumOfDefParams++;
		}
		ulAttrCounter++;
		if (sKeyTemplateInfo.psKeyParams[i].type == CKA_TOKEN)
		{
			if (iDefaultAttrCounters[ulAttrCounter]) break;
			else iDefaultAttrCounters[ulAttrCounter] = i+1;
			iNumOfDefParams++;
		}
		ulAttrCounter++;
		if (sKeyTemplateInfo.psKeyParams[i].type == CKA_ID)
		{
			if (iDefaultAttrCounters[ulAttrCounter]) break;
			else iDefaultAttrCounters[ulAttrCounter] = i+1;
			iNumOfDefParams++;
		}
		ulAttrCounter++;
		if (sKeyTemplateInfo.psKeyParams[i].type == CKA_VALUE_LEN)
		{
			if (iDefaultAttrCounters[ulAttrCounter]) break;
			else iDefaultAttrCounters[ulAttrCounter] = i+1;
			iNumOfDefParams++;
		}
		ulAttrCounter++;
		if (sKeyTemplateInfo.psKeyParams[i].type == CKA_OBJECT_ID)
		{
			if (iDefaultAttrCounters[ulAttrCounter]) break;
			else iDefaultAttrCounters[ulAttrCounter] = i+1;
			iNumOfDefParams++;
		}
		ulAttrCounter++;
		if (sKeyTemplateInfo.psKeyParams[i].type == SH_CKA_G28147_KEY_MESHING)
		{
			if (iDefaultAttrCounters[ulAttrCounter]) break;
			else iDefaultAttrCounters[ulAttrCounter] = i+1;
			iNumOfDefParams++;
		}
		ulAttrCounter++;
		if (sKeyTemplateInfo.psKeyParams[i].type == CKA_GOST28147_PARAMS)
		{
			if (iDefaultAttrCounters[ulAttrCounter]) break;
			else iDefaultAttrCounters[ulAttrCounter] = i+1;
			iNumOfDefParams++;
		}
	}
	if ((sKeyTemplateInfo.ulNumOfParams>i)||(!iDefaultAttrCounters[0]))	//если при поиске были ошибки:
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
#pragma endregion
#pragma region CopyingUserAttrs
	sTempKeyInfo.ulNumOfParams = sKeyTemplateInfo.ulNumOfParams + ulNumOfDefAttrs - iNumOfDefParams;		//we have elements, that are to be in template
	sTempKeyInfo.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sTempKeyInfo.ulNumOfParams);

	for (i = 0; i<sKeyTemplateInfo.ulNumOfParams; i++)
	{
		sTempKeyInfo.psKeyParams[i].pValue = sKeyTemplateInfo.psKeyParams[i].pValue;
		sTempKeyInfo.psKeyParams[i].ulValueLen = sKeyTemplateInfo.psKeyParams[i].ulValueLen;
		sTempKeyInfo.psKeyParams[i].type = sKeyTemplateInfo.psKeyParams[i].type;
	}
#pragma endregion
#pragma region AddingMissingAttrs
	i = sKeyTemplateInfo.ulNumOfParams;
	//check argument list and add missing ones as default
	ulAttrCounter = 1;
	if (!iDefaultAttrCounters[ulAttrCounter])
	{
		sTempKeyInfo.psKeyParams[i].pValue = &ulClass_SecKey;
		sTempKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
		sTempKeyInfo.psKeyParams[i].type = CKA_CLASS;
		i++;
	}
	ulAttrCounter++;
	if (!iDefaultAttrCounters[ulAttrCounter])
	{
		sTempKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempKeyInfo.psKeyParams[i].type = CKA_EXTRACTABLE;
		i++;
	}
	ulAttrCounter++;
	if (!iDefaultAttrCounters[ulAttrCounter])
	{
		sTempKeyInfo.psKeyParams[i].pValue = &blFalse;
		sTempKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempKeyInfo.psKeyParams[i].type = CKA_MODIFIABLE;
		i++;
	}
	ulAttrCounter++;
	if (!iDefaultAttrCounters[ulAttrCounter])
	{
		sTempKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempKeyInfo.psKeyParams[i].type = CKA_ENCRYPT;
		i++;
	}
	ulAttrCounter++;
	if (!iDefaultAttrCounters[ulAttrCounter])
	{
		sTempKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempKeyInfo.psKeyParams[i].type = CKA_DECRYPT;
		i++;
	}
	ulAttrCounter++;
	if (!iDefaultAttrCounters[ulAttrCounter])
	{
		sTempKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempKeyInfo.psKeyParams[i].type = CKA_TOKEN;
		i++;
	}
	ulAttrCounter++;
	if (!iDefaultAttrCounters[ulAttrCounter])
	{
		memset(pbRandomId,0,4);
		rvResult = Pkcs11FuncList->C_GenerateRandom(hSession,(CK_BYTE_PTR)pbRandomId,4);
		if (rvResult != CKR_OK)
		{
			for (CK_ULONG j = 0; j<sTempKeyInfo.ulNumOfParams; j++)
			{
				sTempKeyInfo.psKeyParams[i].type = 0;
				sTempKeyInfo.psKeyParams[i].ulValueLen = 0;
				sTempKeyInfo.psKeyParams[i].pValue = NULL;
			}
			if (sTempKeyInfo.psKeyParams) free (sTempKeyInfo.psKeyParams);
			return;
		}
		sTempKeyInfo.psKeyParams[i].pValue = pbRandomId;
		sTempKeyInfo.psKeyParams[i].ulValueLen = 4;
		sTempKeyInfo.psKeyParams[i].type = CKA_ID;
		i++;
	}
	switch (*((CK_KEY_TYPE *)sKeyTemplateInfo.psKeyParams[iDefaultAttrCounters[0] - 1].pValue))
	{
	case CKK_RC2:
		ulAttrCounter++;
		if (!iDefaultAttrCounters[ulAttrCounter])
		{
			ulKeyLen = 5;
			sTempKeyInfo.psKeyParams[i].pValue = &ulKeyLen;
			sTempKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
			sTempKeyInfo.psKeyParams[i].type = CKA_VALUE_LEN;
		}
		sTempKeyInfo.ulNumOfParams -= ulNumOfDefAttrs - ulRc2AttrsNum;
		break;
	case CKK_G28147:
		ulAttrCounter+=2;
		if (!iDefaultAttrCounters[ulAttrCounter])
		{
			pbKeyOid = OID_CRYPT_A;
			sTempKeyInfo.psKeyParams[i].pValue = pbKeyOid;
			sTempKeyInfo.psKeyParams[i].ulValueLen = strlen(pbKeyOid);
			sTempKeyInfo.psKeyParams[i].type = CKA_OBJECT_ID;
			i++;
		}
		ulAttrCounter++;
		if (!iDefaultAttrCounters[ulAttrCounter])
		{
			sTempKeyInfo.psKeyParams[i].pValue = &blTrue;
			sTempKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
			sTempKeyInfo.psKeyParams[i].type = SH_CKA_G28147_KEY_MESHING;
		}
		sTempKeyInfo.ulNumOfParams -= ulNumOfDefAttrs - ulG28147AttrsNum;
		break;
	case CKK_GOST28147:
		ulAttrCounter+=4;
		if (!iDefaultAttrCounters[ulAttrCounter])
		{
			sTempKeyInfo.psKeyParams[i].pValue = (CK_VOID_PTR)params_oid;
			sTempKeyInfo.psKeyParams[i].ulValueLen = sizeof(params_oid);
			sTempKeyInfo.psKeyParams[i].type = CKA_GOST28147_PARAMS;
		}
		sTempKeyInfo.ulNumOfParams -= ulNumOfDefAttrs - ulGost28147AttrsNum;
		break;
	default:
		sTempKeyInfo.ulNumOfParams -= ulNumOfDefAttrs - ulOtherAttrsNum;
		break;
	}
#pragma endregion
#pragma region MakingMechanism
	//making mehanism:
	if (!pMechanism)
	{
		memset(&ckTempMechanism,0,sizeof(CK_MECHANISM));
		switch (*((CK_KEY_TYPE *)sKeyTemplateInfo.psKeyParams[iDefaultAttrCounters[0] - 1].pValue))
		{
		case CKK_RC2:
			ckTempMechanism.mechanism = CKM_RC2_KEY_GEN;
			break;
		case CKK_G28147:
			ckTempMechanism.mechanism = CKM_G28147_KEY_GEN;
			break;
		case CKK_DES3:
			ckTempMechanism.mechanism = CKM_DES3_KEY_GEN;
			break;
		case CKK_GOST28147:
			ckTempMechanism.mechanism = CKM_GOST28147_KEY_GEN;
			break;
		default:
			rvResult = CKR_ARGUMENTS_BAD;
			for (CK_ULONG j = 0; j<sTempKeyInfo.ulNumOfParams; j++)
			{
				sTempKeyInfo.psKeyParams[i].type = 0;
				sTempKeyInfo.psKeyParams[i].ulValueLen = 0;
				sTempKeyInfo.psKeyParams[i].pValue = NULL;
			}
			if (sTempKeyInfo.psKeyParams) free (sTempKeyInfo.psKeyParams);
			return;
			break;
		}
	}
	else 
	{
		ckTempMechanism.mechanism = pMechanism->mechanism;
		ckTempMechanism.pParameter = pMechanism->pParameter;
		ckTempMechanism.ulParameterLen = pMechanism->ulParameterLen;
	}
#pragma endregion
	CK_OBJECT_HANDLE hGeneratedKey = 0;
	rvResult = Pkcs11FuncList->C_GenerateKey(hSession,&ckTempMechanism,sTempKeyInfo.psKeyParams,sTempKeyInfo.ulNumOfParams,&hGeneratedKey);
#pragma region MemoryDeallocation
	for (CK_ULONG j = 0; j<sTempKeyInfo.ulNumOfParams; j++)
	{
		sTempKeyInfo.psKeyParams[j].type = 0;
		sTempKeyInfo.psKeyParams[j].ulValueLen = 0;
		sTempKeyInfo.psKeyParams[j].pValue = NULL;
	}
	//if (sTempKeyInfo.psKeyParams) free (sTempKeyInfo.psKeyParams);
#pragma endregion
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to generate key pair
@param sPriKeyTemplateInfo(in) - Attributes of private key to be generated; some attributes will be added automatically;
@param sPubKeyTemplateInfo(in) - Attributes of public key to be generated; some attributes will be added automatically;
@param pMechanism(in) - Mechanism of key generation; if NULL then default mechanism for type of key defined in sKeyTemplateInfo will be used;
*/
void KeyManagmentClass::GenerateKeyPair(MY_KEY_TEMPLATE_INFO sPriKeyTemplateInfo, MY_KEY_TEMPLATE_INFO sPubKeyTemplateInfo,
										CK_MECHANISM_PTR pMechanism)
{
	MY_KEY_TEMPLATE_INFO	sTempPriKeyInfo, sTempPubKeyInfo;
	CK_MECHANISM			ckTempMechanism;

	CK_BYTE gostR3410params_oid[] = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01};
	CK_BYTE gostR3411params_oid[] = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01};

	CK_ULONG ulKeySize = 0;
#pragma region PrivateKeyAttributesMaking
	//Default attributes to be setted:			iCounter:
	//CKA_KEY_TYPE - SettedByUser				0
	//CKA_CLASS = CKO_PRIVATE_KEY				1
	//CKA_EXTRACTABLE = CK_TRUE					2
	//CKA_MODIFIABLE = CK_FALSE					3
	//CKA_DECRYPT = CK_TRUE						4
	//CKA_SIGN = CK_TRUE						5
	//CKA_UNWRAP = CK_TRUE						6
	//CKA_TOKEN = CK_TRUE						7
	//CKA_DERIVE = CK_TRUE						8
	const CK_ULONG ulNumOfPriKeyDefAttrs = 9;
	const CK_ULONG ulG3410PriKeyAttrsNum = 9;
	const CK_ULONG ulGost3410PriKeyAttrsNum = 9;
	const CK_ULONG ulRsaPriKeyAttrsNum = 9;
	const CK_ULONG ulOtherPriKeyAttrsNum = 9;
	CK_ULONG iDefaultPriKeyAttrs [ulNumOfPriKeyDefAttrs];		//have default attributes
	int iNumOfPriKeyDefParams = 0;
	memset(iDefaultPriKeyAttrs,0,ulNumOfPriKeyDefAttrs * sizeof(CK_ULONG));

 
#pragma region UserAttributes
	//check, if sKeyTemplateInfo is OK and find all values of default arguments setted by user:
	CK_ULONG i = 0;
	for(i; i<sPriKeyTemplateInfo.ulNumOfParams; i++)
	{
		if (sPriKeyTemplateInfo.psKeyParams[i].type == CKA_KEY_TYPE)
		{
			if (iDefaultPriKeyAttrs[0]) break;
			else iDefaultPriKeyAttrs[0] = i+1;
			iNumOfPriKeyDefParams++;
		}
		if (sPriKeyTemplateInfo.psKeyParams[i].type == CKA_CLASS)
		{
			if (*((CK_OBJECT_CLASS_PTR)sPriKeyTemplateInfo.psKeyParams[i].pValue) == ulClass_PriKey) 
			{
				if (iDefaultPriKeyAttrs[1]) break;
				else iDefaultPriKeyAttrs[1] = i+1;
				iNumOfPriKeyDefParams++;
			}
			else break;
		}
		if (sPriKeyTemplateInfo.psKeyParams[i].type == CKA_EXTRACTABLE)
		{
			if (iDefaultPriKeyAttrs[2]) break;
			else iDefaultPriKeyAttrs[2] = i+1;
			iNumOfPriKeyDefParams++;
		}
		if (sPriKeyTemplateInfo.psKeyParams[i].type == CKA_MODIFIABLE)
		{
			if (iDefaultPriKeyAttrs[3]) break;
			else iDefaultPriKeyAttrs[3] = i+1;
			iNumOfPriKeyDefParams++;
		}
		if (sPriKeyTemplateInfo.psKeyParams[i].type == CKA_DECRYPT)
		{
			if (iDefaultPriKeyAttrs[4]) break;
			else iDefaultPriKeyAttrs[4] = i+1;
			iNumOfPriKeyDefParams++;
		}
		if (sPriKeyTemplateInfo.psKeyParams[i].type == CKA_SIGN)
		{
			if (iDefaultPriKeyAttrs[5]) break;
			else iDefaultPriKeyAttrs[5] = i+1;
			iNumOfPriKeyDefParams++;
		}
		if (sPriKeyTemplateInfo.psKeyParams[i].type == CKA_UNWRAP)
		{
			if (iDefaultPriKeyAttrs[6]) break;
			else iDefaultPriKeyAttrs[6] = i+1;
			iNumOfPriKeyDefParams++;
		}
		if (sPriKeyTemplateInfo.psKeyParams[i].type == CKA_TOKEN)
		{
			if (iDefaultPriKeyAttrs[7]) break;
			else iDefaultPriKeyAttrs[7] = i+1;
			iNumOfPriKeyDefParams++;
		}
		if (sPriKeyTemplateInfo.psKeyParams[i].type == CKA_DERIVE)
		{
			if (iDefaultPriKeyAttrs[8]) break;
			else iDefaultPriKeyAttrs[8] = i+1;
			iNumOfPriKeyDefParams++;
		}
/*		if (sPriKeyTemplateInfo.psKeyParams[i].type == CKA_GOSTR3410_PARAMS)
		{
			if (iDefaultPriKeyAttrs[9]) break;
			else iDefaultPriKeyAttrs[9] = i+1;
			iNumOfPriKeyDefParams++;
		}
		if (sPriKeyTemplateInfo.psKeyParams[i].type == CKA_GOSTR3411_PARAMS)
		{
			if (iDefaultPriKeyAttrs[10]) break;
			else iDefaultPriKeyAttrs[10] = i+1;
			iNumOfPriKeyDefParams++;
		}
		//*/
	}
	if ((sPriKeyTemplateInfo.ulNumOfParams>i)||(!iDefaultPriKeyAttrs[0]))	//если при поиске были ошибки:
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
#pragma endregion
#pragma region CopyingUserAttrs
	sTempPriKeyInfo.ulNumOfParams = sPriKeyTemplateInfo.ulNumOfParams + ulNumOfPriKeyDefAttrs - iNumOfPriKeyDefParams;		//we have 9 elements, that are to be in template
	sTempPriKeyInfo.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sTempPriKeyInfo.ulNumOfParams);

	//Copy attributes:
	for (i = 0; i<sPriKeyTemplateInfo.ulNumOfParams; i++)
	{
		sTempPriKeyInfo.psKeyParams[i].pValue = sPriKeyTemplateInfo.psKeyParams[i].pValue;
		sTempPriKeyInfo.psKeyParams[i].ulValueLen = sPriKeyTemplateInfo.psKeyParams[i].ulValueLen;
		sTempPriKeyInfo.psKeyParams[i].type = sPriKeyTemplateInfo.psKeyParams[i].type;
	}
#pragma endregion
#pragma region AddMissingAttributes
	i = sPriKeyTemplateInfo.ulNumOfParams;
	//check argument list and add missing ones as default
	if (!iDefaultPriKeyAttrs[1])
	{
		sTempPriKeyInfo.psKeyParams[i].pValue = &ulClass_PriKey;
		sTempPriKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
		sTempPriKeyInfo.psKeyParams[i].type = CKA_CLASS;
		i++;
	}
	if (!iDefaultPriKeyAttrs[2])
	{
		sTempPriKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempPriKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempPriKeyInfo.psKeyParams[i].type = CKA_EXTRACTABLE;
		i++;
	}
	if (!iDefaultPriKeyAttrs[3])
	{
		sTempPriKeyInfo.psKeyParams[i].pValue = &blFalse;
		sTempPriKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempPriKeyInfo.psKeyParams[i].type = CKA_MODIFIABLE;
		i++;
	}
	if (!iDefaultPriKeyAttrs[4])
	{
		sTempPriKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempPriKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempPriKeyInfo.psKeyParams[i].type = CKA_DECRYPT;
		i++;
	}
	if (!iDefaultPriKeyAttrs[5])
	{
		sTempPriKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempPriKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempPriKeyInfo.psKeyParams[i].type = CKA_SIGN;
		i++;
	}
	if (!iDefaultPriKeyAttrs[6])
	{
		sTempPriKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempPriKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempPriKeyInfo.psKeyParams[i].type = CKA_UNWRAP;
		i++;
	}
	if (!iDefaultPriKeyAttrs[7])
	{
		sTempPriKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempPriKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempPriKeyInfo.psKeyParams[i].type = CKA_TOKEN;
		i++;
	}
	if (!iDefaultPriKeyAttrs[8])
	{
		sTempPriKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempPriKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempPriKeyInfo.psKeyParams[i].type = CKA_DERIVE;
	}
	/*
	switch (*((CK_KEY_TYPE *)sTempPriKeyInfo.psKeyParams[iDefaultPriKeyAttrs[0] - 1].pValue))
	{
	case CKK_GOSTR3410:
		if (!iDefaultPriKeyAttrs[9])
		{
			sTempPriKeyInfo.psKeyParams[i].pValue = gostR3410params_oid;
			sTempPriKeyInfo.psKeyParams[i].ulValueLen = sizeof(gostR3410params_oid);
			sTempPriKeyInfo.psKeyParams[i].type = CKA_GOSTR3410_PARAMS;
			i++;
		}
		if (!iDefaultPriKeyAttrs[10])
		{
			sTempPriKeyInfo.psKeyParams[i].pValue = gostR3411params_oid;
			sTempPriKeyInfo.psKeyParams[i].ulValueLen = sizeof(gostR3411params_oid);
			sTempPriKeyInfo.psKeyParams[i].type = CKA_GOSTR3411_PARAMS;
		}
		break;
	default:
		sTempPriKeyInfo.ulNumOfParams -= ulNumOfPriKeyDefAttrs - ulOtherPriKeyAttrsNum;
		break;
	}
	//*/
#pragma endregion
#pragma endregion
#pragma region PublicKeyAttributesMaking
	//Default attributes to be setted:			iCounter:
	//CKA_KEY_TYPE - SettedByUser				0
	//CKA_CLASS = CKO_PUBLIC_KEY				1
	//CKA_ENCRYPT = CK_TRUE						2
	//CKA_VERIFY = CK_TRUE						3
	//CKA_WRAP = CK_TRUE						4
	//CKA_TOKEN = CK_TRUE						5
	//CKA_PRIVATE = CK_FALSE					6
	//for RSA: CKA_MODULUS_BITS	= 512			7
	//for GOST: CKA_GR3410_PARAMETER_OID		8
	//for Gost1: GOSTR3410PARAMS and GOSTR3411PARAMS 9, 10
	const CK_ULONG ulNumOfPubKeyDefAttrs = 11;
	const CK_ULONG ulG3410PubKeyAttrsNum = 8;
	const CK_ULONG ulGost3410PubKeyAttrsNum = 9;
	const CK_ULONG ulRsaPubKeyAttrsNum = 8;
	const CK_ULONG ulOtherPubKeyAttrsNum = 7;
	CK_ULONG iDefaultPubKeyAttrs [ulNumOfPubKeyDefAttrs];		//have default attributes
	int iNumOfPubKeyDefParams = 0;
	memset(iDefaultPubKeyAttrs,0,ulNumOfPubKeyDefAttrs * sizeof(CK_ULONG));

#pragma region UserAttributes
	//check, if sKeyTemplateInfo is OK and find all values of default arguments setted by user:
	i = 0;
	for(i; i<sPubKeyTemplateInfo.ulNumOfParams; i++)
	{
		if (sPubKeyTemplateInfo.psKeyParams[i].type == CKA_KEY_TYPE)
		{
			if (iDefaultPubKeyAttrs[0]) break;
			else iDefaultPubKeyAttrs[0] = i+1;
			iNumOfPubKeyDefParams++;
		}
		if (sPubKeyTemplateInfo.psKeyParams[i].type == CKA_CLASS)
		{
			if (*((CK_OBJECT_CLASS_PTR)sPubKeyTemplateInfo.psKeyParams[i].pValue) == ulClass_PubKey) 
			{
				if (iDefaultPubKeyAttrs[1]) break;
				else iDefaultPubKeyAttrs[2] = i+1;
				iNumOfPubKeyDefParams++;
			}
			else break;
		}
		if (sPubKeyTemplateInfo.psKeyParams[i].type == CKA_ENCRYPT)
		{
			if (iDefaultPubKeyAttrs[2]) break;
			else iDefaultPubKeyAttrs[2] = i+1;
			iNumOfPubKeyDefParams++;
		}
		if (sPubKeyTemplateInfo.psKeyParams[i].type == CKA_VERIFY)
		{
			if (iDefaultPubKeyAttrs[3]) break;
			else iDefaultPubKeyAttrs[3] = i+1;
			iNumOfPubKeyDefParams++;
		}
		if (sPubKeyTemplateInfo.psKeyParams[i].type == CKA_WRAP)
		{
			if (iDefaultPubKeyAttrs[4]) break;
			else iDefaultPubKeyAttrs[4] = i+1;
			iNumOfPubKeyDefParams++;
		}
		if (sPubKeyTemplateInfo.psKeyParams[i].type == CKA_TOKEN)
		{
			if (iDefaultPubKeyAttrs[5]) break;
			else iDefaultPubKeyAttrs[5] = i+1;
			iNumOfPubKeyDefParams++;
		}
		if (sPubKeyTemplateInfo.psKeyParams[i].type == CKA_PRIVATE)
		{
			if (iDefaultPubKeyAttrs[6]) break;
			else iDefaultPubKeyAttrs[6] = i+1;
			iNumOfPubKeyDefParams++;
		}
		if (sPubKeyTemplateInfo.psKeyParams[i].type == CKA_MODULUS_BITS)
		{
			if (iDefaultPubKeyAttrs[7]) break;
			else iDefaultPubKeyAttrs[7] = i+1;
			iNumOfPubKeyDefParams++;
		}
		if (sPubKeyTemplateInfo.psKeyParams[i].type == CKA_GR3410_PARAMETER_OID)
		{
			if (iDefaultPubKeyAttrs[8]) break;
			else iDefaultPubKeyAttrs[8] = i+1;
			iNumOfPubKeyDefParams++;
		}
		if (sPriKeyTemplateInfo.psKeyParams[i].type == CKA_GOSTR3410_PARAMS)
		{
			if (iDefaultPriKeyAttrs[9]) break;
			else iDefaultPriKeyAttrs[9] = i+1;
			iNumOfPriKeyDefParams++;
		}
		if (sPriKeyTemplateInfo.psKeyParams[i].type == CKA_GOSTR3411_PARAMS)
		{
			if (iDefaultPriKeyAttrs[10]) break;
			else iDefaultPriKeyAttrs[10] = i+1;
			iNumOfPriKeyDefParams++;
		}
	}
	if ((sPubKeyTemplateInfo.ulNumOfParams>i)||(!iDefaultPubKeyAttrs[0]))	//если при поиске были ошибки:
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
#pragma endregion
#pragma region CopyingUserAttrs
	sTempPubKeyInfo.ulNumOfParams = sPubKeyTemplateInfo.ulNumOfParams + ulNumOfPubKeyDefAttrs - iNumOfPubKeyDefParams;		//we have 9 elements, that are to be in template
	sTempPubKeyInfo.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sTempPubKeyInfo.ulNumOfParams);

	//Copy attributes:
	for (i = 0; i<sPubKeyTemplateInfo.ulNumOfParams; i++)
	{
		sTempPubKeyInfo.psKeyParams[i].pValue = sPubKeyTemplateInfo.psKeyParams[i].pValue;
		sTempPubKeyInfo.psKeyParams[i].ulValueLen = sPubKeyTemplateInfo.psKeyParams[i].ulValueLen;
		sTempPubKeyInfo.psKeyParams[i].type = sPubKeyTemplateInfo.psKeyParams[i].type;
	}
#pragma endregion
#pragma region AddMissingAttributes
	i = sPubKeyTemplateInfo.ulNumOfParams;
	//check argument list and add missing ones as default
	if (!iDefaultPubKeyAttrs[1])
	{
		sTempPubKeyInfo.psKeyParams[i].pValue = &ulClass_PubKey;
		sTempPubKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
		sTempPubKeyInfo.psKeyParams[i].type = CKA_CLASS;
		i++;
	}
	if (!iDefaultPubKeyAttrs[2])
	{
		sTempPubKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempPubKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempPubKeyInfo.psKeyParams[i].type = CKA_ENCRYPT;
		i++;
	}
	if (!iDefaultPubKeyAttrs[3])
	{
		sTempPubKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempPubKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempPubKeyInfo.psKeyParams[i].type = CKA_VERIFY;
		i++;
	}
	if (!iDefaultPubKeyAttrs[4])
	{
		sTempPubKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempPubKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempPubKeyInfo.psKeyParams[i].type = CKA_WRAP;
		i++;
	}
	if (!iDefaultPubKeyAttrs[5])
	{
		sTempPubKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempPubKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempPubKeyInfo.psKeyParams[i].type = CKA_TOKEN;
		i++;
	}
	if (!iDefaultPubKeyAttrs[6])
	{
		sTempPubKeyInfo.psKeyParams[i].pValue = &blTrue;
		sTempPubKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_BBOOL);
		sTempPubKeyInfo.psKeyParams[i].type = CKA_PRIVATE;
		i++;
	}
	switch (*((CK_KEY_TYPE *)sPubKeyTemplateInfo.psKeyParams[iDefaultPubKeyAttrs[0] - 1].pValue))
	{
	case CKK_RSA:
		if (!iDefaultPubKeyAttrs[7])
		{
			ulKeySize = 512;
			sTempPubKeyInfo.psKeyParams[i].pValue = &ulKeySize;
			sTempPubKeyInfo.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
			sTempPubKeyInfo.psKeyParams[i].type = CKA_MODULUS_BITS;
		}
		sTempPubKeyInfo.ulNumOfParams -= ulNumOfPubKeyDefAttrs - ulRsaPubKeyAttrsNum;
		break;
	case CKK_GR3410EL:
		if (!iDefaultPubKeyAttrs[8])
		{
			char *pbKeyOid = OID_EC_A;
			sTempPubKeyInfo.psKeyParams[i].pValue = pbKeyOid;
			sTempPubKeyInfo.psKeyParams[i].ulValueLen = strlen(pbKeyOid);
			sTempPubKeyInfo.psKeyParams[i].type = CKA_GR3410_PARAMETER_OID;
		}
		sTempPubKeyInfo.ulNumOfParams -= ulNumOfPubKeyDefAttrs - ulG3410PubKeyAttrsNum;
		break;
	case CKK_GOSTR3410:
		/*
		if (!iDefaultPubKeyAttrs[8])
		{
			char *pbKeyOid = OID_EC_A;
			sTempPubKeyInfo.psKeyParams[i].pValue = pbKeyOid;
			sTempPubKeyInfo.psKeyParams[i].ulValueLen = strlen(pbKeyOid);
			sTempPubKeyInfo.psKeyParams[i].type = CKA_GR3410_PARAMETER_OID;
			i++;
		}
		//*/
		if (!iDefaultPubKeyAttrs[9])
		{
			sTempPubKeyInfo.psKeyParams[i].pValue = gostR3410params_oid;
			sTempPubKeyInfo.psKeyParams[i].ulValueLen = sizeof(gostR3410params_oid);
			sTempPubKeyInfo.psKeyParams[i].type = CKA_GOSTR3410_PARAMS;
			i++;
		}
		if (!iDefaultPubKeyAttrs[10])
		{
			sTempPubKeyInfo.psKeyParams[i].pValue = gostR3411params_oid;
			sTempPubKeyInfo.psKeyParams[i].ulValueLen = sizeof(gostR3411params_oid);
			sTempPubKeyInfo.psKeyParams[i].type = CKA_GOSTR3411_PARAMS;
		}
		sTempPubKeyInfo.ulNumOfParams -= ulNumOfPubKeyDefAttrs - ulGost3410PubKeyAttrsNum;
		break;
	default:
		sTempPubKeyInfo.ulNumOfParams -= ulNumOfPubKeyDefAttrs - ulOtherPubKeyAttrsNum;
		//if (sTempKeyInfo.psKeyParams) free (sTempKeyInfo.psKeyParams);
		return;
	}
#pragma endregion
#pragma endregion
#pragma region MakingMechanism
	//making mehanism:
	if (!pMechanism)
	{
		memset(&ckTempMechanism,0,sizeof(CK_MECHANISM));
		switch (*((CK_KEY_TYPE *)sPriKeyTemplateInfo.psKeyParams[iDefaultPriKeyAttrs[0] - 1].pValue))
		{
		case CKK_RSA:
			ckTempMechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
			break;
		case CKK_GR3410EL:
			ckTempMechanism.mechanism = CKM_GR3410EL_KEY_PAIR_GEN;
			break;
		case CKK_GOSTR3410:
			ckTempMechanism.mechanism = CKM_GOSTR3410_KEY_PAIR_GEN;
			break;
		default:
			rvResult = CKR_ARGUMENTS_BAD;
			for (CK_ULONG j = 0; j<sTempPriKeyInfo.ulNumOfParams; j++)
			{
				sTempPriKeyInfo.psKeyParams[i].type = 0;
				sTempPriKeyInfo.psKeyParams[i].ulValueLen = 0;
				sTempPriKeyInfo.psKeyParams[i].pValue = NULL;
			}
			for (CK_ULONG j = 0; j<sTempPubKeyInfo.ulNumOfParams; j++)
			{
				sTempPubKeyInfo.psKeyParams[i].type = 0;
				sTempPubKeyInfo.psKeyParams[i].ulValueLen = 0;
				sTempPubKeyInfo.psKeyParams[i].pValue = NULL;
			}
			if (sTempPriKeyInfo.psKeyParams) free (sTempPriKeyInfo.psKeyParams);
			if (sTempPubKeyInfo.psKeyParams) free (sTempPubKeyInfo.psKeyParams);
			return;
		}
	}
	else 
	{
		ckTempMechanism.mechanism = pMechanism->mechanism;
		ckTempMechanism.pParameter = pMechanism->pParameter;
		ckTempMechanism.ulParameterLen = pMechanism->ulParameterLen;
	}
#pragma endregion

	//generating key
	CK_OBJECT_HANDLE	hPubKey = 0, hPriKey = 0;
	rvResult = Pkcs11FuncList->C_GenerateKeyPair(	hSession,
													&ckTempMechanism,
													sTempPubKeyInfo.psKeyParams,
													sTempPubKeyInfo.ulNumOfParams,
													sTempPriKeyInfo.psKeyParams,
													sTempPriKeyInfo.ulNumOfParams,
													&hPubKey,
													&hPriKey);
#pragma region CleaningMemory
	for (CK_ULONG j = 0; j<sTempPriKeyInfo.ulNumOfParams; j++)
	{
		sTempPriKeyInfo.psKeyParams[i].type = 0;
		sTempPriKeyInfo.psKeyParams[i].ulValueLen = 0;
		sTempPriKeyInfo.psKeyParams[i].pValue = NULL;
	}
	for (CK_ULONG j = 0; j<sTempPubKeyInfo.ulNumOfParams; j++)
	{
		sTempPubKeyInfo.psKeyParams[i].type = 0;
		sTempPubKeyInfo.psKeyParams[i].ulValueLen = 0;
		sTempPubKeyInfo.psKeyParams[i].pValue = NULL;
	}
	if (sTempPriKeyInfo.psKeyParams) free (sTempPriKeyInfo.psKeyParams);
#pragma endregion
}
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to delete key or keys by template
@param sKeyTemplateInfo(in) - Attributes of keys to be deleted;
*/
void KeyManagmentClass::DeleteKey(MY_KEY_TEMPLATE_INFO sKeyTemplateInfo)
{
	CK_OBJECT_HANDLE_PTR phKeyList = NULL;
	CK_ULONG ulKeyNumber = 0;

	if (!hSession) 
	{
		rvResult = CKR_SESSION_HANDLE_INVALID;
		return;
	}

	FindKeysByTemplate(sKeyTemplateInfo, phKeyList, &ulKeyNumber);
	if (CKR_OK != rvResult)
		return;
	if (!ulKeyNumber)
	{
		rvResult = CKR_KEYS_NOT_FOUND;
		return;
	}
	//if (ulKeyNumber > 2) 
	//{
	//	rvResult = CKR_ARGUMENTS_BAD;
	//	return;
	//}
	if (NULL == (phKeyList = (CK_OBJECT_HANDLE_PTR) malloc (sizeof(CK_OBJECT_HANDLE) * ulKeyNumber)))
	{
		rvResult = MEMORY_NOT_ALLOCATED;
		return;
	}
	FindKeysByTemplate(sKeyTemplateInfo, phKeyList, &ulKeyNumber);
	if (CKR_OK != rvResult)
	{
		if (phKeyList) free (phKeyList);
		phKeyList = NULL;
		return;
	}

	for (CK_ULONG i = 0; i<ulKeyNumber; i++)
	{
		rvResult = Pkcs11FuncList->C_DestroyObject(hSession,phKeyList[i]);
		if (CKR_OK != rvResult) 
		{
			if (phKeyList) free (phKeyList);
			phKeyList = NULL;
			return;
		}
	}

	if (phKeyList) free (phKeyList);
	phKeyList = NULL;
	return;	
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to export public key
@param sKeyToExport(in) - Attributes of public key to be exported;
@param pbExportedKey(out) - array of CK_BYTEs to contain key info and its value
@param ulExportedKeyLen(out) - length of pbExportedKey
*/
void KeyManagmentClass::ExportPublicKey (MY_KEY_TEMPLATE_INFO sKeyToExport, BYTE *pbExportedKey, CK_ULONG *ulExportedKeyLen)
{
	CK_ULONG ulKeyClass = 0, ulNumOfKeysFound = 0, ulKeyType = 0, ulCounter = 0, ulParsedDataLen = 0;
	CK_OBJECT_HANDLE hKeyToExport = 0;
	MY_KEY_TEMPLATE_INFO sKeyValueAttributes, sKeyInfo;
	CK_ATTRIBUTE sTempAttribute;
	CK_BYTE_PTR pbTempParsedData = NULL;
	CK_ULONG ulTempParsedDataLen = 0;

	*ulExportedKeyLen = 0;
	sKeyInfo.psKeyParams = NULL;
	sKeyInfo.ulNumOfParams = 0;
	sKeyValueAttributes.psKeyParams = NULL;
	sKeyValueAttributes.ulNumOfParams = 0;

#pragma region CheckingIfKeyIsAlreadyWrapped
	ParseAttrs(sKeyToExport,pbTempParsedData, &ulTempParsedDataLen);
	if ((rvResult == CKR_OK)&&(ulTempParsedDataLen))
	{
		pbTempParsedData = (CK_BYTE_PTR) malloc (sizeof(CK_BYTE) * ulTempParsedDataLen);
		ParseAttrs(sKeyToExport,pbTempParsedData, &ulTempParsedDataLen);
		if ((ulInputParsedDataLen == ulTempParsedDataLen)&&(rvResult == CKR_OK))
		{
			if (pbInputParsedData)
			{
				if (!memcmp(pbInputParsedData, pbTempParsedData, ulTempParsedDataLen))
				{
					if ((pbLastExported)&&(ulLastExpLen))
					{
						*ulExportedKeyLen = ulLastExpLen;
						if (pbExportedKey) memcpy(pbExportedKey,pbLastExported,ulLastExpLen);
						free (pbTempParsedData);
						pbTempParsedData = NULL;
						goto EXPORT_PUBLIC_KEY_FINALIZATION;
					}
				}
			}
		}
	}

	if (rvResult != CKR_OK)
	{
		if (pbTempParsedData) free (pbTempParsedData);
		pbTempParsedData = NULL;
		goto EXPORT_PUBLIC_KEY_FINALIZATION;
	}

	if (pbInputParsedData) free (pbInputParsedData);
	pbInputParsedData = pbTempParsedData;
	ulInputParsedDataLen = ulTempParsedDataLen;
	pbTempParsedData = NULL;
#pragma endregion
#pragma region LookingForKeyToExport
	FindKeysByTemplate(sKeyToExport,NULL,&ulNumOfKeysFound);
	if (CKR_OK != rvResult)
		return;
	else if (ulNumOfKeysFound != 1)
	{
		if (ulNumOfKeysFound > 1)
			rvResult = CKR_TOO_MANY_KEYS_FOUND;
		if (ulNumOfKeysFound == 0)
			rvResult = CKR_KEYS_NOT_FOUND;
		return;
	}
	FindKeysByTemplate(sKeyToExport,&hKeyToExport,&ulNumOfKeysFound);
	if (CKR_OK != rvResult)
		return;

	//check, if key is public, or not:
	sTempAttribute.type = CKA_CLASS;
	sTempAttribute.ulValueLen = sizeof(CK_ULONG);
	sTempAttribute.pValue = &ulKeyClass;
	rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hKeyToExport,&sTempAttribute,1);
	if ((sTempAttribute.ulValueLen == -1)||(rvResult != CKR_OK))
	{
		if (rvResult ==CKR_OK)
			rvResult = CKR_ATTRIBUTE_NOT_FOUND;
		return;
	}
	if (ulKeyClass != CKO_PUBLIC_KEY)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
#pragma endregion
#pragma region ChoosingKeyType
	sTempAttribute.type = CKA_KEY_TYPE;
	sTempAttribute.ulValueLen = sizeof(CK_ULONG);
	sTempAttribute.pValue = &ulKeyType;
	rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hKeyToExport,&sTempAttribute,1);
	if ((sTempAttribute.ulValueLen == -1)||(rvResult != CKR_OK))
		ulKeyType = -1;

	switch (ulKeyType)
	{
	case CKK_GOSTR3410:
		sKeyValueAttributes.ulNumOfParams = 3;
		sKeyValueAttributes.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof (CK_ATTRIBUTE) * sKeyValueAttributes.ulNumOfParams);
		sKeyValueAttributes.psKeyParams[0].type = CKA_VALUE;
		sKeyValueAttributes.psKeyParams[0].ulValueLen = 0;
		sKeyValueAttributes.psKeyParams[0].pValue = NULL;
		sKeyValueAttributes.psKeyParams[1].type = CKA_GOSTR3410_PARAMS;
		sKeyValueAttributes.psKeyParams[1].ulValueLen = 0;
		sKeyValueAttributes.psKeyParams[1].pValue = NULL;
		sKeyValueAttributes.psKeyParams[2].type = CKA_GOSTR3411_PARAMS;
		sKeyValueAttributes.psKeyParams[2].ulValueLen = 0;
		sKeyValueAttributes.psKeyParams[2].pValue = NULL;
		break;	
	case CKK_GR3410EL:
		sKeyValueAttributes.ulNumOfParams = 2;
		sKeyValueAttributes.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof (CK_ATTRIBUTE) * sKeyValueAttributes.ulNumOfParams);
		sKeyValueAttributes.psKeyParams[0].type = CKA_VALUE;
		sKeyValueAttributes.psKeyParams[0].ulValueLen = 0;
		sKeyValueAttributes.psKeyParams[0].pValue = NULL;
		sKeyValueAttributes.psKeyParams[1].type = CKA_GR3410_PARAMETER_OID;
		sKeyValueAttributes.psKeyParams[1].ulValueLen = 0;
		sKeyValueAttributes.psKeyParams[1].pValue = NULL;
		break;
	case CKK_RSA:
		sKeyValueAttributes.ulNumOfParams = 2;
		sKeyValueAttributes.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof (CK_ATTRIBUTE) * sKeyValueAttributes.ulNumOfParams);
		sKeyValueAttributes.psKeyParams[0].type = CKA_MODULUS;
		sKeyValueAttributes.psKeyParams[0].ulValueLen = 0;
		sKeyValueAttributes.psKeyParams[0].pValue = NULL;
		sKeyValueAttributes.psKeyParams[1].type = CKA_PUBLIC_EXPONENT;
		sKeyValueAttributes.psKeyParams[1].ulValueLen = 0;
		sKeyValueAttributes.psKeyParams[1].pValue = NULL;
		break;
	default:
		rvResult = CKR_ATTRIBUTE_VALUE_INVALID;
		return;
	}
#pragma endregion
#pragma region GettingPubKeyValue
	rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hKeyToExport,sKeyValueAttributes.psKeyParams,sKeyValueAttributes.ulNumOfParams);
	
	if (rvResult != CKR_OK)
	{
		if (sKeyValueAttributes.psKeyParams) free (sKeyValueAttributes.psKeyParams);
		return;
	}
	for (CK_ULONG i = 0; i<sKeyValueAttributes.ulNumOfParams; i++)
	{
		if (sKeyValueAttributes.psKeyParams[i].ulValueLen == -1)
		{
			rvResult = CKR_ATTRIBUTE_VALUE_INVALID;
			return;
		}
	}
	for (CK_ULONG i = 0; i<sKeyValueAttributes.ulNumOfParams; i++)
	{
		sKeyValueAttributes.psKeyParams[i].pValue = malloc (sKeyValueAttributes.psKeyParams[i].ulValueLen);
	}

	rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hKeyToExport,sKeyValueAttributes.psKeyParams,sKeyValueAttributes.ulNumOfParams);
	
	if (rvResult != CKR_OK)
	{
		goto EXPORT_PUBLIC_KEY_FINALIZATION;
	}
#pragma endregion
#pragma region GettingKeyInfo
	//id+label+type
	sKeyInfo.ulNumOfParams = 4;
	sKeyInfo.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sKeyInfo.ulNumOfParams);
	for (CK_ULONG i = 0; i<sKeyInfo.ulNumOfParams; i++)
	{
		sKeyInfo.psKeyParams[i].pValue = NULL;
		sKeyInfo.psKeyParams[i].ulValueLen = 0;
	}
	sKeyInfo.psKeyParams[ulCounter].type = CKA_ID;
	ulCounter++;
	sKeyInfo.psKeyParams[ulCounter].type = CKA_CLASS;
	ulCounter++;
	sKeyInfo.psKeyParams[ulCounter].type = CKA_LABEL;
	ulCounter++;
	sKeyInfo.psKeyParams[ulCounter].type = CKA_KEY_TYPE;
	rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hKeyToExport,sKeyInfo.psKeyParams,sKeyInfo.ulNumOfParams);
	for (CK_ULONG i = 0; i<sKeyInfo.ulNumOfParams; i++)
	{
		if ((sKeyInfo.psKeyParams[i].ulValueLen == 0)&&(sKeyInfo.psKeyParams[i].type != CKA_LABEL))
		{
			if (rvResult == CKR_OK) rvResult = CKR_ATTRIBUTE_TYPE_INVALID;
			goto EXPORT_PUBLIC_KEY_FINALIZATION;
		}
		if ((sKeyInfo.psKeyParams[i].ulValueLen == -1)&&(sKeyInfo.psKeyParams[i].type != CKA_LABEL))
		{
			if (rvResult == CKR_OK) rvResult = CKR_ATTRIBUTE_NOT_FOUND;
			goto EXPORT_PUBLIC_KEY_FINALIZATION;
		}
		if (sKeyInfo.psKeyParams[i].ulValueLen != -1)
			sKeyInfo.psKeyParams[i].pValue = (CK_BYTE_PTR) malloc (sKeyInfo.psKeyParams[i].ulValueLen);
	}
	rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hKeyToExport,sKeyInfo.psKeyParams,sKeyInfo.ulNumOfParams);
	for (CK_ULONG i = 0; i<sKeyInfo.ulNumOfParams; i++)
		if ((sKeyInfo.psKeyParams[i].ulValueLen == -1)&&(sKeyInfo.psKeyParams[i].type == CKA_LABEL))
			sKeyInfo.psKeyParams[i].ulValueLen = 0;
#pragma endregion
#pragma region ParsingAttributes
	ulTempParsedDataLen = 0;
	ulParsedDataLen = 0;

	ParseAttrs(sKeyInfo,NULL,&ulParsedDataLen);
	ulTempParsedDataLen += ulParsedDataLen;
	ulParsedDataLen = 0;
	ParseAttrs(sKeyValueAttributes,NULL,&ulParsedDataLen);
	ulTempParsedDataLen += ulParsedDataLen;

	if ((rvResult == CKR_OK)&&(ulTempParsedDataLen))
	{
		if (!(pbTempParsedData = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * ulTempParsedDataLen)))
		{
			rvResult = MEMORY_NOT_ALLOCATED;
			goto EXPORT_PUBLIC_KEY_FINALIZATION;
		}
		ulParsedDataLen = 0;
		ParseAttrs(sKeyInfo,pbTempParsedData,&ulParsedDataLen);
		if (rvResult != CKR_OK)
		{
			free(pbTempParsedData);
			goto EXPORT_PUBLIC_KEY_FINALIZATION;
		}
		ParseAttrs(sKeyValueAttributes,(CK_BYTE_PTR)(pbTempParsedData + ulParsedDataLen),&ulParsedDataLen);
		if (rvResult != CKR_OK)
		{
			free(pbTempParsedData);
			goto EXPORT_PUBLIC_KEY_FINALIZATION;
		}
		
		if (pbLastExported) free (pbLastExported);
		ulLastExpLen = ulTempParsedDataLen;
		pbLastExported = pbTempParsedData;
		pbTempParsedData = NULL;
	}
	*ulExportedKeyLen = ulLastExpLen;
	if (pbExportedKey) memcpy (pbExportedKey, pbLastExported, ulLastExpLen);

#pragma endregion
EXPORT_PUBLIC_KEY_FINALIZATION:
#pragma region KeyFinalization
	if (sKeyInfo.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sKeyInfo.ulNumOfParams; i++)
		{
			if (sKeyInfo.psKeyParams[i].pValue) free (sKeyInfo.psKeyParams[i].pValue);
			sKeyInfo.psKeyParams[i].pValue = NULL;
		}
		free (sKeyInfo.psKeyParams);
	}
	for (CK_ULONG i = 0; i<sKeyValueAttributes.ulNumOfParams; i++)
	{
		if (sKeyValueAttributes.psKeyParams[i].pValue) free (sKeyValueAttributes.psKeyParams[i].pValue);
	}
	if (sKeyValueAttributes.psKeyParams) free (sKeyValueAttributes.psKeyParams);
#pragma endregion
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to export secret or private key
@param sKeyToExport(in) - Attributes of secret or private key to be exported;
@param sPubKeyToWrapOn(in) - Attributes of public key to export on;
@param sPriKeyToWrapOn(in) - Attributes of private key to export on, if it is needed (for Gost 3410 for example);
@param pbWrappedKey(out) - array of CK_BYTEs to contain all listed key infos and wrapped key value
@param ulWrappedKeyLen(out) - length of pbWrappedKey
*/
void KeyManagmentClass::ExportSecPriKey (MY_KEY_TEMPLATE_INFO sKeyToExport, MY_KEY_TEMPLATE_INFO sPubKeyToWrapOn, 
										 MY_KEY_TEMPLATE_INFO sPriKeyToWrapOn, BYTE *pbWrappedKey, CK_ULONG *ulWrappedKeyLen)
{
	MY_KEY_TEMPLATE_INFO sKeyToExportExpParams, sPubKeyToWrapOnExpParams, sPriKeyToWrapOnExpParams, sWrappedKey;
	CK_OBJECT_HANDLE hKeyToExport = 0, hPubKeyToWrapOn = 0, hPriKeyToWrapOn = 0, hDHKey = 0, hKeyToWrapOn = 0;
	CK_BYTE_PTR pbPubKeyValue = NULL, pbTempBuffer = NULL;
	CK_ULONG ulPubKeyValueLen = 0, ulNumOfKeysFound = 0, ulTempKeyType = 0, ulTempBufferLen = 0;
	CK_MECHANISM cmDeriveMechanism, cmWrapMechanism;
	CK_ATTRIBUTE sPubKeyValue, sTempAttribute;
	CK_BYTE_PTR pbTempParsedData = NULL;
	CK_ULONG ulTempParsedDataLen = 0, ulParsedDataLen = 0;

#pragma region SomeShitForMakingMechanismsAndKeyDerivation
	CK_GOSTR3410_DERIVE_PARAMS sGost3410DeriveParams;
	CK_GR3410_VKO_DERIVE_PARAMS sGostShDeriveParams;
	CK_CP_G28147_WRAP_PARAMS sGostShWrapParams;
	CK_BYTE pbCryptParams[] = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01};
	char *pbScKeyOid = OID_CRYPT_A;
	CK_BYTE pbIv[] = {1,2,3,4,5,6,7,8};
	CK_ULONG ulKeyType = 0, ulDeriveKeyCount = 0;

	//GOST key derivation templates
	CK_ATTRIBUTE caGost3410DeriveKey[] =
	{
		{CKA_CLASS,			&ulClass_SecKey,		sizeof(CK_ULONG)},
		{CKA_KEY_TYPE,		&ulKeyType,				sizeof(CK_ULONG)},
		{CKA_TOKEN,			&blTrue,				sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,	&blFalse,				sizeof(CK_BBOOL)},
		{CKA_COPYABLE,		&blTrue,				sizeof(CK_BBOOL)},
		{CKA_PRIVATE,		&blTrue,				sizeof(CK_BBOOL)},
		{CKA_ENCRYPT,		&blTrue,				sizeof(CK_BBOOL)},
		{CKA_DECRYPT,		&blTrue,				sizeof(CK_BBOOL)},
		{CKA_WRAP,			&blTrue,				sizeof(CK_BBOOL)},
		{CKA_UNWRAP,		&blTrue,				sizeof(CK_BBOOL)},
		{CKA_GOST28147_PARAMS,	pbCryptParams,	_countof(pbCryptParams)}
	}; 
	CK_ATTRIBUTE caGostShDeriveKey[] =
	{
		{CKA_CLASS,    &ulClass_SecKey,      sizeof(CK_ULONG)},
		{CKA_KEY_TYPE, &ulKeyType,			 sizeof(CK_ULONG)},
		{CKA_TOKEN,    &blTrue,              sizeof(CK_BBOOL)},
		{CKA_PRIVATE,  &blTrue,              sizeof(CK_BBOOL)},
		{CKA_ENCRYPT,  &blTrue,              sizeof(CK_BBOOL)},
		{CKA_DECRYPT,  &blTrue,              sizeof(CK_BBOOL)},
		{CKA_WRAP,     &blTrue,              sizeof(CK_BBOOL)},
		{CKA_UNWRAP,   &blTrue,              sizeof(CK_BBOOL)},
		{SH_CKA_G28147_KEY_MESHING, &blTrue, sizeof(CK_BBOOL)},
		{CKA_OBJECT_ID, pbScKeyOid,          strlen(pbScKeyOid)}
	}; 

	sKeyToExportExpParams.ulNumOfParams = 0;
	sKeyToExportExpParams.psKeyParams = NULL;
	sPubKeyToWrapOnExpParams.ulNumOfParams = 0;
	sPubKeyToWrapOnExpParams.psKeyParams = NULL;
	sPriKeyToWrapOnExpParams.ulNumOfParams = 0;
	sPriKeyToWrapOnExpParams.psKeyParams = NULL;
	sTempAttribute.type = CKA_CLASS;
	sTempAttribute.ulValueLen = sizeof(CK_ULONG);
	sTempAttribute.pValue = &ulTempKeyType;

	*ulWrappedKeyLen = 0;
#pragma endregion
#pragma region ParsingInputAttributesToCheckIfItIsFirstCall
	ulTempParsedDataLen = 0;
	ulParsedDataLen = 0;

	ParseAttrs(sKeyToExport,NULL,&ulParsedDataLen);
	ulTempParsedDataLen += ulParsedDataLen;
	ulParsedDataLen = 0;
	ParseAttrs(sPubKeyToWrapOn,NULL,&ulParsedDataLen);
	ulTempParsedDataLen += ulParsedDataLen;
	ulParsedDataLen = 0;
	if (sPriKeyToWrapOn.ulNumOfParams)
	{
		ParseAttrs(sPriKeyToWrapOn,NULL,&ulParsedDataLen);
		ulTempParsedDataLen += ulParsedDataLen;
		ulParsedDataLen = 0;
	}
	if ((rvResult == CKR_OK)&&(ulTempParsedDataLen))
	{
		if (!(pbTempParsedData = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * ulTempParsedDataLen)))
		{
			rvResult = MEMORY_NOT_ALLOCATED;
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		}
		ulParsedDataLen = 0;
		ulTempParsedDataLen = 0;
		ParseAttrs(sKeyToExport,(CK_BYTE_PTR)(pbTempParsedData + ulTempParsedDataLen),&ulParsedDataLen);
		if (rvResult != CKR_OK)
		{
			free(pbTempParsedData);
			pbTempParsedData = NULL;
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		}
		ulTempParsedDataLen += ulParsedDataLen;
		
		ulParsedDataLen = 0;
		ParseAttrs(sPubKeyToWrapOn,(CK_BYTE_PTR)(pbTempParsedData + ulTempParsedDataLen),&ulParsedDataLen);
		if (rvResult != CKR_OK)
		{
			free(pbTempParsedData);
			pbTempParsedData = NULL;
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		}

		if (sPriKeyToWrapOn.ulNumOfParams)
		{
			ulParsedDataLen = 0;
			ParseAttrs(sPriKeyToWrapOn,(CK_BYTE_PTR)(pbTempParsedData + ulTempParsedDataLen),&ulParsedDataLen);
			if (rvResult != CKR_OK)
			{
				free(pbTempParsedData);
				pbTempParsedData = NULL;
				goto FINALIZE_EXPORT_PRISECKEY_WORK;
			}
			ulTempParsedDataLen += ulParsedDataLen;
		}
	}
	else
	{
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
	}

	if (ulTempParsedDataLen == ulInputParsedDataLen)
	{
		if (!memcmp(pbTempParsedData,pbInputParsedData,ulInputParsedDataLen))
		{
			if ((ulLastExpLen)&&(pbLastExported))
			{
				*ulWrappedKeyLen = ulLastExpLen;
				if (pbWrappedKey) memcpy(pbWrappedKey,pbLastExported,ulLastExpLen);
				goto FINALIZE_EXPORT_PRISECKEY_WORK;
			}
		}
	}

	ulInputParsedDataLen = ulTempParsedDataLen;
	if (pbInputParsedData) free (pbInputParsedData);
	pbInputParsedData = pbTempParsedData;
	pbTempParsedData = NULL;
	ulTempParsedDataLen = 0;
#pragma endregion
#pragma region LookingForKeyToExport
	//Try to find key to export:
	FindKeysByTemplate(sKeyToExport,NULL,&ulNumOfKeysFound);
	if (CKR_OK != rvResult)
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
	else if (ulNumOfKeysFound != 1)
	{
		if (ulNumOfKeysFound > 1)
			rvResult = CKR_TOO_MANY_KEYS_FOUND;
		if (ulNumOfKeysFound == 0)
			rvResult = CKR_KEYS_NOT_FOUND;
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
	}
	FindKeysByTemplate(sKeyToExport,&hKeyToExport,&ulNumOfKeysFound);
	if (CKR_OK != rvResult)
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
	//Check, that key is not public:
	rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hKeyToExport,&sTempAttribute,1);
	if (rvResult != CKR_OK)
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
	if (ulTempKeyType == CKO_PUBLIC_KEY)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
	}

	//Find key attributes to export to file with the key:
	sKeyToExportExpParams.ulNumOfParams = 6;
	sKeyToExportExpParams.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof (CK_ATTRIBUTE) * sKeyToExportExpParams.ulNumOfParams);
	sKeyToExportExpParams.psKeyParams[0].type = CKA_ID;
	sKeyToExportExpParams.psKeyParams[1].type = CKA_CLASS;
	sKeyToExportExpParams.psKeyParams[2].type = CKA_KEY_TYPE;
	sKeyToExportExpParams.psKeyParams[3].type = CKA_LABEL;
	sKeyToExportExpParams.psKeyParams[4].type = CKA_EXTRACTABLE;
	sKeyToExportExpParams.psKeyParams[5].type = CKA_G28147_PARAMETER_OID;
	for (CK_ULONG i = 0; i<sKeyToExportExpParams.ulNumOfParams; i++)
		sKeyToExportExpParams.psKeyParams[i].pValue = NULL;
	
	rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hKeyToExport,sKeyToExportExpParams.psKeyParams,sKeyToExportExpParams.ulNumOfParams);
	for (CK_ULONG i = 0; i<sKeyToExportExpParams.ulNumOfParams; i++)
	{
		if ((i == sKeyToExportExpParams.ulNumOfParams-1)&&(sKeyToExportExpParams.psKeyParams[i].ulValueLen == -1))
		{
			sKeyToExportExpParams.psKeyParams[sKeyToExportExpParams.ulNumOfParams-1].type = CKA_GOST28147_PARAMS;
			rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hKeyToExport,&(sKeyToExportExpParams.psKeyParams[sKeyToExportExpParams.ulNumOfParams-1]),1);
		}
		if (sKeyToExportExpParams.psKeyParams[i].ulValueLen == -1)
		{
			if (i == sKeyToExportExpParams.ulNumOfParams-1)
				sKeyToExportExpParams.ulNumOfParams--;
			else if (i == 3)
			{
				sKeyToExportExpParams.psKeyParams[i].ulValueLen = 0;
				sKeyToExportExpParams.psKeyParams[i].pValue = NULL;
			}
			else
			{
				if (rvResult == CKR_OK)
					rvResult = CKR_ATTRIBUTE_NOT_FOUND;
				goto FINALIZE_EXPORT_PRISECKEY_WORK;
			}
		}
		else
		{
			sKeyToExportExpParams.psKeyParams[i].pValue = malloc (sKeyToExportExpParams.psKeyParams[i].ulValueLen);
		}
	}

	rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hKeyToExport,sKeyToExportExpParams.psKeyParams,sKeyToExportExpParams.ulNumOfParams);
#pragma endregion
#pragma region LookingForPubKeyToWrapOn
	FindKeysByTemplate(sPubKeyToWrapOn,NULL,&ulNumOfKeysFound);
	if (CKR_OK != rvResult)
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
	else if (ulNumOfKeysFound != 1)
	{
		if (ulNumOfKeysFound > 1)
			rvResult = CKR_TOO_MANY_KEYS_FOUND;
		if (ulNumOfKeysFound == 0)
			rvResult = CKR_KEYS_NOT_FOUND;
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
	}
	FindKeysByTemplate(sPubKeyToWrapOn,&hPubKeyToWrapOn,&ulNumOfKeysFound);
	if (CKR_OK != rvResult)
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
	//check, if it is really public key
	rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPubKeyToWrapOn,&sTempAttribute,1);
	if (rvResult != CKR_OK)
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
	if (ulTempKeyType != CKO_PUBLIC_KEY)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
	}

	//Find key attributes to export to file with the key:
	sPubKeyToWrapOnExpParams.ulNumOfParams = 2;
	sPubKeyToWrapOnExpParams.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof (CK_ATTRIBUTE) * sPubKeyToWrapOnExpParams.ulNumOfParams);
	sPubKeyToWrapOnExpParams.psKeyParams[0].type = CKA_ID;
	sPubKeyToWrapOnExpParams.psKeyParams[1].type = CKA_KEY_TYPE;
	for (CK_ULONG i = 0; i<sPubKeyToWrapOnExpParams.ulNumOfParams; i++)
		sPubKeyToWrapOnExpParams.psKeyParams[i].pValue = NULL;
	
	rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPubKeyToWrapOn,sPubKeyToWrapOnExpParams.psKeyParams,sPubKeyToWrapOnExpParams.ulNumOfParams);
	for (CK_ULONG i = 0; i<sPubKeyToWrapOnExpParams.ulNumOfParams; i++)
	{
		if (sPubKeyToWrapOnExpParams.psKeyParams[i].ulValueLen == -1)
		{
			if (rvResult == CKR_OK)
				rvResult = CKR_ATTRIBUTE_NOT_FOUND;
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		}
		else
		{
			sPubKeyToWrapOnExpParams.psKeyParams[i].pValue = malloc (sPubKeyToWrapOnExpParams.psKeyParams[i].ulValueLen);
		}
	}

	rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPubKeyToWrapOn,sPubKeyToWrapOnExpParams.psKeyParams,sPubKeyToWrapOnExpParams.ulNumOfParams);
#pragma endregion
#pragma region LookingForPriKeyToWrapOn
	if (!((*((CK_ULONG_PTR)(sPubKeyToWrapOnExpParams.psKeyParams[1].pValue)) == CKK_GR3410EL)||
		(*((CK_ULONG_PTR)(sPubKeyToWrapOnExpParams.psKeyParams[1].pValue)) == CKK_GOSTR3410)))
	{
		//No need in Private key
		sPriKeyToWrapOnExpParams.ulNumOfParams = 1;
		sPriKeyToWrapOnExpParams.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof (CK_ATTRIBUTE) * sPriKeyToWrapOnExpParams.ulNumOfParams);
		sPriKeyToWrapOnExpParams.psKeyParams[0].type = CKA_ID;
		sPriKeyToWrapOnExpParams.psKeyParams[0].pValue = malloc(4);
		for (CK_ULONG i = 0; i<4; i++)
			((CK_BYTE_PTR)sPriKeyToWrapOnExpParams.psKeyParams[0].pValue)[i] = 0;
		sPriKeyToWrapOnExpParams.psKeyParams[0].ulValueLen = 0;
		//copy key handle to the hKeyToWrapOn
		hKeyToWrapOn = hPubKeyToWrapOn;
	}
	else
	{
		FindKeysByTemplate(sPriKeyToWrapOn,NULL,&ulNumOfKeysFound);
		if (CKR_OK != rvResult)
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		else if (ulNumOfKeysFound != 1)
		{
			if (ulNumOfKeysFound > 1)
				rvResult = CKR_TOO_MANY_KEYS_FOUND;
			if (ulNumOfKeysFound == 0)
				rvResult = CKR_KEYS_NOT_FOUND;
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		}
		FindKeysByTemplate(sPriKeyToWrapOn,&hPriKeyToWrapOn,&ulNumOfKeysFound);
		if (CKR_OK != rvResult)
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		//check if key is private:
		rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPriKeyToWrapOn,&sTempAttribute,1);
		if (rvResult != CKR_OK)
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		if (ulTempKeyType == CKO_PUBLIC_KEY)
		{
			rvResult = CKR_ARGUMENTS_BAD;
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		}

		//Find key attributes to export to file with the key:
		sPriKeyToWrapOnExpParams.ulNumOfParams = 1;
		sPriKeyToWrapOnExpParams.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof (CK_ATTRIBUTE) * sPriKeyToWrapOnExpParams.ulNumOfParams);
		sPriKeyToWrapOnExpParams.psKeyParams[0].type = CKA_ID;
		for (CK_ULONG i = 0; i<sPriKeyToWrapOnExpParams.ulNumOfParams; i++)
			sPriKeyToWrapOnExpParams.psKeyParams[i].pValue = NULL;
		
		rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPriKeyToWrapOn,sPriKeyToWrapOnExpParams.psKeyParams,sPriKeyToWrapOnExpParams.ulNumOfParams);
		for (CK_ULONG i = 0; i<sPriKeyToWrapOnExpParams.ulNumOfParams; i++)
		{
			if (sPriKeyToWrapOnExpParams.psKeyParams[i].ulValueLen == -1)
			{
				if (rvResult == CKR_OK)
					rvResult = CKR_ATTRIBUTE_NOT_FOUND;
				goto FINALIZE_EXPORT_PRISECKEY_WORK;
			}
			else
			{
				sPriKeyToWrapOnExpParams.psKeyParams[i].pValue = (PBYTE) malloc (sPriKeyToWrapOnExpParams.psKeyParams[i].ulValueLen);
			}
		}

		rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPriKeyToWrapOn,sPriKeyToWrapOnExpParams.psKeyParams,sPriKeyToWrapOnExpParams.ulNumOfParams);
	}
#pragma endregion
#pragma region DerivingKeyIfNeeded
	switch(*((CK_ULONG_PTR)(sPubKeyToWrapOnExpParams.psKeyParams[1].pValue)))
	{
	case CKK_GOSTR3410:
		//get info public key value:
		sPubKeyValue.type = CKA_VALUE;
		sPubKeyValue.ulValueLen = 0;
		sPubKeyValue.pValue = pbPubKeyValue;
		rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPubKeyToWrapOn,&sPubKeyValue,1);
		if (rvResult != CKR_OK)
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		if (sPubKeyValue.ulValueLen == -1)
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		pbPubKeyValue = (CK_BYTE_PTR) malloc (sPubKeyValue.ulValueLen);
		sPubKeyValue.pValue = pbPubKeyValue;
		rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPubKeyToWrapOn,&sPubKeyValue,1);
		if (rvResult != CKR_OK)
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		ulPubKeyValueLen = sPubKeyValue.ulValueLen;

		//making derivation mechanism:
		sGost3410DeriveParams.kdf	= CKD_NULL; // not use key diversification
		sGost3410DeriveParams.ulUKMLen	= 8;
		sGost3410DeriveParams.pUKM = (CK_BYTE_PTR)pbIv;

		sGost3410DeriveParams.pPublicData = pbPubKeyValue;
		sGost3410DeriveParams.ulPublicDataLen = ulPubKeyValueLen;

		cmDeriveMechanism.mechanism = CKM_GOSTR3410_DERIVE;
		cmDeriveMechanism.pParameter = &sGost3410DeriveParams;
		cmDeriveMechanism.ulParameterLen = sizeof(CK_GOSTR3410_DERIVE_PARAMS);

		ulKeyType = CKK_GOST28147;
		ulDeriveKeyCount = ARRAYSIZE(caGost3410DeriveKey);

		rvResult = Pkcs11FuncList->C_DeriveKey(hSession,&cmDeriveMechanism,hPriKeyToWrapOn,caGost3410DeriveKey,ulDeriveKeyCount,&hKeyToWrapOn);
		if (rvResult!= CKR_OK)
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		break;
	case CKK_GR3410EL:
		//get info public key value:
		sPubKeyValue.type = CKA_VALUE;
		sPubKeyValue.ulValueLen = 0;
		sPubKeyValue.pValue = pbPubKeyValue;
		rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPubKeyToWrapOn,&sPubKeyValue,1);
		if (rvResult != CKR_OK)
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		if (sPubKeyValue.ulValueLen == -1)
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		pbPubKeyValue = (CK_BYTE_PTR) malloc (sPubKeyValue.ulValueLen);
		sPubKeyValue.pValue = pbPubKeyValue;
		rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPubKeyToWrapOn,&sPubKeyValue,1);
		if (rvResult != CKR_OK)
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		ulPubKeyValueLen = sPubKeyValue.ulValueLen;

		//making derivation mechanism:
		sGostShDeriveParams.kdf	= 0;
		sGostShDeriveParams.ivSrc = CKD_CP_IV_RANDOM;
		for(int i=0; i<8; ++i) sGostShDeriveParams.iv[i] = 0;

		sGostShDeriveParams.ulHashOIDLen = strlen(OID_EC_A);
		sGostShDeriveParams.pHashOID = (CK_BYTE_PTR)OID_EC_A;

		sGostShDeriveParams.pPublicData = (CK_BYTE_PTR) pbPubKeyValue;
		sGostShDeriveParams.ulPublicDataLen = ulPubKeyValueLen;

		cmDeriveMechanism.mechanism = CKM_GR3410EL_DERIVE;
		cmDeriveMechanism.pParameter = &sGostShDeriveParams;
		cmDeriveMechanism.ulParameterLen = sizeof(CK_GR3410_VKO_DERIVE_PARAMS);

		ulKeyType = CKK_G28147;
		ulDeriveKeyCount = ARRAYSIZE(caGostShDeriveKey);

		rvResult = Pkcs11FuncList->C_DeriveKey(hSession,&cmDeriveMechanism,hPriKeyToWrapOn,caGostShDeriveKey,ulDeriveKeyCount,&hKeyToWrapOn);
		if (rvResult!= CKR_OK)
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		break;
	default:
		break;
	}
#pragma endregion
#pragma region MakingWrapMechanismParams
	switch(*((CK_ULONG_PTR)(sPubKeyToWrapOnExpParams.psKeyParams[1].pValue)))
	{
	case CKK_GOSTR3410:
		cmWrapMechanism.mechanism = CKM_GOST28147_KEY_WRAP;
		cmWrapMechanism.ulParameterLen = 8;
		cmWrapMechanism.pParameter = (CK_BYTE_PTR)pbIv;
		break;
	case CKK_GR3410EL:
		sGostShWrapParams.wa = CKD_CP_G28147_WRAP_PRO;
		cmWrapMechanism.pParameter = &sGostShWrapParams;
		cmWrapMechanism.mechanism = CKM_CP_G28147_WRAP;
		cmWrapMechanism.ulParameterLen = sizeof(CK_CP_G28147_WRAP_PARAMS);
		break;
	case CKK_RSA:
		cmWrapMechanism.mechanism = SH_CKM_PKCS1_SIMPLE_BLOB_WRAP_KEY;//CKM_RSA_PKCS;
		cmWrapMechanism.ulParameterLen = 0;
		cmWrapMechanism.pParameter = NULL_PTR;
		break;
	default:
		rvResult = CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
		break;
	}
#pragma endregion
#pragma region WrappingPriSecKey
	sTempAttribute.type = CKA_WRAPPED_KEY;
	sTempAttribute.pValue = NULL;
	sTempAttribute.ulValueLen = 0;
	rvResult = Pkcs11FuncList->C_WrapKey(hSession,&cmWrapMechanism,hKeyToWrapOn,hKeyToExport,(CK_BYTE_PTR)(sTempAttribute.pValue),&(sTempAttribute.ulValueLen));
	if (rvResult != CKR_OK)
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
	sTempAttribute.pValue = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * sTempAttribute.ulValueLen);
	rvResult = Pkcs11FuncList->C_WrapKey(hSession,&cmWrapMechanism,hKeyToWrapOn,hKeyToExport,(CK_BYTE_PTR)(sTempAttribute.pValue),&(sTempAttribute.ulValueLen));
	if (rvResult != CKR_OK)
	{
		if (sTempAttribute.pValue) free (sTempAttribute.pValue);
		sTempAttribute.pValue = NULL;
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
	}
	sWrappedKey.ulNumOfParams = 1;
	sWrappedKey.psKeyParams = &sTempAttribute;
#pragma endregion
#pragma region ParsingWrappedKeyAndItsInfo
	ulTempParsedDataLen = 0;
	
	ulParsedDataLen = 0;
	ParseAttrs(sKeyToExportExpParams,NULL,&ulParsedDataLen);
	ulTempParsedDataLen += ulParsedDataLen;
	ulParsedDataLen = 0;
	ParseAttrs(sPubKeyToWrapOnExpParams,NULL,&ulParsedDataLen);
	ulTempParsedDataLen += ulParsedDataLen;
	ulParsedDataLen = 0;
	ParseAttrs(sPriKeyToWrapOnExpParams,NULL,&ulParsedDataLen);
	ulTempParsedDataLen += ulParsedDataLen;
	ulParsedDataLen = 0;
	ParseAttrs(sWrappedKey,NULL,&ulParsedDataLen);
	ulTempParsedDataLen += ulParsedDataLen;

	if ((rvResult == CKR_OK)&&(ulTempParsedDataLen))
	{
		if (!(pbTempParsedData = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * ulTempParsedDataLen)))
		{
			rvResult = MEMORY_NOT_ALLOCATED;
			goto FINALIZE_EXPORT_PRISECKEY_WORK;
		}
		ulTempParsedDataLen = 0;
		
		ulParsedDataLen = 0;
		ParseAttrs(sKeyToExportExpParams,(CK_BYTE_PTR)(pbTempParsedData + ulTempParsedDataLen),&ulParsedDataLen);
		ulTempParsedDataLen += ulParsedDataLen;
		ulParsedDataLen = 0;  
		ParseAttrs(sPubKeyToWrapOnExpParams,(CK_BYTE_PTR)(pbTempParsedData + ulTempParsedDataLen),&ulParsedDataLen);
		ulTempParsedDataLen += ulParsedDataLen;
		ulParsedDataLen = 0;
		ParseAttrs(sPriKeyToWrapOnExpParams,(CK_BYTE_PTR)(pbTempParsedData + ulTempParsedDataLen),&ulParsedDataLen);
		ulTempParsedDataLen += ulParsedDataLen;
		ulParsedDataLen = 0;
		ParseAttrs(sWrappedKey,(CK_BYTE_PTR)(pbTempParsedData + ulTempParsedDataLen),&ulParsedDataLen);
		ulTempParsedDataLen += ulParsedDataLen;

		if (pbLastExported) free (pbLastExported);
		ulLastExpLen = ulTempParsedDataLen;
		pbLastExported = pbTempParsedData;
		pbTempParsedData = NULL;
	}
	else
	{
		if (rvResult == CKR_OK)
		{
			rvResult = CKR_DATA_INVALID;
		}
		goto FINALIZE_EXPORT_PRISECKEY_WORK;
	}
	*ulWrappedKeyLen = ulLastExpLen;
	if (pbWrappedKey) memcpy (pbWrappedKey, pbLastExported, ulLastExpLen);
#pragma endregion

FINALIZE_EXPORT_PRISECKEY_WORK:
#pragma region FinalizeWork
	sWrappedKey.psKeyParams = NULL;
	if (sTempAttribute.type == CKA_WRAPPED_KEY)
		if (sTempAttribute.pValue) 
			free (sTempAttribute.pValue);

	//deleting derived key, if there is any:
	sTempAttribute.type = CKA_CLASS;
	sTempAttribute.pValue = &ulTempKeyType;
	sTempAttribute.ulValueLen = sizeof(CK_ULONG);

	if (hKeyToWrapOn)
	{
		Pkcs11FuncList->C_GetAttributeValue(hSession,hKeyToWrapOn,&sTempAttribute,1);
		if (ulTempKeyType == CKO_SECRET_KEY)
		{
			Pkcs11FuncList->C_DestroyObject(hSession, hKeyToWrapOn);
		}
	}

	if (pbPubKeyValue) free (pbPubKeyValue);
	if (sKeyToExportExpParams.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sKeyToExportExpParams.ulNumOfParams; i++)
		{
			if (sKeyToExportExpParams.psKeyParams[i].pValue)
				free (sKeyToExportExpParams.psKeyParams[i].pValue);
		}
		free (sKeyToExportExpParams.psKeyParams);
	}
	if (sPubKeyToWrapOnExpParams.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sPubKeyToWrapOnExpParams.ulNumOfParams; i++)
		{
			if (sPubKeyToWrapOnExpParams.psKeyParams[i].pValue)
				free (sPubKeyToWrapOnExpParams.psKeyParams[i].pValue);
		}
		free (sPubKeyToWrapOnExpParams.psKeyParams);
	}
	if (sPriKeyToWrapOnExpParams.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sPriKeyToWrapOnExpParams.ulNumOfParams; i++)
		{
			if (sPriKeyToWrapOnExpParams.psKeyParams[i].pValue)
				free (sPriKeyToWrapOnExpParams.psKeyParams[i].pValue);
		}
		free (sPriKeyToWrapOnExpParams.psKeyParams);
	}
#pragma endregion
}
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to import public key
@param pbExportedKey(in) - array of CK_BYTEs containinig importing key info and its value
@param ulExportedKeyLen(in) - length of pbExportedKey
*/
void KeyManagmentClass::ImportPublicKey (BYTE *pbExportedKey, CK_ULONG ulExportedKeyLen)
{
	MY_KEY_TEMPLATE_INFO sUnparsedAttrs, sAttrsToCheckKey, sAttrsToImportKey;
	CK_ULONG ulNumOfKeysFound = 0, ulLabelCounter = 0, ulAttrCounter = 0, ulClassCounter = 0;
	CK_OBJECT_HANDLE hImportedKey = 0;

	sUnparsedAttrs.ulNumOfParams = 0;
	sUnparsedAttrs.psKeyParams = NULL;
	sAttrsToCheckKey.ulNumOfParams = 0;
	sAttrsToCheckKey.psKeyParams = NULL;
	sAttrsToImportKey.ulNumOfParams = 0;
	sAttrsToImportKey.psKeyParams = NULL;

#pragma region UnparsingAttributes
	UnparseAttrs(pbExportedKey,ulExportedKeyLen,&sUnparsedAttrs);
	if (CKR_OK != rvResult)	goto IMPORT_PUBLIC_KEY_FINALIZATION;
	sUnparsedAttrs.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE) * sUnparsedAttrs.ulNumOfParams);
	for (CK_ULONG i = 0; i<sUnparsedAttrs.ulNumOfParams; i++)
	{
		sUnparsedAttrs.psKeyParams[i].pValue = NULL;
		sUnparsedAttrs.psKeyParams[i].ulValueLen = 0;
	}
	UnparseAttrs(pbExportedKey,ulExportedKeyLen,&sUnparsedAttrs);
	if (CKR_OK != rvResult)	goto IMPORT_PUBLIC_KEY_FINALIZATION;
	for (CK_ULONG i = 0; i<sUnparsedAttrs.ulNumOfParams; i++)
	{
		sUnparsedAttrs.psKeyParams[i].pValue = (CK_BYTE_PTR) malloc (sizeof(CK_BYTE) * sUnparsedAttrs.psKeyParams[i].ulValueLen);
	}
	UnparseAttrs(pbExportedKey,ulExportedKeyLen,&sUnparsedAttrs);
	if (CKR_OK != rvResult)	goto IMPORT_PUBLIC_KEY_FINALIZATION;
#pragma endregion
#pragma region CheckingIfKeyAlreadyExists
	//check by ID, Type and Class 
	sAttrsToCheckKey.ulNumOfParams = 3;
	sAttrsToCheckKey.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE) * sAttrsToCheckKey.ulNumOfParams);
	sAttrsToCheckKey.psKeyParams[0].type = CKA_CLASS;
	sAttrsToCheckKey.psKeyParams[0].ulValueLen = sizeof(CK_ULONG);
	sAttrsToCheckKey.psKeyParams[0].pValue = &ulClass_PubKey;

	for (CK_ULONG i = 0; i<sUnparsedAttrs.ulNumOfParams; i++)
	{
		switch(sUnparsedAttrs.psKeyParams[i].type)
		{
		case CKA_ID:
			sAttrsToCheckKey.psKeyParams[1].type = sUnparsedAttrs.psKeyParams[i].type;
			sAttrsToCheckKey.psKeyParams[1].ulValueLen = sUnparsedAttrs.psKeyParams[i].ulValueLen;
			sAttrsToCheckKey.psKeyParams[1].pValue = sUnparsedAttrs.psKeyParams[i].pValue;
			break;
		case CKA_KEY_TYPE:
			sAttrsToCheckKey.psKeyParams[2].type = sUnparsedAttrs.psKeyParams[i].type;
			sAttrsToCheckKey.psKeyParams[2].ulValueLen = sUnparsedAttrs.psKeyParams[i].ulValueLen;
			sAttrsToCheckKey.psKeyParams[2].pValue = sUnparsedAttrs.psKeyParams[i].pValue;
			break;
		case CKA_LABEL:
			if (sUnparsedAttrs.psKeyParams[i].ulValueLen) ulLabelCounter = 0;
			else ulLabelCounter = -1;		//means it's not present
			break;
		case CKA_CLASS:
			ulClassCounter = -1;		//means it's present
			break;
		default:
			break;
		}
	}
	FindKeysByTemplate(sAttrsToCheckKey,NULL,&ulNumOfKeysFound);
	if (rvResult != CKR_OK)	goto IMPORT_PUBLIC_KEY_FINALIZATION;
	if (ulNumOfKeysFound)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto IMPORT_PUBLIC_KEY_FINALIZATION;
	}
#pragma endregion
#pragma region MakingAttributesToImportKey
	sAttrsToImportKey.ulNumOfParams = sUnparsedAttrs.ulNumOfParams + 2 + ulLabelCounter + ulClassCounter;			//2 def arguments: CKA_TOKEN = TRUE; CKA_CLASS = CKO_PUBLIC_KEY
	sAttrsToImportKey.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE) * sAttrsToImportKey.ulNumOfParams);
	sAttrsToImportKey.psKeyParams[ulAttrCounter].type = CKA_CLASS;
	sAttrsToImportKey.psKeyParams[ulAttrCounter].ulValueLen = sizeof(CK_ULONG);
	sAttrsToImportKey.psKeyParams[ulAttrCounter].pValue = &ulClass_PubKey;
	ulAttrCounter++;
	sAttrsToImportKey.psKeyParams[ulAttrCounter].type = CKA_TOKEN;
	sAttrsToImportKey.psKeyParams[ulAttrCounter].ulValueLen = sizeof(CK_BBOOL);
	sAttrsToImportKey.psKeyParams[ulAttrCounter].pValue = &blTrue;
	ulAttrCounter++;

	for (CK_ULONG i = 0; i<sUnparsedAttrs.ulNumOfParams; i++)
	{
		if ((sUnparsedAttrs.psKeyParams[i].type != CKA_CLASS)&&
			!((sUnparsedAttrs.psKeyParams[i].type == CKA_LABEL)&&(!(sUnparsedAttrs.psKeyParams[i].ulValueLen))))
		{
			sAttrsToImportKey.psKeyParams[ulAttrCounter].type = sUnparsedAttrs.psKeyParams[i].type;
			sAttrsToImportKey.psKeyParams[ulAttrCounter].ulValueLen = sUnparsedAttrs.psKeyParams[i].ulValueLen;
			sAttrsToImportKey.psKeyParams[ulAttrCounter].pValue = sUnparsedAttrs.psKeyParams[i].pValue;
			ulAttrCounter++;
		}
	}
#pragma endregion

#pragma region ImportingKey
	rvResult = Pkcs11FuncList->C_CreateObject(hSession,sAttrsToImportKey.psKeyParams,sAttrsToImportKey.ulNumOfParams,&hImportedKey);
#pragma endregion

#pragma region ImportPubKeyFinalization
IMPORT_PUBLIC_KEY_FINALIZATION:
	if (sAttrsToCheckKey.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sAttrsToCheckKey.ulNumOfParams; i++)
			sAttrsToCheckKey.psKeyParams[i].pValue = NULL;
		free (sAttrsToCheckKey.psKeyParams);
	}
	if (sAttrsToImportKey.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sAttrsToImportKey.ulNumOfParams; i++)
			sAttrsToImportKey.psKeyParams[i].pValue = NULL;
		free (sAttrsToImportKey.psKeyParams);
	}
	if (sUnparsedAttrs.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sUnparsedAttrs.ulNumOfParams; i++)
		{
			if (sUnparsedAttrs.psKeyParams[i].pValue) free (sUnparsedAttrs.psKeyParams[i].pValue);
			sUnparsedAttrs.psKeyParams[i].pValue = NULL;
		}
		free (sUnparsedAttrs.psKeyParams);
	}
#pragma endregion
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to import secret or private key
@param sPubKeyToUnwrapOn(in) - Attributes of public key to import on;
@param sPriKeyToUnwrapOn(in) - Attributes of private key to import on, if it is needed (for Gost 3410 for example);
@param pbExportedKey(out) - array of CK_BYTEs to contain all listed key infos, wrapped key info and value
@param ulExportedKeyLen(out) - length of pbWrappedKey
*/
void KeyManagmentClass::ImportSecPriKey (MY_KEY_TEMPLATE_INFO sPubKeyToUnwrapOn, MY_KEY_TEMPLATE_INFO sPriKeyToUnwrapOn,
										 BYTE *pbExportedKey, CK_ULONG ulExportedKeyLen)
{
	MY_KEY_TEMPLATE_INFO sUnparsedAttrs, sPubKey, sPriKey, sImportedKey;
	CK_ULONG ulCounter = 0, ulNumOfKeysFound = 0, ulPrivateKeyType = -1, ulTempKeyType = 0;
	CK_OBJECT_HANDLE hImportedKey = 0, hPubKey = 0, hPriKey = 0, hKeyToUnwrapOn = 0;
	CK_ATTRIBUTE sTempAttribute, sPubKeyValue;
	CK_MECHANISM cmDeriveMechanism, cmWrapMechanism;

#pragma region SomeTemplatesForKeyDerivation
	CK_ULONG ulKeyType = -1, ulDeriveKeyCount = 0;
	CK_GOSTR3410_DERIVE_PARAMS sGost3410DeriveParams;
	CK_GR3410_VKO_DERIVE_PARAMS sGostShDeriveParams;
	CK_CP_G28147_WRAP_PARAMS sGostShWrapParams;
	CK_BYTE pbCryptParams[] = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01};
	char *pbScKeyOid = OID_CRYPT_A;
	CK_BYTE pbIv[] = {1,2,3,4,5,6,7,8};

	//GOST key derivation templates
	CK_ATTRIBUTE caGost3410DeriveKey[] =
	{
		{CKA_CLASS,			&ulClass_SecKey,		sizeof(CK_ULONG)},
		{CKA_KEY_TYPE,		&ulKeyType,				sizeof(CK_ULONG)},
		{CKA_TOKEN,			&blTrue,				sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,	&blFalse,				sizeof(CK_BBOOL)},
		{CKA_COPYABLE,		&blTrue,				sizeof(CK_BBOOL)},
		{CKA_PRIVATE,		&blTrue,				sizeof(CK_BBOOL)},
		{CKA_ENCRYPT,		&blTrue,				sizeof(CK_BBOOL)},
		{CKA_DECRYPT,		&blTrue,				sizeof(CK_BBOOL)},
		{CKA_WRAP,			&blTrue,				sizeof(CK_BBOOL)},
		{CKA_UNWRAP,		&blTrue,				sizeof(CK_BBOOL)},
		{CKA_GOST28147_PARAMS,	pbCryptParams,	_countof(pbCryptParams)}
	}; 
	CK_ATTRIBUTE caGostShDeriveKey[] =
	{
		{CKA_CLASS,    &ulClass_SecKey,      sizeof(CK_ULONG)},
		{CKA_KEY_TYPE, &ulKeyType,			 sizeof(CK_ULONG)},
		{CKA_TOKEN,    &blTrue,              sizeof(CK_BBOOL)},
		{CKA_PRIVATE,  &blTrue,              sizeof(CK_BBOOL)},
		{CKA_ENCRYPT,  &blTrue,              sizeof(CK_BBOOL)},
		{CKA_DECRYPT,  &blTrue,              sizeof(CK_BBOOL)},
		{CKA_WRAP,     &blTrue,              sizeof(CK_BBOOL)},
		{CKA_UNWRAP,   &blTrue,              sizeof(CK_BBOOL)},
		{SH_CKA_G28147_KEY_MESHING, &blTrue, sizeof(CK_BBOOL)},
		{CKA_OBJECT_ID, pbScKeyOid,          strlen(pbScKeyOid)}
	}; 
#pragma endregion

	sUnparsedAttrs.ulNumOfParams = 0;
	sUnparsedAttrs.psKeyParams = NULL;
	sImportedKey.ulNumOfParams = 0;
	sImportedKey.psKeyParams = NULL;
	sPubKey.ulNumOfParams = 0;
	sPubKey.psKeyParams = NULL;
	sPriKey.ulNumOfParams = 0;
	sPriKey.psKeyParams = NULL;

	sPubKeyValue.pValue = NULL;
	sPubKeyValue.ulValueLen = 0;
	sTempAttribute.pValue = NULL;
	sTempAttribute.ulValueLen = 0;

#pragma region UnparsingAttributes
	UnparseAttrs(pbExportedKey,ulExportedKeyLen,&sUnparsedAttrs);
	if (CKR_OK != rvResult)	goto IMPORT_PRISECKEY_FINALIZATION;
	sUnparsedAttrs.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE) * sUnparsedAttrs.ulNumOfParams);
	for (CK_ULONG i = 0; i<sUnparsedAttrs.ulNumOfParams; i++)
	{
		sUnparsedAttrs.psKeyParams[i].pValue = NULL;
		sUnparsedAttrs.psKeyParams[i].ulValueLen = 0;
	}
	UnparseAttrs(pbExportedKey,ulExportedKeyLen,&sUnparsedAttrs);
	if (CKR_OK != rvResult)	goto IMPORT_PRISECKEY_FINALIZATION;
	for (CK_ULONG i = 0; i<sUnparsedAttrs.ulNumOfParams; i++)
	{
		sUnparsedAttrs.psKeyParams[i].pValue = (CK_BYTE_PTR) malloc (sizeof(CK_BYTE) * sUnparsedAttrs.psKeyParams[i].ulValueLen);
	}
	UnparseAttrs(pbExportedKey,ulExportedKeyLen,&sUnparsedAttrs);
	if (CKR_OK != rvResult)	goto IMPORT_PRISECKEY_FINALIZATION;
#pragma endregion
#pragma region MakingKeyInfos
#pragma region CountingNumOfAttrsForEachKeyInfo
	if (sUnparsedAttrs.psKeyParams[ulCounter].type != CKA_ID)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto IMPORT_PRISECKEY_FINALIZATION;
	}
	sImportedKey.ulNumOfParams = 1;
	ulCounter++;
	while (sUnparsedAttrs.psKeyParams[ulCounter].type != CKA_ID)
	{
		sImportedKey.ulNumOfParams++;
		ulCounter++;
		if (ulCounter == sUnparsedAttrs.ulNumOfParams) break;
	}
	if (ulCounter == sUnparsedAttrs.ulNumOfParams)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto IMPORT_PRISECKEY_FINALIZATION;
	}
	sPriKey.ulNumOfParams = 2;
	ulCounter++;
	while (sUnparsedAttrs.psKeyParams[ulCounter].type != CKA_ID)
	{
		sPriKey.ulNumOfParams++;
		ulCounter++;
		if (ulCounter == sUnparsedAttrs.ulNumOfParams) break;
	}
	if (ulCounter == sUnparsedAttrs.ulNumOfParams)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto IMPORT_PRISECKEY_FINALIZATION;
	}
	sPubKey.ulNumOfParams = 2;
	ulCounter++;
	while (sUnparsedAttrs.psKeyParams[ulCounter].type != CKA_WRAPPED_KEY)
	{
		sPubKey.ulNumOfParams++;
		ulCounter++;
		if (ulCounter == sUnparsedAttrs.ulNumOfParams) break;
	}
	if (ulCounter != sUnparsedAttrs.ulNumOfParams - 1)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto IMPORT_PRISECKEY_FINALIZATION;
	}
#pragma endregion
#pragma region AllocatingMemory
	sImportedKey.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE) * sImportedKey.ulNumOfParams);
	for (CK_ULONG i = 0; i<sImportedKey.ulNumOfParams; i++)
	{
		sImportedKey.psKeyParams[i].pValue = NULL;
		sImportedKey.psKeyParams[i].ulValueLen = 0;
	}
	sPubKey.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE) * sPubKey.ulNumOfParams);
	for (CK_ULONG i = 0; i<sPubKey.ulNumOfParams; i++)
	{
		sPubKey.psKeyParams[i].pValue = NULL;
		sPubKey.psKeyParams[i].ulValueLen = 0;
	}
	sPriKey.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE) * sPriKey.ulNumOfParams);
	for (CK_ULONG i = 0; i<sPriKey.ulNumOfParams; i++)
	{
		sPriKey.psKeyParams[i].pValue = NULL;
		sPriKey.psKeyParams[i].ulValueLen = 0;
	}
#pragma endregion
#pragma region CopyingAttributesIfNeeded
	ulCounter = 0;
	for (CK_ULONG i = 0; i<sImportedKey.ulNumOfParams; i++)
	{
		sImportedKey.psKeyParams[i].type = sUnparsedAttrs.psKeyParams[ulCounter].type;
		sImportedKey.psKeyParams[i].pValue = sUnparsedAttrs.psKeyParams[ulCounter].pValue;
		sImportedKey.psKeyParams[i].ulValueLen = sUnparsedAttrs.psKeyParams[ulCounter].ulValueLen;
		ulCounter++;
	}

	sPriKey.psKeyParams[0].type = CKA_CLASS;
	sPriKey.psKeyParams[0].ulValueLen = sizeof(CK_ULONG);
	sPriKey.psKeyParams[0].pValue = &ulClass_PriKey;
	for (CK_ULONG i = 1; i<sPriKey.ulNumOfParams; i++)
	{
		sPriKey.psKeyParams[i].type = sUnparsedAttrs.psKeyParams[ulCounter].type;
		sPriKey.psKeyParams[i].pValue = sUnparsedAttrs.psKeyParams[ulCounter].pValue;
		sPriKey.psKeyParams[i].ulValueLen = sUnparsedAttrs.psKeyParams[ulCounter].ulValueLen;
		ulCounter++;
	}

	sPubKey.psKeyParams[0].type = CKA_CLASS;
	sPubKey.psKeyParams[0].ulValueLen = sizeof(CK_ULONG);
	sPubKey.psKeyParams[0].pValue = &ulClass_PubKey;
	for (CK_ULONG i = 1; i<sPubKey.ulNumOfParams; i++)
	{
		sPubKey.psKeyParams[i].type = sUnparsedAttrs.psKeyParams[ulCounter].type;
		sPubKey.psKeyParams[i].pValue = sUnparsedAttrs.psKeyParams[ulCounter].pValue;
		sPubKey.psKeyParams[i].ulValueLen = sUnparsedAttrs.psKeyParams[ulCounter].ulValueLen;
		ulCounter++;
	}
#pragma endregion
#pragma endregion
#pragma region CheckIfKeyToImportIsAlreadyInDevice
	ulNumOfKeysFound = 0;
	//Try to find key in device:
	FindKeysByTemplate(sImportedKey,NULL,&ulNumOfKeysFound);
	if (ulNumOfKeysFound)
	{
		rvResult = CKR_TOO_MANY_KEYS_FOUND;
		goto IMPORT_PRISECKEY_FINALIZATION;
	}
#pragma endregion
#pragma region LookingForPriKeyToUnwrapOn
	//checking if there is user key info:
	if (sPriKeyToUnwrapOn.ulNumOfParams)
	{
		ulNumOfKeysFound = 0;
		FindKeysByTemplate(sPriKeyToUnwrapOn,NULL,&ulNumOfKeysFound);
		if (rvResult != CKR_OK) goto IMPORT_PRISECKEY_FINALIZATION;
		if (ulNumOfKeysFound != 1)
		{
			if (ulNumOfKeysFound > 1)
				rvResult = CKR_TOO_MANY_KEYS_FOUND;
			if (ulNumOfKeysFound == 0)
				rvResult = CKR_KEYS_NOT_FOUND;
			goto IMPORT_PRISECKEY_FINALIZATION;
		}
		FindKeysByTemplate(sPriKeyToUnwrapOn,&hPriKey,&ulNumOfKeysFound);
		if (rvResult != CKR_OK) goto IMPORT_PRISECKEY_FINALIZATION;
	}
	else
	{
		ulNumOfKeysFound = 0;
		FindKeysByTemplate(sPriKey,NULL,&ulNumOfKeysFound);
		if (rvResult != CKR_OK) goto IMPORT_PRISECKEY_FINALIZATION;
		if (ulNumOfKeysFound != 1)
		{
			if (ulNumOfKeysFound > 1)
				rvResult = CKR_TOO_MANY_KEYS_FOUND;
			if (ulNumOfKeysFound == 0)
				rvResult = CKR_KEYS_NOT_FOUND;
			goto IMPORT_PRISECKEY_FINALIZATION;
		}
		FindKeysByTemplate(sPriKey,&hPriKey,&ulNumOfKeysFound);
		if (rvResult != CKR_OK) goto IMPORT_PRISECKEY_FINALIZATION;
	}
#pragma endregion
#pragma region LookingForPubKeyToUnwrapOn
	if (sPubKeyToUnwrapOn.ulNumOfParams)
	{
		ulNumOfKeysFound = 0;
		FindKeysByTemplate(sPubKeyToUnwrapOn,NULL,&ulNumOfKeysFound);
		if (rvResult != CKR_OK) goto IMPORT_PRISECKEY_FINALIZATION;
		if (ulNumOfKeysFound != 1)
		{
			if (ulNumOfKeysFound > 1)
				rvResult = CKR_TOO_MANY_KEYS_FOUND;
			if (ulNumOfKeysFound == 0)
				rvResult = CKR_KEYS_NOT_FOUND;
			goto IMPORT_PRISECKEY_FINALIZATION;
		}
		FindKeysByTemplate(sPubKeyToUnwrapOn,&hPubKey,&ulNumOfKeysFound);
		if (rvResult != CKR_OK) goto IMPORT_PRISECKEY_FINALIZATION;
	}
	else
	{
		if (sPubKey.psKeyParams[1].ulValueLen)					//if there is CKA_ID of the public key
		{
			ulNumOfKeysFound = 0;
			FindKeysByTemplate(sPubKey,NULL,&ulNumOfKeysFound);
			if (rvResult != CKR_OK) goto IMPORT_PRISECKEY_FINALIZATION;
			if (ulNumOfKeysFound != 1)
			{
				if (ulNumOfKeysFound > 1)
					rvResult = CKR_TOO_MANY_KEYS_FOUND;
				if (ulNumOfKeysFound == 0)
					rvResult = CKR_KEYS_NOT_FOUND;
				goto IMPORT_PRISECKEY_FINALIZATION;
			}
			FindKeysByTemplate(sPubKey,&hPubKey,&ulNumOfKeysFound);
			if (rvResult != CKR_OK) goto IMPORT_PRISECKEY_FINALIZATION;
		}
	}
#pragma endregion
#pragma region DerivingKeyIfNeeded
	//Getting type of private key
	sTempAttribute.type = CKA_KEY_TYPE;
	sTempAttribute.ulValueLen = sizeof (CK_ULONG);
	sTempAttribute.pValue = &ulPrivateKeyType;
	rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPriKey,&sTempAttribute,1);
	if ((rvResult != CKR_OK)||(sTempAttribute.ulValueLen == -1))
	{
		if (rvResult == CKR_OK) rvResult = CKR_ATTRIBUTE_NOT_FOUND;
		goto IMPORT_PRISECKEY_FINALIZATION;
	}
	switch(ulPrivateKeyType)
	{
	case CKK_GOSTR3410:
		//get info public key value:
		sPubKeyValue.type = CKA_VALUE;
		sPubKeyValue.ulValueLen = 0;
		sPubKeyValue.pValue = NULL;
		rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPubKey,&sPubKeyValue,1);
		if (rvResult != CKR_OK)
			goto IMPORT_PRISECKEY_FINALIZATION;
		if (sPubKeyValue.ulValueLen == -1)
			goto IMPORT_PRISECKEY_FINALIZATION;
		sPubKeyValue.pValue = (CK_BYTE_PTR) malloc (sPubKeyValue.ulValueLen);
		rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPubKey,&sPubKeyValue,1);
		if (rvResult != CKR_OK)
			goto IMPORT_PRISECKEY_FINALIZATION;
		//making derivation mechanism:
		sGost3410DeriveParams.kdf	= CKD_NULL; // not use key diversification
		sGost3410DeriveParams.ulUKMLen	= 8;
		sGost3410DeriveParams.pUKM = (CK_BYTE_PTR)pbIv;

		sGost3410DeriveParams.pPublicData = (CK_BYTE_PTR)sPubKeyValue.pValue;
		sGost3410DeriveParams.ulPublicDataLen = sPubKeyValue.ulValueLen;

		cmDeriveMechanism.mechanism = CKM_GOSTR3410_DERIVE;
		cmDeriveMechanism.pParameter = &sGost3410DeriveParams;
		cmDeriveMechanism.ulParameterLen = sizeof(CK_GOSTR3410_DERIVE_PARAMS);

		ulKeyType = CKK_GOST28147;
		ulDeriveKeyCount = ARRAYSIZE(caGost3410DeriveKey);

		rvResult = Pkcs11FuncList->C_DeriveKey(hSession,&cmDeriveMechanism,hPriKey,caGost3410DeriveKey,ulDeriveKeyCount,&hKeyToUnwrapOn);
		if (rvResult!= CKR_OK)
			goto IMPORT_PRISECKEY_FINALIZATION;
		break;
	case CKK_GR3410EL:
		//get info public key value:
		sPubKeyValue.type = CKA_VALUE;
		sPubKeyValue.ulValueLen = 0;
		sPubKeyValue.pValue = NULL;
		rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPubKey,&sPubKeyValue,1);
		if (rvResult != CKR_OK)
			goto IMPORT_PRISECKEY_FINALIZATION;
		if (sPubKeyValue.ulValueLen == -1)
			goto IMPORT_PRISECKEY_FINALIZATION;
		sPubKeyValue.pValue = (CK_BYTE_PTR) malloc (sPubKeyValue.ulValueLen);
		rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hPubKey,&sPubKeyValue,1);
		if (rvResult != CKR_OK)
			goto IMPORT_PRISECKEY_FINALIZATION;

		//making derivation mechanism:
		sGostShDeriveParams.kdf	= 0;
		sGostShDeriveParams.ivSrc = CKD_CP_IV_RANDOM;
		for(int i=0; i<8; ++i) sGostShDeriveParams.iv[i] = 0;

		sGostShDeriveParams.ulHashOIDLen = strlen(OID_EC_A);
		sGostShDeriveParams.pHashOID = (CK_BYTE_PTR)OID_EC_A;

		sGostShDeriveParams.pPublicData = (CK_BYTE_PTR)sPubKeyValue.pValue;
		sGostShDeriveParams.ulPublicDataLen = sPubKeyValue.ulValueLen;

		cmDeriveMechanism.mechanism = CKM_GR3410EL_DERIVE;
		cmDeriveMechanism.pParameter = &sGostShDeriveParams;
		cmDeriveMechanism.ulParameterLen = sizeof(CK_GR3410_VKO_DERIVE_PARAMS);

		ulKeyType = CKK_G28147;
		ulDeriveKeyCount = ARRAYSIZE(caGostShDeriveKey);

		rvResult = Pkcs11FuncList->C_DeriveKey(hSession,&cmDeriveMechanism,hPriKey,caGostShDeriveKey,ulDeriveKeyCount,&hKeyToUnwrapOn);
		if (rvResult!= CKR_OK)
			goto IMPORT_PRISECKEY_FINALIZATION;
		break;
	case CKK_RSA:
		hKeyToUnwrapOn = hPriKey;
		break;
	default:
		break;
	}
#pragma endregion
#pragma region MakingWrapMechanismParams
	switch(ulPrivateKeyType)
	{
	case CKK_GOSTR3410:
		cmWrapMechanism.mechanism = CKM_GOST28147_KEY_WRAP;
		cmWrapMechanism.ulParameterLen = 8;
		cmWrapMechanism.pParameter = (CK_BYTE_PTR)pbIv;
		break;
	case CKK_GR3410EL:
		sGostShWrapParams.wa = CKD_CP_G28147_WRAP_PRO;
		cmWrapMechanism.pParameter = &sGostShWrapParams;
		cmWrapMechanism.mechanism = CKM_CP_G28147_WRAP;
		cmWrapMechanism.ulParameterLen = sizeof(CK_CP_G28147_WRAP_PARAMS);
		break;
	case CKK_RSA:
		cmWrapMechanism.mechanism = SH_CKM_PKCS1_SIMPLE_BLOB_WRAP_KEY;
		cmWrapMechanism.ulParameterLen = 0;
		cmWrapMechanism.pParameter = NULL_PTR;
		break;
	default:
		rvResult = CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
		goto IMPORT_PRISECKEY_FINALIZATION;
		break;
	}
#pragma endregion
#pragma region UnwrappingKey
	rvResult = Pkcs11FuncList->C_UnwrapKey(hSession,&cmWrapMechanism,hKeyToUnwrapOn,(CK_BYTE_PTR)(sUnparsedAttrs.psKeyParams[sUnparsedAttrs.ulNumOfParams-1].pValue),
		sUnparsedAttrs.psKeyParams[sUnparsedAttrs.ulNumOfParams-1].ulValueLen,sImportedKey.psKeyParams,sImportedKey.ulNumOfParams, &hImportedKey);				
#pragma endregion
IMPORT_PRISECKEY_FINALIZATION:
#pragma region ImportPriSecKeyFinalization
	sTempAttribute.type = CKA_CLASS;
	sTempAttribute.pValue = &ulTempKeyType;
	sTempAttribute.ulValueLen = sizeof(CK_ULONG);

	if (hKeyToUnwrapOn)
	{
		Pkcs11FuncList->C_GetAttributeValue(hSession,hKeyToUnwrapOn,&sTempAttribute,1);
		if (ulTempKeyType == CKO_SECRET_KEY)
		{
			rvResult = Pkcs11FuncList->C_DestroyObject(hSession, hKeyToUnwrapOn);
		}
	}

	if (sPubKeyValue.pValue) free (sPubKeyValue.pValue);
	if (sPubKey.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sPubKey.ulNumOfParams; i++)
		{
			sPubKey.psKeyParams[i].pValue = NULL;
		}
		free(sPubKey.psKeyParams);
		sPubKey.psKeyParams = NULL;
	}
	if (sPriKey.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sPriKey.ulNumOfParams; i++)
		{
			sPriKey.psKeyParams[i].pValue = NULL;
		}
		free(sPriKey.psKeyParams);
		sPriKey.psKeyParams = NULL;
	}
	if (sImportedKey.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sImportedKey.ulNumOfParams; i++)
		{
			sImportedKey.psKeyParams[i].pValue = NULL;
		}
		free(sImportedKey.psKeyParams);
		sImportedKey.psKeyParams = NULL;
	}
	if (sUnparsedAttrs.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sUnparsedAttrs.ulNumOfParams; i++)
		{
			if (sUnparsedAttrs.psKeyParams[i].pValue) free (sUnparsedAttrs.psKeyParams[i].pValue);
			sUnparsedAttrs.psKeyParams[i].pValue = NULL;
		}
		free(sUnparsedAttrs.psKeyParams);
		sUnparsedAttrs.psKeyParams = NULL;
	}
#pragma endregion
};
