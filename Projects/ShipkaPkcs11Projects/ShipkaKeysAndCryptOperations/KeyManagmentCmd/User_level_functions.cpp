#pragma once
#include "User_level_functions.h"
#include <iostream>
/**
@page UserFunctionality
*/

/**
@brief UserFunctionality constructor
*/
UserFunctionality::UserFunctionality()
{
	pKmFuncList = NULL;
	ulClass_SecKey = CKO_SECRET_KEY;
	ulClass_PubKey = CKO_PUBLIC_KEY;
	ulClass_PriKey = CKO_PRIVATE_KEY;
	blTrue = CK_TRUE;
	blFalse = CK_FALSE;

	InitKeyManagmentLib();
	if (rvResult != CKR_OK) return;
};
/**
@brief UserFunctionality parametrized constructor
@param pcDeviceID(in) - ID of device we are working with as string
@param sPinParams(in) - parameters of PIN to this device: PIN and its length;
*/
UserFunctionality::UserFunctionality(char *pcDeviceID, MY_PIN_PARAMS sPinParams)
{
	pKmFuncList = NULL;
	ulClass_SecKey = CKO_SECRET_KEY;
	ulClass_PubKey = CKO_PUBLIC_KEY;
	ulClass_PriKey = CKO_PRIVATE_KEY;
	blTrue = CK_TRUE;
	blFalse = CK_FALSE;

	InitKeyManagmentLib();
	if (rvResult != CKR_OK) return;

	rvResult = pKmFuncList->MakeLoginedSession(pcDeviceID, sPinParams);
	if (rvResult != CKR_OK) return;
};
/**
@brief UserFunctionality destructor
*/
UserFunctionality::~UserFunctionality()
{
	FinalizeKeyManagmentLib();
};
//==================================================================================================================
void UserFunctionality::InitKeyManagmentLib()
{
	rvResult = CKR_OK;
	hGetFuncList = NULL;

	if ((hKeyManagmentLib = LoadLibrary(KEY_MANAGMENT_LIB)) == NULL)		//Failed to load library!
	{
		rvResult = GetLastError();
		return;
	}

	// get address of CreateKeyManagmentClassCopy function
	if (((FARPROC&)hGetFuncList = GetProcAddress(hKeyManagmentLib, "GetFunctionList"))==NULL)
	{	
		//Failed to load CreateKeyManagmentClassCopy function!!!
		rvResult = GetLastError();
		return;
	}

	rvResult = hGetFuncList(&pKmFuncList);
	if (rvResult != CKR_OK) return;

	rvResult = pKmFuncList->Initialize(NULL);
	if (rvResult != CKR_OK) return;
};
//------------------------------------------------------------------------------------------------------------------
void UserFunctionality::FinalizeKeyManagmentLib()
{
	if (hKeyManagmentLib)
	{
		if (pKmFuncList)
		{
			rvResult = pKmFuncList->Finalize(NULL);
			if (rvResult != CKR_OK) return;
		}
		FreeLibrary(hKeyManagmentLib);
	}
};
//==================================================================================================================
/**
@brief Function to get keys info as string array to be printed
@param pcKeysInfo(in) - strings containing attributes to define keys which infos are looking for;
@param ulNumOfParams(in) - number of strings in pcKeysInfo;
@param pcKeyList(in) - strings containing info about keys found by attributes in pcKeysInfo;
@param ulKeyNumber(in) - number of keys found;
*/
void UserFunctionality::GetKeysInfoListByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams, char **pcKeyList, CK_ULONG_PTR ulKeyNumber)
{
	CK_ULONG ulType = 0;
	MY_KEY_TEMPLATE_INFO sMyTemplate;
	char *pcAttrValue = NULL;
	char pcTempId[16];
	char pcTempType[24];
	char pcTempClass[16];
	char pcTempKeyLen[12];
	char pcTempExp[12];
	char *temp = NULL;

	int iKeyLen = 0;
	MY_KEY_INFO_PTR psMyKeyList = NULL;

	if (!ulKeyNumber)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
#pragma region GetAttributesFromStrings
	if ((pcKeysInfo == NULL)&&(!ulNumOfParams))
	{
		sMyTemplate.ulNumOfParams = 0;
		sMyTemplate.psKeyParams = NULL;
	}
	else
	{
		sMyTemplate.ulNumOfParams = ulNumOfParams;
		sMyTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sMyTemplate.ulNumOfParams);
		for (CK_ULONG i = 0; i<ulNumOfParams; i++)
		{
			if (pcKeysInfo[i] == NULL)
			{
				rvResult = CKR_ARGUMENTS_BAD;
				return;
			}
			ulType = -1;
			sMyTemplate.psKeyParams[i].pValue = NULL;
			sMyTemplate.psKeyParams[i].type = -1;
			sMyTemplate.psKeyParams[i].ulValueLen = 0;
			for (int j = 0; j<DEF_KEY_ATTRS_NUM; j++)
			{
				if (!strncmp(pcKeysInfo[i],DEF_KEY_ATTRS[j],strlen(DEF_KEY_ATTRS[j])))
					if (strlen(pcKeysInfo[i]) > strlen(DEF_KEY_ATTRS[j]))
					{
						ulType = DEF_ATTR_VALUES[j];
						sMyTemplate.psKeyParams[i].type = ulType;
						pcAttrValue = pcKeysInfo[i] + strlen(DEF_KEY_ATTRS[j]);
					}
					else
					{
						if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
						rvResult = CKR_ARGUMENTS_BAD;
						return;
					}
			}
			switch (ulType)
			{
			case CKA_CLASS:
				for (int j = 0; j<DEF_NUM_OF_CLASSES; j++) 
				{
					if (!strncmp(pcAttrValue,DEF_CLASS_NAME[j],strlen(DEF_CLASS_NAME[j])))
					{
						sMyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_CLASS_VALUE[j];
					}
				}
				sMyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
				break;
			case CKA_EXTRACTABLE:
				if (!strncmp(pcAttrValue,TRUE_ATTR,strlen(TRUE_ATTR)))
					sMyTemplate.psKeyParams[i].pValue = &blTrue;
				else if (!strncmp(pcAttrValue,FALSE_ATTR,strlen(FALSE_ATTR)))
					sMyTemplate.psKeyParams[i].pValue = &blFalse;
				break;
			case CKA_LABEL:
				sMyTemplate.psKeyParams[i].pValue = pcAttrValue;
				sMyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue);
				break;
			default:
				if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
				rvResult = CKR_ARGUMENTS_BAD;
				return;
			}
			if ((sMyTemplate.psKeyParams[i].pValue == NULL)&&(sMyTemplate.psKeyParams[i].type == -1)&&(sMyTemplate.psKeyParams[i].ulValueLen == 0))
			{
				if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
				rvResult = CKR_ARGUMENTS_BAD;
				return;
			}
		}
	}
#pragma endregion

	rvResult = pKmFuncList->GetKeysInfoList(sMyTemplate,psMyKeyList,ulKeyNumber);
	if (CKR_OK != rvResult)
	{
		if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
		return;
	}
	psMyKeyList = (MY_KEY_INFO_PTR) malloc (sizeof(MY_KEY_INFO) * (*ulKeyNumber));
	rvResult = pKmFuncList->GetKeysInfoList(sMyTemplate,psMyKeyList,ulKeyNumber);
	if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
	if (CKR_OK != rvResult)
	{
		if (psMyKeyList) free (psMyKeyList);
		return;
	}

	if (pcKeyList)
	{
		for (CK_ULONG i = 0; i < (*ulKeyNumber); i++)
		{
			if (pcKeyList[i])
			{
				memset (pcTempId,0,16);
				memset (pcTempType,0,24);
				memset (pcTempClass,0,16);
				memset (pcTempKeyLen,0,12);
				memset (pcTempExp,0,12);
#pragma region MakingId
				if (psMyKeyList[i].ulKeyIdLen != -1)
				{
					temp = pcTempId;
					for (CK_ULONG j = 0; j<psMyKeyList[i].ulKeyIdLen; j++)
					{
						sprintf (temp,"%2.2x",psMyKeyList[i].pbKeyId[j]);
						temp = pcTempId + strlen(pcTempId);
					}
				}
				else
				{
					sprintf (pcTempId,"unknown");
				}
#pragma endregion
#pragma region MakingType
				if (psMyKeyList[i].ulKeyTypeLen != -1)
				{
					switch (psMyKeyList[i].ulKeyType)
					{
					case CKK_RC2:
						sprintf (pcTempType,"RC2");
						break;
					case CKK_DES3:
						sprintf (pcTempType,"DES3");
						break;
					case CKK_DES:
						sprintf (pcTempType,"DES");
						break;
					case CKK_G28147:
						sprintf (pcTempType,"SH_GOST 28147");
						sprintf(pcTempKeyLen,"256");
						break;
					case CKK_GR3410EL:
						sprintf (pcTempType,"SH_GOST 3410");
						sprintf(pcTempKeyLen,"512");
						break;
					case CKK_GOST28147:
						sprintf (pcTempType,"GOST 28147-89");
						sprintf(pcTempKeyLen,"256");
						break;
					case CKK_GOSTR3410:
						sprintf (pcTempType,"GOST R 3410-2001");
						sprintf(pcTempKeyLen,"512");
						break;
					case CKK_RSA:
						sprintf (pcTempType,"RSA");
						break;
					default:
						sprintf (pcTempType, "unknown: 0x%x",psMyKeyList[i].ulKeyType);
						break;
					}
				}
				else
				{
					sprintf (pcTempType, "no value getted");
				}
#pragma endregion
#pragma region MakingClass
				if (psMyKeyList[i].ulKeyClassLen != -1)
				{
					switch (psMyKeyList[i].ulKeyClass)
					{
					case CKO_SECRET_KEY:
						sprintf (pcTempClass,"secret");
						break;
					case CKO_PRIVATE_KEY:
						sprintf (pcTempClass,"private");
						break;
					case CKO_PUBLIC_KEY:
						sprintf (pcTempClass,"public");
						break;
					default:
						sprintf (pcTempClass, "unknown",psMyKeyList[i].ulKeyClass);
						break;
					}
				}
				else
				{
					sprintf (pcTempClass, "unknown");
				}
#pragma endregion
#pragma region MakingLen
				if (psMyKeyList[i].ulKeyLenLen != -1)
				{
					if (psMyKeyList[i].ulKeyLen<128)
						psMyKeyList[i].ulKeyLen = psMyKeyList[i].ulKeyLen * 8;
					sprintf(pcTempKeyLen,"%d",psMyKeyList[i].ulKeyLen);
				}
				else if (pcTempKeyLen[0] == 0)
				{
					sprintf(pcTempKeyLen,"----");
				}
#pragma endregion
#pragma region MakingExt
				if (psMyKeyList[i].ulExportableLen != -1)
				{
					if (((psMyKeyList[i].bExportable)&(0x0F)) == CK_TRUE)
						sprintf(pcTempExp,"true");
					else sprintf(pcTempExp,"false");
				}
				else
				{
					sprintf(pcTempExp,"unknown");
				}
#pragma endregion
				if (psMyKeyList[i].ulLabelLen == -1)
				{
					psMyKeyList[i].pbLabel[0] = '\0';
				}
				sprintf (pcKeyList[i],"ID: %10.10s; Type: %16.16s; Class: %8.8s; Len: %8.8s; Ext: %8.8s; Label: %.160s",
					pcTempId,pcTempType,pcTempClass,pcTempKeyLen,pcTempExp,psMyKeyList[i].pbLabel);		//45 symbols of 255
			}
		}
	}
};

//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to generate secret key
@param pcKeysInfo(in) - strings containing attributes to generate key;
@param ulNumOfParams(in) - number of strings in pcKeysInfo;
*/
void UserFunctionality::GenerateSecKeyByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams)
{
	CK_ULONG ulType = 0;
	MY_KEY_TEMPLATE_INFO sMyTemplate;
	char *pcAttrValue = NULL;
	CK_BYTE *pcCkaIdValue = NULL;
	int iKeyLen = 0;

#pragma region GetAttributesFromStrings
	if ((pcKeysInfo == NULL)&&(!ulNumOfParams))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
	sMyTemplate.ulNumOfParams = ulNumOfParams;
	sMyTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sMyTemplate.ulNumOfParams);
	for (CK_ULONG i = 0; i<ulNumOfParams; i++)
	{
		if (pcKeysInfo[i] == NULL)
		{
			if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
		ulType = -1;
		sMyTemplate.psKeyParams[i].pValue = NULL;
		sMyTemplate.psKeyParams[i].type = -1;
		sMyTemplate.psKeyParams[i].ulValueLen = 0;
		for (int j = 0; j<DEF_KEY_ATTRS_NUM; j++)
		{
			if (!strncmp(pcKeysInfo[i],DEF_KEY_ATTRS[j],strlen(DEF_KEY_ATTRS[j])))
				if (strlen(pcKeysInfo[i]) > strlen(DEF_KEY_ATTRS[j]))
				{
					ulType = DEF_ATTR_VALUES[j];
					sMyTemplate.psKeyParams[i].type = ulType;
					pcAttrValue = pcKeysInfo[i] + strlen(DEF_KEY_ATTRS[j]);
				}
				else
				{
					if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
					rvResult = CKR_ARGUMENTS_BAD;
					return;
				}
		}
		switch (ulType)
		{
		case CKA_KEY_TYPE:
			for (int j = 0; j<DEF_NUM_OF_ALGS; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_ALG_TYPES_NAMES[j],strlen(DEF_ALG_TYPES_NAMES[j])))
				{
					sMyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_ALG_TYPES[j];
				}
			}
			sMyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_CLASS:
			for (CK_ULONG j = 0; j<DEF_NUM_OF_CLASSES; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_CLASS_NAME[j],strlen(DEF_CLASS_NAME[j])))
				{
					sMyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_CLASS_VALUE[j];
				}
			}
			sMyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_ID:
			if (pcCkaIdValue)
			{
				if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
				rvResult = CKR_ARGUMENTS_BAD;
				return;
			}
			sMyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue)/2;
			pcCkaIdValue = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * sMyTemplate.psKeyParams[i].ulValueLen);
			for (CK_ULONG j = 0; j<sMyTemplate.psKeyParams[i].ulValueLen; j++)
			{
				if ((pcAttrValue[2*j]<='9')&&(pcAttrValue[2*j]>='0'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - '0')*16;
				else if ((pcAttrValue[2*j]<='F')&&(pcAttrValue[2*j]>='A'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - 'A' + 10)*16;
				else if ((pcAttrValue[2*j]<='f')&&(pcAttrValue[2*j]>='a'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - 'a' + 10)*16;

				if ((pcAttrValue[2*j+1]<='9')&&(pcAttrValue[2*j+1]>='0'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - '0');
				else if ((pcAttrValue[2*j+1]<='F')&&(pcAttrValue[2*j+1]>='A'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - 'A' + 10);
				else if ((pcAttrValue[2*j+1]<='f')&&(pcAttrValue[2*j+1]>='a'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - 'a' + 10);
			}
			sMyTemplate.psKeyParams[i].pValue = pcCkaIdValue;
			break;
		case CKA_MODULUS_BITS:
			sMyTemplate.psKeyParams[i].type = CKA_VALUE_LEN;
			iKeyLen = atoi(pcAttrValue)/8;
			sMyTemplate.psKeyParams[i].pValue = &iKeyLen;
			sMyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);			
			break;
		case CKA_EXTRACTABLE:
			if (!strncmp(pcAttrValue,TRUE_ATTR,strlen(TRUE_ATTR)))
				sMyTemplate.psKeyParams[i].pValue = &blTrue;
			else if (!strncmp(pcAttrValue,FALSE_ATTR,strlen(FALSE_ATTR)))
				sMyTemplate.psKeyParams[i].pValue = &blFalse;
			break;
		case CKA_LABEL:
			sMyTemplate.psKeyParams[i].pValue = pcAttrValue;
			sMyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue);
			break;
		default:
			if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
		if ((sMyTemplate.psKeyParams[i].pValue == NULL)&&(sMyTemplate.psKeyParams[i].type == -1)&&(sMyTemplate.psKeyParams[i].ulValueLen == 0))
		{
			if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
	}
#pragma endregion

	rvResult = pKmFuncList->GenerateSecKey(sMyTemplate,NULL);
	if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
	if (pcCkaIdValue) free (pcCkaIdValue);
};

//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to generate key pair
@param pcKeysInfo(in) - strings containing attributes to generate key pair;
@param ulNumOfParams(in) - number of strings in pcKeysInfo;
*/
void UserFunctionality::GenerateKeyPairByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams)
{
	CK_ULONG ulType = 0;
	MY_KEY_TEMPLATE_INFO sMyPubTemplate,sMyPriTemplate;
	char *pcAttrValue = NULL;
	CK_BYTE *pcCkaIdValue = NULL;
	int iKeyLen = 0;
	CK_ULONG ulPriAttrCounter = 0;
	CK_ULONG ulParamCounter = 0;

#pragma region GetPubKeyAttributesFromStrings
	if ((pcKeysInfo == NULL)&&(!ulNumOfParams))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
	sMyPubTemplate.ulNumOfParams = ulNumOfParams;
	sMyPubTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sMyPubTemplate.ulNumOfParams);

	for (CK_ULONG i = 0; i<ulNumOfParams; i++)
	{
		if (pcKeysInfo[i] == NULL)
		{
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
		ulType = -1;
		sMyPubTemplate.psKeyParams[ulParamCounter].pValue = NULL;
		sMyPubTemplate.psKeyParams[ulParamCounter].type = -1;
		sMyPubTemplate.psKeyParams[ulParamCounter].ulValueLen = 0;
		for (int j = 0; j<DEF_KEY_ATTRS_NUM; j++)
		{
			if (!strncmp(pcKeysInfo[i],DEF_KEY_ATTRS[j],strlen(DEF_KEY_ATTRS[j])))
				if (strlen(pcKeysInfo[i]) > strlen(DEF_KEY_ATTRS[j]))
				{
					ulType = DEF_ATTR_VALUES[j];
					sMyPubTemplate.psKeyParams[ulParamCounter].type = ulType;
					pcAttrValue = pcKeysInfo[i] + strlen(DEF_KEY_ATTRS[j]);
				}
				else
				{
					if (sMyPubTemplate.psKeyParams) free (sMyPubTemplate.psKeyParams);
					rvResult = CKR_ARGUMENTS_BAD;
					return;
				}
		}
		switch (ulType)
		{
		case CKA_KEY_TYPE:
			for (int j = 0; j<DEF_NUM_OF_ALGS; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_ALG_TYPES_NAMES[j],strlen(DEF_ALG_TYPES_NAMES[j])))
				{
					sMyPubTemplate.psKeyParams[ulParamCounter].pValue = (CK_VOID_PTR)&DEF_ALG_TYPES[j];
				}
			}
			sMyPubTemplate.psKeyParams[ulParamCounter].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_CLASS:
			for (int j = 0; j<DEF_NUM_OF_CLASSES; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_CLASS_NAME[j],strlen(DEF_CLASS_NAME[j])))
				{
					sMyPubTemplate.psKeyParams[ulParamCounter].pValue = (CK_VOID_PTR)&DEF_CLASS_VALUE[j];
				}
			}
			sMyPubTemplate.psKeyParams[ulParamCounter].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_ID:
			if (pcCkaIdValue)
			{
				if (sMyPubTemplate.psKeyParams) free (sMyPubTemplate.psKeyParams);
				rvResult = CKR_ARGUMENTS_BAD;
				return;
			}
			sMyPubTemplate.psKeyParams[ulParamCounter].ulValueLen = strlen(pcAttrValue)/2;
			pcCkaIdValue = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * sMyPubTemplate.psKeyParams[ulParamCounter].ulValueLen);
			for (CK_ULONG j = 0; j<sMyPubTemplate.psKeyParams[ulParamCounter].ulValueLen; j++)
			{
				if ((pcAttrValue[2*j]<='9')&&(pcAttrValue[2*j]>='0'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - '0')*16;
				else if ((pcAttrValue[2*j]<='F')&&(pcAttrValue[2*j]>='A'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - 'A'+10)*16;
				else if ((pcAttrValue[2*j]<='f')&&(pcAttrValue[2*j]>='a'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - 'a'+10)*16;

				if ((pcAttrValue[2*j+1]<='9')&&(pcAttrValue[2*j+1]>='0'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - '0');
				else if ((pcAttrValue[2*j+1]<='F')&&(pcAttrValue[2*j+1]>='A'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - 'A'+10);
				else if ((pcAttrValue[2*j+1]<='f')&&(pcAttrValue[2*j+1]>='a'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - 'a'+10);
			}
			sMyPubTemplate.psKeyParams[ulParamCounter].pValue = pcCkaIdValue;
			break;
		case CKA_MODULUS_BITS:
			sMyPubTemplate.psKeyParams[ulParamCounter].type = CKA_MODULUS_BITS;
			iKeyLen = atoi(pcAttrValue);
			sMyPubTemplate.psKeyParams[ulParamCounter].pValue = &iKeyLen;
			sMyPubTemplate.psKeyParams[ulParamCounter].ulValueLen = sizeof(CK_ULONG);			
			break;
		case CKA_EXTRACTABLE:
			sMyPubTemplate.ulNumOfParams--;
			break;
		case CKA_LABEL:
			sMyPubTemplate.psKeyParams[ulParamCounter].pValue = pcAttrValue;
			sMyPubTemplate.psKeyParams[ulParamCounter].ulValueLen = strlen(pcAttrValue);
			break;
		default:
			if (sMyPubTemplate.psKeyParams) free (sMyPubTemplate.psKeyParams);
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
		if (!((sMyPubTemplate.psKeyParams[ulParamCounter].pValue == NULL)||(sMyPubTemplate.psKeyParams[ulParamCounter].type == -1)||(sMyPubTemplate.psKeyParams[ulParamCounter].ulValueLen == 0)))
			ulParamCounter++;
	}
	if (ulParamCounter != sMyPubTemplate.ulNumOfParams)
	{
		if (sMyPubTemplate.psKeyParams) free (sMyPubTemplate.psKeyParams);
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
#pragma endregion
#pragma region GetPriKeyAttributes
	if ((pcKeysInfo == NULL)&&(!ulNumOfParams))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
	sMyPriTemplate.ulNumOfParams = ulNumOfParams;
	sMyPriTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sMyPriTemplate.ulNumOfParams);
	ulParamCounter = 0;

	for (CK_ULONG i = 0; i<ulNumOfParams; i++)
	{
		if (pcKeysInfo[i] == NULL)
		{
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
		ulType = -1;
		sMyPriTemplate.psKeyParams[ulParamCounter].pValue = NULL;
		sMyPriTemplate.psKeyParams[ulParamCounter].type = -1;
		sMyPriTemplate.psKeyParams[ulParamCounter].ulValueLen = 0;
		for (int j = 0; j<DEF_KEY_ATTRS_NUM; j++)
		{
			if (!strncmp(pcKeysInfo[i],DEF_KEY_ATTRS[j],strlen(DEF_KEY_ATTRS[j])))
				if (strlen(pcKeysInfo[i]) > strlen(DEF_KEY_ATTRS[j]))
				{
					ulType = DEF_ATTR_VALUES[j];
					sMyPriTemplate.psKeyParams[ulParamCounter].type = ulType;
					pcAttrValue = pcKeysInfo[i] + strlen(DEF_KEY_ATTRS[j]);
				}
				else
				{
					if (sMyPriTemplate.psKeyParams) free (sMyPriTemplate.psKeyParams);
					if (sMyPubTemplate.psKeyParams) free (sMyPubTemplate.psKeyParams);
					rvResult = CKR_ARGUMENTS_BAD;
					return;
				}
		}
		switch (ulType)
		{
		case CKA_KEY_TYPE:
			for (int j = 0; j<DEF_NUM_OF_ALGS; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_ALG_TYPES_NAMES[j],strlen(DEF_ALG_TYPES_NAMES[j])))
				{
					sMyPriTemplate.psKeyParams[ulParamCounter].pValue = (CK_VOID_PTR)&DEF_ALG_TYPES[j];
				}
			}
			sMyPriTemplate.psKeyParams[ulParamCounter].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_CLASS:
			for (int j = 0; j<DEF_NUM_OF_CLASSES; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_CLASS_NAME[j],strlen(DEF_CLASS_NAME[j])))
				{
					sMyPriTemplate.psKeyParams[ulParamCounter].pValue = (CK_VOID_PTR)&DEF_CLASS_VALUE[j];
				}
			}
			sMyPriTemplate.psKeyParams[ulParamCounter].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_ID:
			sMyPriTemplate.psKeyParams[ulParamCounter].ulValueLen = strlen(pcAttrValue)/2;
			sMyPriTemplate.psKeyParams[ulParamCounter].pValue = pcCkaIdValue;
			break;
		case CKA_MODULUS_BITS:
			sMyPriTemplate.ulNumOfParams--;		
			break;
		case CKA_EXTRACTABLE:
			if (!strncmp(pcAttrValue,TRUE_ATTR,strlen(TRUE_ATTR)))
				sMyPriTemplate.psKeyParams[ulParamCounter].pValue = &blTrue;
			else if (!strncmp(pcAttrValue,FALSE_ATTR,strlen(FALSE_ATTR)))
				sMyPriTemplate.psKeyParams[ulParamCounter].pValue = &blFalse;
			sMyPriTemplate.psKeyParams[ulParamCounter].ulValueLen = sizeof(CK_BBOOL);
			break;
		case CKA_LABEL:
			sMyPriTemplate.psKeyParams[ulParamCounter].pValue = pcAttrValue;
			sMyPriTemplate.psKeyParams[ulParamCounter].ulValueLen = strlen(pcAttrValue);
			break;
		default:
			if (sMyPriTemplate.psKeyParams) free (sMyPriTemplate.psKeyParams);
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
		if (!((sMyPriTemplate.psKeyParams[ulParamCounter].pValue == NULL)||(sMyPriTemplate.psKeyParams[ulParamCounter].type == -1)||(sMyPriTemplate.psKeyParams[ulParamCounter].ulValueLen == 0)))
			ulParamCounter++;
	}
	if (ulParamCounter != sMyPriTemplate.ulNumOfParams)
	{
		if (sMyPriTemplate.psKeyParams) free (sMyPriTemplate.psKeyParams);
		if (sMyPubTemplate.psKeyParams) free (sMyPubTemplate.psKeyParams);
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
#pragma endregion
	rvResult = pKmFuncList->GenerateKeyPair(sMyPriTemplate,sMyPubTemplate,NULL);
	if (sMyPriTemplate.psKeyParams) free (sMyPriTemplate.psKeyParams);
	if (sMyPubTemplate.psKeyParams) free (sMyPubTemplate.psKeyParams);
	if (pcCkaIdValue) free (pcCkaIdValue);
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to delete key or keys by template
@param pcKeysInfo(in) - strings containing attributes to define, which keys should be deleted;
@param ulNumOfParams(in) - number of strings in pcKeysInfo;
*/
void UserFunctionality::DeleteKeysByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams)
{
	CK_ULONG ulType = 0;
	MY_KEY_TEMPLATE_INFO sMyTemplate;
	CK_BYTE *pcCkaIdValue = NULL;
	char *pcAttrValue = NULL;
	int iKeyLen = 0;

#pragma region GetAttributesFromStrings
	if ((pcKeysInfo == NULL)&&(!ulNumOfParams))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
	sMyTemplate.ulNumOfParams = ulNumOfParams;
	sMyTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sMyTemplate.ulNumOfParams);
	for (CK_ULONG i = 0; i<ulNumOfParams; i++)
	{
		if (pcKeysInfo[i] == NULL)
		{
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
		ulType = -1;
		sMyTemplate.psKeyParams[i].pValue = NULL;
		sMyTemplate.psKeyParams[i].type = -1;
		sMyTemplate.psKeyParams[i].ulValueLen = 0;
		for (int j = 0; j<DEF_KEY_ATTRS_NUM; j++)
		{
			if (!strncmp(pcKeysInfo[i],DEF_KEY_ATTRS[j],strlen(DEF_KEY_ATTRS[j])))
				if (strlen(pcKeysInfo[i]) > strlen(DEF_KEY_ATTRS[j]))
				{
					ulType = DEF_ATTR_VALUES[j];
					sMyTemplate.psKeyParams[i].type = ulType;
					pcAttrValue = pcKeysInfo[i] + strlen(DEF_KEY_ATTRS[j]);
				}
				else
				{
					if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
					rvResult = CKR_ARGUMENTS_BAD;
					return;
				}
		}
		switch (ulType)
		{
		case CKA_KEY_TYPE:
			for (int j = 0; j<DEF_NUM_OF_ALGS; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_ALG_TYPES_NAMES[j],strlen(DEF_ALG_TYPES_NAMES[j])))
				{
					sMyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_ALG_TYPES[j];
				}
			}
			sMyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_CLASS:
			for (int j = 0; j<DEF_NUM_OF_CLASSES; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_CLASS_NAME[j],strlen(DEF_CLASS_NAME[j])))
				{
					sMyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_CLASS_VALUE[j];
				}
			}
			sMyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_ID:
			if (pcCkaIdValue)
			{
				if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
				rvResult = CKR_ARGUMENTS_BAD;
				return;
			}
			sMyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue)/2;
			pcCkaIdValue = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * sMyTemplate.psKeyParams[i].ulValueLen);
			for (CK_ULONG j = 0; j<sMyTemplate.psKeyParams[i].ulValueLen; j++)
			{
				if ((pcAttrValue[2*j]<='9')&&(pcAttrValue[2*j]>='0'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - '0')*16;
				else if ((pcAttrValue[2*j]<='F')&&(pcAttrValue[2*j]>='A'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - 'A' + 10)*16;
				else if ((pcAttrValue[2*j]<='f')&&(pcAttrValue[2*j]>='a'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - 'a' + 10)*16;

				if ((pcAttrValue[2*j+1]<='9')&&(pcAttrValue[2*j+1]>='0'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - '0');
				else if ((pcAttrValue[2*j+1]<='F')&&(pcAttrValue[2*j+1]>='A'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - 'A' + 10);
				else if ((pcAttrValue[2*j+1]<='f')&&(pcAttrValue[2*j+1]>='a'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - 'a' + 10);
			}
			sMyTemplate.psKeyParams[i].pValue = pcCkaIdValue;
			break;
		case CKA_EXTRACTABLE:
			if (!strncmp(pcAttrValue,TRUE_ATTR,strlen(TRUE_ATTR)))
				sMyTemplate.psKeyParams[i].pValue = &blTrue;
			else if (!strncmp(pcAttrValue,FALSE_ATTR,strlen(FALSE_ATTR)))
				sMyTemplate.psKeyParams[i].pValue = &blFalse;
			break;
		case CKA_LABEL:
			sMyTemplate.psKeyParams[i].pValue = pcAttrValue;
			sMyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue);
			break;
		default:
			if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
		if ((sMyTemplate.psKeyParams[i].pValue == NULL)&&(sMyTemplate.psKeyParams[i].type == -1)&&(sMyTemplate.psKeyParams[i].ulValueLen == 0))
		{
			if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
	}
#pragma endregion

	rvResult = pKmFuncList->DeleteKey(sMyTemplate);
	if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
	if (pcCkaIdValue) free (pcCkaIdValue);
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to export public key
@param pcKeysInfo(in) - strings containing attributes to define, which key should be exported
@param ulNumOfParams(in) - number of strings in pcKeysInfo;
@param pbExportedKey(out) - array of CK_BYTEs to contain key info and its value
@param ulExportedKeyLen(out) - length of pbExportedKey
*/
void UserFunctionality::ExportPublicKeyByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams, 
														  CK_BYTE_PTR pbExportedKey, CK_ULONG_PTR ulExportedKeyLen)
{
	CK_ULONG ulType = 0;
	MY_KEY_TEMPLATE_INFO sMyTemplate;
	CK_BYTE *pcCkaIdValue = NULL;
	char *pcAttrValue = NULL;
	int iKeyLen = 0;
	CK_ULONG ulKeyClassInStrings = 0;

#pragma region GetAttributesFromStrings
	if ((pcKeysInfo == NULL)&&(!ulNumOfParams))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
	sMyTemplate.ulNumOfParams = ulNumOfParams + 1;
	sMyTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sMyTemplate.ulNumOfParams);
	for (CK_ULONG i = 0; i<ulNumOfParams; i++)
	{
		if (pcKeysInfo[i] == NULL)
		{
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
		ulType = -1;
		sMyTemplate.psKeyParams[i].pValue = NULL;
		sMyTemplate.psKeyParams[i].type = -1;
		sMyTemplate.psKeyParams[i].ulValueLen = 0;
		for (int j = 0; j<DEF_KEY_ATTRS_NUM; j++)
		{
			if (!strncmp(pcKeysInfo[i],DEF_KEY_ATTRS[j],strlen(DEF_KEY_ATTRS[j])))
				if (strlen(pcKeysInfo[i]) > strlen(DEF_KEY_ATTRS[j]))
				{
					ulType = DEF_ATTR_VALUES[j];
					sMyTemplate.psKeyParams[i].type = ulType;
					pcAttrValue = pcKeysInfo[i] + strlen(DEF_KEY_ATTRS[j]);
				}
				else
				{
					if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
					rvResult = CKR_ARGUMENTS_BAD;
					return;
				}
		}
		switch (ulType)
		{
		case CKA_KEY_TYPE:
			for (int j = 0; j<DEF_NUM_OF_ALGS; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_ALG_TYPES_NAMES[j],strlen(DEF_ALG_TYPES_NAMES[j])))
				{
					sMyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_ALG_TYPES[j];
					if (!ulKeyClassInStrings) 
						ulKeyClassInStrings = DEF_ALG_TYPES[j];
					else
					{
						if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
						rvResult = CKR_ARGUMENTS_BAD;
						return;
					}
				}
			}
			sMyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_CLASS:
			for (int j = 0; j<DEF_NUM_OF_CLASSES; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_CLASS_NAME[j],strlen(DEF_CLASS_NAME[j])))
				{
					sMyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_CLASS_VALUE[j];
				}
			}
			sMyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_ID:
			if (pcCkaIdValue)
			{
				if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
				rvResult = CKR_ARGUMENTS_BAD;
				return;
			}
			sMyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue)/2;
			pcCkaIdValue = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * sMyTemplate.psKeyParams[i].ulValueLen);
			for (CK_ULONG j = 0; j<sMyTemplate.psKeyParams[i].ulValueLen; j++)
			{
				if ((pcAttrValue[2*j]<='9')&&(pcAttrValue[2*j]>='0'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - '0')*16;
				else if ((pcAttrValue[2*j]<='F')&&(pcAttrValue[2*j]>='A'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - 'A' + 10)*16;
				else if ((pcAttrValue[2*j]<='f')&&(pcAttrValue[2*j]>='a'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - 'a' + 10)*16;

				if ((pcAttrValue[2*j+1]<='9')&&(pcAttrValue[2*j+1]>='0'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - '0');
				else if ((pcAttrValue[2*j+1]<='F')&&(pcAttrValue[2*j+1]>='A'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - 'A' + 10);
				else if ((pcAttrValue[2*j+1]<='f')&&(pcAttrValue[2*j+1]>='a'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - 'a' + 10);
			}
			sMyTemplate.psKeyParams[i].pValue = pcCkaIdValue;
			break;
		case CKA_MODULUS_BITS:
			sMyTemplate.psKeyParams[i].type = CKA_MODULUS_BITS;
			iKeyLen = atoi(pcAttrValue)/8;
			sMyTemplate.psKeyParams[i].pValue = &iKeyLen;
			sMyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);			
			break;
		case CKA_EXTRACTABLE:
			if (!strncmp(pcAttrValue,TRUE_ATTR,strlen(TRUE_ATTR)))
				sMyTemplate.psKeyParams[i].pValue = &blTrue;
			else if (!strncmp(pcAttrValue,FALSE_ATTR,strlen(FALSE_ATTR)))
				sMyTemplate.psKeyParams[i].pValue = &blFalse;
			break;
		case CKA_LABEL:
			sMyTemplate.psKeyParams[i].pValue = pcAttrValue;
			sMyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue);
			break;
		default:
			if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
		if ((sMyTemplate.psKeyParams[i].pValue == NULL)&&(sMyTemplate.psKeyParams[i].type == -1)&&(sMyTemplate.psKeyParams[i].ulValueLen == 0))
		{
			if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
	}
#pragma endregion

	if (ulKeyClassInStrings) sMyTemplate.ulNumOfParams--;
	else
	{
		sMyTemplate.psKeyParams[sMyTemplate.ulNumOfParams-1].type = CKA_CLASS;
		sMyTemplate.psKeyParams[sMyTemplate.ulNumOfParams-1].ulValueLen = sizeof (CK_ULONG);
		sMyTemplate.psKeyParams[sMyTemplate.ulNumOfParams-1].pValue = &ulClass_PubKey;
	}

	rvResult = pKmFuncList->ExportPublicKey(sMyTemplate,pbExportedKey,ulExportedKeyLen);
	if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
	if (pcCkaIdValue) free (pcCkaIdValue);
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to export secret or private key
@param pcKeysInfo(in) - strings containing attributes to define, which key should be exported and on which keys
@param ulNumOfParams(in) - number of strings in pcKeysInfo;
@param pbExportedKey(out) - array of CK_BYTEs to contain key info and its value
@param ulExportedKeyLen(out) - length of pbExportedKey
*/
void UserFunctionality::ExportSecPriKeyByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams, 
														  CK_BYTE_PTR pbExportedKey, CK_ULONG_PTR ulExportedKeyLen)
{
	char **pcSecPriKeyInfo = NULL, **pcPubKeyInfo = NULL, **pcPriKeyInfo = NULL;
	CK_ULONG ulSecPriKeyInfoAttrs = 0, ulPubKeyInfoAttrs = 0, ulPriKeyInfoAttrs = 0;
	CK_ULONG ulCounter = 0;
	MY_KEY_TEMPLATE_INFO sSecPriKeyTemplate, sPubKeyTemplate, sPriKeyTemplate;
	CK_ULONG ulSecPriKeyType = 0, ulPubKeyType = 0, ulPriKeyType = 0;
	CK_BYTE *pcSecPriKeyCkaIdValue = NULL, *pcPubKeyCkaIdValue = NULL, *pcPriKeyCkaIdValue = NULL;
	int iSecPriKeyLen = 0, iPubKeyLen = 0, iPriKeyLen = 0;

	char *pcAttrValue = NULL;
	CK_ULONG ulKeyClassInStrings = 0;
	CK_ULONG ulKeyType = 0;

	sSecPriKeyTemplate.psKeyParams = NULL;
	sSecPriKeyTemplate.ulNumOfParams = 0;
	sPubKeyTemplate.psKeyParams = NULL;
	sPubKeyTemplate.ulNumOfParams = 0;
	sPriKeyTemplate.psKeyParams = NULL;
	sPriKeyTemplate.ulNumOfParams = 0;
#pragma region ParsingInputAttributesTo
	if ((strncmp(pcKeysInfo[ulCounter],SECRET_KEY,strlen(SECRET_KEY)))&&
		(strncmp(pcKeysInfo[ulCounter],PRIVATE_KEY,strlen(PRIVATE_KEY))))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto EXPORT_SECPRIKEY_BY_STRINGS;
	}
	ulCounter++;
	pcSecPriKeyInfo = &(pcKeysInfo[ulCounter]);
	while ((strncmp(pcKeysInfo[ulCounter],PUBLIC_KEY,strlen(PUBLIC_KEY)))&&(ulCounter<ulNumOfParams))
	{
		ulCounter++;
		ulSecPriKeyInfoAttrs++;
	}

	if (strncmp(pcKeysInfo[ulCounter],PUBLIC_KEY,strlen(PUBLIC_KEY)))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto EXPORT_SECPRIKEY_BY_STRINGS;
	}
	ulCounter++;
	pcPubKeyInfo = &(pcKeysInfo[ulCounter]);
	while ((ulCounter<ulNumOfParams))
	{
		if (!strncmp(pcKeysInfo[ulCounter],PRIVATE_KEY,strlen(PRIVATE_KEY)))
			break;
		ulCounter++;
		ulPubKeyInfoAttrs++;
	}

	if (ulCounter>=ulNumOfParams)
	{
		pcPriKeyInfo = NULL;
	}
	else
	{
		ulCounter++;
		pcPriKeyInfo = &(pcKeysInfo[ulCounter]);
		while (ulCounter<ulNumOfParams)
		{
			ulCounter++;
			ulPriKeyInfoAttrs++;
		}
	}
#pragma endregion
#pragma region GetAttributesFromStrings
#pragma region GetSecPriKeyAttributesFromStrings
	if ((pcSecPriKeyInfo == NULL)&&(!ulSecPriKeyInfoAttrs))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto EXPORT_SECPRIKEY_BY_STRINGS;
	}
	sSecPriKeyTemplate.ulNumOfParams = ulSecPriKeyInfoAttrs + 1;
	sSecPriKeyTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sSecPriKeyTemplate.ulNumOfParams);
	for (CK_ULONG i = 0; i<sSecPriKeyTemplate.ulNumOfParams; i++)
	{
		sSecPriKeyTemplate.psKeyParams[i].ulValueLen = 0;
		sSecPriKeyTemplate.psKeyParams[i].pValue = NULL;
	}
	ulKeyType = -1;
#pragma region UserAttributes
	for (CK_ULONG i = 0; i<ulSecPriKeyInfoAttrs; i++)
	{
		if (pcSecPriKeyInfo[i] == NULL)
		{
			rvResult = CKR_ARGUMENTS_BAD;
			goto EXPORT_SECPRIKEY_BY_STRINGS;
		}
		ulSecPriKeyType = -1;
		sSecPriKeyTemplate.psKeyParams[i].pValue = NULL;
		sSecPriKeyTemplate.psKeyParams[i].type = -1;
		sSecPriKeyTemplate.psKeyParams[i].ulValueLen = 0;
		for (int j = 0; j<DEF_KEY_ATTRS_NUM; j++)
		{
			if (!strncmp(pcSecPriKeyInfo[i],DEF_KEY_ATTRS[j],strlen(DEF_KEY_ATTRS[j])))
				if (strlen(pcSecPriKeyInfo[i]) > strlen(DEF_KEY_ATTRS[j]))
				{
					ulSecPriKeyType = DEF_ATTR_VALUES[j];
					sSecPriKeyTemplate.psKeyParams[i].type = ulSecPriKeyType;
					pcAttrValue = pcSecPriKeyInfo[i] + strlen(DEF_KEY_ATTRS[j]);
				}
				else
				{
					rvResult = CKR_ARGUMENTS_BAD;
					goto EXPORT_SECPRIKEY_BY_STRINGS;
				}
		}
		switch (ulSecPriKeyType)
		{
		case CKA_KEY_TYPE:
			for (int j = 0; j<DEF_NUM_OF_ALGS; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_ALG_TYPES_NAMES[j],strlen(DEF_ALG_TYPES_NAMES[j])))
				{
					sSecPriKeyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_ALG_TYPES[j];
					if (!ulKeyClassInStrings) 
						ulKeyClassInStrings = DEF_ALG_TYPES[j];
					else
					{
						rvResult = CKR_ARGUMENTS_BAD;
						goto EXPORT_SECPRIKEY_BY_STRINGS;
					}
				}
			}
			sSecPriKeyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_CLASS:
			for (int j = 0; j<DEF_NUM_OF_CLASSES; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_CLASS_NAME[j],strlen(DEF_CLASS_NAME[j])))
				{
					sSecPriKeyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_CLASS_VALUE[j];
					if (ulKeyType != -1)
					{
						rvResult = CKR_ARGUMENTS_BAD;
						goto EXPORT_SECPRIKEY_BY_STRINGS;
					}
					ulKeyType = DEF_CLASS_VALUE[j];
				}
			}
			sSecPriKeyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_ID:
			if (pcSecPriKeyCkaIdValue)
			{
				rvResult = CKR_ARGUMENTS_BAD;
				goto EXPORT_SECPRIKEY_BY_STRINGS;
			}
			sSecPriKeyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue)/2;
			pcSecPriKeyCkaIdValue = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * sSecPriKeyTemplate.psKeyParams[i].ulValueLen);
			for (CK_ULONG j = 0; j<sSecPriKeyTemplate.psKeyParams[i].ulValueLen; j++)
			{
				if ((pcAttrValue[2*j]<='9')&&(pcAttrValue[2*j]>='0'))
					pcSecPriKeyCkaIdValue[j] = (pcAttrValue[2*j] - '0')*16;
				else if ((pcAttrValue[2*j]<='F')&&(pcAttrValue[2*j]>='A'))
					pcSecPriKeyCkaIdValue[j] = (pcAttrValue[2*j] - 'A' + 10)*16;
				else if ((pcAttrValue[2*j]<='f')&&(pcAttrValue[2*j]>='a'))
					pcSecPriKeyCkaIdValue[j] = (pcAttrValue[2*j] - 'a' + 10)*16;

				if ((pcAttrValue[2*j+1]<='9')&&(pcAttrValue[2*j+1]>='0'))
					pcSecPriKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - '0');
				else if ((pcAttrValue[2*j+1]<='F')&&(pcAttrValue[2*j+1]>='A'))
					pcSecPriKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - 'A' + 10);
				else if ((pcAttrValue[2*j+1]<='f')&&(pcAttrValue[2*j+1]>='a'))
					pcSecPriKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - 'a' + 10);
			}
			sSecPriKeyTemplate.psKeyParams[i].pValue = pcSecPriKeyCkaIdValue;
			break;
		case CKA_MODULUS_BITS:
			sSecPriKeyTemplate.psKeyParams[i].type = CKA_VALUE_LEN;
			iSecPriKeyLen = atoi(pcAttrValue)/8;
			sSecPriKeyTemplate.psKeyParams[i].pValue = &iSecPriKeyLen;
			sSecPriKeyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);			
			break;
		case CKA_EXTRACTABLE:
			if (!strncmp(pcAttrValue,TRUE_ATTR,strlen(TRUE_ATTR)))
				sSecPriKeyTemplate.psKeyParams[i].pValue = &blTrue;
			else if (!strncmp(pcAttrValue,FALSE_ATTR,strlen(FALSE_ATTR)))
				sSecPriKeyTemplate.psKeyParams[i].pValue = &blFalse;
			break;
		case CKA_LABEL:
			sSecPriKeyTemplate.psKeyParams[i].pValue = pcAttrValue;
			sSecPriKeyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue);
			break;
		default:
			rvResult = CKR_ARGUMENTS_BAD;
			goto EXPORT_SECPRIKEY_BY_STRINGS;
		}
		if ((sSecPriKeyTemplate.psKeyParams[i].pValue == NULL)&&(sSecPriKeyTemplate.psKeyParams[i].type == -1)&&(sSecPriKeyTemplate.psKeyParams[i].ulValueLen == 0))
		{
			rvResult = CKR_ARGUMENTS_BAD;
			goto EXPORT_SECPRIKEY_BY_STRINGS;
		}
	}
#pragma endregion
	if (ulKeyType != -1)
	{
		sSecPriKeyTemplate.ulNumOfParams--;
	}
	else
	{
		sSecPriKeyTemplate.psKeyParams[sSecPriKeyTemplate.ulNumOfParams-1].type = CKA_CLASS;
		sSecPriKeyTemplate.psKeyParams[sSecPriKeyTemplate.ulNumOfParams-1].ulValueLen = sizeof(CK_ULONG);
		if (!strncmp((pcSecPriKeyInfo - 1)[0],SECRET_KEY,strlen(SECRET_KEY)))
		{
			sSecPriKeyTemplate.psKeyParams[sSecPriKeyTemplate.ulNumOfParams-1].pValue = &ulClass_SecKey;
		}
		else if (!strncmp((pcSecPriKeyInfo - 1)[0],PRIVATE_KEY,strlen(PRIVATE_KEY)))
		{
			sSecPriKeyTemplate.psKeyParams[sSecPriKeyTemplate.ulNumOfParams-1].pValue = &ulClass_PriKey;
		}
		else
		{
			rvResult = CKR_ARGUMENTS_BAD;
			goto EXPORT_SECPRIKEY_BY_STRINGS;
		}
	}
#pragma endregion
#pragma region GetPubKeyAttributesFromStrings
	if ((pcPubKeyInfo == NULL)&&(!ulPubKeyInfoAttrs))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto EXPORT_SECPRIKEY_BY_STRINGS;
	}
	sPubKeyTemplate.ulNumOfParams = ulPubKeyInfoAttrs + 1;
	sPubKeyTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sPubKeyTemplate.ulNumOfParams);
	for (CK_ULONG i = 0; i<sPubKeyTemplate.ulNumOfParams; i++)
	{
		sPubKeyTemplate.psKeyParams[i].ulValueLen = 0;
		sPubKeyTemplate.psKeyParams[i].pValue = NULL;
	}
	ulKeyType = -1;
#pragma region UserAttributes
	for (CK_ULONG i = 0; i<ulPubKeyInfoAttrs; i++)
	{
		if (pcPubKeyInfo[i] == NULL)
		{
			rvResult = CKR_ARGUMENTS_BAD;
			goto EXPORT_SECPRIKEY_BY_STRINGS;
		}
		ulPubKeyType = -1;
		sPubKeyTemplate.psKeyParams[i].pValue = NULL;
		sPubKeyTemplate.psKeyParams[i].type = -1;
		sPubKeyTemplate.psKeyParams[i].ulValueLen = 0;
		for (int j = 0; j<DEF_KEY_ATTRS_NUM; j++)
		{
			if (!strncmp(pcPubKeyInfo[i],DEF_KEY_ATTRS[j],strlen(DEF_KEY_ATTRS[j])))
				if (strlen(pcPubKeyInfo[i]) > strlen(DEF_KEY_ATTRS[j]))
				{
					ulPubKeyType = DEF_ATTR_VALUES[j];
					sPubKeyTemplate.psKeyParams[i].type = ulPubKeyType;
					pcAttrValue = pcPubKeyInfo[i] + strlen(DEF_KEY_ATTRS[j]);
				}
				else
				{
					rvResult = CKR_ARGUMENTS_BAD;
					goto EXPORT_SECPRIKEY_BY_STRINGS;
				}
		}
		switch (ulPubKeyType)
		{
		case CKA_KEY_TYPE:
			for (int j = 0; j<DEF_NUM_OF_ALGS; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_ALG_TYPES_NAMES[j],strlen(DEF_ALG_TYPES_NAMES[j])))
				{
					sPubKeyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_ALG_TYPES[j];
					if (!ulKeyClassInStrings) 
						ulKeyClassInStrings = DEF_ALG_TYPES[j];
					else
					{
						rvResult = CKR_ARGUMENTS_BAD;
						goto EXPORT_SECPRIKEY_BY_STRINGS;
					}
				}
			}
			sPubKeyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_CLASS:
			for (int j = 0; j<DEF_NUM_OF_CLASSES; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_CLASS_NAME[j],strlen(DEF_CLASS_NAME[j])))
				{
					sPubKeyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_CLASS_VALUE[j];
					if (ulKeyType != -1)
					{
						rvResult = CKR_ARGUMENTS_BAD;
						goto EXPORT_SECPRIKEY_BY_STRINGS;
					}
					ulKeyType = DEF_CLASS_VALUE[j];
				}
			}
			sPubKeyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_ID:
			if (pcPubKeyCkaIdValue)
			{
				rvResult = CKR_ARGUMENTS_BAD;
				goto EXPORT_SECPRIKEY_BY_STRINGS;
			}
			sPubKeyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue)/2;
			pcPubKeyCkaIdValue = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * sPubKeyTemplate.psKeyParams[i].ulValueLen);
			for (CK_ULONG j = 0; j<sPubKeyTemplate.psKeyParams[i].ulValueLen; j++)
			{
				if ((pcAttrValue[2*j]<='9')&&(pcAttrValue[2*j]>='0'))
					pcPubKeyCkaIdValue[j] = (pcAttrValue[2*j] - '0')*16;
				else if ((pcAttrValue[2*j]<='F')&&(pcAttrValue[2*j]>='A'))
					pcPubKeyCkaIdValue[j] = (pcAttrValue[2*j] - 'A' + 10)*16;
				else if ((pcAttrValue[2*j]<='f')&&(pcAttrValue[2*j]>='a'))
					pcPubKeyCkaIdValue[j] = (pcAttrValue[2*j] - 'a' + 10)*16;

				if ((pcAttrValue[2*j+1]<='9')&&(pcAttrValue[2*j+1]>='0'))
					pcPubKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - '0');
				else if ((pcAttrValue[2*j+1]<='F')&&(pcAttrValue[2*j+1]>='A'))
					pcPubKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - 'A' + 10);
				else if ((pcAttrValue[2*j+1]<='f')&&(pcAttrValue[2*j+1]>='a'))
					pcPubKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - 'a' + 10);
			}
			sPubKeyTemplate.psKeyParams[i].pValue = pcPubKeyCkaIdValue;
			break;
		case CKA_MODULUS_BITS:
			sPubKeyTemplate.psKeyParams[i].type = CKA_MODULUS_BITS;
			iPubKeyLen = atoi(pcAttrValue)/8;
			sPubKeyTemplate.psKeyParams[i].pValue = &iPubKeyLen;
			sPubKeyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);			
			break;
		case CKA_EXTRACTABLE:
			if (!strncmp(pcAttrValue,TRUE_ATTR,strlen(TRUE_ATTR)))
				sPubKeyTemplate.psKeyParams[i].pValue = &blTrue;
			else if (!strncmp(pcAttrValue,FALSE_ATTR,strlen(FALSE_ATTR)))
				sPubKeyTemplate.psKeyParams[i].pValue = &blFalse;
			break;
		case CKA_LABEL:
			sPubKeyTemplate.psKeyParams[i].pValue = pcAttrValue;
			sPubKeyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue);
			break;
		default:
			rvResult = CKR_ARGUMENTS_BAD;
			goto EXPORT_SECPRIKEY_BY_STRINGS;
		}
		if ((sPubKeyTemplate.psKeyParams[i].pValue == NULL)&&(sPubKeyTemplate.psKeyParams[i].type == -1)&&(sPubKeyTemplate.psKeyParams[i].ulValueLen == 0))
		{
			rvResult = CKR_ARGUMENTS_BAD;
			goto EXPORT_SECPRIKEY_BY_STRINGS;
		}
	}
#pragma endregion
	if (ulKeyType != -1)
	{
		sPubKeyTemplate.ulNumOfParams--;
	}
	else
	{
		sPubKeyTemplate.psKeyParams[sPubKeyTemplate.ulNumOfParams-1].type = CKA_CLASS;
		sPubKeyTemplate.psKeyParams[sPubKeyTemplate.ulNumOfParams-1].ulValueLen = sizeof(CK_ULONG);
		if (!strncmp((pcPubKeyInfo - 1)[0],PUBLIC_KEY,strlen(PUBLIC_KEY)))
		{
			sPubKeyTemplate.psKeyParams[sPubKeyTemplate.ulNumOfParams-1].pValue = &ulClass_PubKey;
		}
		else
		{
			rvResult = CKR_ARGUMENTS_BAD;
			goto EXPORT_SECPRIKEY_BY_STRINGS;
		}
	}
#pragma endregion
#pragma region GetPriKeyAttributesFromStrings
	if ((pcPriKeyInfo == NULL)&&(!ulPriKeyInfoAttrs))
	{
		sPriKeyTemplate.ulNumOfParams = 0;
		sPriKeyTemplate.psKeyParams = NULL;
	}
	else
	{
		sPriKeyTemplate.ulNumOfParams = ulPriKeyInfoAttrs + 1;
		sPriKeyTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sPriKeyTemplate.ulNumOfParams);
		for (CK_ULONG i = 0; i<sPriKeyTemplate.ulNumOfParams; i++)
		{
			sPriKeyTemplate.psKeyParams[i].ulValueLen = 0;
			sPriKeyTemplate.psKeyParams[i].pValue = NULL;
		}
		ulKeyType = -1;
#pragma region UserAttributes
		for (CK_ULONG i = 0; i<ulPriKeyInfoAttrs; i++)
		{
			if (pcPriKeyInfo[i] == NULL)
			{
				rvResult = CKR_ARGUMENTS_BAD;
				goto EXPORT_SECPRIKEY_BY_STRINGS;
			}
			ulPriKeyType = -1;
			sPriKeyTemplate.psKeyParams[i].pValue = NULL;
			sPriKeyTemplate.psKeyParams[i].type = -1;
			sPriKeyTemplate.psKeyParams[i].ulValueLen = 0;
			for (int j = 0; j<DEF_KEY_ATTRS_NUM; j++)
			{
				if (!strncmp(pcPriKeyInfo[i],DEF_KEY_ATTRS[j],strlen(DEF_KEY_ATTRS[j])))
					if (strlen(pcPriKeyInfo[i]) > strlen(DEF_KEY_ATTRS[j]))
					{
						ulPriKeyType = DEF_ATTR_VALUES[j];
						sPriKeyTemplate.psKeyParams[i].type = ulPriKeyType;
						pcAttrValue = pcPriKeyInfo[i] + strlen(DEF_KEY_ATTRS[j]);
					}
					else
					{
						rvResult = CKR_ARGUMENTS_BAD;
						goto EXPORT_SECPRIKEY_BY_STRINGS;
					}
			}
			switch (ulPriKeyType)
			{
			case CKA_KEY_TYPE:
				for (int j = 0; j<DEF_NUM_OF_ALGS; j++) 
				{
					if (!strncmp(pcAttrValue,DEF_ALG_TYPES_NAMES[j],strlen(DEF_ALG_TYPES_NAMES[j])))
					{
						sPriKeyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_ALG_TYPES[j];
						if (!ulKeyClassInStrings) 
							ulKeyClassInStrings = DEF_ALG_TYPES[j];
						else
						{
							rvResult = CKR_ARGUMENTS_BAD;
							goto EXPORT_SECPRIKEY_BY_STRINGS;
						}
					}
				}
				sPriKeyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
				break;
			case CKA_CLASS:
				for (int j = 0; j<DEF_NUM_OF_CLASSES; j++) 
				{
					if (!strncmp(pcAttrValue,DEF_CLASS_NAME[j],strlen(DEF_CLASS_NAME[j])))
					{
						sPriKeyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_CLASS_VALUE[j];
						if (ulKeyType != -1)
						{
							rvResult = CKR_ARGUMENTS_BAD;
							goto EXPORT_SECPRIKEY_BY_STRINGS;
						}
						ulKeyType = DEF_CLASS_VALUE[j];
					}
				}
				sPriKeyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
				break;
			case CKA_ID:
				if (pcPriKeyCkaIdValue)
				{
					rvResult = CKR_ARGUMENTS_BAD;
					goto EXPORT_SECPRIKEY_BY_STRINGS;
				}
				sPriKeyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue)/2;
				pcPriKeyCkaIdValue = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * sPriKeyTemplate.psKeyParams[i].ulValueLen);
				for (CK_ULONG j = 0; j<sPriKeyTemplate.psKeyParams[i].ulValueLen; j++)
				{
					if ((pcAttrValue[2*j]<='9')&&(pcAttrValue[2*j]>='0'))
						pcPriKeyCkaIdValue[j] = (pcAttrValue[2*j] - '0')*16;
					else if ((pcAttrValue[2*j]<='F')&&(pcAttrValue[2*j]>='A'))
						pcPriKeyCkaIdValue[j] = (pcAttrValue[2*j] - 'A' + 10)*16;
					else if ((pcAttrValue[2*j]<='f')&&(pcAttrValue[2*j]>='a'))
						pcPriKeyCkaIdValue[j] = (pcAttrValue[2*j] - 'a' + 10)*16;

					if ((pcAttrValue[2*j+1]<='9')&&(pcAttrValue[2*j+1]>='0'))
						pcPriKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - '0');
					else if ((pcAttrValue[2*j+1]<='F')&&(pcAttrValue[2*j+1]>='A'))
						pcPriKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - 'A' + 10);
					else if ((pcAttrValue[2*j+1]<='f')&&(pcAttrValue[2*j+1]>='a'))
						pcPriKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - 'a' + 10);
				}
				sPriKeyTemplate.psKeyParams[i].pValue = pcPriKeyCkaIdValue;
				break;
			case CKA_EXTRACTABLE:
				if (!strncmp(pcAttrValue,TRUE_ATTR,strlen(TRUE_ATTR)))
					sPriKeyTemplate.psKeyParams[i].pValue = &blTrue;
				else if (!strncmp(pcAttrValue,FALSE_ATTR,strlen(FALSE_ATTR)))
					sPriKeyTemplate.psKeyParams[i].pValue = &blFalse;
				break;
			case CKA_LABEL:
				sPriKeyTemplate.psKeyParams[i].pValue = pcAttrValue;
				sPriKeyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue);
				break;
			default:
				rvResult = CKR_ARGUMENTS_BAD;
				goto EXPORT_SECPRIKEY_BY_STRINGS;
			}
			if ((sPriKeyTemplate.psKeyParams[i].pValue == NULL)&&(sPriKeyTemplate.psKeyParams[i].type == -1)&&(sPriKeyTemplate.psKeyParams[i].ulValueLen == 0))
			{
				rvResult = CKR_ARGUMENTS_BAD;
				goto EXPORT_SECPRIKEY_BY_STRINGS;
			}
		}
#pragma endregion
		if (ulKeyType != -1)
		{
			sPriKeyTemplate.ulNumOfParams--;
		}
		else
		{
			sPriKeyTemplate.psKeyParams[sPriKeyTemplate.ulNumOfParams-1].type = CKA_CLASS;
			sPriKeyTemplate.psKeyParams[sPriKeyTemplate.ulNumOfParams-1].ulValueLen = sizeof(CK_ULONG);
			if (!strncmp((pcPriKeyInfo - 1)[0],PRIVATE_KEY,strlen(PRIVATE_KEY)))
			{
				sPriKeyTemplate.psKeyParams[sPriKeyTemplate.ulNumOfParams-1].pValue = &ulClass_PriKey;
			}
			else
			{
				rvResult = CKR_ARGUMENTS_BAD;
				goto EXPORT_SECPRIKEY_BY_STRINGS;
			}
		}
	}
#pragma endregion
#pragma endregion
#pragma region MakeExportPriSecKey
	rvResult = pKmFuncList->ExportSecPriKey(sSecPriKeyTemplate,sPubKeyTemplate,sPriKeyTemplate,pbExportedKey,ulExportedKeyLen);
#pragma endregion
EXPORT_SECPRIKEY_BY_STRINGS:
#pragma region ExportSecPriKeyByStringsFinalization
	pcSecPriKeyInfo = NULL;
	pcPubKeyInfo = NULL;
	pcPriKeyInfo = NULL;
	if (sSecPriKeyTemplate.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sSecPriKeyTemplate.ulNumOfParams; i++)
		{
			sSecPriKeyTemplate.psKeyParams[i].pValue = NULL;
		}
		free (sSecPriKeyTemplate.psKeyParams);
	}
	if (sPubKeyTemplate.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sPubKeyTemplate.ulNumOfParams; i++)
		{
			sPubKeyTemplate.psKeyParams[i].pValue = NULL;
		}
		free (sPubKeyTemplate.psKeyParams);
	}
	if (sPriKeyTemplate.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sPriKeyTemplate.ulNumOfParams; i++)
		{
			sPriKeyTemplate.psKeyParams[i].pValue = NULL;
		}
		free (sPriKeyTemplate.psKeyParams);
	}
#pragma endregion
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to import secret or private key
@param pcKeysInfo(in) - strings containing attributes to define, on which keys wrapped key should be imported; if no keys defined, then data from pbExportedKey will be used
@param ulNumOfParams(in) - number of strings in pcKeysInfo;
@param pbExportedKey(in) - array of CK_BYTEs containing keys info and its value
@param ulExportedKeyLen(in) - length of pbExportedKey
*/
void UserFunctionality::ImportSecPriKeyByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams, CK_BYTE_PTR pbExportedKey, CK_ULONG ulExportedKeyLen)
{
	char **pcPubKeyInfo = NULL, **pcPriKeyInfo = NULL;
	CK_ULONG ulPubKeyInfoAttrs = 0, ulPriKeyInfoAttrs = 0;
	CK_ULONG ulCounter = 0;
	MY_KEY_TEMPLATE_INFO sPubKeyTemplate, sPriKeyTemplate;
	CK_ULONG ulPubKeyType = 0, ulPriKeyType = 0;
	CK_BYTE *pcPubKeyCkaIdValue = NULL, *pcPriKeyCkaIdValue = NULL;
	int iPubKeyLen = 0, iPriKeyLen = 0;

	char *pcAttrValue = NULL;
	CK_ULONG ulKeyClassInStrings = 0;
	CK_ULONG ulKeyType = 0;

	sPubKeyTemplate.psKeyParams = NULL;
	sPubKeyTemplate.ulNumOfParams = 0;
	sPriKeyTemplate.psKeyParams = NULL;
	sPriKeyTemplate.ulNumOfParams = 0;

	if (ulNumOfParams)
	{
#pragma region ParsingInputAttributesTo
		if (strncmp(pcKeysInfo[ulCounter],PUBLIC_KEY,strlen(PUBLIC_KEY)))
		{
			rvResult = CKR_ARGUMENTS_BAD;
			goto EXPORT_SECPRIKEY_BY_STRINGS;
		}
		ulCounter++;
		pcPubKeyInfo = &(pcKeysInfo[ulCounter]);
		while ((strncmp(pcKeysInfo[ulCounter],PRIVATE_KEY,strlen(PRIVATE_KEY)))&&(ulCounter<ulNumOfParams))
		{
			ulCounter++;
			ulPubKeyInfoAttrs++;
		}

		if (strncmp(pcKeysInfo[ulCounter],PRIVATE_KEY,strlen(PRIVATE_KEY)))
		{
			pcPriKeyInfo = NULL;
		}
		else
		{
			ulCounter++;
			pcPriKeyInfo = &(pcKeysInfo[ulCounter]);
			while (ulCounter<ulNumOfParams)
			{
				ulCounter++;
				ulPriKeyInfoAttrs++;
			}
		}
#pragma endregion
#pragma region GetAttributesFromStrings
#pragma region GetPubKeyAttributesFromStrings
		if ((pcPubKeyInfo == NULL)&&(!ulPubKeyInfoAttrs))
		{
			rvResult = CKR_ARGUMENTS_BAD;
			goto EXPORT_SECPRIKEY_BY_STRINGS;
		}
		sPubKeyTemplate.ulNumOfParams = ulPubKeyInfoAttrs + 1;
		sPubKeyTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sPubKeyTemplate.ulNumOfParams);
		for (CK_ULONG i = 0; i<sPubKeyTemplate.ulNumOfParams; i++)
		{
			sPubKeyTemplate.psKeyParams[i].ulValueLen = 0;
			sPubKeyTemplate.psKeyParams[i].pValue = NULL;
		}
		ulKeyType = -1;
#pragma region UserAttributes
		for (CK_ULONG i = 0; i<ulPubKeyInfoAttrs; i++)
		{
			if (pcPubKeyInfo[i] == NULL)
			{
				rvResult = CKR_ARGUMENTS_BAD;
				goto EXPORT_SECPRIKEY_BY_STRINGS;
			}
			ulPubKeyType = -1;
			sPubKeyTemplate.psKeyParams[i].pValue = NULL;
			sPubKeyTemplate.psKeyParams[i].type = -1;
			sPubKeyTemplate.psKeyParams[i].ulValueLen = 0;
			for (int j = 0; j<DEF_KEY_ATTRS_NUM; j++)
			{
				if (!strncmp(pcPubKeyInfo[i],DEF_KEY_ATTRS[j],strlen(DEF_KEY_ATTRS[j])))
					if (strlen(pcPubKeyInfo[i]) > strlen(DEF_KEY_ATTRS[j]))
					{
						ulPubKeyType = DEF_ATTR_VALUES[j];
						sPubKeyTemplate.psKeyParams[i].type = ulPubKeyType;
						pcAttrValue = pcPubKeyInfo[i] + strlen(DEF_KEY_ATTRS[j]);
					}
					else
					{
						rvResult = CKR_ARGUMENTS_BAD;
						goto EXPORT_SECPRIKEY_BY_STRINGS;
					}
			}
			switch (ulPubKeyType)
			{
			case CKA_KEY_TYPE:
				for (int j = 0; j<DEF_NUM_OF_ALGS; j++) 
				{
					if (!strncmp(pcAttrValue,DEF_ALG_TYPES_NAMES[j],strlen(DEF_ALG_TYPES_NAMES[j])))
					{
						sPubKeyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_ALG_TYPES[j];
						if (!ulKeyClassInStrings) 
							ulKeyClassInStrings = DEF_ALG_TYPES[j];
						else
						{
							rvResult = CKR_ARGUMENTS_BAD;
							goto EXPORT_SECPRIKEY_BY_STRINGS;
						}
					}
				}
				sPubKeyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
				break;
			case CKA_CLASS:
				for (int j = 0; j<DEF_NUM_OF_CLASSES; j++) 
				{
					if (!strncmp(pcAttrValue,DEF_CLASS_NAME[j],strlen(DEF_CLASS_NAME[j])))
					{
						sPubKeyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_CLASS_VALUE[j];
						if (ulKeyType != -1)
						{
							rvResult = CKR_ARGUMENTS_BAD;
							goto EXPORT_SECPRIKEY_BY_STRINGS;
						}
						ulKeyType = DEF_CLASS_VALUE[j];
					}
				}
				sPubKeyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
				break;
			case CKA_ID:
				if (pcPubKeyCkaIdValue)
				{
					rvResult = CKR_ARGUMENTS_BAD;
					goto EXPORT_SECPRIKEY_BY_STRINGS;
				}
				sPubKeyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue)/2;
				pcPubKeyCkaIdValue = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * sPubKeyTemplate.psKeyParams[i].ulValueLen);
				for (CK_ULONG j = 0; j<sPubKeyTemplate.psKeyParams[i].ulValueLen; j++)
				{
					if ((pcAttrValue[2*j]<='9')&&(pcAttrValue[2*j]>='0'))
						pcPubKeyCkaIdValue[j] = (pcAttrValue[2*j] - '0')*16;
					else if ((pcAttrValue[2*j]<='F')&&(pcAttrValue[2*j]>='A'))
						pcPubKeyCkaIdValue[j] = (pcAttrValue[2*j] - 'A' + 10)*16;
					else if ((pcAttrValue[2*j]<='f')&&(pcAttrValue[2*j]>='a'))
						pcPubKeyCkaIdValue[j] = (pcAttrValue[2*j] - 'a' + 10)*16;

					if ((pcAttrValue[2*j+1]<='9')&&(pcAttrValue[2*j+1]>='0'))
						pcPubKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - '0');
					else if ((pcAttrValue[2*j+1]<='F')&&(pcAttrValue[2*j+1]>='A'))
						pcPubKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - 'A' + 10);
					else if ((pcAttrValue[2*j+1]<='f')&&(pcAttrValue[2*j+1]>='a'))
						pcPubKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - 'a' + 10);
				}
				sPubKeyTemplate.psKeyParams[i].pValue = pcPubKeyCkaIdValue;
				break;
			case CKA_MODULUS_BITS:
				sPubKeyTemplate.psKeyParams[i].type = CKA_MODULUS_BITS;
				iPubKeyLen = atoi(pcAttrValue)/8;
				sPubKeyTemplate.psKeyParams[i].pValue = &iPubKeyLen;
				sPubKeyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);			
				break;
			case CKA_EXTRACTABLE:
				if (!strncmp(pcAttrValue,TRUE_ATTR,strlen(TRUE_ATTR)))
					sPubKeyTemplate.psKeyParams[i].pValue = &blTrue;
				else if (!strncmp(pcAttrValue,FALSE_ATTR,strlen(FALSE_ATTR)))
					sPubKeyTemplate.psKeyParams[i].pValue = &blFalse;
				break;
			case CKA_LABEL:
				sPubKeyTemplate.psKeyParams[i].pValue = pcAttrValue;
				sPubKeyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue);
				break;
			default:
				rvResult = CKR_ARGUMENTS_BAD;
				goto EXPORT_SECPRIKEY_BY_STRINGS;
			}
			if ((sPubKeyTemplate.psKeyParams[i].pValue == NULL)&&(sPubKeyTemplate.psKeyParams[i].type == -1)&&(sPubKeyTemplate.psKeyParams[i].ulValueLen == 0))
			{
				rvResult = CKR_ARGUMENTS_BAD;
				goto EXPORT_SECPRIKEY_BY_STRINGS;
			}
		}
#pragma endregion
		if (ulKeyType != -1)
		{
			sPubKeyTemplate.ulNumOfParams--;
		}
		else
		{
			sPubKeyTemplate.psKeyParams[sPubKeyTemplate.ulNumOfParams-1].type = CKA_CLASS;
			sPubKeyTemplate.psKeyParams[sPubKeyTemplate.ulNumOfParams-1].ulValueLen = sizeof(CK_ULONG);
			if (!strncmp((pcPubKeyInfo - 1)[0],PUBLIC_KEY,strlen(PUBLIC_KEY)))
			{
				sPubKeyTemplate.psKeyParams[sPubKeyTemplate.ulNumOfParams-1].pValue = &ulClass_PubKey;
			}
			else
			{
				rvResult = CKR_ARGUMENTS_BAD;
				goto EXPORT_SECPRIKEY_BY_STRINGS;
			}
		}
#pragma endregion
#pragma region GetPriKeyAttributesFromStrings
		if ((pcPriKeyInfo == NULL)&&(!ulPriKeyInfoAttrs))
		{
			sPubKeyTemplate.ulNumOfParams = 0;
			sPubKeyTemplate.psKeyParams = NULL;
		}
		else
		{
			sPriKeyTemplate.ulNumOfParams = ulPriKeyInfoAttrs + 1;
			sPriKeyTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sPriKeyTemplate.ulNumOfParams);
			for (CK_ULONG i = 0; i<sPriKeyTemplate.ulNumOfParams; i++)
			{
				sPriKeyTemplate.psKeyParams[i].ulValueLen = 0;
				sPriKeyTemplate.psKeyParams[i].pValue = NULL;
			}
			ulKeyType = -1;
#pragma region UserAttributes
			for (CK_ULONG i = 0; i<ulPriKeyInfoAttrs; i++)
			{
				if (pcPriKeyInfo[i] == NULL)
				{
					rvResult = CKR_ARGUMENTS_BAD;
					goto EXPORT_SECPRIKEY_BY_STRINGS;
				}
				ulPriKeyType = -1;
				sPriKeyTemplate.psKeyParams[i].pValue = NULL;
				sPriKeyTemplate.psKeyParams[i].type = -1;
				sPriKeyTemplate.psKeyParams[i].ulValueLen = 0;
				for (int j = 0; j<DEF_KEY_ATTRS_NUM; j++)
				{
					if (!strncmp(pcPriKeyInfo[i],DEF_KEY_ATTRS[j],strlen(DEF_KEY_ATTRS[j])))
						if (strlen(pcPriKeyInfo[i]) > strlen(DEF_KEY_ATTRS[j]))
						{
							ulPriKeyType = DEF_ATTR_VALUES[j];
							sPriKeyTemplate.psKeyParams[i].type = ulPriKeyType;
							pcAttrValue = pcPriKeyInfo[i] + strlen(DEF_KEY_ATTRS[j]);
						}
						else
						{
							rvResult = CKR_ARGUMENTS_BAD;
							goto EXPORT_SECPRIKEY_BY_STRINGS;
						}
				}
				switch (ulPriKeyType)
				{
				case CKA_KEY_TYPE:
					for (int j = 0; j<DEF_NUM_OF_ALGS; j++) 
					{
						if (!strncmp(pcAttrValue,DEF_ALG_TYPES_NAMES[j],strlen(DEF_ALG_TYPES_NAMES[j])))
						{
							sPriKeyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_ALG_TYPES[j];
							if (!ulKeyClassInStrings) 
								ulKeyClassInStrings = DEF_ALG_TYPES[j];
							else
							{
								rvResult = CKR_ARGUMENTS_BAD;
								goto EXPORT_SECPRIKEY_BY_STRINGS;
							}
						}
					}
					sPriKeyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
					break;
				case CKA_CLASS:
					for (int j = 0; j<DEF_NUM_OF_CLASSES; j++) 
					{
						if (!strncmp(pcAttrValue,DEF_CLASS_NAME[j],strlen(DEF_CLASS_NAME[j])))
						{
							sPriKeyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_CLASS_VALUE[j];
							if (ulKeyType != -1)
							{
								rvResult = CKR_ARGUMENTS_BAD;
								goto EXPORT_SECPRIKEY_BY_STRINGS;
							}
							ulKeyType = DEF_CLASS_VALUE[j];
						}
					}
					sPriKeyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
					break;
				case CKA_ID:
					if (pcPriKeyCkaIdValue)
					{
						rvResult = CKR_ARGUMENTS_BAD;
						goto EXPORT_SECPRIKEY_BY_STRINGS;
					}
					sPriKeyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue)/2;
					pcPriKeyCkaIdValue = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * sPriKeyTemplate.psKeyParams[i].ulValueLen);
					for (CK_ULONG j = 0; j<sPriKeyTemplate.psKeyParams[i].ulValueLen; j++)
					{
						if ((pcAttrValue[2*j]<='9')&&(pcAttrValue[2*j]>='0'))
							pcPriKeyCkaIdValue[j] = (pcAttrValue[2*j] - '0')*16;
						else if ((pcAttrValue[2*j]<='F')&&(pcAttrValue[2*j]>='A'))
							pcPriKeyCkaIdValue[j] = (pcAttrValue[2*j] - 'A' + 10)*16;
						else if ((pcAttrValue[2*j]<='f')&&(pcAttrValue[2*j]>='a'))
							pcPriKeyCkaIdValue[j] = (pcAttrValue[2*j] - 'a' + 10)*16;

						if ((pcAttrValue[2*j+1]<='9')&&(pcAttrValue[2*j+1]>='0'))
							pcPriKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - '0');
						else if ((pcAttrValue[2*j+1]<='F')&&(pcAttrValue[2*j+1]>='A'))
							pcPriKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - 'A' + 10);
						else if ((pcAttrValue[2*j+1]<='f')&&(pcAttrValue[2*j+1]>='a'))
							pcPriKeyCkaIdValue[j] += (pcAttrValue[2*j+1] - 'a' + 10);
					}
					sPriKeyTemplate.psKeyParams[i].pValue = pcPriKeyCkaIdValue;
					break;
				case CKA_EXTRACTABLE:
					if (!strncmp(pcAttrValue,TRUE_ATTR,strlen(TRUE_ATTR)))
						sPriKeyTemplate.psKeyParams[i].pValue = &blTrue;
					else if (!strncmp(pcAttrValue,FALSE_ATTR,strlen(FALSE_ATTR)))
						sPriKeyTemplate.psKeyParams[i].pValue = &blFalse;
					break;
				case CKA_LABEL:
					sPriKeyTemplate.psKeyParams[i].pValue = pcAttrValue;
					sPriKeyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue);
					break;
				default:
					rvResult = CKR_ARGUMENTS_BAD;
					goto EXPORT_SECPRIKEY_BY_STRINGS;
				}
				if ((sPriKeyTemplate.psKeyParams[i].pValue == NULL)&&(sPriKeyTemplate.psKeyParams[i].type == -1)&&(sPriKeyTemplate.psKeyParams[i].ulValueLen == 0))
				{
					rvResult = CKR_ARGUMENTS_BAD;
					goto EXPORT_SECPRIKEY_BY_STRINGS;
				}
			}
#pragma endregion
			if (ulKeyType != -1)
			{
				sPriKeyTemplate.ulNumOfParams--;
			}
			else
			{
				sPriKeyTemplate.psKeyParams[sPriKeyTemplate.ulNumOfParams-1].type = CKA_CLASS;
				sPriKeyTemplate.psKeyParams[sPriKeyTemplate.ulNumOfParams-1].ulValueLen = sizeof(CK_ULONG);
				if (!strncmp((pcPriKeyInfo - 1)[0],PRIVATE_KEY,strlen(PRIVATE_KEY)))
				{
					sPriKeyTemplate.psKeyParams[sPriKeyTemplate.ulNumOfParams-1].pValue = &ulClass_PriKey;
				}
				else
				{
					rvResult = CKR_ARGUMENTS_BAD;
					goto EXPORT_SECPRIKEY_BY_STRINGS;
				}
			}
		}
#pragma endregion
#pragma endregion
	}
#pragma region MakeExportPriSecKey
	rvResult = pKmFuncList->ImportSecPriKey(sPubKeyTemplate,sPriKeyTemplate,pbExportedKey,ulExportedKeyLen);
#pragma endregion
EXPORT_SECPRIKEY_BY_STRINGS:
#pragma region ExportSecPriKeyByStringsFinalization
	pcPubKeyInfo = NULL;
	pcPriKeyInfo = NULL;
	if (sPubKeyTemplate.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sPubKeyTemplate.ulNumOfParams; i++)
		{
			sPubKeyTemplate.psKeyParams[i].pValue = NULL;
		}
		free (sPubKeyTemplate.psKeyParams);
	}
	if (sPriKeyTemplate.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sPriKeyTemplate.ulNumOfParams; i++)
		{
			sPriKeyTemplate.psKeyParams[i].pValue = NULL;
		}
		free (sPriKeyTemplate.psKeyParams);
	}
#pragma endregion
};
//==================================================================================================================
/**
@brief Function to write buffer of CK_BYTEs to file
@param pcFilename(in) - name of file to write data to
@param pbData(in) - array of CK_BYTEs to be written
@param ulDataLen(in) - length of pbData
*/
void UserFunctionality::WriteDataToFile(char *pcFilename, CK_BYTE_PTR pbData, CK_ULONG ulDataLen)
{
	FILE *f = NULL;
	if ((pcFilename == NULL)||(pbData == NULL)||(!ulDataLen))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
	if (NULL == (f = fopen(pcFilename,"wb+")))
	{
		rvResult = CKR_FILE_ERROR;
		return;
	}
	if (fwrite(pbData,sizeof(CK_BYTE),ulDataLen,f) != ulDataLen)
	{
		fclose(f);
		rvResult = CKR_FILE_ERROR;
		return;
	}
	fclose(f);
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to read buffer of CK_BYTEs from file
@param pcFilename(in) - name of file to read data from
@param pbData(out) - pointer to memory data will be readed to; if NULL only ulDataLen will be returned
@param ulDataLen(out) - length of pbData
*/
void UserFunctionality::ReadDataFromFile(char *pcFilename, CK_BYTE_PTR pbData, CK_ULONG_PTR ulDataLen)
{
	FILE *f = NULL;

	if (pcFilename == NULL)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
	if (NULL == (f = fopen(pcFilename,"rb")))
	{
		rvResult = CKR_FILE_ERROR;
		return;
	}

	fseek(f, 0, 2);
	*ulDataLen = ftell(f);
	if (*ulDataLen == -1) 
	{
		fclose(f);
		rvResult = NOT_ENOUGH_MEMORY;
		return;
	}
	if (pbData)
	{
		rewind(f);
		fread(pbData, *ulDataLen, 1, f);
	}
	fclose(f);
};
//==================================================================================================================
/**
@brief Function to export public key to file
@param pcInputData(in) - strings containing attributes to define, which key should be exported and to which file
@param ulNumOfParams(in) - number of strings in pcInputData;
*/
void UserFunctionality::ExportPublicToFile(char **pcInputData, CK_ULONG ulNumOfParams)
{
	CK_BYTE_PTR pbTempBuffer = NULL;
	CK_ULONG ulTempBufferLen = 0;
	if (ulNumOfParams == 1)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
	ExportPublicKeyByStringAttributes(pcInputData + 1, ulNumOfParams - 1, pbTempBuffer,&ulTempBufferLen);
	if ((rvResult == CKR_OK)&&(ulTempBufferLen))
	{
		pbTempBuffer = (CK_BYTE_PTR) malloc (sizeof(CK_BYTE) * ulTempBufferLen);
		ExportPublicKeyByStringAttributes(pcInputData + 1, ulNumOfParams - 1, pbTempBuffer,&ulTempBufferLen);
		if (rvResult == CKR_OK)
		{
			WriteDataToFile(pcInputData[0], pbTempBuffer, ulTempBufferLen);
		}
	}
	if (pbTempBuffer) free (pbTempBuffer);
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to export secret or private key to file
@param pcInputData(in) - strings containing attributes to define, which key should be exported, on which keys and to which file
@param ulNumOfParams(in) - number of strings in pcInputData;
*/
void UserFunctionality::ExportSecPriToFile(char **pcInputData, CK_ULONG ulNumOfParams)
{
	CK_BYTE_PTR pbTempBuffer = NULL;
	CK_ULONG ulTempBufferLen = 0;
	if (ulNumOfParams == 1)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
	ExportSecPriKeyByStringAttributes(pcInputData + 1, ulNumOfParams - 1, pbTempBuffer,&ulTempBufferLen);
	if ((rvResult == CKR_OK)&&(ulTempBufferLen))
	{
		pbTempBuffer = (CK_BYTE_PTR) malloc (sizeof(CK_BYTE) * ulTempBufferLen);
		ExportSecPriKeyByStringAttributes(pcInputData + 1, ulNumOfParams - 1, pbTempBuffer,&ulTempBufferLen);
		if (rvResult == CKR_OK)
		{
			WriteDataToFile(pcInputData[0], pbTempBuffer, ulTempBufferLen);
		}
	}
	if (pbTempBuffer) free (pbTempBuffer);
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to import public key from file
@param pcInputData(in) - strings containing attributes to define, from which file key should be exported
@param ulNumOfParams(in) - number of strings in pcInputData;
*/
void UserFunctionality::ImportPublicFromFile(char **pcInputData, CK_ULONG ulNumOfParams)
{
	CK_BYTE_PTR pbTempBuffer = NULL;
	CK_ULONG ulTempBufferLen = 0;
	ReadDataFromFile(pcInputData[0],pbTempBuffer,&ulTempBufferLen);
	if ((rvResult == CKR_OK)&&(ulTempBufferLen))
	{
		pbTempBuffer = (CK_BYTE_PTR) malloc (sizeof(CK_BYTE) * ulTempBufferLen);
		ReadDataFromFile(pcInputData[0],pbTempBuffer,&ulTempBufferLen);
		if (rvResult == CKR_OK)
		{
			rvResult = pKmFuncList->ImportPublicKey(pbTempBuffer,ulTempBufferLen);
		}
	}
	if (pbTempBuffer) free (pbTempBuffer);
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to import secret or private key from file
@param pcInputData(in) - strings containing attributes to define, from which file key should be exported and on which keys if this info is needed
@param ulNumOfParams(in) - number of strings in pcInputData;
*/
void UserFunctionality::ImportSecPriFromFile(char **pcInputData, CK_ULONG ulNumOfParams)
{
	CK_BYTE_PTR pbTempBuffer = NULL;
	char **pcTemp = NULL;
	CK_ULONG ulTempBufferLen = 0;
	MY_KEY_TEMPLATE_INFO sPubKeyInfo, sPriKeyInfo;

	if (ulNumOfParams == 1)
	{
		pcTemp = NULL;
	}
	else
	{
		pcTemp = pcInputData + 1;
	}
	sPubKeyInfo.psKeyParams = NULL;
	sPubKeyInfo.ulNumOfParams = 0;
	sPriKeyInfo.psKeyParams = NULL;
	sPriKeyInfo.ulNumOfParams = 0;

	ReadDataFromFile(pcInputData[0],pbTempBuffer,&ulTempBufferLen);
	if ((rvResult == CKR_OK)&&(ulTempBufferLen))
	{
		pbTempBuffer = (CK_BYTE_PTR) malloc (sizeof(CK_BYTE) * ulTempBufferLen);
		ReadDataFromFile(pcInputData[0],pbTempBuffer,&ulTempBufferLen);
		if (rvResult == CKR_OK)
		{
			ImportSecPriKeyByStringAttributes(pcTemp,ulNumOfParams-1,pbTempBuffer,ulTempBufferLen);
		}
	}
	pcTemp = NULL;
	if (pbTempBuffer) free (pbTempBuffer);
};
//==================================================================================================================
/*
//*/
//------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------
void UserFunctionality::GenerateGost3410KeyPairByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams)
{
	CK_RV rvResult = ERROR_SUCCESS;
	MY_KEY_TEMPLATE_INFO sMyPubTemplate,sMyPriTemplate;
	CK_ULONG ulKeyType = CKK_GR3410EL;
	char *gostR3410params_oidA = "1.2.643.2.2.35.1";
	char *gostR3410params_oidB = "1.2.643.2.2.35.2";
	char *gostR3410params_oidC = "1.2.643.2.2.35.3";
	if (ulNumOfParams <= 0)
		return;
	if (ulNumOfParams > 2) 
		return;

	memset (&sMyPubTemplate,0,sizeof(MY_KEY_TEMPLATE_INFO));
	memset (&sMyPriTemplate,0,sizeof(MY_KEY_TEMPLATE_INFO));

	sMyPriTemplate.ulNumOfParams = ulNumOfParams;
	sMyPriTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE) * sMyPriTemplate.ulNumOfParams);
	sMyPriTemplate.psKeyParams[0].type = CKA_KEY_TYPE;
	sMyPriTemplate.psKeyParams[0].ulValueLen = sizeof(CK_ULONG);
	sMyPriTemplate.psKeyParams[0].pValue = &ulKeyType;

	sMyPubTemplate.ulNumOfParams = ulNumOfParams + 1;
	sMyPubTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE) * sMyPubTemplate.ulNumOfParams);
	sMyPubTemplate.psKeyParams[0].type = CKA_KEY_TYPE;
	sMyPubTemplate.psKeyParams[0].ulValueLen = sizeof(CK_ULONG);
	sMyPubTemplate.psKeyParams[0].pValue = &ulKeyType;
	sMyPubTemplate.psKeyParams[1].type = CKA_GR3410_PARAMETER_OID;
	sMyPubTemplate.psKeyParams[1].ulValueLen = strlen(gostR3410params_oidA);
	sMyPubTemplate.psKeyParams[1].pValue = gostR3410params_oidA;

	if (!strncmp(pcKeysInfo[0],GOST_OID_B, strlen(GOST_OID_B)))
	{
		sMyPubTemplate.psKeyParams[1].pValue = gostR3410params_oidB;
	}
	if (!strncmp(pcKeysInfo[0],GOST_OID_C, strlen(GOST_OID_C)))
	{
		sMyPubTemplate.psKeyParams[1].pValue = gostR3410params_oidC;
	}

	if (ulNumOfParams == 2)
	{
		sMyPriTemplate.psKeyParams[1].type = CKA_LABEL;
		sMyPriTemplate.psKeyParams[1].ulValueLen = strlen(pcKeysInfo[1]);
		sMyPriTemplate.psKeyParams[1].pValue = pcKeysInfo[1];
		sMyPubTemplate.psKeyParams[2].type = CKA_LABEL;
		sMyPubTemplate.psKeyParams[2].ulValueLen = strlen(pcKeysInfo[1]);
		sMyPubTemplate.psKeyParams[2].pValue = pcKeysInfo[1];
	}

	rvResult = pKmFuncList->GenerateKeyPair(sMyPriTemplate,sMyPubTemplate,NULL);

	for (CK_ULONG i= 0; i<sMyPubTemplate.ulNumOfParams; i++)
		sMyPubTemplate.psKeyParams[i].pValue = NULL;
	for (CK_ULONG i= 0; i<sMyPriTemplate.ulNumOfParams; i++)
		sMyPriTemplate.psKeyParams[i].pValue = NULL;
	free (sMyPubTemplate.psKeyParams);
	free (sMyPriTemplate.psKeyParams);
};


//------------------------------------------------------------------------------------------------------------------
void UserFunctionality::GenerateGost28147KeyByStringAttributes(char **pcKeyInfo, CK_ULONG ulNumOfParams)
{
	CK_RV rvResult = ERROR_SUCCESS;
	MY_KEY_TEMPLATE_INFO sMyKeyTemplate;
	CK_ULONG ulKeyType = CKK_G28147;
	char *gostR28147params_oidA = OID_CRYPT_A;
	char *gostR28147params_oidB = OID_CRYPT_B;
	char *gostR28147params_oidC = OID_CRYPT_C;
	char *gostR28147params_oidD = OID_CRYPT_D;
	if (ulNumOfParams <= 0)
		return;
	if (ulNumOfParams > 2) 
		return;

	memset (&sMyKeyTemplate,0,sizeof(MY_KEY_TEMPLATE_INFO));

	sMyKeyTemplate.ulNumOfParams = 3;
	sMyKeyTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE) * sMyKeyTemplate.ulNumOfParams);
	sMyKeyTemplate.psKeyParams[0].type = CKA_KEY_TYPE;
	sMyKeyTemplate.psKeyParams[0].ulValueLen = sizeof(CK_ULONG);
	sMyKeyTemplate.psKeyParams[0].pValue = &ulKeyType;
	sMyKeyTemplate.psKeyParams[1].type = CKA_OBJECT_ID;
	sMyKeyTemplate.psKeyParams[1].ulValueLen = strlen(gostR28147params_oidA);
	sMyKeyTemplate.psKeyParams[1].pValue = gostR28147params_oidA;

	if (!strncmp(pcKeyInfo[0],GOST_OID_B, strlen(GOST_OID_B)))
	{
		sMyKeyTemplate.psKeyParams[1].pValue = gostR28147params_oidB;
	}
	if (!strncmp(pcKeyInfo[0],GOST_OID_C, strlen(GOST_OID_C)))
	{
		sMyKeyTemplate.psKeyParams[1].pValue = gostR28147params_oidC;
	}
	if (!strncmp(pcKeyInfo[0],GOST_OID_D, strlen(GOST_OID_D)))
	{
		sMyKeyTemplate.psKeyParams[1].pValue = gostR28147params_oidD;
	}

	if (ulNumOfParams == 2)
	{
		sMyKeyTemplate.psKeyParams[2].type = CKA_LABEL;
		sMyKeyTemplate.psKeyParams[2].ulValueLen = strlen(pcKeyInfo[1]);
		sMyKeyTemplate.psKeyParams[2].pValue = pcKeyInfo[1];
	}
	rvResult = pKmFuncList->GenerateSecKey(sMyKeyTemplate,NULL);

	for (CK_ULONG i= 0; i<sMyKeyTemplate.ulNumOfParams; i++)
		sMyKeyTemplate.psKeyParams[i].pValue = NULL;
	free (sMyKeyTemplate.psKeyParams);
};
