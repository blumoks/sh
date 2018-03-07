#include "ShWorkWithKeys.h"
/**
@page ShWorkWithKeys
*/

/**
@brief WorkWithKeysClass constructor
*/
WorkWithKeysClass::WorkWithKeysClass():BaseClass()
{
	if (rvResult!=CKR_OK) return;
	ulClass_PubKey = CKO_PUBLIC_KEY;
	ulClass_PriKey = CKO_PRIVATE_KEY;
	ulClass_SecKey = CKO_SECRET_KEY;

	blTrue = CK_TRUE;
	blFalse = CK_FALSE;
	hSession = 0;

	LastFoundKeysList = new std::vector<CK_OBJECT_HANDLE>();
//	LastFoundKeysInfos = new std::vector<MY_KEY_INFO>();
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief WorkWithKeysClass parametrized constructor
@param pcDeviceID(in) - ID of device we are working with as string
@param sPinParams(in) - parameters of PIN to this device: PIN and its length;
*/
WorkWithKeysClass::WorkWithKeysClass(char *pcDeviceID, MY_PIN_PARAMS sPinParams):BaseClass()
{
	if (rvResult!=CKR_OK) return;
	ulClass_PubKey = CKO_PUBLIC_KEY;
	ulClass_PriKey = CKO_PRIVATE_KEY;
	ulClass_SecKey = CKO_SECRET_KEY;

	blTrue = CK_TRUE;
	blFalse = CK_FALSE;
	hSession = 0;

	LastFoundKeysList = new std::vector<CK_OBJECT_HANDLE>();
//	LastFoundKeysInfos = new std::vector<MY_KEY_INFO>();

	MakeLoginedSession(pcDeviceID,sPinParams);
	//если неверен по той или иной причине пароль, то меняем значение ошибки:
	if ((rvResult == CKR_PIN_INCORRECT)||(rvResult == CKR_PIN_LEN_RANGE))
	{
		rvResult = CKR_PIN_INCORRECT;
	}
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief WorkWithKeysClass destructor
*/
WorkWithKeysClass::~WorkWithKeysClass()
{
	delete LastFoundKeysList;
	LastFoundKeysInfos.clear();
	if (hSession) 
	{
		Pkcs11FuncList->C_Logout(hSession);
		Pkcs11FuncList->C_CloseSession(hSession);
	}
	if (rvResult!=CKR_OK) return;
};
//==================================================================================================================
/**
@brief Function to make session for device pcDeviceID
@param pcDeviceID(in) - ID of device we are working with as string
*/
void WorkWithKeysClass::MakeSession(char *pcDeviceID)
{
	CK_SLOT_ID				ulSlotID = 0;
	MY_DEVICE_INFO			DeviceInfo;
	
	//проверяем, все ли входные параметры заданы:
	if (pcDeviceID == NULL)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}

	//проверяем, подключено ли данное устройство
	if (DeviceIsConnected(pcDeviceID,&ulSlotID)!=true)
	{
		if (rvResult == CKR_OK) 
			rvResult = CKR_DEVICE_REMOVED;
		return;
	}

	//проверяем, заданы ли параметры авторизации:
	GetDeviceInfo(ulSlotID,&DeviceInfo);
	if ((DeviceInfo.ulFlags&DEVICE_NOT_INITIALIZED)==DEVICE_NOT_INITIALIZED)
	{
		rvResult = AUTH_PARAMS_NOT_SETTED;
		return;
	}
	if ((DeviceInfo.ulFlags&PIN_NOT_SETTED)==PIN_NOT_SETTED) 
	{
		rvResult = PIN_NOT_ENTERED;
		return;
	}
	if ((DeviceInfo.ulFlags&DEVICE_NOT_INITIALIZED)||(DeviceInfo.ulFlags&DEVICE_NOT_FORMATED))
	//||(DeviceInfo.ulFlags&PIN_BLOCKED)||(DeviceInfo.ulFlags&PUK_BLOCKED))
	{
		rvResult = CKR_PUK_NOT_SETTED;	//PUK не был выработан
		//else rvResult = CKR_DEVICE_BLOCKED;	//устройство заблокировано
		return;
	}

	if (hSession != 0)
	{
		//если была открытая сессия - то закрываем ее
		Pkcs11FuncList->C_CloseSession(hSession);
		hSession = 0;
	}

	//Открываем сессию
	rvResult = Pkcs11FuncList->C_OpenSession(ulSlotID,(CKF_SERIAL_SESSION | CKF_RW_SESSION),NULL,0,&hSession);
	if (rvResult!=CKR_OK) 
		return;
};
//==================================================================================================================
/**
@brief Function to make logined session for device pcDeviceID
@param pcDeviceID(in) - ID of device we are working with as string
@param sPinParams(in) - parameters of PIN to this device: PIN and its length;
*/
void WorkWithKeysClass::MakeLoginedSession(char *pcDeviceID, MY_PIN_PARAMS sPinParams)
{
	//открываем сессию:
	MakeSession(pcDeviceID);
	if (rvResult != CKR_OK)
		return;
	//проверяем длину пароля: 
	if ((sPinParams.ulPinLength<7)||(sPinParams.ulPinLength>32))
	{
		rvResult = CKR_PIN_LEN_RANGE;
		return;
	}

	//логинимся
	rvResult = Pkcs11FuncList->C_Login(hSession,CKU_USER,sPinParams.pcPinValue,sPinParams.ulPinLength);
	if (rvResult!=CKR_OK)
	{
		//если пароль неверен - то работаем с незалогиненым устройством:
		if ((rvResult == CKR_PIN_INCORRECT)||(rvResult == CKR_PIN_LEN_RANGE))
		{
			rvResult = CKR_PIN_INCORRECT;
			return;
		}
		//если устройство заблокировано по PIN, то все равно работаем с незалогиненным:
		if (rvResult == CKR_PIN_LOCKED)
		{
			return;
		}
		//иначе - завершаем работу с устройством
		Pkcs11FuncList->C_CloseSession(hSession);
		hSession = 0;
		return;
	}
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to get list of keys info
@param sKeyTemplateInfo(in) - Attributes to find keys by; if CKA_CLASS attributes isn't setted then looking for all types of keys
@param psKeyList(out) - list of keys info; if NULL then only ulKeyNumber will be returned;
@param ulKeyNumber(out) - number of keys found on device by the template;
*/
void WorkWithKeysClass::GetKeysInfoList(MY_KEY_TEMPLATE_INFO sKeyTemplateInfo, 
				MY_KEY_INFO_PTR psKeyList, CK_ULONG_PTR ulKeyNumber)
{
	MY_KEY_TEMPLATE_INFO	sTempKeyInfo;
	sTempKeyInfo.ulNumOfParams = 0;
	sTempKeyInfo.psKeyParams = NULL;

	//проверяем, все ли входные параметры заданы:
	if (ulKeyNumber == NULL)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
	//проверяем, была ли открыта сессия:
	if (hSession == 0)
	{
		rvResult = CKR_SESSION_HANDLE_INVALID;
		return;
	}
	
	if ((psKeyList)&&(LastFoundKeysInfos.empty() == false))
	{
		*ulKeyNumber = (CK_ULONG)(LastFoundKeysInfos.size());
		for (CK_ULONG i = 0; i<*ulKeyNumber; i++)
		{
			//make init value:
			memset(&(psKeyList[i]),0,sizeof(MY_KEY_INFO));
			psKeyList[i].ulKeyIdLen		 = LastFoundKeysInfos[i].ulKeyIdLen;
			memcpy(psKeyList[i].pbKeyId, LastFoundKeysInfos[i].pbKeyId, LastFoundKeysInfos[i].ulKeyIdLen);
			psKeyList[i].ulKeyTypeLen	 = LastFoundKeysInfos[i].ulKeyTypeLen;
			psKeyList[i].ulKeyType		 = LastFoundKeysInfos[i].ulKeyType;
			psKeyList[i].ulKeyClassLen	 = LastFoundKeysInfos[i].ulKeyClassLen;
			psKeyList[i].ulKeyClass		 = LastFoundKeysInfos[i].ulKeyClass;
			psKeyList[i].ulKeyLenLen	 = LastFoundKeysInfos[i].ulKeyLenLen;
			psKeyList[i].ulKeyLen		 = LastFoundKeysInfos[i].ulKeyLen;
			psKeyList[i].ulExportableLen = LastFoundKeysInfos[i].ulExportableLen;
			psKeyList[i].bExportable	 = LastFoundKeysInfos[i].bExportable;
			psKeyList[i].ulLabelLen		 = LastFoundKeysInfos[i].ulLabelLen;
			if (psKeyList[i].ulLabelLen)
				memcpy(psKeyList[i].pbLabel, LastFoundKeysInfos[i].pbLabel, LastFoundKeysInfos[i].ulLabelLen);
		}
		return;
	}
	else 
	{
		if (LastFoundKeysInfos.empty() == false)
		{
			LastFoundKeysInfos.clear();
		}
	}

	//Ищем ключи: Проверяем шаблон и составляем свой, чтобы искать только ключи:
	sTempKeyInfo.ulNumOfParams = (sKeyTemplateInfo.ulNumOfParams) + 1;
	sTempKeyInfo.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sTempKeyInfo.ulNumOfParams * sizeof(CK_ATTRIBUTE));
	for (int i = 0; i<(int)sKeyTemplateInfo.ulNumOfParams; i++)
	{
		//копируем входные данные:
		sTempKeyInfo.psKeyParams[i].type = sKeyTemplateInfo.psKeyParams[i].type;
		sTempKeyInfo.psKeyParams[i].ulValueLen = sKeyTemplateInfo.psKeyParams[i].ulValueLen;
		sTempKeyInfo.psKeyParams[i].pValue = sKeyTemplateInfo.psKeyParams[i].pValue;
		//если тип ключа, который ищем, уже задан, то учитываем это:
		if (sKeyTemplateInfo.psKeyParams[i].type == CKA_CLASS)
		{
			sTempKeyInfo.ulNumOfParams--;
		}
	}

	//ищем ключи
	*ulKeyNumber = 0;
	int iKeyCounter = 0;
	if (sTempKeyInfo.ulNumOfParams > sKeyTemplateInfo.ulNumOfParams)
	{
		sTempKeyInfo.psKeyParams[sTempKeyInfo.ulNumOfParams-1].type = CKA_CLASS;
		//ищем ключи для симметричного шифрования:
		sTempKeyInfo.psKeyParams[sTempKeyInfo.ulNumOfParams-1].pValue = &ulClass_SecKey;
		sTempKeyInfo.psKeyParams[sTempKeyInfo.ulNumOfParams-1].ulValueLen = sizeof(CK_ULONG);

		FindKeysInfos(sTempKeyInfo);
		if ((rvResult!=CKR_OK)&&(rvResult!=CKR_ATTRIBUTE_TYPE_INVALID)&&(rvResult!=CKR_ATTRIBUTE_SENSITIVE))
		{
			goto GET_KEYS_INFO_FINALIZATION;
		}

		//ищем открытые ключи:
		sTempKeyInfo.psKeyParams[sTempKeyInfo.ulNumOfParams-1].pValue = &ulClass_PubKey;
		sTempKeyInfo.psKeyParams[sTempKeyInfo.ulNumOfParams-1].ulValueLen = sizeof(CK_ULONG);

		FindKeysInfos(sTempKeyInfo);
		if ((rvResult!=CKR_OK)&&(rvResult!=CKR_ATTRIBUTE_TYPE_INVALID)&&(rvResult!=CKR_ATTRIBUTE_SENSITIVE))
		{
			goto GET_KEYS_INFO_FINALIZATION;
		}

		//ищем закрытые ключи:
		sTempKeyInfo.psKeyParams[sTempKeyInfo.ulNumOfParams-1].pValue = &ulClass_PriKey;
		sTempKeyInfo.psKeyParams[sTempKeyInfo.ulNumOfParams-1].ulValueLen = sizeof(CK_ULONG);

		FindKeysInfos(sTempKeyInfo);
		if ((rvResult!=CKR_OK)&&(rvResult!=CKR_ATTRIBUTE_TYPE_INVALID)&&(rvResult!=CKR_ATTRIBUTE_SENSITIVE))
		{
			goto GET_KEYS_INFO_FINALIZATION;
		}
	}
	else if (sTempKeyInfo.ulNumOfParams == sKeyTemplateInfo.ulNumOfParams)
	{
		//просто ищем ключи
		FindKeysInfos(sTempKeyInfo);
		if ((rvResult!=CKR_OK)&&(rvResult!=CKR_ATTRIBUTE_TYPE_INVALID)&&(rvResult!=CKR_ATTRIBUTE_SENSITIVE))
		{
			goto GET_KEYS_INFO_FINALIZATION;
		}
	}
	else 
	{
		rvResult = CKR_DATA_INVALID;
	}

	*ulKeyNumber = (CK_ULONG)(LastFoundKeysInfos.size());
	if ((psKeyList)&&(LastFoundKeysInfos.empty() == false))
	{
		for (CK_ULONG i = 0; i<*ulKeyNumber; i++)
		{
			psKeyList[i].ulKeyIdLen		 = LastFoundKeysInfos[i].ulKeyIdLen;
			memcpy(psKeyList[i].pbKeyId, LastFoundKeysInfos[i].pbKeyId, LastFoundKeysInfos[i].ulKeyIdLen);
			psKeyList[i].ulKeyTypeLen	 = LastFoundKeysInfos[i].ulKeyTypeLen;
			psKeyList[i].ulKeyType		 = LastFoundKeysInfos[i].ulKeyType;
			psKeyList[i].ulKeyClassLen	 = LastFoundKeysInfos[i].ulKeyClassLen;
			psKeyList[i].ulKeyClass		 = LastFoundKeysInfos[i].ulKeyClass;
			psKeyList[i].ulKeyLenLen	 = LastFoundKeysInfos[i].ulKeyLenLen;
			psKeyList[i].ulKeyLen		 = LastFoundKeysInfos[i].ulKeyLen;
			psKeyList[i].ulExportableLen = LastFoundKeysInfos[i].ulExportableLen;
			psKeyList[i].bExportable	 = LastFoundKeysInfos[i].bExportable;
			psKeyList[i].ulLabelLen		 = LastFoundKeysInfos[i].ulLabelLen;
			memcpy(psKeyList[i].pbLabel, LastFoundKeysInfos[i].pbLabel, LastFoundKeysInfos[i].ulLabelLen);
		}
	}

GET_KEYS_INFO_FINALIZATION:
	//забиваем на CKR_ATTRIBUTE_TYPE_INVALID
	if (rvResult == CKR_ATTRIBUTE_TYPE_INVALID)
		rvResult = CKR_OK;
	if (rvResult != CKR_OK)
	{
		LastFoundKeysInfos.clear();
	}
	//подчищаем память
	if (sTempKeyInfo.psKeyParams) free (sTempKeyInfo.psKeyParams);
	return;
};

//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to find keys by setted template
@param sKeyTemplateInfo(in) - attributes to find keys by; if it has no attributes in CKR_ARGUMENTS_BAD will be returned
@param phKeyList(out) - array of key handles; if NULL then only ulKeyNumber will be returned;
@param ulKeyNumber(out) - number of keys found on device by the template;
*/
void WorkWithKeysClass::FindKeysByTemplate(MY_KEY_TEMPLATE_INFO sKeyTemplateInfo, 
										   CK_OBJECT_HANDLE_PTR phKeyList, CK_ULONG_PTR pulKeyNumber)
{
	CK_OBJECT_HANDLE hKeyHandle = 0;
	CK_ULONG ulObjectFound = 1;
	std::vector <CK_OBJECT_HANDLE> TempVector = *LastFoundKeysList;


	*pulKeyNumber = 0;
	//checking, if input data are correct:
	if ((hSession == NULL)||(sKeyTemplateInfo.ulNumOfParams == 0)||(sKeyTemplateInfo.psKeyParams == NULL)||(pulKeyNumber == NULL))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}

	//if this is the second call (LastFoundKeysList isn't empty) and some memory for phKeyList was allocated:
	if ((LastFoundKeysList->empty() == false)&&(phKeyList))
	{
		(*pulKeyNumber) = (CK_ULONG)LastFoundKeysList->size();
		for (CK_ULONG i = 0; i<(*pulKeyNumber); i++)
		{
			phKeyList[i] = (*LastFoundKeysList)[i];
		}
		return;
	}
	else
	{
		if (LastFoundKeysList->empty() == false)
		{
			LastFoundKeysList->clear();
		}
	}

	//find objects init:
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_FindObjectsInit(hSession,sKeyTemplateInfo.psKeyParams,sKeyTemplateInfo.ulNumOfParams)))
		return;

	//find objects one by one:
	while ((rvResult == CKR_OK)&&(ulObjectFound == 1))
	{
		rvResult = Pkcs11FuncList->C_FindObjects(hSession,&hKeyHandle,1,&ulObjectFound);
		if ((rvResult == CKR_OK)&&(ulObjectFound == 1))
		{
			LastFoundKeysList->push_back(hKeyHandle);
		}
	}
	
	TempVector = (*LastFoundKeysList);
	(*pulKeyNumber) = (CK_ULONG)TempVector.size();
	if (phKeyList)
	{
		for (CK_ULONG i = 0; i<(*pulKeyNumber); i++)
		{
			phKeyList[i] = TempVector[i];
		}
	}

	rvResult = Pkcs11FuncList->C_FindObjectsFinal(hSession);
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to get info about certain key
@param hKey(in) - handle of key to get info about
@param psKeyInfo(out) - structure containing info about key;
*/
void WorkWithKeysClass::GetKeyInfo(CK_OBJECT_HANDLE hKey, MY_KEY_INFO_PTR psKeyInfo)
{
	//checking, if input data are correct:
	if ((hSession == NULL)||(hKey == 0)||(psKeyInfo == NULL))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}

	psKeyInfo->ulKeyIdLen = 32;
	memset(psKeyInfo->pbKeyId,0,psKeyInfo->ulKeyIdLen);
	psKeyInfo->ulKeyClass = 0;
	psKeyInfo->ulKeyLen = 0;
	psKeyInfo->ulKeyType = 0;
	psKeyInfo->bExportable = 0;
	psKeyInfo->ulLabelLen = 128;
	memset(psKeyInfo->pbLabel,0,psKeyInfo->ulLabelLen);

	CK_ATTRIBUTE AttrTemplate[] = {
		{CKA_ID, psKeyInfo->pbKeyId, psKeyInfo->ulKeyIdLen},
		{CKA_CLASS, &(psKeyInfo->ulKeyClass), sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE, &(psKeyInfo->ulKeyType), sizeof(CK_KEY_TYPE)},
		{CKA_VALUE_LEN, &(psKeyInfo->ulKeyLen), sizeof(CK_ULONG)},
		{CKA_LABEL, psKeyInfo->pbLabel, psKeyInfo->ulLabelLen},
		{CKA_MODULUS_BITS, &(psKeyInfo->ulKeyLen), sizeof(CK_ULONG)},
		{CKA_EXTRACTABLE, &(psKeyInfo->bExportable), sizeof(CK_BBOOL)}
	};

	rvResult = Pkcs11FuncList->C_GetAttributeValue(hSession,hKey,AttrTemplate,ARRAYSIZE(AttrTemplate)); 

	psKeyInfo->ulKeyIdLen = AttrTemplate[0].ulValueLen;
	psKeyInfo->ulKeyTypeLen = AttrTemplate[1].ulValueLen;
	psKeyInfo->ulKeyClassLen = AttrTemplate[2].ulValueLen;
	psKeyInfo->ulKeyLenLen = (AttrTemplate[3].ulValueLen)&(AttrTemplate[5].ulValueLen);
	psKeyInfo->ulLabelLen = AttrTemplate[4].ulValueLen;
	psKeyInfo->ulExportableLen = AttrTemplate[6].ulValueLen;
};
//================================================================================================
void WorkWithKeysClass::FindKeysInfos(MY_KEY_TEMPLATE_INFO sTempKeyInfo)
{
	CK_OBJECT_HANDLE_PTR	pKeysHandlesList = NULL;
	CK_ULONG				ulKeysHandlesNum = 0;
	MY_KEY_INFO				sMyKeyInfo;
	std::vector <MY_KEY_INFO> TempKeysInfos = (LastFoundKeysInfos);
	CK_ULONG				ulLastInfo = 0;

	FindKeysByTemplate(sTempKeyInfo,NULL,&ulKeysHandlesNum);
	if (rvResult==CKR_OK)
	{
		if (ulKeysHandlesNum != 0)
		{
			pKeysHandlesList = (CK_OBJECT_HANDLE_PTR) malloc (ulKeysHandlesNum * sizeof (CK_OBJECT_HANDLE));
			FindKeysByTemplate(sTempKeyInfo, pKeysHandlesList,&ulKeysHandlesNum);
			//получаем информацию о ключах
			if (rvResult == CKR_OK)
			{
				for(int i = 0; i<(int)ulKeysHandlesNum; i++)
				{
					GetKeyInfo(pKeysHandlesList[i],&sMyKeyInfo);
					if ((rvResult!=CKR_OK)&&(rvResult!=CKR_ATTRIBUTE_TYPE_INVALID)&&(rvResult!=CKR_ATTRIBUTE_SENSITIVE))
					{
						if (pKeysHandlesList) free (pKeysHandlesList);
						return;
					}
					LastFoundKeysInfos.push_back(sMyKeyInfo);

					LastFoundKeysInfos.back().ulKeyIdLen	 = sMyKeyInfo.ulKeyIdLen;
					LastFoundKeysInfos.back().ulKeyIdLen	 = sMyKeyInfo.ulKeyIdLen;
					memcpy(LastFoundKeysInfos.back().pbKeyId, sMyKeyInfo.pbKeyId, sMyKeyInfo.ulKeyIdLen);
					LastFoundKeysInfos.back().ulKeyTypeLen	 = sMyKeyInfo.ulKeyTypeLen;
					LastFoundKeysInfos.back().ulKeyType		 = sMyKeyInfo.ulKeyType;
					LastFoundKeysInfos.back().ulKeyClassLen	 = sMyKeyInfo.ulKeyClassLen;
					LastFoundKeysInfos.back().ulKeyClass	 = sMyKeyInfo.ulKeyClass;
					LastFoundKeysInfos.back().ulKeyLenLen	 = sMyKeyInfo.ulKeyLenLen;
					LastFoundKeysInfos.back().ulKeyLen		 = sMyKeyInfo.ulKeyLen;
					if (sMyKeyInfo.ulKeyClass == CKO_PUBLIC_KEY)
					{
						LastFoundKeysInfos.back().ulExportableLen = sizeof(CK_BBOOL);
						LastFoundKeysInfos.back().bExportable	 = CK_TRUE;
					}
					else
					{
						LastFoundKeysInfos.back().ulExportableLen = sMyKeyInfo.ulExportableLen;
						LastFoundKeysInfos.back().bExportable	 = sMyKeyInfo.bExportable;
					}
					LastFoundKeysInfos.back().ulLabelLen	 = sMyKeyInfo.ulLabelLen;
					memcpy(LastFoundKeysInfos.back().pbLabel, sMyKeyInfo.pbLabel, sMyKeyInfo.ulLabelLen);
					//*/
				}
			}
		}
	}
	if (pKeysHandlesList) free (pKeysHandlesList);
};
//==================================================================================================================
/**
@brief Function to parse incomming attributes
@param sAttrsToParse(in) - Attributes to be parsed;
@param pbParsedAttrs(out) - array of CK_BYTEs to contain parsed data, if NULL only ulParsedAttrsLen will be returned
@param ulParsedAttrsLen(out) - length of pbParsedAttrs
*/
void WorkWithKeysClass::ParseAttrs (MY_KEY_TEMPLATE_INFO sAttrsToParse, BYTE *pbParsedAttrs, CK_ULONG *ulParsedAttrsLen)
{
	*ulParsedAttrsLen = 0;
	CK_BYTE_PTR pbTemp = pbParsedAttrs;
	for (CK_ULONG i = 0; i<sAttrsToParse.ulNumOfParams; i++)
	{
		(*ulParsedAttrsLen) += sAttrsToParse.psKeyParams[i].ulValueLen + (4 - sAttrsToParse.psKeyParams[i].ulValueLen%4)%4 + 4 + 4 /*sizeof (CK_ULONG) + sizeof (CK_ATTRIBUTE_TYPE)//*/;
		if (pbParsedAttrs)
		{
			pbTemp[3] = (CK_BYTE)((sAttrsToParse.psKeyParams[i].type) % 0x100);
			pbTemp[2] = (CK_BYTE)(((sAttrsToParse.psKeyParams[i].type) % 0x10000)/0x100);
			pbTemp[1] = (CK_BYTE)(((sAttrsToParse.psKeyParams[i].type) % 0x1000000)/0x10000);
			pbTemp[0] = (CK_BYTE)(((sAttrsToParse.psKeyParams[i].type) % 0x100000000)/0x1000000);
			pbTemp += 4;
			pbTemp[3] = (CK_BYTE)((sAttrsToParse.psKeyParams[i].ulValueLen) % 0x100);
			pbTemp[2] = (CK_BYTE)(((sAttrsToParse.psKeyParams[i].ulValueLen) % 0x10000)/0x100);
			pbTemp[1] = (CK_BYTE)(((sAttrsToParse.psKeyParams[i].ulValueLen) % 0x1000000)/0x10000);
			pbTemp[0] = (CK_BYTE)(((sAttrsToParse.psKeyParams[i].ulValueLen) % 0x100000000)/0x1000000);
			pbTemp += 4;
			for (CK_ULONG j = 0; j<sAttrsToParse.psKeyParams[i].ulValueLen; j++)
			{
				pbTemp[j] = ((CK_BYTE_PTR)(sAttrsToParse.psKeyParams[i].pValue))[j];
			}
			pbTemp += sAttrsToParse.psKeyParams[i].ulValueLen;
			memset(pbTemp,0,(4 - sAttrsToParse.psKeyParams[i].ulValueLen%4)%4);
			pbTemp += (4 - sAttrsToParse.psKeyParams[i].ulValueLen%4)%4;
		}
	}
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to unparse parsed attributes
@param pbParsedAttrs(in) - array of CK_BYTEs containing parsed data;
@param ulParsedAttrsLen(in) - length of pbParsedAttrs;
@param sAttrsUnparsed(out) - struct to contain unparsed attributes, if its field psKeyParams is NULL number of unparsed attributes will be returned;
*/
void WorkWithKeysClass::UnparseAttrs(BYTE *pbParsedAttrs, CK_ULONG ulParsedAttrsLen, MY_KEY_TEMPLATE_INFO_PTR sAttrsUnparsed)
{
	CK_BYTE_PTR pbTemp = NULL;
	CK_ULONG i = 0, ulAttrsCounter = 0;
	CK_ULONG ulTempLen = 0, ulTempType = 0;
	if ((!pbParsedAttrs)||(!sAttrsUnparsed))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}

	pbTemp = pbParsedAttrs;
	while (i<ulParsedAttrsLen)
	{
		ulTempType = pbTemp[3] + pbTemp[2]*0x100 + pbTemp[1]*0x10000 + pbTemp[0]*0x1000000;
		i+=4;
		pbTemp += 4;			// + sizeof(CK_ULONG)
		ulTempLen = pbTemp[3] + pbTemp[2]*0x100 + pbTemp[1]*0x10000 + pbTemp[0]*0x1000000;
		i+=4;
		pbTemp += 4;			// + sizeof(CK_ULONG)
		if ((sAttrsUnparsed->psKeyParams)&&(ulAttrsCounter<sAttrsUnparsed->ulNumOfParams))
		{
			sAttrsUnparsed->psKeyParams[ulAttrsCounter].type = ulTempType;
			sAttrsUnparsed->psKeyParams[ulAttrsCounter].ulValueLen = ulTempLen;
			if (sAttrsUnparsed->psKeyParams[ulAttrsCounter].pValue)
			{
				for (CK_ULONG j = 0; j<sAttrsUnparsed->psKeyParams[ulAttrsCounter].ulValueLen; j++)
				{
					((CK_BYTE_PTR)(sAttrsUnparsed->psKeyParams[ulAttrsCounter].pValue))[j] = pbTemp[j];
				}
			}
		}
		ulAttrsCounter++;
		pbTemp += ulTempLen + (4 - ulTempLen%4)%4;
		i += ulTempLen + (4 - ulTempLen%4)%4;
		ulTempType = 0;
		ulTempLen = 0;
	}
	if (sAttrsUnparsed->ulNumOfParams != ulAttrsCounter)
	{
		sAttrsUnparsed->ulNumOfParams = ulAttrsCounter;
	}
	pbTemp = NULL;
	return;
};
//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to get CKA_CLASS parameter from parsed attributes
@param pbParsedAttrs(in) - array of CK_BYTEs containing parsed data;
@param ulParsedAttrsLen(in) - length of pbParsedAttrs;
@rezult Value of CKA_CLASS parameter;
*/
CK_ULONG WorkWithKeysClass::GetParsedKeyClass(CK_BYTE *pbParsedAttrs, CK_ULONG ulParsedAttrsLen)
{
	CK_BYTE_PTR pbTemp = NULL;
	CK_ULONG i = 0;
	CK_ULONG ulTempLen = 0, ulTempType = 0;
	CK_ULONG ulKeyClass = -1;

	if (!pbParsedAttrs)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto GET_PARSED_KEY_CLASS_FINALIZATION;
	}

	pbTemp = pbParsedAttrs;
	while (i<ulParsedAttrsLen)
	{
		ulTempType = pbTemp[3] + pbTemp[2]*0x100 + pbTemp[1]*0x10000 + pbTemp[0]*0x1000000;
		i+=4;
		pbTemp += 4;			// + sizeof(CK_ULONG)
		ulTempLen = pbTemp[3] + pbTemp[2]*0x100 + pbTemp[1]*0x10000 + pbTemp[0]*0x1000000;
		i+=4;
		pbTemp += 4;			// + sizeof(CK_ULONG)
		if (ulTempType == CKA_CLASS)
		{
			if (ulTempLen != sizeof (CK_ULONG))
				goto GET_PARSED_KEY_CLASS_FINALIZATION;

			for (CK_ULONG j = 0; j<ulTempLen; j++)
			{
				((CK_BYTE_PTR)(&(ulKeyClass)))[j] = pbTemp[j];
			}
			goto GET_PARSED_KEY_CLASS_FINALIZATION;
		}
		pbTemp += ulTempLen + (4 - ulTempLen%4)%4;
		i += ulTempLen + (4 - ulTempLen%4)%4;
		ulTempType = 0;
		ulTempLen = 0;
	}

GET_PARSED_KEY_CLASS_FINALIZATION:
	pbTemp = NULL;
	return ulKeyClass;
};

//------------------------------------------------------------------------------------------------------------------
/**
@brief Function to get CKA_CLASS parameter from parsed attributes
@param pbParsedAttrs(in) - array of CK_BYTEs containing parsed data;
@param ulParsedAttrsLen(in) - length of pbParsedAttrs;
@rezult Value of CKA_CLASS parameter;
*/
void WorkWithKeysClass::GetParsedKeyAttribute(CK_BYTE *pbParsedAttrs, CK_ULONG ulParsedAttrsLen, CK_ATTRIBUTE_TYPE ulAttrType, CK_BYTE_PTR pbAttrValue, CK_ULONG_PTR pulAttrValueLen)
{
	CK_BYTE_PTR pbTemp = NULL;
	CK_ULONG i = 0;
	CK_ULONG ulTempLen = 0, ulTempType = 0;

	if ((!pbParsedAttrs)||(!pulAttrValueLen))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto GET_PARSED_KEY_CLASS_FINALIZATION;
	}

	pbTemp = pbParsedAttrs;
	while (i<ulParsedAttrsLen)
	{
		ulTempType = pbTemp[3] + pbTemp[2]*0x100 + pbTemp[1]*0x10000 + pbTemp[0]*0x1000000;
		i+=4;
		pbTemp += 4;			// + sizeof(CK_ULONG)
		ulTempLen = pbTemp[3] + pbTemp[2]*0x100 + pbTemp[1]*0x10000 + pbTemp[0]*0x1000000;
		i+=4;
		pbTemp += 4;			// + sizeof(CK_ULONG)
		if (ulTempType == ulAttrType)
		{
			*pulAttrValueLen = ulTempLen;
			if (pbAttrValue)
			{
				for (CK_ULONG j = 0; j<ulTempLen; j++)
				{
					pbAttrValue[j] = pbTemp[j];
				}
			}
			goto GET_PARSED_KEY_CLASS_FINALIZATION;
		}
		pbTemp += ulTempLen + (4 - ulTempLen%4)%4;
		i += ulTempLen + (4 - ulTempLen%4)%4;
		ulTempType = 0;
		ulTempLen = 0;
	}

GET_PARSED_KEY_CLASS_FINALIZATION:
	pbTemp = NULL;
};

//*/
