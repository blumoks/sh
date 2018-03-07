#include "ShAuthParams.h"
//==================================================================================================================================
AuthParamsInit::AuthParamsInit():BaseClass()
{
};
//----------------------------------------------------------------------------------------------------------------------------------
AuthParamsInit::~AuthParamsInit()
{
};
//==================================================================================================================================
void AuthParamsInit::ChangeSOPIN(char *pcDeviceID, char *pcOldSOPIN, CK_ULONG ulOldSOPinLen, char *pcNewSOPIN, CK_ULONG ulNewSOPinLen)
{
	SHEX_SO_PASSWORD sOldSoPassword;
	SHEX_SO_PASSWORD sNewSoPassword;
	MY_DEVICE_INFO DeviceInfo;
	CK_ULONG ulSlotID = 0;

	sOldSoPassword.ulPswLength = 0;
	memset(sOldSoPassword.pcPswValue,0,SHEX_MAX_SO_PASSWORD_LEN);
	sNewSoPassword.ulPswLength = 0;
	memset(sNewSoPassword.pcPswValue,0,SHEX_MAX_SO_PASSWORD_LEN);

	if (DeviceIsConnected(pcDeviceID,&ulSlotID)==true)
	{
		//получаем информацию об устройстве
		GetDeviceInfo(ulSlotID,&DeviceInfo);
		if (!strncmp((char *)(DeviceInfo.cDeviceType),SHIPKA_LITE,strlen(SHIPKA_LITE)))
		{
			rvResult = CKR_SHIPKA_NOT_SUPPORTED;
			return;
		}
		//If device isn't inited, need to init it first:
		if ((DeviceInfo.ulFlags&DEVICE_NOT_INITIALIZED)==DEVICE_NOT_INITIALIZED)
		{
			rvResult = CKR_DEVICE_WASNT_INITED;
			return;
		}

		//check old pin params
		if ((ulOldSOPinLen==0)||(pcOldSOPIN==NULL))
		{
			rvResult = PIN_NOT_ENTERED;
			return;
		}
		sOldSoPassword.ulPswLength = ulOldSOPinLen;
		memcpy(sOldSoPassword.pcPswValue,pcOldSOPIN,ulOldSOPinLen);

		//check new PIN parameters:
		if ((ulNewSOPinLen==0)||(pcNewSOPIN==NULL))
		{
			rvResult = PIN_NOT_ENTERED;
			return;
		}
		sNewSoPassword.ulPswLength = ulNewSOPinLen;
		memcpy(sNewSoPassword.pcPswValue,pcNewSOPIN,ulNewSOPinLen);
		rvResult = pcExFuncList->SHEX_ChangeSOPassword(ulSlotID,&sOldSoPassword,&sNewSoPassword);
	}
	else
	{
		if (rvResult == CKR_OK) rvResult = CKR_DEVICE_REMOVED;
	}
};
//----------------------------------------------------------------------------------------------------------------------------------
void AuthParamsInit::SetAuthParams (bool bForOneDevice, char *pcDeviceID, CK_ULONG ulSOPinLen, char *pcSOPIN, 
						bool bWithPUK, CK_ULONG ulPukLen, CK_ULONG ulNumOfPukAttempts, CK_ULONG ulNumOfPinAttempts,
						CK_ULONG ulAlphabetFlag, CK_ULONG ulMinPinLen, CK_ULONG ulMaxPinLen, bool bMakeConstant)
{
	SHEX_IA_PARAMS sIaParams;
	MY_DEVICE_INFO DeviceInfo;
	CK_ULONG ulSlotID = 0;
	CK_ULONG_PTR pulSlotIds = NULL;
	CK_ULONG ulNumOfDevices = 0;
	CK_BBOOL bTemp = CK_FALSE;
	CK_ULONG ulLiteCounter = 0;

	sIaParams.SOPassword.ulPswLength = 0;
	memset(sIaParams.SOPassword.pcPswValue,0,SHEX_MAX_SO_PASSWORD_LEN);

	//form structures for init:
	//PIN params
	//Set default values
	if (ulMinPinLen == 0)
		ulMinPinLen = 7;
	if (ulMaxPinLen == 0)
		ulMaxPinLen = 7;
	if (ulNumOfPinAttempts == 0)
		ulNumOfPinAttempts = 3;
	//Check if params are correct:
	if ((ulMinPinLen>ulMaxPinLen)||(ulMinPinLen>32)||(ulMaxPinLen>32))
	{
		rvResult = CKR_PIN_LEN_RANGE;
		return;
	}
	//set them in structure:
	sIaParams.PINParams.ulStructVersion = 0;
	sIaParams.PINParams.ulPinMinLen = ulMinPinLen;
	sIaParams.PINParams.ulPinMaxLen = ulMaxPinLen;
	sIaParams.PINParams.ulPinAlphabetSet = ulAlphabetFlag;
	sIaParams.PINParams.ulPinMaxWrongAttemps = ulNumOfPinAttempts;

	//PUK params
	sIaParams.PUKParams.ulStructVersion = 0;
	if (false == bWithPUK)
	{
		sIaParams.PUKParams.ulPukLen = 0;
	}
	else
	{
		//Set default values
		if (ulNumOfPukAttempts == 0)
		{
			ulNumOfPukAttempts = 3;
		}
		if (ulPukLen == 0)
		{
			ulPukLen = 10;
		}
		//Check if params are correct:
		if (ulPukLen%2)
		{
			rvResult = PUK_INVALID_LENGTH;
			return;
		}
		//set them in structure:
		sIaParams.PUKParams.ulPukLen = ulPukLen/2;
		sIaParams.PUKParams.ulPukMaxWrongAttemps = ulNumOfPukAttempts;
	}

	//lock parameter:
	if (bMakeConstant == true)
	{
		sIaParams.blLockParams = CK_TRUE;
	}
	else
	{
		sIaParams.blLockParams = CK_FALSE;
	}

	//SO password:
	sIaParams.SOPassword.ulPswLength = 0;
	memset(sIaParams.SOPassword.pcPswValue,0,SHEX_MAX_SO_PASSWORD_LEN);
	if ((ulSOPinLen)&&(pcSOPIN))
	{
		sIaParams.SOPassword.ulPswLength = ulSOPinLen;
		memcpy(sIaParams.SOPassword.pcPswValue,pcSOPIN,ulSOPinLen);
	}

	//choosing device to work with:
	if (bForOneDevice == true)
	{
		if (DeviceIsConnected(pcDeviceID,&ulSlotID)==true)
		{
			//if not lite
			GetDeviceInfo(ulSlotID,&DeviceInfo);
			if (!strncmp((char *)(DeviceInfo.cDeviceType),SHIPKA_LITE,strlen(SHIPKA_LITE)))
			{
				rvResult = CKR_SHIPKA_NOT_SUPPORTED;
				return;
			}

			rvResult = pcExFuncList->SHEX_InitIASystem(ulSlotID,&sIaParams);
		}
		else
		{
			if (rvResult == CKR_OK) rvResult = CKR_DEVICE_REMOVED;
			return;
		}
	}
	else
	{
		GetDeviceList(NULL,&ulNumOfDevices);
		if ((ulNumOfDevices)&&(CKR_OK == rvResult))
		{
			if (NULL == (pulSlotIds = (CK_ULONG_PTR)malloc (sizeof(CK_ULONG) * ulNumOfDevices)))
			{
				rvResult = NOT_ENOUGH_MEMORY;
				return;
			}
			GetDeviceList(pulSlotIds,&ulNumOfDevices);
			if (CKR_OK != rvResult)
				return;
			for (CK_ULONG i = 0; i<ulNumOfDevices; i++)
			{
				GetDeviceInfo(ulSlotID,&DeviceInfo);
				if (strncmp((char *)(DeviceInfo.cDeviceType),SHIPKA_LITE,strlen(SHIPKA_LITE)))
				{
					rvResult = pcExFuncList->SHEX_InitIASystem(pulSlotIds[i],&sIaParams);
					if (rvResult != CKR_OK)
						return;	//in old utility there was a question to user, if it is needed to continue
				}
				else
				{
					ulLiteCounter++;
				}
			}
			if (rvResult != CKR_OK)
				return;
			if (ulLiteCounter == ulNumOfDevices)
			{
				rvResult = CKR_SHIPKA_NOT_SUPPORTED;
				return;
			}
		}
		else
		{
			if (CKR_OK == rvResult)
			{
				rvResult = CKR_DEVICE_REMOVED;
			}
			return;
		}
	}

};
//----------------------------------------------------------------------------------------------------------------------------------
void AuthParamsInit::BlockFormatting(char *pcDeviceID, char *pcSOPIN, CK_ULONG ulSOPinLen)
{
	SHEX_SO_PASSWORD sSoPassword;
	MY_DEVICE_INFO DeviceInfo;
	CK_ULONG ulSlotID = 0;
	sSoPassword.ulPswLength = 0;
	memset(sSoPassword.pcPswValue,0,SHEX_MAX_SO_PASSWORD_LEN);

	if (DeviceIsConnected(pcDeviceID,&ulSlotID)==true)
	{
		//получаем информацию об устройстве
		GetDeviceInfo(ulSlotID,&DeviceInfo);
		if (!strncmp((char *)(DeviceInfo.cDeviceType),SHIPKA_LITE,strlen(SHIPKA_LITE)))
		{
			rvResult = CKR_SHIPKA_NOT_SUPPORTED;
			return;
		}
		//check PIN parameters:
		if (((ulSOPinLen<1)||(pcSOPIN == NULL))||									//if PIN not entered
			((DeviceInfo.ulFlags&DEVICE_NOT_INITIALIZED)==DEVICE_NOT_INITIALIZED))	//or device is not initialized
		{
			if ((DeviceInfo.ulFlags&DEVICE_NOT_INITIALIZED)!=DEVICE_NOT_INITIALIZED) 
				rvResult = PIN_NOT_ENTERED;
			else rvResult = CKR_DEVICE_WASNT_INITED;
			return;
		}
		sSoPassword.ulPswLength = ulSOPinLen;
		memcpy(sSoPassword.pcPswValue,pcSOPIN,ulSOPinLen);
		rvResult = pcExFuncList->SHEX_LockDeviceFormatting(ulSlotID,&sSoPassword);
	}
	else
	{
		if (rvResult == CKR_OK) rvResult = CKR_DEVICE_REMOVED;
	}
};
//----------------------------------------------------------------------------------------------------------------------------------
void AuthParamsInit::UnblockFormatting(char *pcDeviceID, char *pcSOPIN, CK_ULONG ulSOPinLen)
{
	SHEX_SO_PASSWORD sSoPassword;
	MY_DEVICE_INFO DeviceInfo;
	CK_ULONG ulSlotID = 0;
	sSoPassword.ulPswLength = 0;
	memset(sSoPassword.pcPswValue,0,SHEX_MAX_SO_PASSWORD_LEN);

	if (DeviceIsConnected(pcDeviceID,&ulSlotID)==true)
	{
		//получаем информацию об устройстве
		GetDeviceInfo(ulSlotID,&DeviceInfo);
		if (!strncmp((char *)(DeviceInfo.cDeviceType),SHIPKA_LITE,strlen(SHIPKA_LITE)))
		{
			rvResult = CKR_SHIPKA_NOT_SUPPORTED;
			return;
		}
		//check PIN parameters:
		if (((ulSOPinLen<1)||(pcSOPIN == NULL))||									//if PIN not entered
			((DeviceInfo.ulFlags&DEVICE_NOT_INITIALIZED)==DEVICE_NOT_INITIALIZED))	//or device is not initialized
		{
			if ((DeviceInfo.ulFlags&DEVICE_NOT_INITIALIZED)!=DEVICE_NOT_INITIALIZED) 
				rvResult = PIN_NOT_ENTERED;
			else rvResult = CKR_DEVICE_WASNT_INITED;
			return;
		}
		sSoPassword.ulPswLength = ulSOPinLen;
		memcpy(sSoPassword.pcPswValue,pcSOPIN,ulSOPinLen);
		rvResult = pcExFuncList->SHEX_UnlockDeviceFormatting(ulSlotID,&sSoPassword);
	}
	else
	{
		if (rvResult == CKR_OK) rvResult = CKR_DEVICE_REMOVED;
	}
};
//==================================================================================================================================
