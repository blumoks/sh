#include "low_layer_func.h"

#pragma comment(lib, "Version.lib")

BaseClass::BaseClass()
{
	pSlotList = NULL;
	ulSlotCount = 0;
	pCallbackFunc = NULL;
	hThreadHandle = NULL;
	InitializePKCS11Lib();
	if (rvResult!=CKR_OK) return;
	UpdateDeviceList();
	if (rvResult!=CKR_OK) return;
};
//--------------------------------------------------------------------------------------
BaseClass::~BaseClass()
{
	if (pSlotList != NULL)
	{
		free(pSlotList);
		pSlotList = NULL;
	}
	if (hThreadHandle)
		TerminateThread(hThreadHandle,0);
	CloseHandle(hThreadHandle);
	hThreadHandle = NULL;
	pCallbackFunc = NULL;

	FinalizePKCS11Lib();
};
//--------------------------------------------------------------------------------------
void BaseClass::InitializePKCS11Lib()
{
	rvResult = CKR_OK;

#ifndef unix
	//check for version of pkcs11 dll
	DWORD dwVersionLen = GetFileVersionInfoSize(LIBNAME,NULL);
	LPVOID lpvVersionInfo = NULL;
	if (NULL == (lpvVersionInfo = (LPVOID) malloc (dwVersionLen)))
	{
		rvResult = CKR_CANCEL;
		return;
	}
	if (!GetFileVersionInfo(LIBNAME,NULL,dwVersionLen,lpvVersionInfo)) 
	{
		rvResult = CKR_CANCEL;
		if (lpvVersionInfo) free (lpvVersionInfo);
		return;
	}
	VS_FIXEDFILEINFO *pFileInfo;	
	if( VerQueryValue( lpvVersionInfo, "\\", (LPVOID *) &pFileInfo, (PUINT)&dwVersionLen ) ) 
	{
		//minor and major versions (default 4.0):
		if ((HIWORD(pFileInfo->dwFileVersionMS)<4)&&(LOWORD(pFileInfo->dwFileVersionMS)<0))
		{
			rvResult = CKR_CANCEL;
			if (lpvVersionInfo) free (lpvVersionInfo);
			return;
		}
		//build number and revision number:
		if ((HIWORD(pFileInfo->dwFileVersionLS)<2)&&(LOWORD(pFileInfo->dwFileVersionLS)<46))
		{
			rvResult = CKR_CANCEL;
			if (lpvVersionInfo) free (lpvVersionInfo);
			return;
		}
	}
	else 
	{
		rvResult = CKR_CANCEL;
		if (lpvVersionInfo) free (lpvVersionInfo);
		return;
	}

	if (lpvVersionInfo) free (lpvVersionInfo);
#endif

	if ((hPkcsLib = LoadLibrary(LIBNAME)) == NULL)		//Failed to load library!
	{
		rvResult = GetLastError();
		return;
	}

	// get address of C_GetFunctionList function
	if (((FARPROC&)pcGetFunctionList = GetProcAddress(hPkcsLib, "C_GetFunctionList"))==NULL)
	{	
		//Failed to load C_GetFunctionList function!!!
		rvResult = !CKR_OK;
		return;
	}

	// get address of SHEX_GetFunctionList function
	if (((FARPROC&)pcGetFunctionListEx = GetProcAddress(hPkcsLib, "SHEX_GetFunctionList")) == NULL)
	{	
		//Failed to load SHEX_GetFunctionList function!!!
		rvResult = !CKR_OK;
		return;
	}

	// get PKCS #11 function list
	rvResult = pcGetFunctionList(&Pkcs11FuncList);
	if (rvResult != CKR_OK) return;

	// get extended function list
	rvResult = pcGetFunctionListEx(&pcExFuncList);
	if (rvResult != CKR_OK) return;

	// initialize Cryptoki
	rvResult = Pkcs11FuncList->C_Initialize(NULL);
	if (rvResult != CKR_OK) return;
};
//--------------------------------------------------------------------------------------
void BaseClass::FinalizePKCS11Lib()
{
	rvResult = Pkcs11FuncList->C_Finalize(NULL);
	if (rvResult != CKR_OK) return;

	// release PKCS #11 library
	FreeLibrary(hPkcsLib);
};
//--------------------------------------------------------------------------------------
void BaseClass::UpdateDeviceList()
{
	if (pSlotList!=NULL) 
	{
		free(pSlotList);
		pSlotList = NULL;
	}

	rvResult = Pkcs11FuncList->C_GetSlotList(CK_TRUE, NULL, &ulSlotCount);

	if ((rvResult == CKR_OK) && (ulSlotCount > 0))
	{       
		// allocate memory for slot list
		pSlotList = (CK_SLOT_ID_PTR) calloc(ulSlotCount, sizeof(CK_SLOT_ID));
		rvResult = Pkcs11FuncList->C_GetSlotList(CK_TRUE, pSlotList, &ulSlotCount);
		if (rvResult != CKR_OK) return;
	}
	else return;
};
//--------------------------------------------------------------------------------------
CK_RV BaseClass::WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	return Pkcs11FuncList->C_WaitForSlotEvent(flags,pSlot,pReserved);
};
//--------------------------------------------------------------------------------------
void BaseClass::RegisterCallback(void (*pCallback)(CK_SLOT_ID, CK_BBOOL))
{
	DWORD dwThreadId = -1;
	pCallbackFunc = pCallback;
	hThreadHandle = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)SlotCallback,this,0,&dwThreadId);
};
//--------------------------------------------------------------------------------------
DWORD WINAPI BaseClass::SlotCallback(LPVOID lpClassPtr)
{
	((BaseClass *)lpClassPtr)->RunCallback();
	return 0;
};
//--------------------------------------------------------------------------------------
void BaseClass::RunCallback()
{
	CK_SLOT_ID siSlotId = -1;
	CK_BBOOL bExecuted = CK_FALSE;
	CK_SLOT_INFO sSlotInfo;

	while (true)
	{
		rvResult = Pkcs11FuncList->C_WaitForSlotEvent(0,&siSlotId,NULL);
		if (rvResult != CKR_OK)
		{
			return;
		}

		rvResult = Pkcs11FuncList->C_GetSlotInfo(siSlotId,&sSlotInfo);
		if (rvResult!=CKR_OK)
		{
			return;
		}
		if ((sSlotInfo.flags&CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT)
		{
			bExecuted = CK_TRUE;
		}
		else
		{
			bExecuted = CK_FALSE;
		}

		pCallbackFunc(siSlotId, bExecuted);
		UpdateDeviceList();
	}
};
//--------------------------------------------------------------------------------------
void BaseClass::GetDeviceList(CK_SLOT_ID_PTR pDevicesList,CK_ULONG *ulNumOfDevices)
{
	CK_ULONG j = 0;
	//проверяем, подключены ли устройства, и задаем начальные значения
	*ulNumOfDevices = ulSlotCount;
	if ((ulSlotCount==0)||(pDevicesList==NULL)) return;
	for (CK_ULONG i=0;i<ulSlotCount;i++)
	{
		pDevicesList[i] = pSlotList[i];
	}
};
//--------------------------------------------------------------------------------------
void BaseClass::GetDeviceInfo(CK_SLOT_ID ulSlotID, MY_DEVICE_INFO_PTR pDeviceInfo)
{
	CK_TOKEN_INFO				sTokenInfo;
//	SHEX_EX_DEVICE_PROPERTY		sDeviceProperties;
//	SHEX_DEVICE_PUK_PARAMS		sDevicePUKParams; function still isn't realized
//	SHEX_DEVICE_FIRMWARE_INFO	sDeviceFirmware;
	SHEX_DEVICE_IA_PARAMETERS	sDeviceParameters;
	sDeviceParameters.ulStructVersion = 1;

	CK_ULONG j = 0;
	//сотри тут длину пин
	rvResult = Pkcs11FuncList->C_GetTokenInfo(ulSlotID,&sTokenInfo);
	if (rvResult != CKR_OK) return;
	//rvResult = pcExFuncList->SHEX_GetExFirmwareInfo(ulSlotID,&sDeviceFirmware);
	//if (rvResult != CKR_OK) return;



	//смотри тут блокировку
	rvResult = pcExFuncList->SHEX_GetExIAParametersInfo(ulSlotID,&sDeviceParameters);
	if (rvResult != CKR_OK) return;

	(*pDeviceInfo).ulMaxPinLen = sTokenInfo.ulMaxPinLen;
	(*pDeviceInfo).ulMinPinLen = sTokenInfo.ulMinPinLen;

	for (j = 0; j<DEVICE_ID_LEN; j++)
	{
		(*pDeviceInfo).cDeviceID[j] = sTokenInfo.serialNumber[j];
	}
	(*pDeviceInfo).cDeviceID[j] = '\0';
	j = 0;
	while ((sTokenInfo.model[j]!=' ')&&(j<16))
	{
		(*pDeviceInfo).cDeviceType[j] = sTokenInfo.model[j];
		j++;
	}
	(*pDeviceInfo).cDeviceType[j] = '\0';

	if (strcmp((char *)((*pDeviceInfo).cDeviceType),SHIPKA_LITE))	//there are no flags for Shipka-lite device
	{
		(*pDeviceInfo).ulFlags = 0x00000000;
		if (!(sTokenInfo.flags&CKF_TOKEN_INITIALIZED)) 
					(*pDeviceInfo).ulFlags = (*pDeviceInfo).ulFlags|DEVICE_NOT_INITIALIZED;
		if (sDeviceParameters.blNeedCreatePuk==CK_TRUE) 
					(*pDeviceInfo).ulFlags = (*pDeviceInfo).ulFlags|DEVICE_NOT_FORMATED;	//it's the same flag as PUK_NOT_SETTED now, cause if we once set 
																							//the PUK we can work with it without formatting device later
		if ((sTokenInfo.flags&CKF_USER_PIN_TO_BE_CHANGED)||((sTokenInfo.flags&CKF_USER_PIN_INITIALIZED)!=CKF_USER_PIN_INITIALIZED)) 
					(*pDeviceInfo).ulFlags = (*pDeviceInfo).ulFlags|PIN_NOT_SETTED;
		//if () (*pDeviceInfo).ulFlags = (*pDeviceInfo).ulFlags|PUK_NOT_SETTED;
		if (sDeviceParameters.blPukMode!=CK_TRUE) 
					(*pDeviceInfo).ulFlags = (*pDeviceInfo).ulFlags|PUK_NOT_REQUIRED;
		if ((sDeviceParameters.ulRemainInvalidPinAttempts==0)||(sTokenInfo.flags&CKF_USER_PIN_LOCKED)) 
					(*pDeviceInfo).ulFlags = (*pDeviceInfo).ulFlags|PIN_BLOCKED;
		//if () (*pDeviceInfo).ulFlags = (*pDeviceInfo).ulFlags|PUK_BLOCKED;				//there is no flag for this situation
	}
	else 
	{
		(*pDeviceInfo).ulFlags = 0x00000000;
		if (sDeviceParameters.blNeedCreatePuk==CK_TRUE) 
					(*pDeviceInfo).ulFlags = (*pDeviceInfo).ulFlags|DEVICE_NOT_FORMATED;
	}
};
//--------------------------------------------------------------------------------------
bool BaseClass::DeviceIsConnected(char *pcDeviceID, CK_SLOT_ID_PTR pulSlotID)
{
	int iLenOfDeviceTypeStr = 0;
	//ID устройства должен состоять из 8 цифр
	if (strlen(pcDeviceID)!=DEVICE_ID_LEN) return false;
	CK_TOKEN_INFO tiSlotInfoList;
	//ищем нужный нам ID среди подключенных токенов и запоминаем ID
	for (CK_ULONG i=0;i<ulSlotCount;i++)
	{
		rvResult = Pkcs11FuncList->C_GetTokenInfo(pSlotList[i],&tiSlotInfoList);
		if (rvResult != CKR_OK) return false;
		if (!strncmp(pcDeviceID,(char *)(tiSlotInfoList.serialNumber),DEVICE_ID_LEN)) 
		{
			*pulSlotID = pSlotList[i];
			return true;
		}
	}
	return false;
};
//--------------------------------------------------------------------------------------
