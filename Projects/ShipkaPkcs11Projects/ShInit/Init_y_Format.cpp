#include "Init_y_Format.h"
#include <stdio.h>
InitializationClass::InitializationClass():BaseClass()
{
	if (rvResult!=CKR_OK) return;
	hSession=0;
};
//--------------------------------------------------------------------------------------
InitializationClass::~InitializationClass()
{
	if (rvResult!=CKR_OK) return;
	if (hSession!=0) rvResult = Pkcs11FuncList->C_CloseSession(hSession);
	if (rvResult!=CKR_OK) return;
};
//--------------------------------------------------------------------------------------
void InitializationClass::ChangePIN(char *pcDeviceID, char *pcOldPIN, CK_ULONG ulOldPinLen, char *pcNewPIN, CK_ULONG ulNewPinLen)
{
	CK_SLOT_ID ulSlotID = 0;
	MY_DEVICE_INFO DeviceInfo;
	//≈сли была открыта€ сесси€, то нужно ее закрыть и заново потом открыть
	if (hSession!=0) 
	{
		rvResult = Pkcs11FuncList->C_CloseSession(hSession);
		if (rvResult!=CKR_OK) return;
		hSession = 0;
	}


	//ѕровер€ем, есть ли устройство с данным ID
	if (DeviceIsConnected(pcDeviceID,&ulSlotID)==true)
	{
		//получаем информацию об устройстве
		GetDeviceInfo(ulSlotID,&DeviceInfo);
		//провер€ем параметры PIN:
		/*if ((((ulOldPinLen<7)||(ulOldPinLen>32))&&
			((DeviceInfo.ulFlags&PIN_NOT_SETTED)!=PIN_NOT_SETTED))||
			(ulNewPinLen<7)||(ulNewPinLen>32))*/
		if ((ulNewPinLen<7)||(ulNewPinLen>32))
		{
			if ((ulOldPinLen==0)&&((DeviceInfo.ulFlags&PIN_NOT_SETTED)!=PIN_NOT_SETTED)) 
				rvResult = PIN_NOT_ENTERED;
			else rvResult = CKR_PIN_LEN_RANGE;
			return;
		}
		//провер€ем, что PIN можно мен€ть:
		if ((DeviceInfo.ulFlags&DEVICE_NOT_INITIALIZED)||(DeviceInfo.ulFlags&DEVICE_NOT_FORMATED))
			//||(DeviceInfo.ulFlags&PIN_BLOCKED)||(DeviceInfo.ulFlags&PUK_BLOCKED))
		{
			if ((DeviceInfo.ulFlags&DEVICE_NOT_INITIALIZED)||(DeviceInfo.ulFlags&DEVICE_NOT_FORMATED))
				rvResult = CKR_PUK_NOT_SETTED;	//PUK не был выработан
			//else rvResult = CKR_DEVICE_BLOCKED;	//устройство заблокировано
			return;
		}
		//ќткрываем сессию
		rvResult = Pkcs11FuncList->C_OpenSession(ulSlotID,(CKF_SERIAL_SESSION | CKF_RW_SESSION),NULL,0,&hSession);
		if (rvResult != CKR_OK)
		{
			return;
		}
		
		//пытаемс€ изменить PIN
		
		rvResult = Pkcs11FuncList->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)pcOldPIN, ulOldPinLen, (CK_UTF8CHAR_PTR)pcNewPIN, ulNewPinLen);
		//CK_SESSION_INFO inf;
		//Pkcs11FuncList->C_GetSessionInfo(hSession, &inf);
		if (rvResult!=CKR_OK)
		{
			//если PIN вообще еще не был задан, то пытаемс€ его задать:
			if (rvResult==CKR_USER_PIN_NOT_INITIALIZED)
			{
				rvResult = Pkcs11FuncList->C_InitPIN(hSession, (CK_UTF8CHAR_PTR)pcNewPIN, ulNewPinLen);
				if (rvResult!=CKR_OK) 
				{
					Pkcs11FuncList->C_CloseSession(hSession);
					hSession = 0;
					return;
				}
			}
			else
			{
				Pkcs11FuncList->C_CloseSession(hSession);
				hSession = 0;
				return;
			}
		}
		rvResult = Pkcs11FuncList->C_CloseSession(hSession);
		hSession = 0;
		if (rvResult != CKR_OK)
		{
			return;
		}
	}
	else 
	{
		if (rvResult == CKR_OK) rvResult = CKR_DEVICE_REMOVED;
		
	}		return;
};
//--------------------------------------------------------------------------------------
void InitializationClass::CheckPIN(char *pcDeviceID, char *pcOldPIN, CK_ULONG ulOldPinLen, char *pcNewPIN, CK_ULONG ulNewPinLen)
{
	CK_SLOT_ID ulSlotID = 0;
	MY_DEVICE_INFO DeviceInfo;
	//≈сли была открыта€ сесси€, то нужно ее закрыть и заново потом открыть
	if (hSession != 0)
	{
		rvResult = Pkcs11FuncList->C_CloseSession(hSession);
		if (rvResult != CKR_OK) return;
		hSession = 0;
	}

	//ѕровер€ем, есть ли устройство с данным ID
	if (DeviceIsConnected(pcDeviceID, &ulSlotID) == true)
	{
		//получаем информацию об устройстве
		GetDeviceInfo(ulSlotID, &DeviceInfo);
		//провер€ем параметры PIN:
		/*if ((((ulOldPinLen<7)||(ulOldPinLen>32))&&
		((DeviceInfo.ulFlags&PIN_NOT_SETTED)!=PIN_NOT_SETTED))||
		(ulNewPinLen<7)||(ulNewPinLen>32))*/
		
		//провер€ем, что PIN можно мен€ть:
		if ((DeviceInfo.ulFlags&DEVICE_NOT_INITIALIZED) || (DeviceInfo.ulFlags&DEVICE_NOT_FORMATED))
			//||(DeviceInfo.ulFlags&PIN_BLOCKED)||(DeviceInfo.ulFlags&PUK_BLOCKED))
		{
			if ((DeviceInfo.ulFlags&DEVICE_NOT_INITIALIZED) || (DeviceInfo.ulFlags&DEVICE_NOT_FORMATED))
				rvResult = CKR_PUK_NOT_SETTED;	//PUK не был выработан
												//else rvResult = CKR_DEVICE_BLOCKED;	//устройство заблокировано
			return;
		}
		//ќткрываем сессию
		rvResult = Pkcs11FuncList->C_OpenSession(ulSlotID, (CKF_SERIAL_SESSION | CKF_RW_SESSION), NULL, 0, &hSession);
		if (rvResult != CKR_OK)
		{
			return;
		}

		//пытаемс€ изменить PIN

		rvResult = Pkcs11FuncList->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)pcOldPIN, ulOldPinLen, (CK_UTF8CHAR_PTR)pcNewPIN, ulNewPinLen);
		//CK_SESSION_INFO inf;
		//Pkcs11FuncList->C_GetSessionInfo(hSession, &inf);
		if (rvResult != CKR_OK)
		{
			//если PIN вообще еще не был задан, то пытаемс€ его задать:
			if (rvResult == CKR_USER_PIN_NOT_INITIALIZED)
			{
				rvResult = Pkcs11FuncList->C_InitPIN(hSession, (CK_UTF8CHAR_PTR)pcNewPIN, ulNewPinLen);
				if (rvResult != CKR_OK)
				{
					Pkcs11FuncList->C_CloseSession(hSession);
					hSession = 0;
					return;
				}
			}
			else
			{
				Pkcs11FuncList->C_CloseSession(hSession);
				hSession = 0;
				return;
			}
		}
		rvResult = Pkcs11FuncList->C_CloseSession(hSession);
		hSession = 0;
		if (rvResult != CKR_OK)
		{
			return;
		}
	}
	else
	{
		if (rvResult == CKR_OK) rvResult = CKR_DEVICE_REMOVED;

	}		return;
};

//----------------------------------------------------------------------------------------------------------------------------



void InitializationClass::UnblockDevice(char *pcDeviceID, char *pcPUK, CK_ULONG ulPukLen, CK_UTF8CHAR_PTR pcNewPIN, CK_ULONG ulNewPinLen)
{
	CK_SLOT_ID ulSlotID = 0;
	MY_DEVICE_INFO DeviceInfo;
	char *pcDeviceType = NULL;
	CK_UTF8CHAR_PTR pcPUK_hex = NULL;
	//провер€ем длину PUK
	if ((ulPukLen%2)||(ulPukLen<2)||(ulPukLen>32)) 
	{
		rvResult = PUK_INVALID_LENGTH;
		return;
	}
	//переводим PUK в шестнадцатеричную форму
	pcPUK_hex = (CK_UTF8CHAR_PTR) calloc ((ulPukLen/2)+1,sizeof(CK_UTF8CHAR));
	for (size_t i = 0; i<ulPukLen/2; i++)
	{
		switch (pcPUK[i*2]){
			case '0':case '1': case '2': case '3': case '4': case '5':
				 case '6': case '7': case '8': case '9':
					 pcPUK_hex[i] = 0x10*(pcPUK[i*2]-'0');
					 break;
			case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': 
					 pcPUK_hex[i] = 0x10*(pcPUK[i*2]-'A'+10);
					 break;
			case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
					 pcPUK_hex[i] = 0x10*(pcPUK[i*2]-'a'+10);
					 break;
			default: rvResult = PUK_INVALID_VALUE;
				break;
		} 
		
		switch (pcPUK[i*2+1]){
			case '0':case '1': case '2': case '3': case '4': case '5':
				 case '6': case '7': case '8': case '9':
					 pcPUK_hex[i] += (pcPUK[i*2+1]-'0');
					 break;
			case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': 
					 pcPUK_hex[i] += (pcPUK[i*2+1]-'A'+10);
					 break;
			case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
					 pcPUK_hex[i] += (pcPUK[i*2+1]-'a'+10);
					 break;
			default: rvResult = PUK_INVALID_VALUE;
				break;
		}
		if (rvResult!=CKR_OK) return;
	}
	pcPUK_hex[ulPukLen/2] = '\0';
	//провер€ем, подключено ли данное устройство
	if (DeviceIsConnected(pcDeviceID,&ulSlotID)==true)
	{
		//провер€ем параметры PIN:
		if ((ulNewPinLen<7)||(ulNewPinLen>32))
		{
			rvResult = CKR_PIN_LEN_RANGE;
			return;
		}
		//провер€ем, заблокировано ли устройство:
		GetDeviceInfo(ulSlotID,&DeviceInfo);
		if (!(DeviceInfo.ulFlags&PIN_BLOCKED)&&
			strncmp(SHIPKA_LITE,(char *)DeviceInfo.cDeviceType,strlen(SHIPKA_LITE)))	//Ў»ѕ ј-лайт не выставл€ет флаг
		{
			rvResult = CKR_DEVICE_NOT_BLOCKED;
			return;
		}
		//разблокируем устройство
		rvResult = pcExFuncList->SHEX_UnblockDevice(ulSlotID, pcPUK_hex, ulPukLen/2);
		if (rvResult!=CKR_OK) return;

		/*//Ќужно изменить пароль по умолчанию на пароль пользовател€
		rvResult = Pkcs11FuncList->C_OpenSession(ulSlotID,(CKF_SERIAL_SESSION | CKF_RW_SESSION),NULL,0,&hSession);
		if (rvResult!=CKR_OK) return;
		rvResult = Pkcs11FuncList->C_SetPIN(hSession, SHIPKA_LITE_DEFAULT_PIN, strlen((char *)SHIPKA_LITE_DEFAULT_PIN), (CK_UTF8CHAR_PTR)pcNewPIN, ulNewPinLen);
		if (rvResult!=CKR_OK)
		{
			//если PIN вообще еще не был задан, то пытаемс€ его задать:
			if (rvResult==CKR_USER_PIN_NOT_INITIALIZED)
			{
				rvResult = Pkcs11FuncList->C_InitPIN(hSession, pcNewPIN, ulNewPinLen);
				if (rvResult!=CKR_OK) 
				{
					Pkcs11FuncList->C_CloseSession(hSession);
					hSession = 0;
					return;
				}
			}
			else
			{
				Pkcs11FuncList->C_CloseSession(hSession);
				hSession = 0;
				return;
			}
		}
		Pkcs11FuncList->C_CloseSession(hSession);*/
	}
	else 
	{
		if (rvResult == CKR_OK) rvResult = CKR_DEVICE_REMOVED;
	}
	return;
};
//--------------------------------------------------------------------------------------
void InitializationClass::FormatDevice(char *pcDeviceID, bool bWithPUK, CK_UTF8CHAR_PTR PIN, CK_ULONG ulPinLen, 
										CK_UTF8CHAR_PTR pPUK, CK_ULONG_PTR pulPUKLen)
{
	CK_SLOT_ID ulSlotID = 0;
	MY_DEVICE_INFO DeviceInfo;
	//CK_RV rvErrorOccured;
	//провер€ем, подключено ли данное устройство
	if (DeviceIsConnected(pcDeviceID,&ulSlotID)==true)
	{
		//провер€ем, заданы ли параметры авторизации:
		GetDeviceInfo(ulSlotID,&DeviceInfo);
		if ((DeviceInfo.ulFlags&DEVICE_NOT_INITIALIZED)==DEVICE_NOT_INITIALIZED)
		{
			rvResult = AUTH_PARAMS_NOT_SETTED;
			return;
		}
		//провер€ем, форматирование с PUK или без:
		if (bWithPUK==false)
		{
			//дл€ Ў»ѕ и-лайт требуетс€ Login()
			if (!(strcmp((char *)(DeviceInfo.cDeviceType),SHIPKA_LITE)))
			{
				//провер€ем пароль: 
				if ((ulPinLen<7)||(ulPinLen>32)||(strlen((char*)PIN)<7)||(strlen((char*)PIN)>32))
				{
					rvResult = CKR_PIN_LEN_RANGE;
					return;
				}
				//ќткрываем сессию
				rvResult = Pkcs11FuncList->C_OpenSession(ulSlotID,(CKF_SERIAL_SESSION | CKF_RW_SESSION),NULL,0,&hSession);
				if (rvResult!=CKR_OK) return;
				rvResult = Pkcs11FuncList->C_Login(hSession,CKU_USER,PIN,ulPinLen);
				if (rvResult!=CKR_OK)
				{
					Pkcs11FuncList->C_CloseSession(hSession);
					return;
				}
			}
			//форматируем без PUK
			rvResult = pcExFuncList->SHEX_Format(ulSlotID);
			//logoff
			if (!(strcmp((char *)(DeviceInfo.cDeviceType),SHIPKA_LITE)))
			{
				Pkcs11FuncList->C_Logout(hSession);
				Pkcs11FuncList->C_CloseSession(hSession);
			}
		}
		else
		{
			//дл€ Ў»ѕ и-лайт требуетс€ Login()
			if (!(strcmp((char *)(DeviceInfo.cDeviceType),SHIPKA_LITE)))
			{
				//провер€ем пароль: 
				if ((ulPinLen<7)||(ulPinLen>32)||(strlen((char*)PIN)<7)||(strlen((char*)PIN)>32))
				{
					rvResult = CKR_PIN_LEN_RANGE;
					return;
				}
				//ќткрываем сессию
				rvResult = Pkcs11FuncList->C_OpenSession(ulSlotID,(CKF_SERIAL_SESSION | CKF_RW_SESSION),NULL,0,&hSession);
				if (rvResult!=CKR_OK) return;
				/*rvResult = Pkcs11FuncList->C_Login(hSession,CKU_USER,PIN,ulPinLen);
				if (rvResult!=CKR_OK)
				{
					Pkcs11FuncList->C_CloseSession(hSession);
					return;
				}*/
			}
			//форматируем c PUK
			rvResult = pcExFuncList->SHEX_FormatWithPUKCode(ulSlotID,pPUK,pulPUKLen);
			//logoff
			if (!(strcmp((char *)(DeviceInfo.cDeviceType),SHIPKA_LITE)))
			{
				//Ќужно изменить пароль по умолчанию на пароль пользовател€

				rvResult = Pkcs11FuncList->C_SetPIN(hSession, SHIPKA_LITE_DEFAULT_PIN, 
					strlen((char *)SHIPKA_LITE_DEFAULT_PIN), PIN, ulPinLen);
				Pkcs11FuncList->C_Logout(hSession);
				Pkcs11FuncList->C_CloseSession(hSession);
			}
		}
	}
	else 
	{
		if (rvResult == CKR_OK) rvResult = CKR_DEVICE_REMOVED;
	}
	return;
}
