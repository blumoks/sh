#pragma once
#include "low_layer_func.h"

class InitializationClass:public BaseClass {
public:
	InitializationClass();
	~InitializationClass();
	void CheckPIN(char *pcDeviceID, char *pcOldPIN, CK_ULONG ulOldPinLen, char *pcNewPIN, CK_ULONG ulNewPinLen);
	void ChangePIN(char *pcDeviceID, char *pcOldPIN, CK_ULONG ulOldPinLen, char *pcNewPIN, CK_ULONG ulNewPinLen);
	void FormatDevice(char *pcDeviceID, bool bWithPUK, CK_UTF8CHAR_PTR PIN, CK_ULONG ulPinLen, 
			CK_UTF8CHAR_PTR pPUK, CK_ULONG_PTR pulPUKLen);
	void UnblockDevice(char *pcDeviceID, char *pcPUK, CK_ULONG ulPukLen, CK_UTF8CHAR_PTR pcNewPIN, CK_ULONG ulNewPinLen);
protected:
	CK_SESSION_HANDLE hSession;
};