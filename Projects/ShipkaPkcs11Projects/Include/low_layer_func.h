#ifndef LOW_LAYER_FUNCTIONS_H
#define LOW_LAYER_FUNCTIONS_H

#include "defines_and_constants.h"

class DLL_USAGE BaseClass {
public:
	BaseClass();
	~BaseClass();
	void						FinalizePKCS11Lib();
	virtual void				GetDeviceList(CK_SLOT_ID_PTR pDevicesList,CK_ULONG *ulNumOfDevices);
	virtual void				GetDeviceInfo(CK_SLOT_ID ulSlotID, MY_DEVICE_INFO_PTR pDeviceInfo);
	virtual bool				DeviceIsConnected(char *pcDeviceID, CK_SLOT_ID_PTR pulSlotID);
	virtual void				UpdateDeviceList();
	virtual CK_RV				WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);
	virtual void				RegisterCallback(void (*pCallback)(CK_SLOT_ID, CK_BBOOL));

	CK_FUNCTION_LIST_PTR		Pkcs11FuncList; // pointer to PKCS #11 function list
	CK_SHEX_FUNCTION_LIST_PTR   pcExFuncList;	// pointer to PKCS #11 extended function list
	CK_RV						rvResult;		// return value for PKCS #11 functions

private:
	HINSTANCE					hPkcsLib;			// pointer to PKCS #11 library
	CK_C_GetFunctionList		pcGetFunctionList;	// pointer to PKCS #11 function C_GetFunctionList
	CK_SHEX_GetFunctionList		pcGetFunctionListEx;// pointer to PKCS #11 function SHEX_GetFunctionList
	CK_ULONG					ulSlotCount;        // slot count
	CK_SLOT_ID_PTR				pSlotList;			// pointer to slot list
	int							iLanguageValue;		// language value

	HANDLE						hThreadHandle;
	void						(*pCallbackFunc)(CK_SLOT_ID, CK_BBOOL);

	void						InitializePKCS11Lib();


	void						RunCallback();
	static DWORD WINAPI			SlotCallback(LPVOID lpClassPtr);
};
#endif