#include "KeyManagmentLib.h"

KeyManagmentClass *MyClassToWorkWith;

KM_FUNCTION_LIST FunctionList = {{1,0},&Initialize,&Finalize,&GetFunctionList,&GetDeviceList,&GetDeviceInfo,
						&DeviceIsConnected,&WaitForSlotEvent,&RegisterCallback,&UpdateDeviceList,&MakeSession,&MakeLoginedSession,&GetKeysInfoList,
						&GetKeyInfo,&FindKeysByTemplate,&GenerateSecKey,&GenerateKeyPair,&DeleteKey,
						&ExportSecPriKey,&ExportPublicKey,&ImportSecPriKey,&ImportPublicKey,&ParseAttrs,&UnparseAttrs,&GetParsedKeyClass};
//======================================================================================*/
KM_DECLARE_FUNCTION(CK_RV, Initialize)
(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
)
{
	if (pReserved != NULL_PTR)
		return CKR_ARGUMENTS_BAD;
	MyClassToWorkWith = new KeyManagmentClass();
	return MyClassToWorkWith->rvResult;
};
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, Finalize)
(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
)
{
	delete MyClassToWorkWith;
	return CKR_OK;
};
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, GetFunctionList)
(
  KM_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
                                            * function list */
)
{
	if (ppFunctionList == NULL)
		return CKR_ARGUMENTS_BAD;
	*ppFunctionList = &FunctionList;
	return CKR_OK;
};
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, GetDeviceList)
(
  CK_SLOT_ID_PTR pDevicesList,
  CK_ULONG *ulNumOfDevices
)
{
	MyClassToWorkWith->GetDeviceList(pDevicesList,ulNumOfDevices);
	return MyClassToWorkWith->rvResult;
};
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, GetDeviceInfo)
(
  CK_SLOT_ID ulSlotID, 
  MY_DEVICE_INFO_PTR pDeviceInfo
)
{
	MyClassToWorkWith->GetDeviceInfo(ulSlotID,pDeviceInfo);
	return MyClassToWorkWith->rvResult;
};
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, DeviceIsConnected)
(
	char *pcDeviceID,
	CK_SLOT_ID_PTR pulSlotID
)
{
	if (MyClassToWorkWith->DeviceIsConnected(pcDeviceID,pulSlotID) == true)
	{
		return CKR_OK;
	}
	else
	{
		if (MyClassToWorkWith->rvResult != CKR_OK)
			return MyClassToWorkWith->rvResult;
		else 
			return CKR_DEVICE_REMOVED;
	}
};
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, WaitForSlotEvent)
(
	 CK_FLAGS flags, 
	 CK_SLOT_ID_PTR pSlot, 
	 CK_VOID_PTR pReserved
)
{
	return MyClassToWorkWith->WaitForSlotEvent(flags, pSlot, pReserved);
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, RegisterCallback)
(
	void (*pCallback)(CK_SLOT_ID, CK_BBOOL)
)
{
	MyClassToWorkWith->RegisterCallback(pCallback);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, UpdateDeviceList)
(
)
{
	MyClassToWorkWith->UpdateDeviceList();
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, MakeSession)
(
	char *pcDeviceID
)
{
	MyClassToWorkWith->MakeSession(pcDeviceID);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, MakeLoginedSession)
(
	char *pcDeviceID, 
	MY_PIN_PARAMS sPinParams
)
{
	MyClassToWorkWith->MakeLoginedSession(pcDeviceID,sPinParams);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, GetKeysInfoList)
(
	MY_KEY_TEMPLATE_INFO sKeyTemplateInfo,
	MY_KEY_INFO_PTR psKeyList, 
	CK_ULONG_PTR ulKeyNumber
)
{
	MyClassToWorkWith->GetKeysInfoList(sKeyTemplateInfo,psKeyList,ulKeyNumber);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, GetKeyInfo)
(
	CK_OBJECT_HANDLE hKey, 
	MY_KEY_INFO_PTR psKeyInfo
)
{
	MyClassToWorkWith->GetKeyInfo(hKey,psKeyInfo);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, FindKeysByTemplate)
(
	MY_KEY_TEMPLATE_INFO sKeyTemplateInfo, 
	CK_OBJECT_HANDLE_PTR phKeyList, 
	CK_ULONG_PTR pulKeyNumber
)
{
	MyClassToWorkWith->FindKeysByTemplate(sKeyTemplateInfo,phKeyList,pulKeyNumber);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, GenerateSecKey)
(
	MY_KEY_TEMPLATE_INFO sKeyTemplateInfo, 
	CK_MECHANISM_PTR pMechanism
)
{
	MyClassToWorkWith->GenerateSecKey(sKeyTemplateInfo,pMechanism);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, GenerateKeyPair)
(
	MY_KEY_TEMPLATE_INFO sPriKeyTemplateInfo, 
	MY_KEY_TEMPLATE_INFO sPubKeyTemplateInfo, 
	CK_MECHANISM_PTR pMechanism
)
{
	MyClassToWorkWith->GenerateKeyPair(sPriKeyTemplateInfo,sPubKeyTemplateInfo,pMechanism);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, DeleteKey)
(
	MY_KEY_TEMPLATE_INFO sKeyTemplateInfo
)
{
	MyClassToWorkWith->DeleteKey(sKeyTemplateInfo);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, ExportSecPriKey)
(
	MY_KEY_TEMPLATE_INFO sKeyToExport, 
	MY_KEY_TEMPLATE_INFO sPubKeyToWrapOn, 
	MY_KEY_TEMPLATE_INFO sPriKeyToWrapOn, 
	BYTE *pbWrappedKey, 
	CK_ULONG *ulWrappedKeyLen
)
{
	MyClassToWorkWith->ExportSecPriKey(sKeyToExport,sPubKeyToWrapOn,sPriKeyToWrapOn,pbWrappedKey,ulWrappedKeyLen);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, ExportPublicKey)
(
	MY_KEY_TEMPLATE_INFO sKeyToExport, 
	BYTE *pbExportedKey, 
	CK_ULONG *ulExportedKeyLen
)
{
	MyClassToWorkWith->ExportPublicKey(sKeyToExport,pbExportedKey,ulExportedKeyLen);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, ImportSecPriKey)
(
	MY_KEY_TEMPLATE_INFO sPubKeyToUnwrapOn, 
	MY_KEY_TEMPLATE_INFO sPriKeyToUnwrapOn, 
	BYTE *pbExportedKey, 
	CK_ULONG ulExportedKeyLen
)
{
	MyClassToWorkWith->ImportSecPriKey(sPubKeyToUnwrapOn,sPriKeyToUnwrapOn,pbExportedKey,ulExportedKeyLen);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, ImportPublicKey)
(
	CK_BYTE *pbExportedKey, 
	CK_ULONG ulExportedKeyLen
)
{
	MyClassToWorkWith->ImportPublicKey(pbExportedKey,ulExportedKeyLen);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, ParseAttrs)
(
	MY_KEY_TEMPLATE_INFO sAttrsToParse, 
	BYTE *pbParsedAttrs, 
	CK_ULONG *ulParsedAttrsLen
)
{
	MyClassToWorkWith->ParseAttrs(sAttrsToParse,pbParsedAttrs,ulParsedAttrsLen);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, UnparseAttrs)
(
	CK_BYTE *pbParsedAttrs, 
	CK_ULONG ulParsedAttrsLen, 
	MY_KEY_TEMPLATE_INFO_PTR sAttrsUnparsed
)
{
	MyClassToWorkWith->UnparseAttrs(pbParsedAttrs,ulParsedAttrsLen,sAttrsUnparsed);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
KM_DECLARE_FUNCTION(CK_RV, GetParsedKeyClass)
(
	CK_BYTE *pbParsedAttrs, 
	CK_ULONG ulParsedAttrsLen,
	CK_ULONG_PTR pulKeyClass
)
{
	if (pulKeyClass == NULL)
		return CKR_ARGUMENTS_BAD;
	*pulKeyClass = MyClassToWorkWith->GetParsedKeyClass(pbParsedAttrs,ulParsedAttrsLen);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
