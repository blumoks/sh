#include "ShEncSigLib.h"

ShEncSigClass *MyClassToWorkWith;

ES_FUNCTION_LIST FunctionList = {{1,0},&Initialize,&Finalize,&GetFunctionList,&GetDeviceList,&GetDeviceInfo,
						&DeviceIsConnected,&RegisterCallback,&UpdateDeviceList,&MakeSession,&MakeLoginedSession,&GetKeysInfoList,
						&GetKeyInfo,&FindKeysByTemplate,&EncryptData,&DecryptData,&SignData,&VerifyData,
						&ParseAttrs,&UnparseAttrs,&GetParsedKeyAttribute};
//======================================================================================*/
ES_DECLARE_FUNCTION(CK_RV, Initialize)
(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
)
{
	if (pReserved != NULL_PTR)
		return CKR_ARGUMENTS_BAD;
	MyClassToWorkWith = new ShEncSigClass();
	return MyClassToWorkWith->rvResult;
};
//--------------------------------------------------------------------------------------
ES_DECLARE_FUNCTION(CK_RV, Finalize)
(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
)
{
	delete MyClassToWorkWith;
	return CKR_OK;
};
//--------------------------------------------------------------------------------------
ES_DECLARE_FUNCTION(CK_RV, GetFunctionList)
(
  ES_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
                                            * function list */
)
{
	if (ppFunctionList == NULL)
		return CKR_ARGUMENTS_BAD;
	*ppFunctionList = &FunctionList;
	return CKR_OK;
};
//--------------------------------------------------------------------------------------
ES_DECLARE_FUNCTION(CK_RV, GetDeviceList)
(
  CK_SLOT_ID_PTR pDevicesList,
  CK_ULONG *ulNumOfDevices
)
{
	MyClassToWorkWith->GetDeviceList(pDevicesList,ulNumOfDevices);
	return MyClassToWorkWith->rvResult;
};
//--------------------------------------------------------------------------------------
ES_DECLARE_FUNCTION(CK_RV, GetDeviceInfo)
(
  CK_SLOT_ID ulSlotID, 
  MY_DEVICE_INFO_PTR pDeviceInfo
)
{
	MyClassToWorkWith->GetDeviceInfo(ulSlotID,pDeviceInfo);
	return MyClassToWorkWith->rvResult;
};
//--------------------------------------------------------------------------------------
ES_DECLARE_FUNCTION(CK_RV, DeviceIsConnected)
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
ES_DECLARE_FUNCTION(CK_RV, RegisterCallback)
(
	void (*pCallback)(CK_SLOT_ID, CK_BBOOL)
)
{
	MyClassToWorkWith->RegisterCallback(pCallback);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
ES_DECLARE_FUNCTION(CK_RV, UpdateDeviceList)
(
)
{
	MyClassToWorkWith->UpdateDeviceList();
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
ES_DECLARE_FUNCTION(CK_RV, MakeSession)
(
	char *pcDeviceID
)
{
	MyClassToWorkWith->MakeSession(pcDeviceID);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
ES_DECLARE_FUNCTION(CK_RV, MakeLoginedSession)
(
	char *pcDeviceID, 
	MY_PIN_PARAMS sPinParams
)
{
	MyClassToWorkWith->MakeLoginedSession(pcDeviceID,sPinParams);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
ES_DECLARE_FUNCTION(CK_RV, GetKeysInfoList)
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
ES_DECLARE_FUNCTION(CK_RV, GetKeyInfo)
(
	CK_OBJECT_HANDLE hKey, 
	MY_KEY_INFO_PTR psKeyInfo
)
{
	MyClassToWorkWith->GetKeyInfo(hKey,psKeyInfo);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
ES_DECLARE_FUNCTION(CK_RV, FindKeysByTemplate)
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
ES_DECLARE_FUNCTION(CK_RV, EncryptData)
(
	BYTE *pbDataToEncrypt, 
	CK_ULONG ulDataToEncryptLen, 
	MY_KEY_TEMPLATE_INFO sKeyToEncryptOn,
	CK_MECHANISM_PTR pMechanism, 
	BYTE *pbEncryptedData, 
	CK_ULONG *ulEncryptedDataLen
)
{
	MyClassToWorkWith->EncryptData(pbDataToEncrypt,ulDataToEncryptLen,sKeyToEncryptOn,pMechanism,pbEncryptedData,ulEncryptedDataLen);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
ES_DECLARE_FUNCTION(CK_RV, DecryptData)
(
	BYTE *pbDataToDecrypt, 
	CK_ULONG ulDataToDecryptLen, 
	MY_KEY_TEMPLATE_INFO sKeyToDecryptOn, 
	CK_MECHANISM_PTR pMechanism, 
	BYTE *pbDecryptedData, 
	CK_ULONG *ulDecryptedDataLen
)
{
	MyClassToWorkWith->DecryptData(pbDataToDecrypt,ulDataToDecryptLen,sKeyToDecryptOn,pMechanism,pbDecryptedData,ulDecryptedDataLen);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
ES_DECLARE_FUNCTION(CK_RV, SignData)
(
	BYTE *pbDataToSign, 
	CK_ULONG ulDataToSignLen, 
	MY_KEY_TEMPLATE_INFO sKeyToSignOn, 
	CK_MECHANISM_PTR pHashMechanism, 
	CK_MECHANISM_PTR pSignMechanism, 
	BYTE *pbSignedData,
	CK_ULONG *ulSignedDataLen
)
{
	MyClassToWorkWith->SignData(pbDataToSign,ulDataToSignLen,sKeyToSignOn,pHashMechanism,pSignMechanism,pbSignedData,ulSignedDataLen);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
ES_DECLARE_FUNCTION(CK_RV, VerifyData)
(
	BYTE *pbDataToVerify, 
	CK_ULONG ulDataToVerifyLen, 
	BYTE *pbSignature, 
	CK_ULONG ulSignatureLen, 
	MY_KEY_TEMPLATE_INFO sKeyToVerifyOn, 
	CK_MECHANISM_PTR pHashMechanism, 
	CK_MECHANISM_PTR pVerifyMechanism, 
	CK_BBOOL *bVerifyResult
)
{
	MyClassToWorkWith->VerifyData(pbDataToVerify,ulDataToVerifyLen,pbSignature,ulSignatureLen,sKeyToVerifyOn,pHashMechanism,pVerifyMechanism,bVerifyResult);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
ES_DECLARE_FUNCTION(CK_RV, ParseAttrs)
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
ES_DECLARE_FUNCTION(CK_RV, UnparseAttrs)
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
ES_DECLARE_FUNCTION(CK_RV, GetParsedKeyAttribute)
(
	CK_BYTE *pbParsedAttrs, 
	CK_ULONG ulParsedAttrsLen, 
	CK_ATTRIBUTE_TYPE ulAttrType, 
	CK_BYTE_PTR pbAttrValue, 
	CK_ULONG_PTR pulAttrValueLen
)
{
	MyClassToWorkWith->GetParsedKeyAttribute(pbParsedAttrs,ulParsedAttrsLen,ulAttrType,pbAttrValue,pulAttrValueLen);
	return MyClassToWorkWith->rvResult;
}
//--------------------------------------------------------------------------------------
