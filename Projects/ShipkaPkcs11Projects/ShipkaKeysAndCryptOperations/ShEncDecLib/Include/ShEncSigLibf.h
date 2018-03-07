//Functions for initialization of ShEncSig library
/* CK_Initialize initializes the ShEncSig library. */
CK_ES_FUNCTION_INFO(Initialize)
#ifdef CK_NEED_ARG_LIST
(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
);
#endif


/* CK_Finalize indicates that an application is done with the
 * ShEncSig library. */
CK_ES_FUNCTION_INFO(Finalize)
#ifdef CK_NEED_ARG_LIST
(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
);
#endif

/* CK_GetFunctionList returns the function list. */
CK_ES_FUNCTION_INFO(GetFunctionList)
#ifdef CK_NEED_ARG_LIST
(
  ES_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
                                            * function list */
);
#endif

//User-defined functions:
CK_ES_FUNCTION_INFO(GetDeviceList)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID_PTR pDevicesList,
  CK_ULONG *ulNumOfDevices
);
#endif
CK_ES_FUNCTION_INFO(GetDeviceInfo)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID ulSlotID, 
  MY_DEVICE_INFO_PTR pDeviceInfo
);
#endif
CK_ES_FUNCTION_INFO(DeviceIsConnected)
#ifdef CK_NEED_ARG_LIST
(
	char *pcDeviceID,
	CK_SLOT_ID_PTR pulSlotID
);
#endif
CK_ES_FUNCTION_INFO(RegisterCallback)
#ifdef CK_NEED_ARG_LIST
(
	void (*pCallback)(CK_SLOT_ID, CK_BBOOL)
);
#endif
CK_ES_FUNCTION_INFO(UpdateDeviceList)
#ifdef CK_NEED_ARG_LIST
(
);
#endif

CK_ES_FUNCTION_INFO(MakeSession)
#ifdef CK_NEED_ARG_LIST
(
	char *pcDeviceID
);
#endif
CK_ES_FUNCTION_INFO(MakeLoginedSession)
#ifdef CK_NEED_ARG_LIST
(
	char *pcDeviceID, 
	MY_PIN_PARAMS sPinParams
);
#endif
CK_ES_FUNCTION_INFO(GetKeysInfoList)
#ifdef CK_NEED_ARG_LIST
(
	MY_KEY_TEMPLATE_INFO sKeyTemplateInfo,
	MY_KEY_INFO_PTR psKeyList, 
	CK_ULONG_PTR ulKeyNumber
);
#endif
CK_ES_FUNCTION_INFO(GetKeyInfo)
#ifdef CK_NEED_ARG_LIST
(
	CK_OBJECT_HANDLE hKey, 
	MY_KEY_INFO_PTR psKeyInfo
);
#endif
CK_ES_FUNCTION_INFO(FindKeysByTemplate)
#ifdef CK_NEED_ARG_LIST
(
	MY_KEY_TEMPLATE_INFO sKeyTemplateInfo, 
	CK_OBJECT_HANDLE_PTR phKeyList, 
	CK_ULONG_PTR pulKeyNumber
);
#endif

CK_ES_FUNCTION_INFO(EncryptData)
#ifdef CK_NEED_ARG_LIST
(
	BYTE *pbDataToEncrypt, 
	CK_ULONG ulDataToEncryptLen, 
	MY_KEY_TEMPLATE_INFO sKeyToEncryptOn,
	CK_MECHANISM_PTR pMechanism, 
	BYTE *pbEncryptedData, 
	CK_ULONG *ulEncryptedDataLen
);
#endif
CK_ES_FUNCTION_INFO(DecryptData)
#ifdef CK_NEED_ARG_LIST
(
	BYTE *pbDataToDecrypt, 
	CK_ULONG ulDataToDecryptLen, 
	MY_KEY_TEMPLATE_INFO sKeyToDecryptOn, 
	CK_MECHANISM_PTR pMechanism, 
	BYTE *pbDecryptedData, 
	CK_ULONG *ulDecryptedDataLen
);
#endif
CK_ES_FUNCTION_INFO(SignData)
#ifdef CK_NEED_ARG_LIST
(
	BYTE *pbDataToSign, 
	CK_ULONG ulDataToSignLen, 
	MY_KEY_TEMPLATE_INFO sKeyToSignOn, 
	CK_MECHANISM_PTR pHashMechanism, 
	CK_MECHANISM_PTR pSignMechanism, 
	BYTE *pbSignedData,
	CK_ULONG *ulSignedDataLen
);
#endif
CK_ES_FUNCTION_INFO(VerifyData)
#ifdef CK_NEED_ARG_LIST
(
	BYTE *pbDataToVerify, 
	CK_ULONG ulDataToVerifyLen, 
	BYTE *pbSignature, 
	CK_ULONG ulSignatureLen, 
	MY_KEY_TEMPLATE_INFO sKeyToVerifyOn, 
	CK_MECHANISM_PTR pHashMechanism, 
	CK_MECHANISM_PTR pVerifyMechanism, 
	CK_BBOOL *bVerifyResult
);
#endif

CK_ES_FUNCTION_INFO(ParseAttrs)
#ifdef CK_NEED_ARG_LIST
(
	MY_KEY_TEMPLATE_INFO sAttrsToParse, 
	BYTE *pbParsedAttrs, 
	CK_ULONG *ulParsedAttrsLen
);
#endif
CK_ES_FUNCTION_INFO(UnparseAttrs)
#ifdef CK_NEED_ARG_LIST
(
	CK_BYTE *pbParsedAttrs, 
	CK_ULONG ulParsedAttrsLen, 
	MY_KEY_TEMPLATE_INFO_PTR sAttrsUnparsed
);
#endif
CK_ES_FUNCTION_INFO(GetParsedKeyAttribute)
#ifdef CK_NEED_ARG_LIST
(
	CK_BYTE *pbParsedAttrs, 
	CK_ULONG ulParsedAttrsLen, 
	CK_ATTRIBUTE_TYPE ulAttrType, 
	CK_BYTE_PTR pbAttrValue, 
	CK_ULONG_PTR pulAttrValueLen
);
#endif
