//#define CK_NEED_ARG_LIST 1

//Functions for initialization of KeyManagment library
/* CK_Initialize initializes the KeyManagment library. */
CK_KM_FUNCTION_INFO(Initialize)
#ifdef CK_NEED_ARG_LIST
(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
);
#endif


/* CK_Finalize indicates that an application is done with the
 * KeyManagment library. */
CK_KM_FUNCTION_INFO(Finalize)
#ifdef CK_NEED_ARG_LIST
(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
);
#endif

/* CK_GetFunctionList returns the function list. */
CK_KM_FUNCTION_INFO(GetFunctionList)
#ifdef CK_NEED_ARG_LIST
(
  KM_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
                                            * function list */
);
#endif

//User-defined functions:
CK_KM_FUNCTION_INFO(GetDeviceList)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID_PTR pDevicesList,
  CK_ULONG *ulNumOfDevices
);
#endif
CK_KM_FUNCTION_INFO(GetDeviceInfo)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID ulSlotID, 
  MY_DEVICE_INFO_PTR pDeviceInfo
);
#endif
CK_KM_FUNCTION_INFO(DeviceIsConnected)
#ifdef CK_NEED_ARG_LIST
(
	char *pcDeviceID,
	CK_SLOT_ID_PTR pulSlotID
);
#endif
CK_KM_FUNCTION_INFO(WaitForSlotEvent)
#ifdef CK_NEED_ARG_LIST
(
	 CK_FLAGS flags, 
	 CK_SLOT_ID_PTR pSlot, 
	 CK_VOID_PTR pReserved
);
#endif
CK_KM_FUNCTION_INFO(RegisterCallback)
#ifdef CK_NEED_ARG_LIST
(
	void (*pCallback)(CK_SLOT_ID, CK_BBOOL)
);
#endif
CK_KM_FUNCTION_INFO(UpdateDeviceList)
#ifdef CK_NEED_ARG_LIST
(
);
#endif

CK_KM_FUNCTION_INFO(MakeSession)
#ifdef CK_NEED_ARG_LIST
(
	char *pcDeviceID
);
#endif
CK_KM_FUNCTION_INFO(MakeLoginedSession)
#ifdef CK_NEED_ARG_LIST
(
	char *pcDeviceID, 
	MY_PIN_PARAMS sPinParams
);
#endif
CK_KM_FUNCTION_INFO(GetKeysInfoList)
#ifdef CK_NEED_ARG_LIST
(
	MY_KEY_TEMPLATE_INFO sKeyTemplateInfo,
	MY_KEY_INFO_PTR psKeyList, 
	CK_ULONG_PTR ulKeyNumber
);
#endif
CK_KM_FUNCTION_INFO(GetKeyInfo)
#ifdef CK_NEED_ARG_LIST
(
	CK_OBJECT_HANDLE hKey, 
	MY_KEY_INFO_PTR psKeyInfo
);
#endif
CK_KM_FUNCTION_INFO(FindKeysByTemplate)
#ifdef CK_NEED_ARG_LIST
(
	MY_KEY_TEMPLATE_INFO sKeyTemplateInfo, 
	CK_OBJECT_HANDLE_PTR phKeyList, 
	CK_ULONG_PTR pulKeyNumber
);
#endif

CK_KM_FUNCTION_INFO(GenerateSecKey)
#ifdef CK_NEED_ARG_LIST
(
	MY_KEY_TEMPLATE_INFO sKeyTemplateInfo, 
	CK_MECHANISM_PTR pMechanism
);
#endif
CK_KM_FUNCTION_INFO(GenerateKeyPair)
#ifdef CK_NEED_ARG_LIST
(
	MY_KEY_TEMPLATE_INFO sPriKeyTemplateInfo, 
	MY_KEY_TEMPLATE_INFO sPubKeyTemplateInfo, 
	CK_MECHANISM_PTR pMechanism
);
#endif
CK_KM_FUNCTION_INFO(DeleteKey)
#ifdef CK_NEED_ARG_LIST
(
	MY_KEY_TEMPLATE_INFO sKeyTemplateInfo
);
#endif
CK_KM_FUNCTION_INFO(ExportSecPriKey)
#ifdef CK_NEED_ARG_LIST
(
	MY_KEY_TEMPLATE_INFO sKeyToExport, 
	MY_KEY_TEMPLATE_INFO sPubKeyToWrapOn, 
	MY_KEY_TEMPLATE_INFO sPriKeyToWrapOn, 
	BYTE *pbWrappedKey, 
	CK_ULONG *ulWrappedKeyLen
);
#endif
CK_KM_FUNCTION_INFO(ExportPublicKey)
#ifdef CK_NEED_ARG_LIST
(
	MY_KEY_TEMPLATE_INFO sKeyToExport, 
	BYTE *pbExportedKey, 
	CK_ULONG *ulExportedKeyLen
);
#endif
CK_KM_FUNCTION_INFO(ImportSecPriKey)
#ifdef CK_NEED_ARG_LIST
(
	MY_KEY_TEMPLATE_INFO sPubKeyToUnwrapOn, 
	MY_KEY_TEMPLATE_INFO sPriKeyToUnwrapOn, 
	BYTE *pbExportedKey, 
	CK_ULONG ulExportedKeyLen
);
#endif
CK_KM_FUNCTION_INFO(ImportPublicKey)
#ifdef CK_NEED_ARG_LIST
(
	CK_BYTE *pbExportedKey, 
	CK_ULONG ulExportedKeyLen
);
#endif
CK_KM_FUNCTION_INFO(ParseAttrs)
#ifdef CK_NEED_ARG_LIST
(
	MY_KEY_TEMPLATE_INFO sAttrsToParse, 
	BYTE *pbParsedAttrs, 
	CK_ULONG *ulParsedAttrsLen
);
#endif
CK_KM_FUNCTION_INFO(UnparseAttrs)
#ifdef CK_NEED_ARG_LIST
(
	CK_BYTE *pbParsedAttrs, 
	CK_ULONG ulParsedAttrsLen, 
	MY_KEY_TEMPLATE_INFO_PTR sAttrsUnparsed
);
#endif
CK_KM_FUNCTION_INFO(GetParsedKeyClass)
#ifdef CK_NEED_ARG_LIST
(
	CK_BYTE *pbParsedAttrs, 
	CK_ULONG ulParsedAttrsLen,
	CK_ULONG_PTR pulKeyClass
);
#endif
