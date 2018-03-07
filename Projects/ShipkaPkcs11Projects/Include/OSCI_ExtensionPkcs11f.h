/************************************************************************************************************
 Файл shPkcsExtension_f.h
 Ревизия 1.0.0.0
 Содержит обявления функций расширения стандарта PKCS #11 для OSCI-устройств
************************************************************************************************************/

CK_PKCS11_FUNCTION_INFO(SHEX_GetFunctionList)
#ifdef CK_NEED_ARG_LIST
(
	CK_SHEX_FUNCTION_LIST_PTR_PTR ppFunctionListEx /* receives pointer to extention functions list */
);
#endif

CK_PKCS11_FUNCTION_INFO(SHEX_GetExDeviceProperty)
#ifdef CK_NEED_ARG_LIST
(
	CK_SLOT_ID					ulSlotID,
	SHEX_EX_DEVICE_PROPERTY_PTR pDeviceProperty
);
#endif

CK_PKCS11_FUNCTION_INFO(SHEX_UnblockDevice)
#ifdef CK_NEED_ARG_LIST
(
	CK_SLOT_ID			ulSlotID,
	CK_UTF8CHAR_PTR		pPUK,
	CK_ULONG			ulPUKLen
);
#endif

CK_PKCS11_FUNCTION_INFO(SHEX_FormatWithPUKCode)
#ifdef CK_NEED_ARG_LIST
(
	CK_SLOT_ID			ulSlotID,
	CK_UTF8CHAR_PTR		pPUK,
	CK_ULONG_PTR		pulPUKLen
);
#endif

CK_PKCS11_FUNCTION_INFO (SHEX_Format)
#ifdef CK_NEED_ARG_LIST
(	CK_SLOT_ID			ulSlotID
);
#endif

CK_PKCS11_FUNCTION_INFO (SHEX_GetExFirmwareInfo)
#ifdef CK_NEED_ARG_LIST
(	CK_SLOT_ID						ulSlotID,
	SHEX_DEVICE_FIRMWARE_INFO_PTR	pFirmwareInfo
);
#endif

CK_PKCS11_FUNCTION_INFO (SHEX_GetExIAParametersInfo)
#ifdef CK_NEED_ARG_LIST
(	CK_SLOT_ID					ulSlotID,
	SHEX_DEVICE_IA_PARAMETERS_PTR pDeviceIAParams
);
#endif

CK_PKCS11_FUNCTION_INFO (SHEX_InitIASystem)
#ifdef CK_NEED_ARG_LIST
(	CK_SLOT_ID			ulSlotID,
	PSHEX_IA_PARAMS_PTR pDeviceIAParams
);
#endif

CK_PKCS11_FUNCTION_INFO (SHEX_ChangeSOPassword)
#ifdef CK_NEED_ARG_LIST
(	CK_SLOT_ID			ulSlotID,
	SHEX_SO_PASSWORD_PTR pOldSOPassword,
	SHEX_SO_PASSWORD_PTR pNewSOPassword
);
#endif

CK_PKCS11_FUNCTION_INFO (SHEX_LockDeviceFormatting)
#ifdef CK_NEED_ARG_LIST
(	CK_SLOT_ID				ulSlotID,
	SHEX_SO_PASSWORD_PTR	pSOPassword
);
#endif

CK_PKCS11_FUNCTION_INFO (SHEX_UnlockDeviceFormatting)
#ifdef CK_NEED_ARG_LIST
(	CK_SLOT_ID				ulSlotID,
	SHEX_SO_PASSWORD_PTR	pSOPassword
);
#endif
