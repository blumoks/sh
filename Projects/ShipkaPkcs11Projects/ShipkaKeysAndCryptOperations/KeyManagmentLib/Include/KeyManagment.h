#ifndef KEY_MANAGMENT_H
#define KEY_MANAGMENT_H

#include "ShWorkWithKeys.h"

class DLL_USAGE KeyManagmentClass:public WorkWithKeysClass {
public:
	KeyManagmentClass();
	KeyManagmentClass(char *pcDeviceID, MY_PIN_PARAMS sPinParams);
	~KeyManagmentClass();
	
	virtual void GenerateSecKey(MY_KEY_TEMPLATE_INFO sKeyTemplateInfo, CK_MECHANISM_PTR pMechanism);
	virtual void GenerateKeyPair(MY_KEY_TEMPLATE_INFO sPriKeyTemplateInfo, MY_KEY_TEMPLATE_INFO sPubKeyTemplateInfo, CK_MECHANISM_PTR pMechanism);
	virtual void DeleteKey(MY_KEY_TEMPLATE_INFO sKeyTemplateInfo);

	virtual void ExportSecPriKey (MY_KEY_TEMPLATE_INFO sKeyToExport, MY_KEY_TEMPLATE_INFO sPubKeyToWrapOn, MY_KEY_TEMPLATE_INFO sPriKeyToWrapOn, BYTE *pbWrappedKey, CK_ULONG *ulWrappedKeyLen);
	virtual void ExportPublicKey (MY_KEY_TEMPLATE_INFO sKeyToExport, BYTE *pbExportedKey, CK_ULONG *ulExportedKeyLen);

	virtual void ImportSecPriKey (MY_KEY_TEMPLATE_INFO sPubKeyToUnwrapOn, MY_KEY_TEMPLATE_INFO sPriKeyToUnwrapOn, BYTE *pbExportedKey, CK_ULONG ulExportedKeyLen);
	virtual void ImportPublicKey (CK_BYTE *pbExportedKey, CK_ULONG ulExportedKeyLen);
private:
	CK_BYTE_PTR pbLastExported, pbInputParsedData;
	CK_ULONG ulLastExpLen, ulInputParsedDataLen;
	/*
	void DerivePubKey(MY_KEY_TEMPLATE_INFO sKeyTemplateInfo);
	//*/
};
#endif