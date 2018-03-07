#ifndef WORK_WITH_KEYS_H
#define WORK_WITH_KEYS_H

#include "low_layer_func.h"
#include <vector>

//need to do this, cause there was a warning about vector of structures
#pragma warning(disable:4251)

class DLL_USAGE WorkWithKeysClass:public BaseClass {
public:
	WorkWithKeysClass();
	WorkWithKeysClass(char *pcDeviceID, MY_PIN_PARAMS sPinParams);
	~WorkWithKeysClass();
	
	virtual void MakeLoginedSession(char *pcDeviceID, MY_PIN_PARAMS sPinParams);
	virtual void MakeSession(char *pcDeviceID);
	virtual void GetKeysInfoList(MY_KEY_TEMPLATE_INFO sKeyTemplateInfo, 
				MY_KEY_INFO_PTR psKeyList, CK_ULONG_PTR ulKeyNumber);
	virtual void GetKeyInfo(CK_OBJECT_HANDLE hKey, MY_KEY_INFO_PTR psKeyInfo);
	virtual void FindKeysByTemplate(MY_KEY_TEMPLATE_INFO sKeyTemplateInfo, CK_OBJECT_HANDLE_PTR phKeyList, CK_ULONG_PTR pulKeyNumber);

	virtual void ParseAttrs (MY_KEY_TEMPLATE_INFO sAttrsToParse, BYTE *pbParsedAttrs, CK_ULONG *ulParsedAttrsLen);
	virtual void UnparseAttrs (CK_BYTE *pbParsedAttrs, CK_ULONG ulParsedAttrsLen, MY_KEY_TEMPLATE_INFO_PTR sAttrsUnparsed);

	virtual CK_ULONG GetParsedKeyClass(CK_BYTE *pbParsedAttrs, CK_ULONG ulParsedAttrsLen);
	virtual void GetParsedKeyAttribute(CK_BYTE *pbParsedAttrs, CK_ULONG ulParsedAttrsLen, CK_ATTRIBUTE_TYPE ulAttrType, CK_BYTE_PTR pbAttrValue, CK_ULONG_PTR pulAttrValueLen);

	CK_OBJECT_CLASS			ulClass_PubKey, ulClass_PriKey, ulClass_SecKey;
	CK_BBOOL				blTrue, blFalse;
	char					*pbKeyOid;
	CK_ULONG				ulKeyLen;
	
	CK_SESSION_HANDLE		hSession;

private:

	std::vector <CK_OBJECT_HANDLE>	*LastFoundKeysList;				//list of keys
	std::vector <MY_KEY_INFO>		LastFoundKeysInfos;			//list of key infos
	
	void FindKeysInfos(MY_KEY_TEMPLATE_INFO sTempKeyInfo);
	//void GetMaxKeyNumber(char *pcDeviceID, CK_ULONG_PTR ulMaxKeyNumber);

//	void UpdateKeyList();
};

#endif