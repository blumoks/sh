#pragma once
#include "KeyManagment.h"

class UserFunctionality:public KeyManagmentClass {
public:
	UserFunctionality();
	UserFunctionality(char *pcDeviceID, MY_PIN_PARAMS sPinParams);
	~UserFunctionality();

	void GetKeysInfoListByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams, char **pcKeyList, CK_ULONG_PTR ulKeyNumber);
	void GenerateSecKeyByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams);
	void GenerateKeyPairByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams);
	void DeleteKeysByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams);
	void ExportPublicKeyByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams, CK_BYTE_PTR pbExportedKey, CK_ULONG_PTR ulExportedKeyLen);
	void ExportSecPriKeyByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams, CK_BYTE_PTR pbExportedKey, CK_ULONG_PTR ulExportedKeyLen);

	void WriteDataToFile(char *pcFilename, CK_BYTE_PTR pbData, CK_ULONG ulDataLen);
	void ReadDataFromFile(char *pcFilename, CK_BYTE_PTR pbData, CK_ULONG_PTR ulDataLen);

	void ExportPublicToFile(char **pcInputData, CK_ULONG ulNumOfParams);
	void ExportSecPriToFile(char **pcInputData, CK_ULONG ulNumOfParams);
	void ImportPublicFromFile(char **pcInputData, CK_ULONG ulNumOfParams);
	void ImportSecPriFromFile(char **pcInputData, CK_ULONG ulNumOfParams);
	void ImportSecPriKeyByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams, CK_BYTE_PTR pbExportedKey, CK_ULONG ulExportedKeyLen);
private:	
	//void GetAttributesFromStrings(char **pcKeysInfo, CK_ULONG ulNumOfParams, MY_KEY_TEMPLATE_INFO sKeyTemplateInfo);
	//*/
};
