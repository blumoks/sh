#ifndef USER_FUNCTIONS_H
#define USER_FUNCTIONS_H

#define KEY_MANAGMENT_LIB		(char *)("KeyManagment.dll")

#include "KeyManagmentLib.h"
#include "KeyManCmdAndConstants.h"

typedef CK_RV (*_GetFunctionList)(KM_FUNCTION_LIST_PTR_PTR );

class UserFunctionality{
public:
	UserFunctionality();
	UserFunctionality(char *pcDeviceID, MY_PIN_PARAMS sPinParams);
	~UserFunctionality();

	void InitKeyManagmentLib();
	void FinalizeKeyManagmentLib();

	void GetKeysInfoListByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams, char **pcKeyList, CK_ULONG_PTR ulKeyNumber);
	void GenerateSecKeyByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams);
	void GenerateKeyPairByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams);
	void GenerateGost3410KeyPairByStringAttributes(char **pcKeysInfo, CK_ULONG ulNumOfParams);
	void GenerateGost28147KeyByStringAttributes(char **pcKeyInfo, CK_ULONG ulNumOfParams);
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
	CK_RV							rvResult;

private:	
	HINSTANCE						hKeyManagmentLib;
	_GetFunctionList				hGetFuncList;
	CK_BBOOL						blTrue, blFalse;
	CK_ULONG						ulClass_SecKey, ulClass_PubKey, ulClass_PriKey;
	KM_FUNCTION_LIST_PTR			pKmFuncList;
	//MyKeyManagmentClass
};

#endif