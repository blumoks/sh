#ifndef _SH_ENC_SIG_CMD_FUNC_
#define _SH_ENC_SIG_CMD_FUNC_
#include "ShEncSigLib.h"
#include "ShEncSigCmdAndParams.h"
#include <iostream>
#include <bitset>

typedef CK_RV (*_GetFunctionList)(ES_FUNCTION_LIST_PTR_PTR );

class CmdFunctionsClassForEncSig
{
public:
	CmdFunctionsClassForEncSig();
	~CmdFunctionsClassForEncSig();
	void GetCmdFromCmdLine(int argc, char **argv);

	CK_RV rvResult;
private:
	void InitializeEncSigLib();
	void FinalizeEncSigLib();
	void MakeKeyParamsFromCmd(int argc, char **argv, MY_KEY_TEMPLATE_INFO_PTR pKeyInfo);

	void GetDeviceList();
	void GetDeviceInfo(char *DeviceId, bool bGetExInfo);
	void GetKeysList(int iNumOfKeyParams, char **psKeyParams);

	void EncryptData(BYTE *pbDataToEncrypt, CK_ULONG ulDataToEncryptLen, int iNumOfKeyParams, 
		char **psKeyParams, BYTE *pbEncryptedData, CK_ULONG *ulEncryptedDataLen);
	void EncryptFile(char *pcFileToEncrypt,int iNumOfKeyParams, char **psKeyParams, char *pcFileToEncryptTo);

	void DecryptData(BYTE *pbDataToDecrypt, CK_ULONG ulDataToDecryptLen, int iNumOfKeyParams, 
		char **psKeyParams, BYTE *pbDecryptedData, CK_ULONG *ulDecryptedDataLen);
	void DecryptFile(char *pcFileToDecrypt,int iNumOfKeyParams, char **psKeyParams, char *pcFileToDecryptTo);

	void SignData(BYTE *pbDataToSign, CK_ULONG ulDataToSignLen, int iNumOfParams, 
		char **psParams, BYTE *pbSignature, CK_ULONG *ulSignatureLen);
	void SignFile(char *pcFileToSign,int iNumOfParams, char **psParams, char *pcFileToPutSignTo);

	void VerifyData(BYTE *pbDataToVerify, CK_ULONG ulDataToVerifyLen, BYTE *pbSignature, CK_ULONG *ulSignatureLen,
		int iNumOfParams, char **psParams, CK_BBOOL *bVerifyResult);
	void VerifyFile(char *pcFileToVerify, char *pcFileSignature, int iNumOfParams, char **psParams, CK_BBOOL *bVerifyResult);

	void ReadDataFromFile(char *pcFilename, CK_BYTE_PTR pbData, CK_ULONG_PTR ulDataLen);
	void WriteDataToFile(char *pcFilename, CK_BYTE_PTR pbData, CK_ULONG ulDataLen);

	void PrintWorkResult(char *InFunction);
	void PrintDeviceInfo(CK_SLOT_ID ulSlotID);
	void PrintDeviceInfoEx(CK_SLOT_ID ulSlotID);

	HINSTANCE						hShEncSigLib;
	_GetFunctionList				hGetFuncList;
	CK_BBOOL						blTrue, blFalse;
	CK_ULONG						ulClass_SecKey, ulClass_PubKey, ulClass_PriKey;
	ES_FUNCTION_LIST_PTR			pEsFuncList;
};
#endif