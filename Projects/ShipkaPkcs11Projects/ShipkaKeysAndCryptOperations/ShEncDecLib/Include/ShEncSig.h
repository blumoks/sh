#ifndef _SH_ENC_DEC_H_
#define _SH_ENC_DEC_H_

#include "ShWorkWithKeys.h"

class DLL_USAGE ShEncSigClass:public WorkWithKeysClass {
public:
	ShEncSigClass();
	ShEncSigClass(char *pcDeviceID, MY_PIN_PARAMS sPinParams);
	~ShEncSigClass();

	void EncryptData(BYTE *pbDataToEncrypt, CK_ULONG ulDataToEncryptLen, MY_KEY_TEMPLATE_INFO sKeyToEncryptOn,
		CK_MECHANISM_PTR pMechanism, BYTE *pbEncryptedData, CK_ULONG *ulEncryptedDataLen);
	void DecryptData(BYTE *pbDataToDecrypt, CK_ULONG ulDataToDecryptLen, MY_KEY_TEMPLATE_INFO sKeyToDecryptOn, 
		CK_MECHANISM_PTR pMechanism, BYTE *pbDecryptedData, CK_ULONG *ulDecryptedDataLen);
	void SignData(BYTE *pbDataToSign, CK_ULONG ulDataToSignLen, MY_KEY_TEMPLATE_INFO sKeyToSignOn, CK_MECHANISM_PTR pHashMechanism, 
		CK_MECHANISM_PTR pSignMechanism, BYTE *pbSignedData, CK_ULONG *ulSignedDataLen);
	void VerifyData(BYTE *pbDataToVerify, CK_ULONG ulDataToVerifyLen, BYTE *pbSignature, CK_ULONG ulSignatureLen, 
		MY_KEY_TEMPLATE_INFO sKeyToVerifyOn, CK_MECHANISM_PTR pHashMechanism, CK_MECHANISM_PTR pVerifyMechanism, CK_BBOOL *bVerifyResult);
		
	/*
	//*/
private:
	CK_BYTE_PTR pbLastEncrypted, pbLastDecrypted, pbInputParsedData, pbLastSigned;
	CK_ULONG ulLastEncryptedLen, ulLastDecryptedLen, ulInputParsedDataLen, ulLastSignedLen;
};

#endif