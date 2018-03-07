#include "ShEncSig.h"

/**
@page EncSig
*/
//===========================================================================
/**
@brief ShEncSigClass constructor
*/
ShEncSigClass::ShEncSigClass():WorkWithKeysClass()
{
	pbLastEncrypted = NULL;
	pbLastDecrypted = NULL;
	pbInputParsedData = NULL;
	pbLastSigned = NULL;
	ulLastEncryptedLen = 0;
	ulLastDecryptedLen = 0;
	ulInputParsedDataLen = 0;
	ulLastSignedLen = 0;
};
/**
@brief ShEncSigClass parametrized constructor
@param pcDeviceID(in) - ID of device we are working with as string
@param sPinParams(in) - parameters of PIN to this device: PIN and its length;
*/
ShEncSigClass::ShEncSigClass(char *pcDeviceID, MY_PIN_PARAMS sPinParams):WorkWithKeysClass(pcDeviceID, sPinParams)
{
	pbLastEncrypted = NULL;
	pbLastDecrypted = NULL;
	pbInputParsedData = NULL;
	pbLastSigned = NULL;
	ulLastEncryptedLen = 0;
	ulLastDecryptedLen = 0;
	ulInputParsedDataLen = 0;
	ulLastSignedLen = 0;
};
/**
@brief ShEncSigClass destructor
*/
ShEncSigClass::~ShEncSigClass()
{
	if (pbLastEncrypted) free (pbLastEncrypted);
	if (pbLastDecrypted) free (pbLastDecrypted);
	if (pbInputParsedData) free (pbInputParsedData);
	if (pbLastSigned) free (pbLastSigned);
};
//===========================================================================
void ShEncSigClass::EncryptData(BYTE *pbDataToEncrypt, CK_ULONG ulDataToEncryptLen, MY_KEY_TEMPLATE_INFO sKeyToEncryptOn, 
								CK_MECHANISM_PTR pMechanism, BYTE *pbEncryptedData, CK_ULONG *ulEncryptedDataLen)
{
#pragma region ParametersInitialisation
	CK_ULONG ulNumOfKeysFound = 0;
	CK_OBJECT_HANDLE hKeyToEncryptOn = 0;
	MY_KEY_INFO sKeyToEncryptOnInfo;
	CK_MECHANISM sMyMechanism;
	CK_BYTE	pbIV[] = {1, 2, 3, 4, 5, 6, 7, 8}; // 8-byte initialization vector
	CK_BYTE_PTR pbEncResult = NULL;
	CK_ULONG ulEncResultLen = 0;
	MY_KEY_TEMPLATE_INFO sEncResultToParse;

	rvResult = CKR_OK;
	memset (&sKeyToEncryptOnInfo,0,sizeof(MY_KEY_INFO));	
	memset (&sMyMechanism,0,sizeof(CK_MECHANISM));	
	memset (&sEncResultToParse,0,sizeof(MY_KEY_TEMPLATE_INFO));	
	//Check if there is input:
	if (!((pbDataToEncrypt)&&(ulDataToEncryptLen)))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto SH_ENCRYPT_DATA_FINALIZATION;
	}
#pragma endregion
#pragma region CheckForSecondCall
	//Check if it is second call:
	if ((pbEncryptedData)&&(pbLastEncrypted)&&(ulLastEncryptedLen))
	{
		//it is the second call
		*ulEncryptedDataLen = ulLastEncryptedLen;
		memcpy(pbEncryptedData,pbLastEncrypted,ulLastEncryptedLen);
		if (pbLastEncrypted)
		{
			free (pbLastEncrypted);
			pbLastEncrypted = NULL;
			ulLastEncryptedLen = 0;
		}
		goto SH_ENCRYPT_DATA_FINALIZATION;
	}
	else
	{
		//it is not second call, need to free global, if any:
		if (pbLastEncrypted)
		{
			free (pbLastEncrypted);
			pbLastEncrypted = NULL;
			ulLastEncryptedLen = 0;
		}
	}
#pragma endregion
#pragma region LookingForKey
	//Find Key to encrypt on:
 	FindKeysByTemplate(sKeyToEncryptOn,NULL,&ulNumOfKeysFound);
	//if only one key is found:
	if ((ulNumOfKeysFound!=1)||(rvResult != CKR_OK))
	{
		if (rvResult==CKR_OK)
		{
			if (ulNumOfKeysFound)
				rvResult = CKR_TOO_MANY_KEYS_FOUND;
			else
				rvResult = CKR_KEYS_NOT_FOUND;
			goto SH_ENCRYPT_DATA_FINALIZATION;
		}
	}
 	FindKeysByTemplate(sKeyToEncryptOn,&hKeyToEncryptOn,&ulNumOfKeysFound);
	if (CKR_OK != rvResult)
		goto SH_ENCRYPT_DATA_FINALIZATION;

	//Get info about key:
	GetKeyInfo(hKeyToEncryptOn,&sKeyToEncryptOnInfo);
	if (CKR_ATTRIBUTE_TYPE_INVALID == rvResult)		//all ok, no bit parameter...
		rvResult = CKR_OK;
	if (CKR_OK != rvResult)
		goto SH_ENCRYPT_DATA_FINALIZATION;
#pragma endregion
#pragma region MakingMechanism
	//Copy or make mechanism
	if (NULL == pMechanism)
	{
		//if there is no mechanism then need to create it:
		switch(sKeyToEncryptOnInfo.ulKeyType)
		{
		case CKK_DES3:
			sMyMechanism.mechanism = CKM_DES3_CBC;
			break;
		case CKK_GOST28147:
			sMyMechanism.mechanism = CKM_GOST28147;
			sMyMechanism.pParameter = pbIV;
			sMyMechanism.ulParameterLen = _countof(pbIV);
			break;
		case CKK_RC2:
			CK_RC2_CBC_PARAMS sRC2Params;
			memset(&sRC2Params,0,sizeof(CK_RC2_CBC_PARAMS));
			memcpy(sRC2Params.iv,pbIV,8);
			sRC2Params.ulEffectiveBits = 0;
			sMyMechanism.mechanism = CKM_RC2_CBC;
			sMyMechanism.pParameter = &sRC2Params;
			sMyMechanism.ulParameterLen = sizeof(CK_RC2_CBC_PARAMS);
			break;
		case CKK_G28147:
			sMyMechanism.mechanism = CKM_G28147_ECB;
			break;
		default:
			rvResult = CKR_ATTRIBUTE_TYPE_INVALID;
			return;
		}
	}
	else
	{
		sMyMechanism.mechanism = pMechanism->mechanism;
		sMyMechanism.ulParameterLen = pMechanism->ulParameterLen;
		sMyMechanism.pParameter = pMechanism->pParameter;
	}
#pragma endregion
#pragma region Encryption
	//Encrypt init:
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_EncryptInit(hSession,&sMyMechanism,hKeyToEncryptOn)))
	{
		goto SH_ENCRYPT_DATA_FINALIZATION;
	}
	//Encrypt
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_Encrypt(hSession,pbDataToEncrypt,ulDataToEncryptLen,pbEncResult,&ulEncResultLen)))
	{
		goto SH_ENCRYPT_DATA_FINALIZATION;
	}
	if (NULL == (pbEncResult = (CK_BYTE_PTR) malloc (ulEncResultLen)))
	{
		rvResult = NOT_ENOUGH_MEMORY;
		goto SH_ENCRYPT_DATA_FINALIZATION;
	}
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_Encrypt(hSession,pbDataToEncrypt,ulDataToEncryptLen,pbEncResult,&ulEncResultLen)))
	{
		goto SH_ENCRYPT_DATA_FINALIZATION;
	}
	/*
	//Encrypt final
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_EncryptFinal(hSession,NULL,&ulNumOfKeysFound)))
	{
		return;
	}
	//*/
#pragma endregion
#pragma region ParsingEncodedDataAndKeyInfo
	//parsing data
	if (pbLastEncrypted)
	{
		free (pbLastEncrypted);
		pbLastEncrypted = NULL;
		ulLastEncryptedLen = 0;
	}

	sEncResultToParse.ulNumOfParams = 4;	//id, class, type, enc_data
	if (NULL == (sEncResultToParse.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof (CK_ATTRIBUTE) * sEncResultToParse.ulNumOfParams)))
	{
		rvResult = NOT_ENOUGH_MEMORY;
		goto SH_ENCRYPT_DATA_FINALIZATION;
	}
	sEncResultToParse.psKeyParams[0].type = CKA_ID;
	sEncResultToParse.psKeyParams[1].type = CKA_KEY_TYPE;
	sEncResultToParse.psKeyParams[2].type = CKA_CLASS;
	sEncResultToParse.psKeyParams[3].type = CKA_ENCRYPTED_DATA;

	sEncResultToParse.psKeyParams[0].pValue = sKeyToEncryptOnInfo.pbKeyId;
	sEncResultToParse.psKeyParams[0].ulValueLen = sKeyToEncryptOnInfo.ulKeyIdLen;
	sEncResultToParse.psKeyParams[1].pValue = &(sKeyToEncryptOnInfo.ulKeyType);
	sEncResultToParse.psKeyParams[1].ulValueLen = sKeyToEncryptOnInfo.ulKeyTypeLen;
	sEncResultToParse.psKeyParams[2].pValue = &(sKeyToEncryptOnInfo.ulKeyClass);
	sEncResultToParse.psKeyParams[2].ulValueLen = sKeyToEncryptOnInfo.ulKeyClassLen;
	sEncResultToParse.psKeyParams[3].pValue = pbEncResult;
	sEncResultToParse.psKeyParams[3].ulValueLen = ulEncResultLen;

	ParseAttrs(sEncResultToParse,pbLastEncrypted,&ulLastEncryptedLen);
	if (CKR_OK != rvResult)
	{
		goto SH_ENCRYPT_DATA_FINALIZATION;
	}
	if (NULL == (pbLastEncrypted = (CK_BYTE_PTR) malloc (ulLastEncryptedLen)))
	{
		rvResult = NOT_ENOUGH_MEMORY;
		goto SH_ENCRYPT_DATA_FINALIZATION;
	}
	ParseAttrs(sEncResultToParse,pbLastEncrypted,&ulLastEncryptedLen);
	if (CKR_OK != rvResult)
	{
		goto SH_ENCRYPT_DATA_FINALIZATION;
	}
#pragma endregion
#pragma region OutputResultIfNeeded
	*ulEncryptedDataLen = ulLastEncryptedLen;
	if (pbEncryptedData)
	{
		memcpy(pbEncryptedData,pbLastEncrypted,ulLastEncryptedLen);
	}
#pragma endregion
SH_ENCRYPT_DATA_FINALIZATION:
#pragma region Finalization
	if (sEncResultToParse.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sEncResultToParse.ulNumOfParams; i++)
		{
			sEncResultToParse.psKeyParams[i].pValue = NULL;
		}
		free (sEncResultToParse.psKeyParams);
		sEncResultToParse.psKeyParams = NULL;
	}
	if (pbEncResult)
	{
		free (pbEncResult);
		pbEncResult = NULL;
	}
	if (CKR_OK != rvResult)
	{
		if (pbLastEncrypted)
		{
			free (pbLastEncrypted);
			pbLastEncrypted = NULL;
			ulLastEncryptedLen = 0;
		}
	}
#pragma endregion
};
//---------------------------------------------------------------------------
void ShEncSigClass::DecryptData(BYTE *pbDataToDecrypt, CK_ULONG ulDataToDecryptLen, MY_KEY_TEMPLATE_INFO sKeyToDecryptOn, 
								CK_MECHANISM_PTR pMechanism, BYTE *pbDecryptedData, CK_ULONG *ulDecryptedDataLen)
{
#pragma region ParametersInitialisation
	CK_ULONG ulNumOfKeysFound = 0;
	CK_OBJECT_HANDLE hKeyToDecryptOn = 0;
	MY_KEY_INFO sKeyToDecryptOnInfo;
	CK_MECHANISM sMyMechanism;
	CK_BYTE	pbIV[] = {1, 2, 3, 4, 5, 6, 7, 8}; // 8-byte initialization vector

	CK_BYTE_PTR pbEncResult = NULL;
	CK_ULONG ulEncResultLen = 0;
	MY_KEY_TEMPLATE_INFO sDecUnparseResult;
	MY_KEY_TEMPLATE_INFO sUnparsedKeyParams;

	rvResult = CKR_OK;
	memset (&sMyMechanism,0,sizeof(CK_MECHANISM));	
	memset (&sDecUnparseResult,0,sizeof(MY_KEY_TEMPLATE_INFO));	
	memset (&sUnparsedKeyParams,0,sizeof(MY_KEY_TEMPLATE_INFO));	
	memset (&sKeyToDecryptOnInfo,0,sizeof(MY_KEY_INFO));	

	//Check if there is input:
	if (!((pbDataToDecrypt)&&(ulDataToDecryptLen)))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
#pragma endregion
#pragma region CheckForSecondCall
	//Check if it is second call:
	if ((pbDecryptedData)&&(pbLastDecrypted)&&(ulLastDecryptedLen))
	{
		//it is the second call
		*ulDecryptedDataLen = ulLastDecryptedLen;
		memcpy(pbDecryptedData,pbLastDecrypted,ulLastDecryptedLen);
		if (pbLastDecrypted)
		{
			free (pbLastDecrypted);
			pbLastDecrypted = NULL;
			ulLastDecryptedLen = 0;
		}
		goto SH_DEC_DATA_FINALIZATION;
	}
	else
	{
		//it is not second call, need to free global, if any:
		if (pbLastDecrypted)
		{
			free (pbLastDecrypted);
			pbLastDecrypted = NULL;
			ulLastDecryptedLen = 0;
		}
	}
#pragma endregion

#pragma region UnparsingAttributes
	//unparsing attributes:
	UnparseAttrs(pbDataToDecrypt,ulDataToDecryptLen,&sDecUnparseResult);
	if (CKR_OK != rvResult)	goto SH_DEC_DATA_FINALIZATION;
	sDecUnparseResult.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE) * sDecUnparseResult.ulNumOfParams);
	for (CK_ULONG i = 0; i<sDecUnparseResult.ulNumOfParams; i++)
	{
		sDecUnparseResult.psKeyParams[i].pValue = NULL;
		sDecUnparseResult.psKeyParams[i].ulValueLen = 0;
	}
	UnparseAttrs(pbDataToDecrypt,ulDataToDecryptLen,&sDecUnparseResult);
	if (CKR_OK != rvResult)	goto SH_DEC_DATA_FINALIZATION;
	for (CK_ULONG i = 0; i<sDecUnparseResult.ulNumOfParams; i++)
	{
		sDecUnparseResult.psKeyParams[i].pValue = (CK_BYTE_PTR) malloc (sizeof(CK_BYTE) * sDecUnparseResult.psKeyParams[i].ulValueLen);
	}
	UnparseAttrs(pbDataToDecrypt,ulDataToDecryptLen,&sDecUnparseResult);
	if (CKR_OK != rvResult)	goto SH_DEC_DATA_FINALIZATION;
#pragma endregion
#pragma region GetNeededAttributesFromUnparsedOnes
	sUnparsedKeyParams.ulNumOfParams = 3;	//id, class, type
	if (NULL == (sUnparsedKeyParams.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sUnparsedKeyParams.ulNumOfParams)))
	{
		rvResult = NOT_ENOUGH_MEMORY;
		goto SH_DEC_DATA_FINALIZATION;
	}
	for (CK_ULONG i = 0; i<sUnparsedKeyParams.ulNumOfParams; i++)
	{
		sUnparsedKeyParams.psKeyParams[i].pValue = NULL;
	}

	for (CK_ULONG i = 0; i<sDecUnparseResult.ulNumOfParams; i++)
	{
		switch (sDecUnparseResult.psKeyParams[i].type)
		{
		case CKA_ID:
			sUnparsedKeyParams.psKeyParams[0].type = CKA_ID;
			sUnparsedKeyParams.psKeyParams[0].pValue = sDecUnparseResult.psKeyParams[i].pValue;
			sUnparsedKeyParams.psKeyParams[0].ulValueLen = sDecUnparseResult.psKeyParams[i].ulValueLen;
			break;
		case CKA_KEY_TYPE:
			sUnparsedKeyParams.psKeyParams[1].type = CKA_KEY_TYPE;
			sUnparsedKeyParams.psKeyParams[1].pValue = sDecUnparseResult.psKeyParams[i].pValue;
			sUnparsedKeyParams.psKeyParams[1].ulValueLen = sDecUnparseResult.psKeyParams[i].ulValueLen;
			break;
		case CKA_CLASS:
			sUnparsedKeyParams.psKeyParams[2].type = CKA_CLASS;
			sUnparsedKeyParams.psKeyParams[2].pValue = sDecUnparseResult.psKeyParams[i].pValue;
			sUnparsedKeyParams.psKeyParams[2].ulValueLen = sDecUnparseResult.psKeyParams[i].ulValueLen;
			break;
		case CKA_ENCRYPTED_DATA:
			pbEncResult = (CK_BYTE_PTR)sDecUnparseResult.psKeyParams[i].pValue;
			ulEncResultLen = sDecUnparseResult.psKeyParams[i].ulValueLen;
			break;
		default:
			break;
		}
	}

	for (CK_ULONG i = 0; i<sUnparsedKeyParams.ulNumOfParams; i++)
	{
		if (!(sUnparsedKeyParams.psKeyParams[i].pValue))
		{
			rvResult = CKR_ATTRIBUTE_NOT_FOUND;
			goto SH_DEC_DATA_FINALIZATION;
		}
	}
#pragma endregion
#pragma region LookingForKey
	//Find Key to Decrypt on:
	if (sKeyToDecryptOn.ulNumOfParams)
	{
		for (CK_ULONG i = 0; i<sUnparsedKeyParams.ulNumOfParams; i++)
			sUnparsedKeyParams.psKeyParams[i].pValue = NULL;
		free (sUnparsedKeyParams.psKeyParams);
		sUnparsedKeyParams.ulNumOfParams = sKeyToDecryptOn.ulNumOfParams;
		if (NULL == (sUnparsedKeyParams.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sUnparsedKeyParams.ulNumOfParams)))
		{
			rvResult = NOT_ENOUGH_MEMORY;
			goto SH_DEC_DATA_FINALIZATION;
		}
		for (CK_ULONG i = 0; i<sUnparsedKeyParams.ulNumOfParams; i++)
		{
			sUnparsedKeyParams.psKeyParams[i].pValue = sKeyToDecryptOn.psKeyParams[i].pValue;
			sUnparsedKeyParams.psKeyParams[i].ulValueLen = sKeyToDecryptOn.psKeyParams[i].ulValueLen;
			sUnparsedKeyParams.psKeyParams[i].type = sKeyToDecryptOn.psKeyParams[i].type;
		}
	}

 	FindKeysByTemplate(sUnparsedKeyParams,NULL,&ulNumOfKeysFound);
	//if only one key is found:
	if ((ulNumOfKeysFound!=1)||(rvResult != CKR_OK))
	{
		if (rvResult==CKR_OK)
		{
			if (ulNumOfKeysFound)
				rvResult = CKR_TOO_MANY_KEYS_FOUND;
			else
				rvResult = CKR_KEYS_NOT_FOUND;
			goto SH_DEC_DATA_FINALIZATION;
		}
	}
 	FindKeysByTemplate(sUnparsedKeyParams,&hKeyToDecryptOn,&ulNumOfKeysFound);
	if (CKR_OK != rvResult)
		goto SH_DEC_DATA_FINALIZATION;

	//Get info about key:
	GetKeyInfo(hKeyToDecryptOn,&sKeyToDecryptOnInfo);
	if (CKR_ATTRIBUTE_TYPE_INVALID == rvResult)		//all ok, no bit parameter...
		rvResult = CKR_OK;
	if (CKR_OK != rvResult)
		goto SH_DEC_DATA_FINALIZATION;
#pragma endregion
#pragma region MakingMechanism
	//Copy or make mechanism
	if (NULL == pMechanism)
	{
		//if there is no mechanism then need to create it:
		switch(sKeyToDecryptOnInfo.ulKeyType)
		{
		case CKK_DES3:
			sMyMechanism.mechanism = CKM_DES3_CBC;
			break;
		case CKK_GOST28147:
			sMyMechanism.mechanism = CKM_GOST28147;
			sMyMechanism.pParameter = pbIV;
			sMyMechanism.ulParameterLen = _countof(pbIV);
			break;
		case CKK_RC2:
			CK_RC2_CBC_PARAMS sRC2Params;
			memset(&sRC2Params,0,sizeof(CK_RC2_CBC_PARAMS));
			memcpy(sRC2Params.iv,pbIV,8);
			sRC2Params.ulEffectiveBits = 0;
			sMyMechanism.mechanism = CKM_RC2_CBC;
			sMyMechanism.pParameter = &sRC2Params;
			sMyMechanism.ulParameterLen = sizeof(CK_RC2_CBC_PARAMS);
			break;
		case CKK_G28147:
			sMyMechanism.mechanism = CKM_G28147_ECB;
			break;
		default:
			rvResult = CKR_ATTRIBUTE_TYPE_INVALID;
			goto SH_DEC_DATA_FINALIZATION;
		}
	}
	else
	{
		sMyMechanism.mechanism = pMechanism->mechanism;
		sMyMechanism.ulParameterLen = pMechanism->ulParameterLen;
		sMyMechanism.pParameter = pMechanism->pParameter;
	}
#pragma endregion
#pragma region Decryption
	//Decrypt init:
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_DecryptInit(hSession,&sMyMechanism,hKeyToDecryptOn)))
	{
		goto SH_DEC_DATA_FINALIZATION;
	}
	//Decrypt
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_Decrypt(hSession,pbEncResult,ulEncResultLen,NULL,&ulLastDecryptedLen)))
	{
		goto SH_DEC_DATA_FINALIZATION;
	}
	if (pbLastDecrypted)
	{
		free(pbLastDecrypted);
		pbLastDecrypted = NULL;
	}
	if (NULL == (pbLastDecrypted = (CK_BYTE_PTR) malloc (ulLastDecryptedLen)))
	{
		rvResult = NOT_ENOUGH_MEMORY;
		goto SH_DEC_DATA_FINALIZATION;
	}
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_Decrypt(hSession,pbEncResult,ulEncResultLen,pbLastDecrypted,&ulLastDecryptedLen)))
	{
		goto SH_DEC_DATA_FINALIZATION;
	}
	*ulDecryptedDataLen = ulLastDecryptedLen;
	/*
	//Decrypt final
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_DecryptFinal(hSession,NULL,&ulNumOfKeysFound)))
	{
		return;
	}
	//*/
#pragma endregion
SH_DEC_DATA_FINALIZATION:
#pragma region Finalization
	if (sUnparsedKeyParams.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sUnparsedKeyParams.ulNumOfParams; i++)
			sUnparsedKeyParams.psKeyParams[i].pValue = NULL;
		free (sUnparsedKeyParams.psKeyParams);
	}
	pbEncResult = NULL;
	if (sDecUnparseResult.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sDecUnparseResult.ulNumOfParams; i++)
			if (sDecUnparseResult.psKeyParams[i].pValue) free (sDecUnparseResult.psKeyParams[i].pValue);
		free (sDecUnparseResult.psKeyParams);
	}
	sMyMechanism.pParameter = NULL;
#pragma endregion
};
//---------------------------------------------------------------------------
void ShEncSigClass::SignData(BYTE *pbDataToSign, CK_ULONG ulDataToSignLen, MY_KEY_TEMPLATE_INFO sKeyToSignOn, CK_MECHANISM_PTR pHashMechanism, 
								CK_MECHANISM_PTR pSignMechanism, BYTE *pbSignedData, CK_ULONG *ulSignedDataLen)
{
#pragma region ParametersInitialisation
	CK_ULONG ulNumOfKeysFound = 0;
	CK_OBJECT_HANDLE hKeyToSignOn = 0;
	MY_KEY_INFO sKeyToSignOnInfo;
	CK_MECHANISM sMyHashMechanism,sMySignMechanism;
	CK_BYTE_PTR pbHashResult = NULL, pbSignResult = NULL;
	CK_ULONG ulHashResultLen = 0, ulSignResultLen = 0;
	MY_KEY_TEMPLATE_INFO sSignResultToParse;

	CK_BYTE pbHashParams[] = {0x6, 0x7, 0x2a, 0x85, 0x03, 2, 2, 30, 1};

	rvResult = CKR_OK;
	memset (&sKeyToSignOnInfo,0,sizeof(MY_KEY_INFO));	
	memset (&sMyHashMechanism,0,sizeof(CK_MECHANISM));	
	memset (&sMySignMechanism,0,sizeof(CK_MECHANISM));	
	memset (&sSignResultToParse,0,sizeof(MY_KEY_TEMPLATE_INFO));	
	//Check if there is input:
	if (!((pbDataToSign)&&(ulDataToSignLen)))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
#pragma endregion
#pragma region CheckForSecondCall
	//Check if it is second call:
	if ((pbSignedData)&&(pbLastSigned)&&(ulLastSignedLen))
	{
		//it is the second call
		*ulSignedDataLen = ulLastSignedLen;
		memcpy(pbSignedData,pbLastSigned,ulLastSignedLen);
		if (pbLastSigned)
		{
			free (pbLastSigned);
			pbLastSigned = NULL;
			ulLastSignedLen = 0;
		}
	goto SH_SIGN_DATA_FINALIZATION;
	}
	else
	{
		//it is not second call, need to free global, if any:
		if (pbLastSigned)
		{
			free (pbLastSigned);
			pbLastSigned = NULL;
			ulLastSignedLen = 0;
		}
	}
#pragma endregion
#pragma region LookingForKey
	//Find Key to encrypt on:
 	FindKeysByTemplate(sKeyToSignOn,NULL,&ulNumOfKeysFound);
	//if only one key is found:
	if ((ulNumOfKeysFound!=1)||(rvResult != CKR_OK))
	{
		if (rvResult==CKR_OK)
		{
			if (ulNumOfKeysFound)
				rvResult = CKR_TOO_MANY_KEYS_FOUND;
			else
				rvResult = CKR_KEYS_NOT_FOUND;
			return;
		}
	}
 	FindKeysByTemplate(sKeyToSignOn,&hKeyToSignOn,&ulNumOfKeysFound);
	if (CKR_OK != rvResult)
		goto SH_SIGN_DATA_FINALIZATION;

	//Get info about key:
	GetKeyInfo(hKeyToSignOn,&sKeyToSignOnInfo);
	if (CKR_ATTRIBUTE_TYPE_INVALID == rvResult)		//all ok, no bit parameter...
		rvResult = CKR_OK;
	if (CKR_OK != rvResult)
		goto SH_SIGN_DATA_FINALIZATION;
	//Key should be private
	if (sKeyToSignOnInfo.ulKeyClass != CKO_PRIVATE_KEY)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		goto SH_SIGN_DATA_FINALIZATION;
	}
#pragma endregion
#pragma region MakingHashMechanism
	//Copy or make mechanism
	if (NULL == pHashMechanism)
	{
		//if there is no mechanism then need to create it:
		switch(sKeyToSignOnInfo.ulKeyType)
		{
		case CKK_RSA:
			sMyHashMechanism.mechanism = CKM_SHA_1;
			break;
		case CKK_GOSTR3410:
			sMyHashMechanism.mechanism = CKM_GOSTR3411;
			sMyHashMechanism.pParameter = pbHashParams;
			sMyHashMechanism.ulParameterLen = _countof(pbHashParams);
			break;
		case CKK_GR3410EL:
			sMyHashMechanism.mechanism = CKM_GR3411;
			break;
		default:
			rvResult = CKR_ATTRIBUTE_TYPE_INVALID;
			goto SH_SIGN_DATA_FINALIZATION;
		}
	}
	else
	{
		sMyHashMechanism.mechanism = pHashMechanism->mechanism;
		sMyHashMechanism.ulParameterLen = pHashMechanism->ulParameterLen;
		sMyHashMechanism.pParameter = pHashMechanism->pParameter;
	}
#pragma endregion
#pragma region Hashing
	//Digest init:
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_DigestInit(hSession,&sMyHashMechanism)))
	{
		goto SH_SIGN_DATA_FINALIZATION;
	}
	//Digest
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_Digest(hSession,pbDataToSign,ulDataToSignLen,NULL,&ulHashResultLen)))
	{
		goto SH_SIGN_DATA_FINALIZATION;
	}
	if (NULL == (pbHashResult = (CK_BYTE_PTR) malloc (ulHashResultLen)))
	{
		rvResult = NOT_ENOUGH_MEMORY;
		goto SH_SIGN_DATA_FINALIZATION;
	}
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_Digest(hSession,pbDataToSign,ulDataToSignLen,pbHashResult,&ulHashResultLen)))
	{
		goto SH_SIGN_DATA_FINALIZATION;
	}
	/*
	//Digest final
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_DigestFinal(hSession,NULL,&ulNumOfKeysFound)))
	{
		return;
	}
	//*/
#pragma endregion
#pragma region MakingSignMechanism
	//Copy or make mechanism
	if (NULL == pSignMechanism)
	{
		//if there is no mechanism then need to create it:
		switch(sKeyToSignOnInfo.ulKeyType)
		{
		case CKK_RSA:
			sMySignMechanism.mechanism = CKM_RSA_PKCS;
			break;
		case CKK_GOSTR3410:
			sMySignMechanism.mechanism = CKM_GOSTR3410;
			break;
		case CKK_GR3410EL:
			sMySignMechanism.mechanism = CKM_GR3410EL;
			break;
		default:
			rvResult = CKR_ATTRIBUTE_TYPE_INVALID;
			goto SH_SIGN_DATA_FINALIZATION;
		}
	}
	else
	{
		sMySignMechanism.mechanism = pSignMechanism->mechanism;
		sMySignMechanism.ulParameterLen = pSignMechanism->ulParameterLen;
		sMySignMechanism.pParameter = pSignMechanism->pParameter;
	}
#pragma endregion
#pragma region Signing
	//Sign init:
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_SignInit(hSession,&sMySignMechanism,hKeyToSignOn)))
	{
		goto SH_SIGN_DATA_FINALIZATION;
	}
	//Sign
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_Sign(hSession,pbHashResult,ulHashResultLen,NULL,&ulSignResultLen)))
	{
		goto SH_SIGN_DATA_FINALIZATION;
	}
	if (NULL == (pbSignResult = (CK_BYTE_PTR) malloc (ulSignResultLen)))
	{
		rvResult = NOT_ENOUGH_MEMORY;
		goto SH_SIGN_DATA_FINALIZATION;
	}
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_Sign(hSession,pbHashResult,ulHashResultLen,pbSignResult,&ulSignResultLen)))
	{
		goto SH_SIGN_DATA_FINALIZATION;
	}
	/*
	//Sign final
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_SignFinal(hSession,NULL,&ulNumOfKeysFound)))
	{
		return;
	}
	//*/
#pragma endregion
#pragma region ParsingSignedDataAndKeyInfo
	//parsing data
	if (pbLastSigned)
	{
		free (pbLastSigned);
		pbLastSigned = NULL;
		ulLastSignedLen = 0;
	}

	sSignResultToParse.ulNumOfParams = 4;	//id, class, type, signature
	if (NULL == (sSignResultToParse.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof (CK_ATTRIBUTE) * sSignResultToParse.ulNumOfParams)))
	{
		rvResult = NOT_ENOUGH_MEMORY;
		return;
	}
	sSignResultToParse.psKeyParams[0].type = CKA_ID;
	sSignResultToParse.psKeyParams[1].type = CKA_KEY_TYPE;
	sSignResultToParse.psKeyParams[2].type = CKA_CLASS;
	sSignResultToParse.psKeyParams[3].type = CKA_SIGNATURE;

	sSignResultToParse.psKeyParams[0].pValue = sKeyToSignOnInfo.pbKeyId;
	sSignResultToParse.psKeyParams[0].ulValueLen = sKeyToSignOnInfo.ulKeyIdLen;
	sSignResultToParse.psKeyParams[1].pValue = &(sKeyToSignOnInfo.ulKeyType);
	sSignResultToParse.psKeyParams[1].ulValueLen = sKeyToSignOnInfo.ulKeyTypeLen;
	sSignResultToParse.psKeyParams[2].pValue = &(sKeyToSignOnInfo.ulKeyClass);
	sSignResultToParse.psKeyParams[2].ulValueLen = sKeyToSignOnInfo.ulKeyClassLen;
	sSignResultToParse.psKeyParams[3].pValue = pbSignResult;
	sSignResultToParse.psKeyParams[3].ulValueLen = ulSignResultLen;

	ParseAttrs(sSignResultToParse,pbLastSigned,&ulLastSignedLen);
	if (CKR_OK != rvResult)
	{
		goto SH_SIGN_DATA_FINALIZATION;
	}
	if (NULL == (pbLastSigned = (CK_BYTE_PTR) malloc (ulLastSignedLen)))
	{
		rvResult = NOT_ENOUGH_MEMORY;
		goto SH_SIGN_DATA_FINALIZATION;
	}
	ParseAttrs(sSignResultToParse,pbLastSigned,&ulLastSignedLen);
	if (CKR_OK != rvResult)
	{
		goto SH_SIGN_DATA_FINALIZATION;
	}
#pragma endregion
#pragma region OutputResultIfNeeded
	*ulSignedDataLen = ulLastSignedLen;
	if (pbSignedData)
	{
		memcpy(pbSignedData,pbLastSigned,ulLastSignedLen);
	}
#pragma endregion
SH_SIGN_DATA_FINALIZATION:
#pragma region Finalization
	if (sSignResultToParse.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sSignResultToParse.ulNumOfParams; i++)
		{
			sSignResultToParse.psKeyParams[i].pValue = NULL;
		}
		free (sSignResultToParse.psKeyParams);
		sSignResultToParse.psKeyParams = NULL;
	}
	if (pbHashResult)
	{
		free (pbHashResult);
		pbHashResult = NULL;
	}
	if (pbSignResult)
	{
		free (pbSignResult);
		pbSignResult = NULL;
	}
	if (CKR_OK != rvResult)
	{
		if (pbLastSigned)
		{
			free (pbLastSigned);
			pbLastSigned = NULL;
			ulLastSignedLen = 0;
		}
	}
#pragma endregion
};
//---------------------------------------------------------------------------
void ShEncSigClass::VerifyData(BYTE *pbDataToVerify, CK_ULONG ulDataToVerifyLen, BYTE *pbSignature, CK_ULONG ulSignatureLen, MY_KEY_TEMPLATE_INFO sKeyToVerifyOn, 
							   CK_MECHANISM_PTR pHashMechanism, CK_MECHANISM_PTR pVerifyMechanism, CK_BBOOL *bVerifyResult)
{
#pragma region ParametersInitialisation
	CK_ULONG ulNumOfKeysFound = 0;
	CK_OBJECT_HANDLE hKeyToVerifyOn = 0;
	MY_KEY_INFO sKeyToVerifyOnInfo;
	CK_MECHANISM sMyHashMechanism,sMyVerifyMechanism;

	CK_BYTE_PTR pbHashResult = NULL, pbSignResult = NULL;
	CK_ULONG ulHashResultLen = 0, ulSignResultLen = 0;
	MY_KEY_TEMPLATE_INFO sVerifyUnparseResult;
	MY_KEY_TEMPLATE_INFO sUnparsedKeyParams;

	CK_BYTE pbHashParams[] = {0x6, 0x7, 0x2a, 0x85, 0x03, 2, 2, 30, 1};

	rvResult = CKR_OK;
	memset (&sMyHashMechanism,0,sizeof(CK_MECHANISM));	
	memset (&sMyVerifyMechanism,0,sizeof(CK_MECHANISM));	
	memset (&sVerifyUnparseResult,0,sizeof(MY_KEY_TEMPLATE_INFO));	
	memset (&sUnparsedKeyParams,0,sizeof(MY_KEY_TEMPLATE_INFO));	
	memset (&sKeyToVerifyOnInfo,0,sizeof(MY_KEY_INFO));	

	//Check if there is input:
	if (!((pbDataToVerify)&&(ulDataToVerifyLen)&&(pbSignature)&&(ulSignatureLen)))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
#pragma endregion
#pragma region UnparsingAttributes
	//unparsing attributes:
	UnparseAttrs(pbSignature,ulSignatureLen,&sVerifyUnparseResult);
	if (CKR_OK != rvResult)	goto SH_VERIFY_DATA_FINALIZATION;
	sVerifyUnparseResult.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE) * sVerifyUnparseResult.ulNumOfParams);
	for (CK_ULONG i = 0; i<sVerifyUnparseResult.ulNumOfParams; i++)
	{
		sVerifyUnparseResult.psKeyParams[i].pValue = NULL;
		sVerifyUnparseResult.psKeyParams[i].ulValueLen = 0;
	}
	UnparseAttrs(pbSignature,ulSignatureLen,&sVerifyUnparseResult);
	if (CKR_OK != rvResult)	goto SH_VERIFY_DATA_FINALIZATION;
	for (CK_ULONG i = 0; i<sVerifyUnparseResult.ulNumOfParams; i++)
	{
		sVerifyUnparseResult.psKeyParams[i].pValue = (CK_BYTE_PTR) malloc (sizeof(CK_BYTE) * sVerifyUnparseResult.psKeyParams[i].ulValueLen);
	}
	UnparseAttrs(pbSignature,ulSignatureLen,&sVerifyUnparseResult);
	if (CKR_OK != rvResult)	goto SH_VERIFY_DATA_FINALIZATION;
#pragma endregion
#pragma region GetNeededAttributesFromUnparsedOnes
	sUnparsedKeyParams.ulNumOfParams = 3;	//id, class, type
	if (NULL == (sUnparsedKeyParams.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sUnparsedKeyParams.ulNumOfParams)))
	{
		rvResult = NOT_ENOUGH_MEMORY;
		goto SH_VERIFY_DATA_FINALIZATION;
	}
	for (CK_ULONG i = 0; i<sUnparsedKeyParams.ulNumOfParams; i++)
	{
		sUnparsedKeyParams.psKeyParams[i].pValue = NULL;
	}

	for (CK_ULONG i = 0; i<sVerifyUnparseResult.ulNumOfParams; i++)
	{
		switch (sVerifyUnparseResult.psKeyParams[i].type)
		{
		case CKA_ID:
			sUnparsedKeyParams.psKeyParams[0].type = CKA_ID;
			sUnparsedKeyParams.psKeyParams[0].pValue = sVerifyUnparseResult.psKeyParams[i].pValue;
			sUnparsedKeyParams.psKeyParams[0].ulValueLen = sVerifyUnparseResult.psKeyParams[i].ulValueLen;
			break;
		case CKA_KEY_TYPE:
			sUnparsedKeyParams.psKeyParams[1].type = CKA_KEY_TYPE;
			sUnparsedKeyParams.psKeyParams[1].pValue = sVerifyUnparseResult.psKeyParams[i].pValue;
			sUnparsedKeyParams.psKeyParams[1].ulValueLen = sVerifyUnparseResult.psKeyParams[i].ulValueLen;
			break;
		case CKA_CLASS:
			sUnparsedKeyParams.psKeyParams[2].type = CKA_CLASS;
			sUnparsedKeyParams.psKeyParams[2].pValue = sVerifyUnparseResult.psKeyParams[i].pValue;
			sUnparsedKeyParams.psKeyParams[2].ulValueLen = sVerifyUnparseResult.psKeyParams[i].ulValueLen;
			break;
		case CKA_SIGNATURE:
			pbSignResult = (CK_BYTE_PTR)sVerifyUnparseResult.psKeyParams[i].pValue;
			ulSignResultLen = sVerifyUnparseResult.psKeyParams[i].ulValueLen;
			break;
		default:
			break;
		}
	}

	for (CK_ULONG i = 0; i<sUnparsedKeyParams.ulNumOfParams; i++)
	{
		if (!(sUnparsedKeyParams.psKeyParams[i].pValue))
		{
			rvResult = CKR_ATTRIBUTE_NOT_FOUND;
			goto SH_VERIFY_DATA_FINALIZATION;
		}
	}
#pragma endregion
#pragma region LookingForKey
	//Find Key to Verify on:
	if (sKeyToVerifyOn.ulNumOfParams)
	{
		for (CK_ULONG i = 0; i<sUnparsedKeyParams.ulNumOfParams; i++)
			sUnparsedKeyParams.psKeyParams[i].pValue = NULL;
		free (sUnparsedKeyParams.psKeyParams);
		sUnparsedKeyParams.ulNumOfParams = sKeyToVerifyOn.ulNumOfParams;
		if (NULL == (sUnparsedKeyParams.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sUnparsedKeyParams.ulNumOfParams)))
		{
			rvResult = NOT_ENOUGH_MEMORY;
			goto SH_VERIFY_DATA_FINALIZATION;
		}
		for (CK_ULONG i = 0; i<sUnparsedKeyParams.ulNumOfParams; i++)
		{
			sUnparsedKeyParams.psKeyParams[i].pValue = sKeyToVerifyOn.psKeyParams[i].pValue;
			sUnparsedKeyParams.psKeyParams[i].ulValueLen = sKeyToVerifyOn.psKeyParams[i].ulValueLen;
			sUnparsedKeyParams.psKeyParams[i].type = sKeyToVerifyOn.psKeyParams[i].type;
		}
	}

 	FindKeysByTemplate(sUnparsedKeyParams,NULL,&ulNumOfKeysFound);
	//if only one key is found:
	if ((ulNumOfKeysFound!=1)||(rvResult != CKR_OK))
	{
		if (rvResult==CKR_OK)
		{
			if (ulNumOfKeysFound)
				rvResult = CKR_TOO_MANY_KEYS_FOUND;
			else
				rvResult = CKR_KEYS_NOT_FOUND;
			goto SH_VERIFY_DATA_FINALIZATION;
		}
	}
 	FindKeysByTemplate(sUnparsedKeyParams,&hKeyToVerifyOn,&ulNumOfKeysFound);
	if (CKR_OK != rvResult)
		goto SH_VERIFY_DATA_FINALIZATION;

	//Get info about key:
	GetKeyInfo(hKeyToVerifyOn,&sKeyToVerifyOnInfo);
	if (CKR_ATTRIBUTE_TYPE_INVALID == rvResult)		//all ok, no bit parameter...
		rvResult = CKR_OK;
	if (CKR_OK != rvResult)
		goto SH_VERIFY_DATA_FINALIZATION;
#pragma endregion
#pragma region MakingHashMechanism
	//Copy or make mechanism
	if (NULL == pHashMechanism)
	{
		//if there is no mechanism then need to create it:
		switch(sKeyToVerifyOnInfo.ulKeyType)
		{
		case CKK_RSA:
			sMyHashMechanism.mechanism = CKM_SHA_1;
			break;
		case CKK_GOSTR3410:
			sMyHashMechanism.mechanism = CKM_GOSTR3411;
			sMyHashMechanism.pParameter = pbHashParams;
			sMyHashMechanism.ulParameterLen = _countof(pbHashParams);
			break;
		case CKK_GR3410EL:
			sMyHashMechanism.mechanism = CKM_GR3411;
			break;
		default:
			rvResult = CKR_ATTRIBUTE_TYPE_INVALID;
			goto SH_VERIFY_DATA_FINALIZATION;
		}
	}
	else
	{
		sMyHashMechanism.mechanism = pHashMechanism->mechanism;
		sMyHashMechanism.ulParameterLen = pHashMechanism->ulParameterLen;
		sMyHashMechanism.pParameter = pHashMechanism->pParameter;
	}
#pragma endregion
#pragma region Hashing
	//Verify init:
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_DigestInit(hSession,&sMyHashMechanism)))
	{
		goto SH_VERIFY_DATA_FINALIZATION;
	}
	//Verify
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_Digest(hSession,pbDataToVerify,ulDataToVerifyLen,NULL,&ulHashResultLen)))
	{
		goto SH_VERIFY_DATA_FINALIZATION;
	}
	if (NULL == (pbHashResult = (CK_BYTE_PTR) malloc (ulHashResultLen)))
	{
		rvResult = NOT_ENOUGH_MEMORY;
		goto SH_VERIFY_DATA_FINALIZATION;
	}
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_Digest(hSession,pbDataToVerify,ulDataToVerifyLen,pbHashResult,&ulHashResultLen)))
	{
		goto SH_VERIFY_DATA_FINALIZATION;
	}
	/*
	//Digest final
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_DigestFinal(hSession,NULL,&ulNumOfKeysFound)))
	{
		return;
	}
	//*/
#pragma endregion
#pragma region MakingVerifyMechanism
	//Copy or make mechanism
	if (NULL == pVerifyMechanism)
	{
		//if there is no mechanism then need to create it:
		switch(sKeyToVerifyOnInfo.ulKeyType)
		{
		case CKK_RSA:
			sMyVerifyMechanism.mechanism = CKM_RSA_PKCS;
			break;
		case CKK_GOSTR3410:
			sMyVerifyMechanism.mechanism = CKM_GOSTR3410;
			break;
		case CKK_GR3410EL:
			sMyVerifyMechanism.mechanism = CKM_GR3410EL;
			break;
		default:
			rvResult = CKR_ATTRIBUTE_TYPE_INVALID;
			goto SH_VERIFY_DATA_FINALIZATION;
		}
	}
	else
	{
		sMyVerifyMechanism.mechanism = pVerifyMechanism->mechanism;
		sMyVerifyMechanism.ulParameterLen = pVerifyMechanism->ulParameterLen;
		sMyVerifyMechanism.pParameter = pVerifyMechanism->pParameter;
	}
#pragma endregion
#pragma region Verifying
	//Verify init:
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_VerifyInit(hSession,&sMyVerifyMechanism,hKeyToVerifyOn)))
	{
		goto SH_VERIFY_DATA_FINALIZATION;
	}
	//Verify
	rvResult = Pkcs11FuncList->C_Verify(hSession,pbHashResult,ulHashResultLen,pbSignResult,ulSignResultLen);
	if ((CKR_OK != rvResult)&&(rvResult != CKR_SIGNATURE_INVALID)&&(rvResult != CKR_SIGNATURE_LEN_RANGE))	//worked ok
	{
		goto SH_VERIFY_DATA_FINALIZATION;
	}
	
	if (rvResult != CKR_OK)
	{
		*bVerifyResult = CK_FALSE;
		rvResult = CKR_OK;
	}
	else
	{
		*bVerifyResult = CK_TRUE;
	}
	/*
	//Verify final
	if (CKR_OK != (rvResult = Pkcs11FuncList->C_VerifyFinal(hSession,NULL,&ulNumOfKeysFound)))
	{
		return;
	}
	//*/
#pragma endregion
SH_VERIFY_DATA_FINALIZATION:
#pragma region Finalization
	if (pbHashResult)
	{
		free (pbHashResult);
		pbHashResult = NULL;
	}
	if (sUnparsedKeyParams.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sUnparsedKeyParams.ulNumOfParams; i++)
			sUnparsedKeyParams.psKeyParams[i].pValue = NULL;
		free (sUnparsedKeyParams.psKeyParams);
	}
	pbSignResult = NULL;
	if (sVerifyUnparseResult.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sVerifyUnparseResult.ulNumOfParams; i++)
			if (sVerifyUnparseResult.psKeyParams[i].pValue) free (sVerifyUnparseResult.psKeyParams[i].pValue);
		free (sVerifyUnparseResult.psKeyParams);
	}
	sMyVerifyMechanism.pParameter = NULL;
	sMyHashMechanism.pParameter = NULL;
#pragma endregion
};
//---------------------------------------------------------------------------
/*

//*/