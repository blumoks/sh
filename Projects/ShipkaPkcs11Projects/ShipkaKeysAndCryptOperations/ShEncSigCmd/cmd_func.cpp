#include "cmd_func.h"
using namespace std;
//================================================================================================
CmdFunctionsClassForEncSig::CmdFunctionsClassForEncSig()
{
	hShEncSigLib = NULL;
	hGetFuncList = NULL;
	blTrue = CK_TRUE;
	blFalse = CK_FALSE;
	pEsFuncList = NULL;
	ulClass_SecKey = CKO_SECRET_KEY; 
	ulClass_PubKey = CKO_PUBLIC_KEY; 
	ulClass_PriKey = CKO_PRIVATE_KEY;
	rvResult = CKR_OK;
	InitializeEncSigLib();
};
//------------------------------------------------------------------------------------------------
CmdFunctionsClassForEncSig::~CmdFunctionsClassForEncSig()
{
	FinalizeEncSigLib();
};
//================================================================================================
void CmdFunctionsClassForEncSig::InitializeEncSigLib()
{
	hShEncSigLib = NULL;
	hGetFuncList = NULL;

	if ((hShEncSigLib = LoadLibrary(SH_ENC_SIG_DLL)) == NULL)		//Failed to load library!
	{
		rvResult = GetLastError();
		return;
	}

	if (((FARPROC&)hGetFuncList = GetProcAddress(hShEncSigLib, "GetFunctionList"))==NULL)
	{	
		rvResult = GetLastError();
		return;
	}

	rvResult = hGetFuncList(&pEsFuncList);
	if (rvResult != CKR_OK) return;

	rvResult = pEsFuncList->Initialize(NULL);
	if (rvResult != CKR_OK) return;
};
//------------------------------------------------------------------------------------------------
void CmdFunctionsClassForEncSig::FinalizeEncSigLib()
{
	if (hShEncSigLib)
	{
		if (pEsFuncList)
		{
			rvResult = pEsFuncList->Finalize(NULL);
			if (rvResult != CKR_OK) return;
		}
		FreeLibrary(hShEncSigLib);
	}
};
//================================================================================================
void CmdFunctionsClassForEncSig::GetCmdFromCmdLine(int argc, char **argv)
{
#pragma region CheckForInput
	if (!argc)
	{
		cout<<"No input parameters"<<endl
			<<"Use -h parameter to get help"<<endl;
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
#pragma endregion
#pragma region EncryptData
	if (!strncmp(argv[0],ENCRYPT,strlen(ENCRYPT)))
	{
		return;
	}
#pragma endregion
#pragma region EncryptFile
	if (!strncmp(argv[0],ENCRYPT_FILE,strlen(ENCRYPT_FILE)))
	{
		char pcDeviceId[0x10];
		char pcUserPassword[0x20];
		MY_PIN_PARAMS sPinParams;
		char *pcSecKeyParams = "Class=SecretKey";
		char pcOneStringKeyParameters[0x100];
		char *psKeyParams [0x10];
		int iNumOfKeyParams = 0;

		memset(pcDeviceId,0,0x10);
		memset(pcUserPassword,0,0x20);
		memset(psKeyParams,0,(0x10)*sizeof(char *));
		memset(&sPinParams,0,sizeof(MY_PIN_PARAMS));
		memset(pcOneStringKeyParameters,0,0x100);

		if (argc != 3)
		{
			rvResult = CKR_ARGUMENTS_BAD;
			goto ENCRYPT_FILE_FINALIZATION;
		}
		cout<<"Looking for devices..."<<endl;
		GetDeviceList();
		if (rvResult == CKR_DEVICE_REMOVED)
		{
			cout<<"Terminating..."<<endl;
			rvResult = CKR_OK;
			goto ENCRYPT_FILE_FINALIZATION;
		}
		if (rvResult != CKR_OK)
			goto ENCRYPT_FILE_FINALIZATION;
		cout<<endl<<"Enter Device ID and its Password:"<<endl;
		cin>>pcDeviceId>>pcUserPassword;
		sPinParams.ulPinLength = strlen(pcUserPassword);
		memcpy(sPinParams.pcPinValue,pcUserPassword,sPinParams.ulPinLength+1);
		rvResult = pEsFuncList->MakeLoginedSession(pcDeviceId,sPinParams);
		if (rvResult != CKR_OK)
		{
			goto ENCRYPT_FILE_FINALIZATION;
		}
		cout<<endl<<"Looking for the secret keys on device..."<<endl;
		GetKeysList(1,&pcSecKeyParams);
		cout<<endl<<"Enter key to encrypt on parameters:"<<endl;
		scanf("%s",pcOneStringKeyParameters);
		psKeyParams[iNumOfKeyParams] = pcOneStringKeyParameters;
		iNumOfKeyParams++;
		for (int i = 0; i<(int)strlen(pcOneStringKeyParameters);i++)
		{
			if (pcOneStringKeyParameters[i] == ' ')
			{
				pcOneStringKeyParameters[i] = 0;
				psKeyParams[iNumOfKeyParams] = &pcOneStringKeyParameters[i+1];
				iNumOfKeyParams++;
			}
		}
		EncryptFile(argv[1],iNumOfKeyParams,psKeyParams,argv[2]);
	ENCRYPT_FILE_FINALIZATION:
		memset(pcDeviceId,0,0x10);
		memset(psKeyParams,0,(0x10)*sizeof(char *));
		memset(&sPinParams,0,sizeof(MY_PIN_PARAMS));
		memset(pcOneStringKeyParameters,0,0x100);
		PrintWorkResult(ENCRYPT_FILE);
		return;
	}
#pragma endregion
#pragma region DecryptData
	if (!strncmp(argv[0],DECRYPT,strlen(DECRYPT)))
	{
		return;
	}
#pragma endregion
#pragma region DecryptFile
	if (!strncmp(argv[0],DECRYPT_FILE,strlen(DECRYPT_FILE)))
	{
		char pcDeviceId[0x10];
		char pcUserPassword[0x20];
		MY_PIN_PARAMS sPinParams;
		char *pcSecKeyParams = "Class=SecretKey";
		char pcOneStringKeyParameters[0x100];
		char *psKeyParams [0x10];
		int iNumOfKeyParams = 0;

		memset(pcDeviceId,0,0x10);
		memset(pcUserPassword,0,0x20);
		memset(psKeyParams,0,(0x10)*sizeof(char *));
		memset(&sPinParams,0,sizeof(MY_PIN_PARAMS));
		memset(pcOneStringKeyParameters,0,0x100);

		if (argc != 3)
		{
			rvResult = CKR_ARGUMENTS_BAD;
			goto DECRYPT_FILE_FINALIZATION;
		}
		cout<<"Looking for devices..."<<endl;
		GetDeviceList();
		if (rvResult == CKR_DEVICE_REMOVED)
		{
			cout<<"Terminating..."<<endl;
			rvResult = CKR_OK;
			goto DECRYPT_FILE_FINALIZATION;
		}
		if (rvResult != CKR_OK)
			goto DECRYPT_FILE_FINALIZATION;
		cout<<endl<<"Enter Device ID and its Password:"<<endl;
		cin>>pcDeviceId>>pcUserPassword;
		sPinParams.ulPinLength = strlen(pcUserPassword);
		memcpy(sPinParams.pcPinValue,pcUserPassword,sPinParams.ulPinLength+1);
		rvResult = pEsFuncList->MakeLoginedSession(pcDeviceId,sPinParams);
		if (rvResult != CKR_OK)
		{
			goto DECRYPT_FILE_FINALIZATION;
		}
		cout<<endl<<"Looking for the secret keys on device..."<<endl;
		GetKeysList(1,&pcSecKeyParams);
		cout<<endl<<"Enter key to decrypt on parameters:"<<endl;
		scanf("%s",pcOneStringKeyParameters);
		if (!strcmp("Default",pcOneStringKeyParameters))
		{
			iNumOfKeyParams = 0;
			psKeyParams[0] = NULL;
		}
		else
		{
			psKeyParams[iNumOfKeyParams] = pcOneStringKeyParameters;
			iNumOfKeyParams++;
			for (int i = 0; i<(int)strlen(pcOneStringKeyParameters);i++)
			{
				if (pcOneStringKeyParameters[i] == ' ')
				{
					pcOneStringKeyParameters[i] = 0;
					psKeyParams[iNumOfKeyParams] = &pcOneStringKeyParameters[i+1];
					iNumOfKeyParams++;
				}
			}
		}
		DecryptFile(argv[1],iNumOfKeyParams,psKeyParams,argv[2]);
	DECRYPT_FILE_FINALIZATION:
		memset(pcDeviceId,0,0x10);
		memset(psKeyParams,0,(0x10)*sizeof(char *));
		memset(&sPinParams,0,sizeof(MY_PIN_PARAMS));
		memset(pcOneStringKeyParameters,0,0x100);
		PrintWorkResult(DECRYPT_FILE);
		return;
	}
#pragma endregion
#pragma region SignData
	if (!strncmp(argv[0],SIGN,strlen(SIGN)))
	{
		return;
	}
#pragma endregion
#pragma region SignFile
	if (!strncmp(argv[0],SIGN_FILE,strlen(SIGN_FILE)))
	{
		char pcDeviceId[0x10];
		char pcUserPassword[0x20];
		MY_PIN_PARAMS sPinParams;
		char *pcPriKeyParams = "Class=PrivateKey";
		char pcOneStringKeyParameters[0x100];
		char *psKeyParams [0x10];
		int iNumOfKeyParams = 0;

		memset(pcDeviceId,0,0x10);
		memset(pcUserPassword,0,0x20);
		memset(psKeyParams,0,(0x10)*sizeof(char *));
		memset(&sPinParams,0,sizeof(MY_PIN_PARAMS));
		memset(pcOneStringKeyParameters,0,0x100);

		if (argc != 3)
		{
			rvResult = CKR_ARGUMENTS_BAD;
			goto SIGN_FILE_FINALIZATION;
		}
		cout<<"Looking for devices..."<<endl;
		GetDeviceList();
		if (rvResult == CKR_DEVICE_REMOVED)
		{
			cout<<"Terminating..."<<endl;
			rvResult = CKR_OK;
			goto SIGN_FILE_FINALIZATION;
		}
		if (rvResult != CKR_OK)
			goto SIGN_FILE_FINALIZATION;
		cout<<endl<<"Enter Device ID and its Password:"<<endl;
		cin>>pcDeviceId>>pcUserPassword;
		sPinParams.ulPinLength = strlen(pcUserPassword);
		memcpy(sPinParams.pcPinValue,pcUserPassword,sPinParams.ulPinLength+1);
		rvResult = pEsFuncList->MakeLoginedSession(pcDeviceId,sPinParams);
		if (rvResult != CKR_OK)
		{
			goto SIGN_FILE_FINALIZATION;
		}
		cout<<endl<<"Looking for the private keys on device..."<<endl;
		GetKeysList(1,&pcPriKeyParams);
		cout<<endl<<"Enter key to sign on parameters:"<<endl;
		scanf("%s",pcOneStringKeyParameters);
		psKeyParams[iNumOfKeyParams] = pcOneStringKeyParameters;
		iNumOfKeyParams++;
		for (int i = 0; i<(int)strlen(pcOneStringKeyParameters);i++)
		{
			if (pcOneStringKeyParameters[i] == ' ')
			{
				pcOneStringKeyParameters[i] = 0;
				psKeyParams[iNumOfKeyParams] = &pcOneStringKeyParameters[i+1];
				iNumOfKeyParams++;
			}
		}
		SignFile(argv[1],iNumOfKeyParams,psKeyParams,argv[2]);
	SIGN_FILE_FINALIZATION:
		memset(pcDeviceId,0,0x10);
		memset(psKeyParams,0,(0x10)*sizeof(char *));
		memset(&sPinParams,0,sizeof(MY_PIN_PARAMS));
		memset(pcOneStringKeyParameters,0,0x100);
		PrintWorkResult(SIGN_FILE);
		return;
	}
#pragma endregion
#pragma region VerifyData
	if (!strncmp(argv[0],VERIFY,strlen(VERIFY)))
	{
		return;
	}
#pragma endregion
#pragma region VerifyFile
	if (!strncmp(argv[0],VERIFY_FILE,strlen(VERIFY_FILE)))
	{
		char pcDeviceId[0x10];
		char pcUserPassword[0x20];
		MY_PIN_PARAMS sPinParams;
		CK_BBOOL bVerifyResult = CK_FALSE;
		char *pcPubKeyParams = "Class=PublicKey";
		char pcOneStringKeyParameters[0x100];
		char *psKeyParams [0x10];
		int iNumOfKeyParams = 0;

		memset(pcDeviceId,0,0x10);
		memset(pcUserPassword,0,0x20);
		memset(psKeyParams,0,(0x10)*sizeof(char *));
		memset(&sPinParams,0,sizeof(MY_PIN_PARAMS));
		memset(pcOneStringKeyParameters,0,0x100);

		if (argc != 3)
		{
			rvResult = CKR_ARGUMENTS_BAD;
			goto VERIFY_FILE_FINALIZATION;
		}
		cout<<"Looking for devices..."<<endl;
		GetDeviceList();
		if (rvResult == CKR_DEVICE_REMOVED)
		{
			cout<<"Terminating..."<<endl;
			rvResult = CKR_OK;
			goto VERIFY_FILE_FINALIZATION;
		}
		if (rvResult != CKR_OK)
			goto VERIFY_FILE_FINALIZATION;
		cout<<endl<<"Enter Device ID and its Password:"<<endl;
		cin>>pcDeviceId>>pcUserPassword;
		sPinParams.ulPinLength = strlen(pcUserPassword);
		memcpy(sPinParams.pcPinValue,pcUserPassword,sPinParams.ulPinLength+1);
		rvResult = pEsFuncList->MakeLoginedSession(pcDeviceId,sPinParams);
		if (rvResult != CKR_OK)
		{
			goto VERIFY_FILE_FINALIZATION;
		}
		cout<<endl<<"Looking for the public keys on device..."<<endl;
		GetKeysList(1,&pcPubKeyParams);
		cout<<endl<<"Enter key to verify on parameters:"<<endl;
		scanf("%s",pcOneStringKeyParameters);
		if (!strcmp("Default",pcOneStringKeyParameters))
		{
			iNumOfKeyParams = 0;
			psKeyParams[0] = NULL;
		}
		else
		{
			psKeyParams[iNumOfKeyParams] = pcOneStringKeyParameters;
			iNumOfKeyParams++;
			for (int i = 0; i<(int)strlen(pcOneStringKeyParameters);i++)
			{
				if (pcOneStringKeyParameters[i] == ' ')
				{
					pcOneStringKeyParameters[i] = 0;
					psKeyParams[iNumOfKeyParams] = &pcOneStringKeyParameters[i+1];
					iNumOfKeyParams++;
				}
			}
		}
		VerifyFile(argv[1],argv[2],iNumOfKeyParams,psKeyParams,&bVerifyResult);
		if (rvResult != CKR_OK)
		{
			goto VERIFY_FILE_FINALIZATION;
		}
		if (bVerifyResult == CK_TRUE)
		{
			cout<<"Signature is correct"<<endl;
		}
		else
		{
			cout<<"Signature is not correct"<<endl;
		}
	VERIFY_FILE_FINALIZATION:
		memset(pcDeviceId,0,0x10);
		memset(psKeyParams,0,(0x10)*sizeof(char *));
		memset(&sPinParams,0,sizeof(MY_PIN_PARAMS));
		memset(pcOneStringKeyParameters,0,0x100);
		PrintWorkResult(VERIFY_FILE);
		return;
	}
#pragma endregion
#pragma region GetDeviceInfo
	if (!strncmp(argv[0],GET_DEVICE_INFO,strlen(GET_DEVICE_INFO)))
	{
		bool bExInfo = false;
		if (argc == 2)
		{
			bExInfo = false;
		}
		else if (argc == 3)
		{
			if (!strncmp(argv[2],READABLE_INFO,strlen(READABLE_INFO)))
			{
				bExInfo = true;
			}
			else
			{
				rvResult = CKR_WRONG_INPUT;
			}
		}
		else
		{
			rvResult = CKR_WRONG_INPUT;
		}
		if (CKR_OK == rvResult)
		{
			GetDeviceInfo(argv[1],bExInfo);
		}
		PrintWorkResult(GET_DEVICE_INFO);
		return;
	}
#pragma endregion
#pragma region GetDeviceList
	if (!strncmp(argv[0],GET_DEVICE_LIST,strlen(GET_DEVICE_LIST)))
	{
		if (argc>1)
		{
			rvResult = CKR_WRONG_INPUT;
		}
		else
		{
			GetDeviceList();
			if (rvResult == CKR_DEVICE_REMOVED)
				rvResult = CKR_OK;
		}
		PrintWorkResult(GET_DEVICE_LIST);
		return;
	}
#pragma endregion
#pragma region GetKeysInfoList
	if (!strncmp(argv[0],GET_KEYS_LIST,strlen(GET_KEYS_LIST)))
	{
		if (argc<3)
		{
			rvResult = CKR_WRONG_INPUT;
		}
		else
		{
			MY_PIN_PARAMS sPinParams;
			memcpy(sPinParams.pcPinValue,argv[2],strlen(argv[2])+1);
			sPinParams.ulPinLength = strlen(argv[2]);
			rvResult = pEsFuncList->MakeLoginedSession(argv[1],sPinParams);
			if (rvResult == CKR_OK)
				GetKeysList(argc - 3, argv + 3);
		}
		PrintWorkResult(GET_KEYS_LIST);
		return;
	}
#pragma endregion
#pragma region ChangeLanguage
	if (!strncmp(argv[0],CHANGE_LANGUAGE,strlen(CHANGE_LANGUAGE)))
	{
		return;
	}
#pragma endregion
#pragma region UseHelp
	if (!strncmp(argv[0],USE_HELP,strlen(USE_HELP)))
	{
		return;
	}
#pragma endregion
};
//================================================================================================
void CmdFunctionsClassForEncSig::MakeKeyParamsFromCmd(int argc, char **argv, MY_KEY_TEMPLATE_INFO_PTR pKeyInfo)
{
	char *pcAttrValue = NULL;
	char *pcCkaIdValue = NULL;
	if (!pKeyInfo)
	{
		rvResult = CKR_WRONG_INPUT;
		return;
	}
	if ((!argv)||(!argc))
	{
		pKeyInfo->psKeyParams = NULL;
		pKeyInfo->ulNumOfParams = 0;
		return;
	}
	if ((pKeyInfo->ulNumOfParams != argc)||(!(pKeyInfo->psKeyParams)))
	{
		rvResult = CKR_BUFFER_TOO_SMALL;
		return;
	}

	for (int i = 0; i<argc; i++)
	{
		pKeyInfo->psKeyParams[i].type = 0;
		pcAttrValue = NULL;
		for (int j = 0; j<DEF_KEY_ATTRS_NUM; j++)
		{
			if (!strncmp(DEF_KEY_ATTRS[j],argv[i],strlen(DEF_KEY_ATTRS[j])))
			{
				if (strlen(argv[i]) > strlen(DEF_KEY_ATTRS[j]))
				{
					pKeyInfo->psKeyParams[i].type = DEF_ATTR_VALUES[j];
					pcAttrValue = argv[i] + strlen(DEF_KEY_ATTRS[j]);
				}
			}
		}
		if (!pcAttrValue)
		{
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
		switch (pKeyInfo->psKeyParams[i].type)
		{
		case CKA_KEY_TYPE:
			for (int j = 0; j<DEF_NUM_OF_ALGS; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_ALG_TYPES_NAMES[j],strlen(DEF_ALG_TYPES_NAMES[j])))
				{
					pKeyInfo->psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_ALG_TYPES[j];
				}
			}
			pKeyInfo->psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_CLASS:
			for (int j = 0; j<DEF_NUM_OF_CLASSES; j++) 
			{
				if (!strncmp(pcAttrValue,DEF_CLASS_NAME[j],strlen(DEF_CLASS_NAME[j])))
				{
					pKeyInfo->psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_CLASS_VALUE[j];
				}
			}
			pKeyInfo->psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
			break;
		case CKA_ID:
			if (pcCkaIdValue)
			{
				rvResult = CKR_ARGUMENTS_BAD;
				return;
			}
			pKeyInfo->psKeyParams[i].ulValueLen = strlen(pcAttrValue)/2;
			pcCkaIdValue = (char *) malloc (sizeof (CK_BYTE) * pKeyInfo->psKeyParams[i].ulValueLen);
			for (CK_ULONG j = 0; j<pKeyInfo->psKeyParams[i].ulValueLen; j++)
			{
				if ((pcAttrValue[2*j]<='9')&&(pcAttrValue[2*j]>='0'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - '0')*16;
				else if ((pcAttrValue[2*j]<='F')&&(pcAttrValue[2*j]>='A'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - 'A' + 10)*16;
				else if ((pcAttrValue[2*j]<='f')&&(pcAttrValue[2*j]>='a'))
					pcCkaIdValue[j] = (pcAttrValue[2*j] - 'a' + 10)*16;

				if ((pcAttrValue[2*j+1]<='9')&&(pcAttrValue[2*j+1]>='0'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - '0');
				else if ((pcAttrValue[2*j+1]<='F')&&(pcAttrValue[2*j+1]>='A'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - 'A' + 10);
				else if ((pcAttrValue[2*j+1]<='f')&&(pcAttrValue[2*j+1]>='a'))
					pcCkaIdValue[j] += (pcAttrValue[2*j+1] - 'a' + 10);
			}
			pKeyInfo->psKeyParams[i].pValue = pcCkaIdValue;
			break;
		case CKA_EXTRACTABLE:
			if (!strncmp(pcAttrValue,TRUE_ATTR,strlen(TRUE_ATTR)))
				pKeyInfo->psKeyParams[i].pValue = &blTrue;
			else if (!strncmp(pcAttrValue,FALSE_ATTR,strlen(FALSE_ATTR)))
				pKeyInfo->psKeyParams[i].pValue = &blFalse;
			break;
		case CKA_LABEL:
			pKeyInfo->psKeyParams[i].pValue = pcAttrValue;
			pKeyInfo->psKeyParams[i].ulValueLen = strlen(pcAttrValue);
			break;
		default:
			rvResult = CKR_ARGUMENTS_BAD;
			return;
		}
	}
};
//------------------------------------------------------------------------------------------------
void CmdFunctionsClassForEncSig::GetDeviceList()
{
	CK_SLOT_ID_PTR pDeviceList = NULL;
	CK_ULONG ulDeviceNumber = 0;
	pEsFuncList->GetDeviceList(pDeviceList, &ulDeviceNumber);
	if (rvResult==CKR_OK)
	{
		if (ulDeviceNumber==0)
		{
			cout<<"No devices are connected"<<endl;
			rvResult = CKR_DEVICE_REMOVED;
		}
		else
		{
			pDeviceList = (CK_SLOT_ID_PTR)malloc(ulDeviceNumber*sizeof(CK_SLOT_ID));
			pEsFuncList->GetDeviceList(pDeviceList, &ulDeviceNumber);
			if (rvResult==CKR_OK)
			{
				for (CK_ULONG i = 0; i<ulDeviceNumber; i++)
				{
					PrintDeviceInfo(pDeviceList[i]);
					if (rvResult!=CKR_OK)
					{
						i = ulDeviceNumber;
					}
				}
			}
			free(pDeviceList);
		}
	}
};
//------------------------------------------------------------------------------------------------
void CmdFunctionsClassForEncSig::GetDeviceInfo(char *DeviceId, bool bGetExInfo)
{	
	CK_SLOT_ID ulSlotID;
	if (pEsFuncList->DeviceIsConnected(DeviceId,&ulSlotID)==0)
	{
		if (bGetExInfo==false)
		{
			PrintDeviceInfo(ulSlotID);
		}
		else
		{
			PrintDeviceInfoEx(ulSlotID);
		}
	}
	else
	{
		if (rvResult==CKR_OK) rvResult = CKR_DEVICE_REMOVED;
	}
};
//------------------------------------------------------------------------------------------------
void CmdFunctionsClassForEncSig::GetKeysList(int iNumOfKeyParams, char **psKeyParams)
{
	CK_ULONG ulType = 0;
	MY_KEY_TEMPLATE_INFO sMyTemplate;
	CK_ULONG ulKeyNumber = 0;
	char *pcAttrValue = NULL;
	char pcTempId[16];
	char pcTempType[24];
	char pcTempClass[16];
	char pcTempKeyLen[12];
	char pcTempExp[12];
	char *temp = NULL;

	int iKeyLen = 0;
	MY_KEY_INFO_PTR psMyKeyList = NULL;

#pragma region GetAttributesFromStrings
	if ((psKeyParams == NULL)&&(!iNumOfKeyParams))
	{
		sMyTemplate.ulNumOfParams = 0;
		sMyTemplate.psKeyParams = NULL;
	}
	else
	{
		sMyTemplate.ulNumOfParams = iNumOfKeyParams;
		sMyTemplate.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sizeof(CK_ATTRIBUTE)*sMyTemplate.ulNumOfParams);
		for (int i = 0; i<iNumOfKeyParams; i++)
		{
			if (psKeyParams[i] == NULL)
			{
				rvResult = CKR_ARGUMENTS_BAD;
				return;
			}
			ulType = -1;
			sMyTemplate.psKeyParams[i].pValue = NULL;
			sMyTemplate.psKeyParams[i].type = -1;
			sMyTemplate.psKeyParams[i].ulValueLen = 0;
			for (int j = 0; j<DEF_KEY_ATTRS_NUM; j++)
			{
				if (!strncmp(psKeyParams[i],DEF_KEY_ATTRS[j],strlen(DEF_KEY_ATTRS[j])))
					if (strlen(psKeyParams[i]) > strlen(DEF_KEY_ATTRS[j]))
					{
						ulType = DEF_ATTR_VALUES[j];
						sMyTemplate.psKeyParams[i].type = ulType;
						pcAttrValue = psKeyParams[i] + strlen(DEF_KEY_ATTRS[j]);
					}
					else
					{
						if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
						rvResult = CKR_ARGUMENTS_BAD;
						return;
					}
			}
			switch (ulType)
			{
			case CKA_CLASS:
				for (int j = 0; j<DEF_NUM_OF_CLASSES; j++) 
				{
					if (!strncmp(pcAttrValue,DEF_CLASS_NAME[j],strlen(DEF_CLASS_NAME[j])))
					{
						sMyTemplate.psKeyParams[i].pValue = (CK_VOID_PTR)&DEF_CLASS_VALUE[j];
					}
				}
				sMyTemplate.psKeyParams[i].ulValueLen = sizeof(CK_ULONG);
				break;
			case CKA_EXTRACTABLE:
				if (!strncmp(pcAttrValue,TRUE_ATTR,strlen(TRUE_ATTR)))
					sMyTemplate.psKeyParams[i].pValue = &blTrue;
				else if (!strncmp(pcAttrValue,FALSE_ATTR,strlen(FALSE_ATTR)))
					sMyTemplate.psKeyParams[i].pValue = &blFalse;
				break;
			case CKA_LABEL:
				sMyTemplate.psKeyParams[i].pValue = pcAttrValue;
				sMyTemplate.psKeyParams[i].ulValueLen = strlen(pcAttrValue);
				break;
			default:
				if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
				rvResult = CKR_ARGUMENTS_BAD;
				return;
			}
			if ((sMyTemplate.psKeyParams[i].pValue == NULL)&&(sMyTemplate.psKeyParams[i].type == -1)&&(sMyTemplate.psKeyParams[i].ulValueLen == 0))
			{
				if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
				rvResult = CKR_ARGUMENTS_BAD;
				return;
			}
		}
	}
#pragma endregion

	rvResult = pEsFuncList->GetKeysInfoList(sMyTemplate,psMyKeyList,&ulKeyNumber);
	if (CKR_OK != rvResult)
	{
		if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
		return;
	}
	psMyKeyList = (MY_KEY_INFO_PTR) malloc (sizeof(MY_KEY_INFO) * (ulKeyNumber));
	rvResult = pEsFuncList->GetKeysInfoList(sMyTemplate,psMyKeyList,&ulKeyNumber);
	if (sMyTemplate.psKeyParams) free (sMyTemplate.psKeyParams);
	if (CKR_OK != rvResult)
	{
		if (psMyKeyList) free (psMyKeyList);
		return;
	}

	for (CK_ULONG i = 0; i < ulKeyNumber; i++)
	{
		memset (pcTempId,0,16);
		memset (pcTempType,0,24);
		memset (pcTempClass,0,16);
		memset (pcTempKeyLen,0,12);
		memset (pcTempExp,0,12);
#pragma region MakingId
		if (psMyKeyList[i].ulKeyIdLen != -1)
		{
			temp = pcTempId;
			for (CK_ULONG j = 0; j<psMyKeyList[i].ulKeyIdLen; j++)
			{
				sprintf (temp,"%2.2x",psMyKeyList[i].pbKeyId[j]);
				temp = pcTempId + strlen(pcTempId);
			}
		}
		else
		{
			sprintf (pcTempId,"unknown");
		}
#pragma endregion
#pragma region MakingType
		if (psMyKeyList[i].ulKeyTypeLen != -1)
		{
			switch (psMyKeyList[i].ulKeyType)
			{
			case CKK_RC2:
				sprintf (pcTempType,"RC2");
				break;
			case CKK_DES3:
				sprintf (pcTempType,"DES3");
				break;
			case CKK_DES:
				sprintf (pcTempType,"DES");
				break;
			case CKK_G28147:
				sprintf (pcTempType,"SH_GOST 28147");
				sprintf(pcTempKeyLen,"256");
				break;
			case CKK_GR3410EL:
				sprintf (pcTempType,"SH_GOST 3410");
				sprintf(pcTempKeyLen,"512");
				break;
			case CKK_GOST28147:
				sprintf (pcTempType,"GOST 28147-89");
				sprintf(pcTempKeyLen,"256");
				break;
			case CKK_GOSTR3410:
				sprintf (pcTempType,"GOST R 3410-2001");
				sprintf(pcTempKeyLen,"512");
				break;
			case CKK_RSA:
				sprintf (pcTempType,"RSA");
				break;
			default:
				sprintf (pcTempType, "unknown: 0x%x",psMyKeyList[i].ulKeyType);
				break;
			}
		}
		else
		{
			sprintf (pcTempType, "no value getted");
		}
#pragma endregion
#pragma region MakingClass
		if (psMyKeyList[i].ulKeyClassLen != -1)
		{
			switch (psMyKeyList[i].ulKeyClass)
			{
			case CKO_SECRET_KEY:
				sprintf (pcTempClass,"secret");
				break;
			case CKO_PRIVATE_KEY:
				sprintf (pcTempClass,"private");
				break;
			case CKO_PUBLIC_KEY:
				sprintf (pcTempClass,"public");
				break;
			default:
				sprintf (pcTempClass, "unknown",psMyKeyList[i].ulKeyClass);
				break;
			}
		}
		else
		{
			sprintf (pcTempClass, "unknown");
		}
#pragma endregion
#pragma region MakingLen
		if (psMyKeyList[i].ulKeyLenLen != -1)
		{
			if (psMyKeyList[i].ulKeyLen<128)
				psMyKeyList[i].ulKeyLen = psMyKeyList[i].ulKeyLen * 8;
			sprintf(pcTempKeyLen,"%d",psMyKeyList[i].ulKeyLen);
		}
		else if (pcTempKeyLen[0] == 0)
		{
			sprintf(pcTempKeyLen,"----");
		}
#pragma endregion
#pragma region MakingExt
		if (psMyKeyList[i].ulExportableLen != -1)
		{
			if (((psMyKeyList[i].bExportable)&(0x0F)) == CK_TRUE)
				sprintf(pcTempExp,"true");
			else sprintf(pcTempExp,"false");
		}
		else
		{
			sprintf(pcTempExp,"unknown");
		}
#pragma endregion
		if (psMyKeyList[i].ulLabelLen == -1)
		{
			psMyKeyList[i].pbLabel[0] = '\0';
		}
		printf("ID: %10.10s; Type: %16.16s; Class: %8.8s; Len: %8.8s; Ext: %8.8s; Label: %s\n",
			pcTempId,pcTempType,pcTempClass,pcTempKeyLen,pcTempExp,psMyKeyList[i].pbLabel);	
	}
};
//================================================================================================
void CmdFunctionsClassForEncSig::EncryptFile(char *pcFileToEncrypt,int iNumOfKeyParams, char **psKeyParams, char *pcFileToEncryptTo)
{
	CK_BYTE_PTR pbDataToEncrypt = NULL, pbEncryptionResult = NULL;
	CK_ULONG ulDataToEncryptLen = 0, ulEncryptionResult = 0;
	MY_KEY_TEMPLATE_INFO sUserKeyInfo;

	memset(&sUserKeyInfo,0,sizeof(MY_KEY_TEMPLATE_INFO));
	ReadDataFromFile(pcFileToEncrypt,NULL,&ulDataToEncryptLen);
	if ((ulDataToEncryptLen)&&(rvResult == CKR_OK))
	{
		if (NULL == (pbDataToEncrypt = (CK_BYTE_PTR)malloc(ulDataToEncryptLen)))
		{
			rvResult = MEMORY_NOT_ALLOCATED;
			return;
		}
	}
	else
	{
		if (CKR_OK == rvResult)
		{
			rvResult = CKR_FILE_ERROR;
		}
		return;
	}
	ReadDataFromFile(pcFileToEncrypt,pbDataToEncrypt,&ulDataToEncryptLen);
	if (CKR_OK != rvResult)
	{
		goto ENCRYPT_FILE_REALISE_FINALIZATION;
	}
	if ((!iNumOfKeyParams)||(!psKeyParams))
	{
		rvResult = CKR_WRONG_INPUT;
		goto ENCRYPT_FILE_REALISE_FINALIZATION;
	}
	sUserKeyInfo.ulNumOfParams = iNumOfKeyParams;
	sUserKeyInfo.psKeyParams = (CK_ATTRIBUTE_PTR) malloc ((sUserKeyInfo.ulNumOfParams + 1) * sizeof(CK_ATTRIBUTE));
	MakeKeyParamsFromCmd(iNumOfKeyParams,psKeyParams,&sUserKeyInfo);
	if (rvResult != CKR_OK)
	{
		goto ENCRYPT_FILE_REALISE_FINALIZATION;
	}
	sUserKeyInfo.psKeyParams[sUserKeyInfo.ulNumOfParams].type = CKA_CLASS;
	sUserKeyInfo.psKeyParams[sUserKeyInfo.ulNumOfParams].ulValueLen = sizeof(CK_ULONG);
	sUserKeyInfo.psKeyParams[sUserKeyInfo.ulNumOfParams].pValue = &ulClass_SecKey;
	sUserKeyInfo.ulNumOfParams++;

	rvResult = pEsFuncList->EncryptData(pbDataToEncrypt,ulDataToEncryptLen,sUserKeyInfo,NULL,NULL,&ulEncryptionResult);
	if ((ulEncryptionResult)&&(rvResult == CKR_OK))
	{
		if (NULL == (pbEncryptionResult = (CK_BYTE_PTR)malloc(ulEncryptionResult)))
		{
			rvResult = MEMORY_NOT_ALLOCATED;
			goto ENCRYPT_FILE_REALISE_FINALIZATION;
		}
	}
	else
	{
		if (CKR_OK == rvResult)
		{
			rvResult = CKR_DATA_LEN_RANGE;
		}
		goto ENCRYPT_FILE_REALISE_FINALIZATION;
	}
	rvResult = pEsFuncList->EncryptData(pbDataToEncrypt,ulDataToEncryptLen,sUserKeyInfo,NULL,pbEncryptionResult,&ulEncryptionResult);
	if (CKR_OK != rvResult)
	{
		goto ENCRYPT_FILE_REALISE_FINALIZATION;
	}
	WriteDataToFile(pcFileToEncryptTo,pbEncryptionResult,ulEncryptionResult);
ENCRYPT_FILE_REALISE_FINALIZATION:
	if (pbEncryptionResult) free(pbEncryptionResult);
	if (pbDataToEncrypt) free(pbDataToEncrypt);
	if (sUserKeyInfo.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sUserKeyInfo.ulNumOfParams; i++)
		{
			sUserKeyInfo.psKeyParams[i].pValue = NULL;
		}
		free(sUserKeyInfo.psKeyParams);
	}
};
//------------------------------------------------------------------------------------------------
void CmdFunctionsClassForEncSig::DecryptFile(char *pcFileToDecrypt,int iNumOfKeyParams, char **psKeyParams, char *pcFileToDecryptTo)
{
	CK_BYTE_PTR pbDataToDecrypt = NULL, pbDecryptionResult = NULL;
	CK_ULONG ulDataToDecryptLen = 0, ulDecryptionResult = 0;
	MY_KEY_TEMPLATE_INFO sUserKeyInfo;

	memset(&sUserKeyInfo,0,sizeof(MY_KEY_TEMPLATE_INFO));
	ReadDataFromFile(pcFileToDecrypt,NULL,&ulDataToDecryptLen);
	if ((ulDataToDecryptLen)&&(rvResult == CKR_OK))
	{
		if (NULL == (pbDataToDecrypt = (CK_BYTE_PTR)malloc(ulDataToDecryptLen)))
		{
			rvResult = MEMORY_NOT_ALLOCATED;
			return;
		}
	}
	else
	{
		if (CKR_OK == rvResult)
		{
			rvResult = CKR_FILE_ERROR;
		}
		return;
	}
	ReadDataFromFile(pcFileToDecrypt,pbDataToDecrypt,&ulDataToDecryptLen);
	if (CKR_OK != rvResult)
	{
		goto DECRYPT_FILE_REALISE_FINALIZATION;
	}
	if ((!iNumOfKeyParams)||(!psKeyParams))
	{
		sUserKeyInfo.ulNumOfParams = 0;
		sUserKeyInfo.psKeyParams = 0;
	}
	else
	{
		sUserKeyInfo.ulNumOfParams = iNumOfKeyParams;
		sUserKeyInfo.psKeyParams = (CK_ATTRIBUTE_PTR) malloc (sUserKeyInfo.ulNumOfParams * sizeof(CK_ATTRIBUTE));
		MakeKeyParamsFromCmd(iNumOfKeyParams,psKeyParams,&sUserKeyInfo);
		if (rvResult != CKR_OK)
		{
			goto DECRYPT_FILE_REALISE_FINALIZATION;
		}
	}
	rvResult = pEsFuncList->DecryptData(pbDataToDecrypt,ulDataToDecryptLen,sUserKeyInfo,NULL,NULL,&ulDecryptionResult);
	if ((ulDecryptionResult)&&(rvResult == CKR_OK))
	{
		if (NULL == (pbDecryptionResult = (CK_BYTE_PTR)malloc(ulDecryptionResult)))
		{
			rvResult = MEMORY_NOT_ALLOCATED;
			goto DECRYPT_FILE_REALISE_FINALIZATION;
		}
	}
	else
	{
		if (CKR_OK == rvResult)
		{
			rvResult = CKR_DATA_LEN_RANGE;
		}
		goto DECRYPT_FILE_REALISE_FINALIZATION;
	}
	rvResult = pEsFuncList->DecryptData(pbDataToDecrypt,ulDataToDecryptLen,sUserKeyInfo,NULL,pbDecryptionResult,&ulDecryptionResult);
	if (CKR_OK != rvResult)
	{
		goto DECRYPT_FILE_REALISE_FINALIZATION;
	}
	WriteDataToFile(pcFileToDecryptTo,pbDecryptionResult,ulDecryptionResult);
DECRYPT_FILE_REALISE_FINALIZATION:
	if (pbDecryptionResult) free(pbDecryptionResult);
	if (pbDataToDecrypt) free(pbDataToDecrypt);
	if (sUserKeyInfo.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sUserKeyInfo.ulNumOfParams; i++)
		{
			sUserKeyInfo.psKeyParams[i].pValue = NULL;
		}
		free(sUserKeyInfo.psKeyParams);
	}
};
//------------------------------------------------------------------------------------------------
void CmdFunctionsClassForEncSig::SignFile(char *pcFileToSign,int iNumOfParams, char **psParams, char *pcFileToPutSignTo)
{
	CK_BYTE_PTR pbDataToSign = NULL, pbSignature = NULL;
	CK_ULONG ulDataToSignLen = 0, ulSignatureLen = 0;
	MY_KEY_TEMPLATE_INFO sUserKeyInfo;

	memset(&sUserKeyInfo,0,sizeof(MY_KEY_TEMPLATE_INFO));
	ReadDataFromFile(pcFileToSign,NULL,&ulDataToSignLen);
	if ((ulDataToSignLen)&&(rvResult == CKR_OK))
	{
		if (NULL == (pbDataToSign = (CK_BYTE_PTR)malloc(ulDataToSignLen)))
		{
			rvResult = MEMORY_NOT_ALLOCATED;
			return;
		}
	}
	else
	{
		if (CKR_OK == rvResult)
		{
			rvResult = CKR_FILE_ERROR;
		}
		return;
	}
	ReadDataFromFile(pcFileToSign,pbDataToSign,&ulDataToSignLen);
	if (CKR_OK != rvResult)
	{
		goto SIGN_FILE_REALISE_FINALIZATION;
	}
	if ((!iNumOfParams)||(!psParams))
	{
		rvResult = CKR_WRONG_INPUT;
		goto SIGN_FILE_REALISE_FINALIZATION;
	}
	sUserKeyInfo.ulNumOfParams = iNumOfParams;
	sUserKeyInfo.psKeyParams = (CK_ATTRIBUTE_PTR) malloc ((sUserKeyInfo.ulNumOfParams + 1) * sizeof(CK_ATTRIBUTE));
	MakeKeyParamsFromCmd(iNumOfParams,psParams,&sUserKeyInfo);
	if (rvResult != CKR_OK)
	{
		goto SIGN_FILE_REALISE_FINALIZATION;
	}
	sUserKeyInfo.psKeyParams[sUserKeyInfo.ulNumOfParams].type = CKA_CLASS;
	sUserKeyInfo.psKeyParams[sUserKeyInfo.ulNumOfParams].ulValueLen = sizeof(CK_ULONG);
	sUserKeyInfo.psKeyParams[sUserKeyInfo.ulNumOfParams].pValue = &ulClass_PriKey;
	sUserKeyInfo.ulNumOfParams++;

	rvResult = pEsFuncList->SignData(pbDataToSign,ulDataToSignLen,sUserKeyInfo,NULL,NULL,NULL,&ulSignatureLen);
	if ((ulSignatureLen)&&(rvResult == CKR_OK))
	{
		if (NULL == (pbSignature = (CK_BYTE_PTR)malloc(ulSignatureLen)))
		{
			rvResult = MEMORY_NOT_ALLOCATED;
			goto SIGN_FILE_REALISE_FINALIZATION;
		}
	}
	else
	{
		if (CKR_OK == rvResult)
		{
			rvResult = CKR_DATA_LEN_RANGE;
		}
		goto SIGN_FILE_REALISE_FINALIZATION;
	}
	rvResult = pEsFuncList->SignData(pbDataToSign,ulDataToSignLen,sUserKeyInfo,NULL,NULL,pbSignature,&ulSignatureLen);
	if (CKR_OK != rvResult)
	{
		goto SIGN_FILE_REALISE_FINALIZATION;
	}
	WriteDataToFile(pcFileToPutSignTo,pbSignature,ulSignatureLen);
SIGN_FILE_REALISE_FINALIZATION:
	if (pbSignature) free(pbSignature);
	if (pbDataToSign) free(pbDataToSign);
	if (sUserKeyInfo.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sUserKeyInfo.ulNumOfParams; i++)
		{
			sUserKeyInfo.psKeyParams[i].pValue = NULL;
		}
		free(sUserKeyInfo.psKeyParams);
	}
};
//------------------------------------------------------------------------------------------------
void CmdFunctionsClassForEncSig::VerifyFile(char *pcFileToVerify, char *pcFileSignature, int iNumOfParams, char **psParams, CK_BBOOL *bVerifyResult)
{
	CK_BYTE_PTR pbDataToVerify = NULL, pbSignature = NULL;
	CK_ULONG ulDataToVerifyLen = 0, ulSignatureLen = 0;
	MY_KEY_TEMPLATE_INFO sUserKeyInfo;

	memset(&sUserKeyInfo,0,sizeof(MY_KEY_TEMPLATE_INFO));
	ReadDataFromFile(pcFileToVerify,NULL,&ulDataToVerifyLen);
	if ((ulDataToVerifyLen)&&(rvResult == CKR_OK))
	{
		if (NULL == (pbDataToVerify = (CK_BYTE_PTR)malloc(ulDataToVerifyLen)))
		{
			rvResult = MEMORY_NOT_ALLOCATED;
			return;
		}
	}
	else
	{
		if (CKR_OK == rvResult)
		{
			rvResult = CKR_FILE_ERROR;
		}
		return;
	}
	ReadDataFromFile(pcFileToVerify,pbDataToVerify,&ulDataToVerifyLen);
	if (CKR_OK != rvResult)
	{
		goto VERIFY_FILE_REALISE_FINALIZATION;
	}

	ReadDataFromFile(pcFileSignature,NULL,&ulSignatureLen);
	if ((ulSignatureLen)&&(rvResult == CKR_OK))
	{
		if (NULL == (pbSignature = (CK_BYTE_PTR)malloc(ulSignatureLen)))
		{
			rvResult = MEMORY_NOT_ALLOCATED;
			return;
		}
	}
	else
	{
		if (CKR_OK == rvResult)
		{
			rvResult = CKR_FILE_ERROR;
		}
		return;
	}
	ReadDataFromFile(pcFileSignature,pbSignature,&ulSignatureLen);
	if (CKR_OK != rvResult)
	{
		goto VERIFY_FILE_REALISE_FINALIZATION;
	}

	if ((!iNumOfParams)||(!psParams))
	{
		rvResult = CKR_WRONG_INPUT;
		goto VERIFY_FILE_REALISE_FINALIZATION;
	}
	sUserKeyInfo.ulNumOfParams = iNumOfParams;
	sUserKeyInfo.psKeyParams = (CK_ATTRIBUTE_PTR) malloc ((sUserKeyInfo.ulNumOfParams + 1) * sizeof(CK_ATTRIBUTE));
	MakeKeyParamsFromCmd(iNumOfParams,psParams,&sUserKeyInfo);
	if (rvResult != CKR_OK)
	{
		goto VERIFY_FILE_REALISE_FINALIZATION;
	}
	sUserKeyInfo.psKeyParams[sUserKeyInfo.ulNumOfParams].type = CKA_CLASS;
	sUserKeyInfo.psKeyParams[sUserKeyInfo.ulNumOfParams].ulValueLen = sizeof(CK_ULONG);
	sUserKeyInfo.psKeyParams[sUserKeyInfo.ulNumOfParams].pValue = &ulClass_PubKey;
	sUserKeyInfo.ulNumOfParams++;

	rvResult = pEsFuncList->VerifyData(pbDataToVerify,ulDataToVerifyLen,pbSignature,ulSignatureLen,sUserKeyInfo,NULL,NULL,bVerifyResult);
	if (CKR_OK != rvResult)
	{
		goto VERIFY_FILE_REALISE_FINALIZATION;
	}
VERIFY_FILE_REALISE_FINALIZATION:
	if (pbSignature) free(pbSignature);
	if (pbDataToVerify) free(pbDataToVerify);
	if (sUserKeyInfo.psKeyParams)
	{
		for (CK_ULONG i = 0; i<sUserKeyInfo.ulNumOfParams; i++)
		{
			sUserKeyInfo.psKeyParams[i].pValue = NULL;
		}
		free(sUserKeyInfo.psKeyParams);
	}
};
//------------------------------------------------------------------------------------------------
/*
//*/
//================================================================================================
void CmdFunctionsClassForEncSig::ReadDataFromFile(char *pcFilename, CK_BYTE_PTR pbData, CK_ULONG_PTR ulDataLen)
{
	FILE *f = NULL;

	if (pcFilename == NULL)
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
	if (NULL == (f = fopen(pcFilename,"rb")))
	{
		rvResult = CKR_FILE_ERROR;
		return;
	}

	fseek(f, 0, 2);
	*ulDataLen = ftell(f);
	if (*ulDataLen == -1) 
	{
		fclose(f);
		rvResult = NOT_ENOUGH_MEMORY;
		return;
	}
	if (pbData)
	{
		rewind(f);
		fread(pbData, *ulDataLen, 1, f);
	}
	fclose(f);
};
//------------------------------------------------------------------------------------------------
void CmdFunctionsClassForEncSig::WriteDataToFile(char *pcFilename, CK_BYTE_PTR pbData, CK_ULONG ulDataLen)
{
	FILE *f = NULL;
	if ((pcFilename == NULL)||(pbData == NULL)||(!ulDataLen))
	{
		rvResult = CKR_ARGUMENTS_BAD;
		return;
	}
	if (NULL == (f = fopen(pcFilename,"wb+")))
	{
		rvResult = CKR_FILE_ERROR;
		return;
	}
	if (fwrite(pbData,sizeof(CK_BYTE),ulDataLen,f) != ulDataLen)
	{
		fclose(f);
		rvResult = CKR_FILE_ERROR;
		return;
	}
	fclose(f);
};
//================================================================================================
void CmdFunctionsClassForEncSig::PrintWorkResult(char *InFunction)
{
	cout<<"Function "<<InFunction;
	if (rvResult!=CKR_OK)
	{
		cout<<" failed!"<<endl;
	}
	else
	{
		cout<<" succeeded!"<<endl;
		return;
	}
	switch (rvResult) {
	case NOT_ENOUGH_MEMORY:
		cout<<hex<<"Error: not enough memory aviable"<<endl;
		break;
	case PUK_INVALID_LENGTH:
		cout<<hex<<"Error: invalid PUK length"<<endl;
		break;
	case PUK_INVALID_VALUE:
		cout<<hex<<"Error: invalid PUK format.\nPUK can contain only symbols from 0 to 9 and from A to F"<<endl;
		break;
	case CKR_PUK_NOT_SETTED:
		cout<<hex<<"Error: PUK wasn't generated. Please, try again after formating with PUK"<<endl;
		break;
	case CKR_DEVICE_BLOCKED:
	case CKR_PIN_LOCKED:
		cout<<hex<<"Error: device is blocked (PIN)"<<endl;
		break;
	case CKR_DEVICE_NOT_BLOCKED:
		cout<<hex<<"Error: device isn't blocked (PIN)"<<endl;
		break;
	case AUTH_PARAMS_NOT_SETTED:
		cout<<hex<<"Error: authorisation parameters weren't setted"<<endl;
		break;
	case DIFFERENT_PINS:
		cout<<hex<<"Error: entered new PINs are not equal"<<endl;
		break;
	case CKR_DEVICE_REMOVED:
		cout<<"Error: device isn't connected. Please, try again after connecting device"<<endl;
		break;
	case CKR_PIN_LEN_RANGE:
		cout<<"Error: Wrong length of PIN"<<endl;
		break;
	case CKR_PIN_INVALID:
		cout<<"Error: PIN doesn't contain symbols from all alfabets needed"<<endl;
		break;
	case PIN_NOT_ENTERED:
		cout<<"Error: PIN wasn't entered"<<endl;
		break;
	case CKR_PIN_INCORRECT:
		cout<<"Error: incorrect PIN entered"<<endl;
		break;
	case CKR_DEVICE_ERROR:
		cout<<"Error: Device is blocked (PUK)"<<endl;
		break;
	case CKR_DEVICE_WASNT_INITED:
		cout<<"Error: Device wasn't inited \nPlease, try again after initing device"<<endl;
		break;
	case CKR_WRONG_INPUT:
		cout<<"Error: Wrong format of input parameters \nPlease use -h parameter to get help"<<endl;
		break;
	case CKR_SHIPKA_NOT_SUPPORTED:
		cout<<"Error: Shipka-lite isn't supported in this utility"<<endl;
		break;
	default: cout<<hex<<"Unknown error: 0x"<<rvResult<<endl;
	}
};
//------------------------------------------------------------------------------------------------
void CmdFunctionsClassForEncSig::PrintDeviceInfo(CK_SLOT_ID ulSlotID)
{
	MY_DEVICE_INFO diDeviceInfo;
	pEsFuncList->GetDeviceInfo(ulSlotID,&diDeviceInfo);
	if (rvResult==CKR_OK)
	{
		cout<<"DeviceID: "<<diDeviceInfo.cDeviceID;
		cout<<" - "<<diDeviceInfo.cDeviceType;
		cout<<" - "<<(bitset<8>(diDeviceInfo.ulFlags))<<endl;
	}
};
//------------------------------------------------------------------------------------------------
void CmdFunctionsClassForEncSig::PrintDeviceInfoEx(CK_SLOT_ID ulSlotID)
{
	MY_DEVICE_INFO diDeviceInfo;
	pEsFuncList->GetDeviceInfo(ulSlotID,&diDeviceInfo);
	if (rvResult==CKR_OK)
	{
		cout<<"DeviceID: "<<diDeviceInfo.cDeviceID<<endl;
		cout<<"Device Type: "<<diDeviceInfo.cDeviceType<<endl;
		cout<<"Info: ";
		if ((diDeviceInfo.ulFlags&DEVICE_NOT_INITIALIZED)==DEVICE_NOT_INITIALIZED) 
		{
			cout<<"Device not initialized!"<<endl;
			return;
		}
		if ((diDeviceInfo.ulFlags&PUK_BLOCKED)==PUK_BLOCKED) 
		{
			cout<<"Device is blocked by PUK!"<<endl;
			return;
		}
		if ((diDeviceInfo.ulFlags&PIN_BLOCKED)==PUK_NOT_REQUIRED) cout<<"Format only without PUK generation is allowed."<<endl;
		else cout<<"Format with PUK generation is allowed."<<endl;
		if ((diDeviceInfo.ulFlags&DEVICE_NOT_FORMATED)==DEVICE_NOT_FORMATED) cout<<"      Device isn't formatted"<<endl;
		if ((diDeviceInfo.ulFlags&PIN_BLOCKED)==PIN_BLOCKED) cout<<"      Device is blocked by PIN"<<endl;
		if ((diDeviceInfo.ulFlags&PIN_NOT_SETTED)==PIN_NOT_SETTED) cout<<"      PIN for device wasn't setted"<<endl;
	}
};
//================================================================================================


