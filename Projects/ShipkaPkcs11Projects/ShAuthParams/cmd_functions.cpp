#include "cmd_functions.h"
#include "ShAuthCmdAndParams.h"
#include <iostream>
#include <bitset>

using namespace std;

CommandLineWork::CommandLineWork():AuthParamsInit(){};

bool CommandLineWork::GetCommandFromCommandLine(int argc, char **argv)
{
	bool bReturnValue = true;
	if (argc==1) 
	{
		cout<<"ShAuthParams utility"<<endl<<"Version 1.0.0"<<endl<<endl
		<<"Use -h parameter to get functions list"<<endl;
		return false;
	}
#pragma region ChangeSoPin
	if (!strcmp(CHANGE_SO_PIN,argv[1]))
	{
		if (argc>2)
			if (!strcmp(USE_HELP,argv[2]))
			{
				cout<<endl<<"Function to change SO PIN"<<endl<<endl
				<<CHANGE_SO_PIN<<" [Device ID] [Old SO Pin] [New SO Pin]"<<endl<<endl
				<<"\t"<<"Device ID - Device Identifier to work with"<<endl
				<<"\t"<<"Old SO Pin - old SO Pin to be changed"<<endl
				<<"\t"<<"New SO Pin - new SO Pin"<<endl;
				return true;
			}
		if (argc==5)
		{
			ChangeSOPIN(argv[2],argv[3],strlen(argv[3]),argv[4],strlen(argv[4]));
		}
		else if (argc==4)
		{
			ChangeSOPIN(argv[2],NULL,0,argv[3],strlen(argv[3]));
		}
		else
		{
			rvResult = CKR_WRONG_INPUT;
			bReturnValue = false;
		}
		PrintWorkResult((char*)"Change SO PIN");
		return bReturnValue;
	}
#pragma endregion
#pragma region LockFormatting
	if (!strcmp(LOCK_FORMATTING,argv[1]))
	{
		if (argc>2)
			if (!strcmp(USE_HELP,argv[2]))
			{
				cout<<endl<<"Function to lock formatting"<<endl<<endl
				<<LOCK_FORMATTING<<" [Device ID] [SO Pin]"<<endl<<endl
				<<"\t"<<"Device ID - Device Identifier to work with"<<endl
				<<"\t"<<"SO Pin - SO Pin of device"<<endl;
				return true;
			}
		if (argc==4)
		{
			BlockFormatting(argv[2],argv[3],strlen(argv[3]));
		}
		else
		{
			rvResult = CKR_WRONG_INPUT;
			bReturnValue = false;
		}
		PrintWorkResult((char*)"Lock formatting");
		return bReturnValue;
	}
#pragma endregion
#pragma region UnLockFormatting
	if (!strcmp(UNLOCK_FORMATTING,argv[1]))
	{
		if (argc>2)
			if (!strcmp(USE_HELP,argv[2]))
			{
				cout<<endl<<"Function to unlock formatting"<<endl<<endl
				<<UNLOCK_FORMATTING<<" [Device ID] [SO Pin]"<<endl<<endl
				<<"\t"<<"Device ID - Device Identifier to work with"<<endl
				<<"\t"<<"SO Pin - SO Pin of device"<<endl;
				return true;
			}
		if (argc==4)
		{
			UnblockFormatting(argv[2],argv[3],strlen(argv[3]));
		}
		else
		{
			rvResult = CKR_WRONG_INPUT;
			bReturnValue = false;
		}
		PrintWorkResult((char*)"Unlock formatting");
		return bReturnValue;
	}
#pragma endregion
#pragma region SetIaParams
	if (!strcmp(SET_IA_PARAMS,argv[1]))
	{
		if (argc>2)
			if (!strcmp(USE_HELP,argv[2]))
			{
				cout<<endl<<"Function to set IA parameters"<<endl<<endl
				<<SET_IA_PARAMS<<" [Device ID] "<<SO_PIN<<"[SO Password] [Pin Parameters] [Puk Parameters] [Other Parameters]"<<endl<<endl
				<<"\t"<<"Device ID - Device Identifier to work with or -all flag to work with all devices connected"<<endl
				<<"\t"<<"SO Password - SO Password of device"<<endl<<endl
				<<"\t"<<"Optional parameters:"<<endl
				<<"\t"<<"Pin Parameters:"<<endl<<"\t\t"<<" "<<PIN_LEN_PARAM<<"[MinValue]-[MaxValue] "<<PIN_ATTEMPTS_NUM<<"[Value] "<<PIN_CHAR_PARAM<<"[Value]"<<endl
				<<"\t"<<"Puk Parameters:"<<endl<<"\t\t"<<" [With/Without Puk] "<<PUK_LEN_PARAM<<"[Value] "<<PUK_ATTEMPTS_NUM<<"[Value]"<<endl<<endl
				<<"\t"<<"Other Parameters:"<<endl<<"\t\t"<<"[MakeConstant]"<<endl<<endl
				<<"Example:"<<endl<<"\t"<<"SetParams -all "<<SO_PIN<<"1234567 "<<FORMAT_WITH_PUK<<" "<<PUK_LEN_PARAM<<"12 "<<PUK_ATTEMPTS_NUM<<"5 "<<PIN_LEN_PARAM<<"10-16 "<<MAKE_CONSTANT
				<<endl;
				return true;
			}
		char *pcPinMin = NULL,*pcPinMax = NULL,*temp = NULL;
		char *pcDeviceID = NULL;
		char *pcSoPin = NULL;
		CK_ULONG ulMinPinLen = 0, ulMaxPinLen = 0, ulPukLen = 0, ulMaxPinAtt = 0, ulMaxPukAtt = 0;
		CK_ULONG ulPinChar = 0;
		bool bWithPuk = true, bForOneDevice = true, bMakeConstant = false;
		if (argc<4)
		{
			rvResult = CKR_WRONG_INPUT;
			bReturnValue = false;
			goto SetIaParamsFin;
		}
		if (!strncmp(ALL_DEVICES_PARAM,argv[2],strlen(ALL_DEVICES_PARAM)))
		{
			bForOneDevice = false;
		}
		else 
		{
			bForOneDevice = true;
			pcDeviceID = argv[2];
		}

		for (int i = 3; i<argc; i++)
		{
			if (!strncmp(argv[i],SO_PIN,strlen(SO_PIN)))
			{
				pcSoPin = argv[i] + strlen(SO_PIN);
			}
			else if (!strncmp(argv[i],PIN_LEN_PARAM,strlen(PIN_LEN_PARAM)))
			{
				pcPinMin = argv[i] + strlen(PIN_LEN_PARAM);
				//pin length parameter has format PinLen=7<10
				while ((pcPinMin[0]!='-')&&(strlen(pcPinMin)))
					pcPinMin++;
				if (strlen(pcPinMin))
				{
					pcPinMin[0] = 0;
					pcPinMin++;
					pcPinMax = argv[i] + strlen(PIN_LEN_PARAM);
				}
				else
				{
					pcPinMax = argv[i] + strlen(PIN_LEN_PARAM);
					pcPinMin = argv[i] + strlen(PIN_LEN_PARAM);
				}
				if (strlen(pcPinMax)) ulMaxPinLen = atol(pcPinMax);
				else ulMaxPinLen = 0;
				if (strlen(pcPinMin)) ulMinPinLen = atol(pcPinMin);
				else ulMinPinLen = 0;
				pcPinMax = NULL;
				pcPinMin = NULL;
				if ((!ulMinPinLen)||(!ulMaxPinLen))
					goto SetIaParamsFin;
				if (ulMinPinLen > ulMaxPinLen)
				{
					ulMinPinLen += ulMaxPinLen;
					ulMaxPinLen = ulMinPinLen - ulMaxPinLen;
					ulMinPinLen -= ulMaxPinLen;
				}
			}
			else if (!strncmp(argv[i],PUK_LEN_PARAM,strlen(PUK_LEN_PARAM)))
			{
				ulPukLen = atol(argv[i] + strlen(PUK_LEN_PARAM));
			}
			else if (!strncmp(argv[i],PIN_ATTEMPTS_NUM,strlen(PIN_ATTEMPTS_NUM)))
			{
				ulMaxPinAtt = atol(argv[i] + strlen(PIN_ATTEMPTS_NUM));
			}
			else if (!strncmp(argv[i],PUK_ATTEMPTS_NUM,strlen(PUK_ATTEMPTS_NUM)))
			{
				ulMaxPukAtt = atol(argv[i] + strlen(PUK_ATTEMPTS_NUM));
			}
			else if (!strncmp(argv[i],PIN_CHAR_PARAM,strlen(PIN_CHAR_PARAM)))
			{
				temp = argv[i] + strlen(PIN_CHAR_PARAM);
				while (strlen(temp)>1)
				{
					switch(temp[1])
					{
					case 'd':
						ulPinChar = ulPinChar|SHEX_PIN_SET_NUMBERS_FLAG;
						break;
					case 'u':
						ulPinChar = ulPinChar|SHEX_PIN_SET_UP_CASE_FLAG;
						break;
					case 'l':
						ulPinChar = ulPinChar|SHEX_PIN_SET_LOW_CASE_FLAG;
						break;
					case 'w':
						ulPinChar = ulPinChar|SHEX_PIN_SET_SPECIAL_FLAG;
						break;
					default:
						rvResult = CKR_WRONG_INPUT;
						goto SetIaParamsFin;
						break;
					}
					temp +=2;
				}
			}
			else if (!strncmp(argv[i],FORMAT_WITH_PUK,strlen(FORMAT_WITH_PUK)))
			{
				bWithPuk = true;
			}
			else if (!strncmp(argv[i],FORMAT_WITHOUT_PUK,strlen(FORMAT_WITHOUT_PUK)))
			{
				bWithPuk = false;
			}
			else if (!strncmp(argv[i],MAKE_CONSTANT,strlen(MAKE_CONSTANT)))
			{
				bMakeConstant = true;
			}
			else
			{
				rvResult = CKR_WRONG_INPUT;
				goto SetIaParamsFin;
			}
		}
		SetAuthParams(bForOneDevice,pcDeviceID,strlen(pcSoPin),pcSoPin,bWithPuk,ulPukLen,ulMaxPukAtt,ulMaxPinAtt,ulPinChar,ulMinPinLen,ulMaxPinLen,bMakeConstant);
SetIaParamsFin:
		PrintWorkResult((char*)"Set IA parameters");
		pcPinMin = NULL; pcPinMax = NULL; temp = NULL; pcDeviceID = NULL; pcSoPin = NULL;
		return bReturnValue;
	}
#pragma endregion
#pragma region GetDeviceInfo
	if (!strcmp(GET_DEVICE_INFO,argv[1]))
	{
		if (argc>2)
			if (!strcmp(USE_HELP,argv[2]))
			{
				cout<<endl<<"Function to get information about device"<<endl<<endl
				<<GET_DEVICE_INFO<<" [Device ID] [params]"<<endl<<endl
				<<"\t"<<"Device ID - Device Identifier to work with"<<endl
				<<"\t"<<"params - optional parameter: -more"<<endl;
				return true;
			}
		CK_SLOT_ID ulSlotID;
		if ((argc==4)||(argc==3))
		{
			if (DeviceIsConnected(argv[2],&ulSlotID)==true)
			{
				if (argc==3)
				{
					PrintDeviceInfo(ulSlotID);
				}
				if (argc==4)
				{
					if (!strcmp(argv[3],READABLE_INFO))
						PrintDeviceInfoEx(ulSlotID);
					else
					{
						rvResult = CKR_WRONG_INPUT;
						PrintWorkResult((char*)"GetDeviceInfo");
						return false;
					}
				}
			}
			else
			{
				if (rvResult==CKR_OK) rvResult = CKR_DEVICE_REMOVED;
			}
			bReturnValue = true;
		}
		else
		{
			rvResult = CKR_WRONG_INPUT;
			bReturnValue = false;
		}
		PrintWorkResult((char*)"GetDeviceInfo");
		return bReturnValue;
	}
#pragma endregion
#pragma region GetDeviceList
	if (!strcmp(GET_DEVICE_LIST,argv[1]))
	{
		if (argc>2)
			if (!strcmp(USE_HELP,argv[2]))
			{
				cout<<endl<<"Function to get the list of devices"<<endl<<endl
				<<GET_DEVICE_LIST<<" [ ]"<<endl
				<<"No parameters needed"
				<<endl;
				return true;
			}
		if (argc==2)
		{
			CK_SLOT_ID_PTR pDeviceList = NULL;
			CK_ULONG ulDeviceNumber = 0;
			GetDeviceList(pDeviceList, &ulDeviceNumber);
			if (rvResult==CKR_OK)
			{
				if (ulDeviceNumber==0)
				{
					cout<<"No devices are connected"<<endl;
				}
				else
				{
					pDeviceList = (CK_SLOT_ID_PTR)malloc(ulDeviceNumber*sizeof(CK_SLOT_ID));
					GetDeviceList(pDeviceList, &ulDeviceNumber);
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
			bReturnValue = true;
		}
		else
		{
			rvResult = CKR_WRONG_INPUT;
			bReturnValue = false;
		}
		PrintWorkResult((char*)"GetDeviceList");
		return bReturnValue;
	}
#pragma endregion
#pragma region ChangeLang
	if (!strcmp(CHANGE_LANGUAGE,argv[1]))
	{
		return false;
	}
#pragma endregion
#pragma region Help
	if (!strcmp(USE_HELP,argv[1]))
	{
		cout<<"ShAuthParams.exe"<<endl
			<<"Functions:"<<endl
			<<"\t"<<GET_DEVICE_LIST<<endl
			<<"\t"<<GET_DEVICE_INFO<<endl
//			<<"\t"<<CHANGE_LANGUAGE<<endl
			<<"\t"<<CHANGE_SO_PIN<<endl
			<<"\t"<<LOCK_FORMATTING<<endl
			<<"\t"<<UNLOCK_FORMATTING<<endl
			<<"\t"<<SET_IA_PARAMS<<endl<<endl
			<<"\t"<<"Use Function parameter -h to get more about each function"
			<<endl;
		return true;
	}
#pragma endregion
	cout<<"Incorrect arguments!"<<endl
		<<"Use -h for some help"<<endl;
	return false;
};
void CommandLineWork::PrintWorkResult(char *InFunction)
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

void CommandLineWork::PrintDeviceInfo(CK_SLOT_ID ulSlotID)
{
	MY_DEVICE_INFO diDeviceInfo;
	GetDeviceInfo(ulSlotID,&diDeviceInfo);
	if (rvResult==CKR_OK)
	{
		cout<<"DeviceID: "<<diDeviceInfo.cDeviceID;
		cout<<" - "<<diDeviceInfo.cDeviceType;
		cout<<" - "<<(bitset<8>(diDeviceInfo.ulFlags))<<endl;
	}
};

void CommandLineWork::PrintDeviceInfoEx(CK_SLOT_ID ulSlotID)
{
	MY_DEVICE_INFO diDeviceInfo;
	GetDeviceInfo(ulSlotID,&diDeviceInfo);
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
