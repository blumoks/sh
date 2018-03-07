#define _CRT_SECURE_NO_WARNINGS
#include "cmd_functions.h"
#include <iostream>
#include <bitset>
#include <ctime>

using namespace std;

void PUKtoAnotherView(CK_UTF8CHAR_PTR pPUK,CK_ULONG ulPUKLen,char *pPUKBetterView);

CommandLineWork::CommandLineWork():InitializationClass(){};

bool CommandLineWork::GetCommandFromCommandLine(int argc, char **argv)
{
	if (argc==1) return false;


	if (!strcmp(CHANGE_DEVICE_PIN, argv[1]))
	{
		if (argc == 6)
		{
			if (!strcmp(argv[4], argv[5]))
			{
				ChangePIN(argv[2], argv[3], strlen(argv[3]), argv[4], strlen(argv[4]));
			}
			else
			{
				rvResult = DIFFERENT_PINS;
			}
			PrintWorkResult((char*)"ChangePIN");
			FinalizePKCS11Lib();
			return true;
		}
		if (argc == 5)
		{
			if (!strcmp(argv[3], argv[4]))
			{
				ChangePIN(argv[2], NULL, 0, argv[3], strlen(argv[3]));
			}
			else
			{
				rvResult = DIFFERENT_PINS;
			}

			PrintWorkResult((char*)"ChangePIN");
			FinalizePKCS11Lib();
			return true;
		}
		FinalizePKCS11Lib();
		return false;
	}

	if (!strcmp(CHECK_DEVICE_PIN,argv[1]))
	{
		if (argc==6)
		{
			if (!strcmp(argv[4],argv[5]))
			{
				CheckPIN(argv[2],argv[3],strlen(argv[3]),argv[4],strlen(argv[4]));
			}
			else 
			{
				rvResult = DIFFERENT_PINS;
			}
			PrintWorkResult((char*)"CheckPIN");
			FinalizePKCS11Lib();
			return true;
		}
		
	}
	if (!strcmp(UNBLOCK_DEVICE,argv[1]))
	{
		if (argc==6)
		{
			if (!strcmp(argv[4],argv[5]))
			{
				UnblockDevice(argv[2],argv[3],strlen(argv[3]),(CK_UTF8CHAR_PTR)argv[4],strlen(argv[4]));
			}
			else 
			{
				rvResult = DIFFERENT_PINS;
			}

			PrintWorkResult((char*)"UnblockDevice");
			FinalizePKCS11Lib();
			return true;
		}
		FinalizePKCS11Lib();
		return false;
	}
	if (!strcmp(FORMAT_DEVICE,argv[1]))
	{
		bool bWithPUK = false,bSaveToFile = false;
		char *pcFileName;
		CK_ULONG ulPUKLen = 32, ulFileNameLen = 0;
		CK_SLOT_ID ckDeviceID = 0;
		MY_DEVICE_INFO myDeviceInfo;
		char pPUKBetterView[32];
		char OldPIN[16];
		memset(OldPIN, 0, 16);
		CK_UTF8CHAR pPUK[32];

		if (argc>=5)
		{
			if (!strcmp(argv[4],FORMAT_WITH_PUK))
			{
				bWithPUK = true;
				if ((argc==7)&&(!strcmp(argv[5],SAVE_TO_FILE)))
				{
					bSaveToFile = true;
					if (!strcmp(argv[6],DEFAULT_ATTR))
					{
						pcFileName=(char*)DEFAULT_PUK_FILE;
						ulFileNameLen = strlen(DEFAULT_PUK_FILE);
					}
					else
					{
						pcFileName=argv[6];
						ulFileNameLen = strlen(argv[6]);
					}
				}
				else if (argc!=5)
				{
					FinalizePKCS11Lib();
					return false;
				}
			}
			else if ((!strcmp(argv[4],FORMAT_WITHOUT_PUK))&&(argc==5))
			{
				bWithPUK = false;
			}
			else
			{
				FinalizePKCS11Lib();
				return false;
			}
			
			if (DeviceIsConnected(argv[2],&ckDeviceID)==false)
			{
				if (rvResult==CKR_OK) rvResult = CKR_DEVICE_REMOVED;
			}
			else
			{
				GetDeviceInfo(ckDeviceID,&myDeviceInfo);
				//here should be some code to check, if device is already formated with PUK 
				//and if auth parameters are setted
				if (!strcmp((char *)(myDeviceInfo.cDeviceType),SHIPKA_LITE))
				{
					strcpy(OldPIN,argv[3]);
				}
				else
				{
					OldPIN[0] = '\0';
				}

				FormatDevice(argv[2],bWithPUK,(CK_UTF8CHAR_PTR)OldPIN,strlen(OldPIN),pPUK,&ulPUKLen);
				
			}
			
			PrintWorkResult((char*)"FormatDevice");
			if ((rvResult==CKR_OK)&&(bWithPUK==true))
			{
				PUKtoAnotherView(pPUK,ulPUKLen,pPUKBetterView);
				cout<<"PUK: "<<pPUKBetterView<<endl;
				//saving PUK to file
				if (bSaveToFile==true)
				{
					FILE *f = NULL;
					if ((f = fopen(pcFileName,"a+"))!=NULL)
					{
						char buffer[80];
						time_t seconds = time(NULL);
						tm* timeinfo = localtime(&seconds);
						char* format = "%d.%m.%Y %H:%M:%S";
						strftime(buffer, 80, format, timeinfo);
						char buffer2[80];
						sprintf( buffer2," Device ¹: %s PUK: %s\n",argv[2],pPUKBetterView);
						strcat(buffer, buffer2);
						fprintf(f, buffer);
						fclose(f);
					}
					else
					{
						std::cout<<"Cannot save PUK to file.\n"<<std::endl;
					}
				}
			}
			FinalizePKCS11Lib();
			return true;
		}
		FinalizePKCS11Lib();
		return false;
	}
	if (!strcmp(GET_DEVICE_INFO,argv[1]))
	{
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
						FinalizePKCS11Lib();
						return false;
					}
				}
			}
			else
			{
				if (rvResult==CKR_OK) rvResult = CKR_DEVICE_REMOVED;
			}
			PrintWorkResult((char*)"GetDeviceInfo");
			FinalizePKCS11Lib();
			return true;
		}
		FinalizePKCS11Lib();
		return false;
	}
	if (!strcmp(GET_DEVICE_LIST,argv[1]))
	{
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
			PrintWorkResult((char*)"GetDeviceList");
			FinalizePKCS11Lib();
			return true;
		}
		FinalizePKCS11Lib();
		return false;
	}
	if (!strcmp(CHANGE_LANGUAGE,argv[1]))
	{
		return false;
	}

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
		cout<<hex<<"Error: PUK wasn't generated. Try again after formating with PUK"<<endl;
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
		cout<<"Error: device isn't connected. Connect device and try again"<<endl;
		break;
	case CKR_PIN_LEN_RANGE:
		cout<<"Error: Wrong length of PIN"<<endl;
		break;
	case CKR_PIN_INVALID:
		cout<<"Error: PIN doesn't contain symbols from all alfabets needed"<<endl;
		break;
	case PIN_NOT_ENTERED:
		cout<<"Error: enter old PIN to be changed"<<endl;
		break;
	case CKR_PIN_INCORRECT:
		cout<<"Error: incorrect old PIN"<<endl;
		break;
	case CKR_DEVICE_ERROR:
		cout<<"Error: Device is blocked (PUK)"<<endl;
		break;
	default: cout<<hex<<"Unknown error: 0x"<<rvResult<<endl;
	}
};

void PUKtoAnotherView(CK_UTF8CHAR_PTR pPUK, CK_ULONG ulPUKLen,char *pPUKBetterView)
{
	for(CK_ULONG i=0;i<ulPUKLen;i++)
	{
		if (pPUK[i]/0x10<10)	pPUKBetterView[2*i] = pPUK[i]/0x10 + '0';
		else					pPUKBetterView[2*i] = pPUK[i]/0x10 + 'A'-10;
		if (pPUK[i]%0x10<10)	pPUKBetterView[2*i+1] = pPUK[i]%0x10 + '0';
		else					pPUKBetterView[2*i+1] = pPUK[i]%0x10 + 'A'-10;
	}
	pPUKBetterView[ulPUKLen*2] = '\0';
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
