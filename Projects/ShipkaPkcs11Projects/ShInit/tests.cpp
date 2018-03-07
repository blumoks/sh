#include "tests.h"

using namespace std;
CK_RV Test_Low_GetInfo()
{
	cout<<"Test_Init_GetInfo\n"<<endl;
	CK_RV rvResult = CKR_OK;
	CK_SLOT_ID_PTR pDeviceList = NULL;
	CK_ULONG ulDeviceNumber = 0;
	MY_DEVICE_INFO diDeviceInfo;

	BaseClass *nuClass = new BaseClass();
	if (nuClass->rvResult==CKR_OK)
	{
		cout<<"Try GetDeviceList first time"<<endl;
		nuClass->GetDeviceList(pDeviceList, &ulDeviceNumber);
		if (rvResult==CKR_OK)
		{
			if (ulDeviceNumber==0)
			{
				cout<<"No devices are connected"<<endl;
			}
			else
			{
				cout<<"Allocating memory for "<<ulDeviceNumber<<" devices"<<endl;
				pDeviceList = (CK_SLOT_ID_PTR)malloc(ulDeviceNumber*sizeof(CK_SLOT_ID));
				cout<<"Try GetDeviceList second time"<<endl;
				nuClass->GetDeviceList(pDeviceList, &ulDeviceNumber);
				if (rvResult==CKR_OK)
				{
					cout<<"Print each device info"<<endl;
					for (CK_ULONG i = 0; i<ulDeviceNumber; i++)
					{
						nuClass->GetDeviceInfo(pDeviceList[i],&diDeviceInfo);
						if (rvResult==CKR_OK)
						{
							cout<<"DeviceID: "<<diDeviceInfo.cDeviceID;
							cout<<" - "<<diDeviceInfo.cDeviceType;
							cout<<" - "<<(bitset<8>(diDeviceInfo.ulFlags))<<endl;
						}
						else
						{
							i = ulDeviceNumber;
						}
					}
				}
				free(pDeviceList);
			}
		}
	}
	rvResult = nuClass->rvResult;
	delete nuClass;
	if (rvResult!=CKR_OK)
	{
		cout<<"Error occured in test Test_Init_GetInfo\n"<<endl;
	}
	return rvResult;
};
CK_RV Test_Init_GetInfo()
{
	cout<<"Test_Init_GetInfo\n"<<endl;
	CK_RV rvResult = CKR_OK;
	CK_SLOT_ID_PTR pDeviceList = NULL;
	CK_ULONG ulDeviceNumber = 0;
	MY_DEVICE_INFO diDeviceInfo;

	InitializationClass *nuClass = new InitializationClass();
	if (nuClass->rvResult==CKR_OK)
	{
		cout<<"Try GetDeviceList first time"<<endl;
		nuClass->GetDeviceList(pDeviceList, &ulDeviceNumber);
		if (rvResult==CKR_OK)
		{
			if (ulDeviceNumber==0)
			{
				cout<<"No devices are connected"<<endl;
			}
			else
			{
				cout<<"Allocating memory for "<<ulDeviceNumber<<" devices"<<endl;
				pDeviceList = (CK_SLOT_ID_PTR)malloc(ulDeviceNumber*sizeof(CK_SLOT_ID));
				cout<<"Try GetDeviceList second time"<<endl;
				nuClass->GetDeviceList(pDeviceList, &ulDeviceNumber);
				if (rvResult==CKR_OK)
				{
					cout<<"Print each device info"<<endl;
					for (CK_ULONG i = 0; i<ulDeviceNumber; i++)
					{
						nuClass->GetDeviceInfo(pDeviceList[i],&diDeviceInfo);
						if (rvResult==CKR_OK)
						{
							cout<<"DeviceID: "<<diDeviceInfo.cDeviceID;
							cout<<" - "<<diDeviceInfo.cDeviceType;
							cout<<" - "<<(bitset<8>(diDeviceInfo.ulFlags))<<endl;
						}
						else
						{
							i = ulDeviceNumber;
						}
					}
				}
				free(pDeviceList);
			}
		}
	}
	rvResult = nuClass->rvResult;
	delete nuClass;
	if (rvResult!=CKR_OK)
	{
		cout<<"Error occured in test Test_Init_GetInfo\n"<<endl;
	}
	return rvResult;
};
CK_RV Test_Init_ChangePIN()
{
	cout<<"Test_Init_ChangePIN\n"<<endl;
	CK_RV rvResult = CKR_OK;
	CK_SLOT_ID ckDeviceID = 0;
	MY_DEVICE_INFO myDeviceInfo;
	char DeviceID[10], OldPIN[32], NewPIN[32];
	InitializationClass *ClassToWorkWith = new InitializationClass();
	if (ClassToWorkWith->rvResult==CKR_OK)
	{
		cout<<"Enter Device ID: ";
		cin>>DeviceID;
		ClassToWorkWith->DeviceIsConnected(DeviceID,&ckDeviceID);
		if (ClassToWorkWith->rvResult !=CKR_OK)
		{
			cout<<"Device not connected\n"<<endl;
			rvResult = ClassToWorkWith->rvResult;
			delete ClassToWorkWith;
			return rvResult;
		}
		ClassToWorkWith->GetDeviceInfo(ckDeviceID,&myDeviceInfo);
		if (ClassToWorkWith->rvResult !=CKR_OK)
		{
			cout<<"Cannot get info\n"<<endl;
			rvResult = ClassToWorkWith->rvResult;
			delete ClassToWorkWith;
			return rvResult;
		}
		if ((myDeviceInfo.ulFlags&PIN_NOT_SETTED)==PIN_NOT_SETTED)
		{
			cout<<"Old PIN not required\n"<<endl;
			OldPIN[0] = '\0';
		}
		else
		{
			cout<<"Enter old PIN: ";
			cin>>OldPIN;
		}
		cout<<"Enter new PIN: ";
		cin>>NewPIN;
		cout<<endl;
		ClassToWorkWith->ChangePIN(DeviceID,OldPIN,strlen(OldPIN),NewPIN,strlen(NewPIN));//123123123
	}
	if (ClassToWorkWith->rvResult!=CKR_OK)
	{
		cout<<"Error!\n"<<hex<<ClassToWorkWith->rvResult<<dec<<endl;
	}
	else cout<<"PIN was successfully changed\n"<<endl;
	rvResult = ClassToWorkWith->rvResult;
	delete ClassToWorkWith;
	return rvResult;
};
CK_RV Test_Init_Unblock()
{
	cout<<"Test_Init_Unblock\n"<<endl;
	CK_RV rvResult = CKR_OK;
	char DeviceID[10], PUK[32], NewPIN[32];
	CK_SLOT_ID ckDeviceID = 0;
	MY_DEVICE_INFO myDeviceInfo;
	InitializationClass *ClassToWorkWith = new InitializationClass();
	if (ClassToWorkWith->rvResult==CKR_OK)
	{
		cout<<"Enter Device ID: ";
		cin>>DeviceID;
		ClassToWorkWith->DeviceIsConnected(DeviceID,&ckDeviceID);
		if (ClassToWorkWith->rvResult !=CKR_OK)
		{
			cout<<"Device not connected\n"<<endl;
			rvResult = ClassToWorkWith->rvResult;
			delete ClassToWorkWith;
			return rvResult;
		}
		ClassToWorkWith->GetDeviceInfo(ckDeviceID,&myDeviceInfo);
		if (ClassToWorkWith->rvResult !=CKR_OK)
		{
			cout<<"Cannot get info\n"<<endl;
			rvResult = ClassToWorkWith->rvResult;
			delete ClassToWorkWith;
			return rvResult;
		}
		if ((myDeviceInfo.ulFlags&PIN_BLOCKED)!=PIN_BLOCKED)
		{
			cout<<"Device isn't blocked\n"<<endl;
			rvResult = ClassToWorkWith->rvResult;
			delete ClassToWorkWith;
			return rvResult;
		}
		cout<<"Enter PUK: ";
		cin>>PUK;
		cout<<"Enter new PIN: ";
		cin>>NewPIN;
		cout<<endl;
		ClassToWorkWith->UnblockDevice(DeviceID,PUK,strlen(PUK),(CK_UTF8CHAR_PTR)NewPIN,strlen(NewPIN));//123123123
	}
	if (ClassToWorkWith->rvResult!=CKR_OK)
	{
		cout<<"Error!\n"<<hex<<ClassToWorkWith->rvResult<<dec<<endl;
	}
	else cout<<"Device was successfully unlocked\n"<<endl;
	rvResult = ClassToWorkWith->rvResult;
	delete ClassToWorkWith;
	return rvResult;
};
CK_RV Test_Init_FormatWithPUK()
{
	cout<<"Test_Init_FormatWithPUK\n"<<endl;
	CK_RV rvResult = CKR_OK;
	CK_SLOT_ID ckDeviceID = 0;
	MY_DEVICE_INFO myDeviceInfo;
	char DeviceID[10], OldPIN[32];
	CK_UTF8CHAR pPUK[32];
	char pPUKBetterView[32];
	CK_ULONG ulPUKLen = 32, ulPinLen = 0;
	InitializationClass *ClassToWorkWith = new InitializationClass();
	if (ClassToWorkWith->rvResult==CKR_OK)
	{
		cout<<"Enter Device ID: ";
		cin>>DeviceID;
		ClassToWorkWith->DeviceIsConnected(DeviceID,&ckDeviceID);
		if ((ClassToWorkWith->rvResult !=CKR_OK)||(ClassToWorkWith->DeviceIsConnected(DeviceID,&ckDeviceID)==false))
		{
			cout<<"Device not connected\n"<<endl;
			rvResult = ClassToWorkWith->rvResult;
			delete ClassToWorkWith;
			return rvResult;
		}
		ClassToWorkWith->GetDeviceInfo(ckDeviceID,&myDeviceInfo);
		//here should be some code to check, if device is already formated with PUK and if auth parameters are setted
		if (!strcmp((char *)(myDeviceInfo.cDeviceType),SHIPKA_LITE))
		{
			cout<<"Enter PIN: ";
			cin>>OldPIN;
		}
		else
		{
			OldPIN[0] = '\0';
		}
		cout<<endl;
		
		ulPinLen = strlen((char *)OldPIN);
		ClassToWorkWith->FormatDevice(DeviceID,true,(CK_UTF8CHAR_PTR)OldPIN,ulPinLen,pPUK,&ulPUKLen);
	}
	if (ClassToWorkWith->rvResult!=CKR_OK)
	{
		cout<<"Error!\n"<<hex<<ClassToWorkWith->rvResult<<dec<<endl;
	}
	else
	{
		cout<<"Device was successfully formatted\n"<<endl;
		for(CK_ULONG i=0;i<ulPUKLen;i++)
		{
			if (pPUK[i]/0x10<10)	pPUKBetterView[2*i] = pPUK[i]/0x10 + '0';
			else					pPUKBetterView[2*i] = pPUK[i]/0x10 + 'A'-10;
			if (pPUK[i]%0x10<10)	pPUKBetterView[2*i+1] = pPUK[i]%0x10 + '0';
			else					pPUKBetterView[2*i+1] = pPUK[i]%0x10 + 'A'-10;
		}
		pPUKBetterView[ulPUKLen*2] = '\0';
		cout<<"PUK: "<<pPUKBetterView<<endl;
	}
	rvResult = ClassToWorkWith->rvResult;
	delete ClassToWorkWith;
	return rvResult;
};
CK_RV Test_Init_FormatWithoutPUK()
{
	cout<<"Test_Init_FormatWithoutPUK\n"<<endl;
	CK_RV rvResult = CKR_OK;
	CK_SLOT_ID ckDeviceID = 0;
	MY_DEVICE_INFO myDeviceInfo;
	char DeviceID[10], OldPIN[32];
	CK_ULONG ulPinLen = 0;
	InitializationClass *ClassToWorkWith = new InitializationClass();
	if (ClassToWorkWith->rvResult==CKR_OK)
	{
		cout<<"Enter Device ID: ";
		cin>>DeviceID;
		ClassToWorkWith->DeviceIsConnected(DeviceID,&ckDeviceID);
		if ((ClassToWorkWith->rvResult !=CKR_OK)||(ClassToWorkWith->DeviceIsConnected(DeviceID,&ckDeviceID)==false))
		{
			cout<<"Device not connected\n"<<endl;
			rvResult = ClassToWorkWith->rvResult;
			delete ClassToWorkWith;
			return rvResult;
		}
		ClassToWorkWith->GetDeviceInfo(ckDeviceID,&myDeviceInfo);
		//here should be some code to check, if device is already formated with PUK and if auth parameters are setted
		if (!strcmp((char *)(myDeviceInfo.cDeviceType),SHIPKA_LITE))
		{
			cout<<"Enter PIN: ";
			cin>>OldPIN;
		}
		else
		{
			OldPIN[0] = '\0';
		}
		cout<<endl;
		
		ulPinLen = strlen((char *)OldPIN);
		ClassToWorkWith->FormatDevice(DeviceID,false,(CK_UTF8CHAR_PTR)OldPIN,ulPinLen,NULL,NULL);
	}
	if (ClassToWorkWith->rvResult!=CKR_OK)
	{
		cout<<"Error!\n"<<hex<<ClassToWorkWith->rvResult<<dec<<endl;
	}
	else cout<<"Device was successfully formatted\n"<<endl;
	rvResult = ClassToWorkWith->rvResult;
	delete ClassToWorkWith;
	return rvResult;
};

