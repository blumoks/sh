#include "User_level_functions.h"
#include <iostream>
#include <bitset>

using namespace std;

int main(int argc, char **argv)
{
	if (argc < 3)
		return -1;
	char **temp = NULL;
	char *pcDeviceID = argv[1];
	MY_PIN_PARAMS sMyPin;
	strncpy((char *)(sMyPin.pcPinValue),argv[2], strlen(argv[2]));
	sMyPin.ulPinLength = strlen((char *)sMyPin.pcPinValue);

	UserFunctionality *NuClass = new UserFunctionality(pcDeviceID,sMyPin);

	if (NuClass->rvResult == CKR_OK)
		printf("Login succeeded\n");
	else if (NuClass->rvResult == CKR_PIN_INCORRECT)
		printf("Login failed: wrong PIN\n");
	else 
	{
		printf("Cannot init work with device\n");
		NuClass->~UserFunctionality();
		return 1;
	}

	if (argc > 4)
		temp = argv + 4;
	else
		temp = NULL;
	if (!strcmp(argv[3],GEN_SEC_KEY))
	{
		NuClass->GenerateSecKeyByStringAttributes(temp, argc - 4);
	}
	else if (!strcmp(argv[3],GEN_KEY_PAIR))
	{
		NuClass->GenerateKeyPairByStringAttributes(temp, argc - 4);
	}
	else if (!strcmp(argv[3],DELETE_KEYS))
	{
		NuClass->DeleteKeysByStringAttributes(temp, argc - 4);
	}
	else if (!strcmp(argv[3],EXPORT_PUBKEY_TO_FILE))
	{
		NuClass->ExportPublicToFile(temp, argc - 4);
	}
	else if (!strcmp(argv[3],EXPORT_KEY_TO_FILE))
	{
		NuClass->ExportSecPriToFile(temp, argc - 4);
	}
	else if (!strcmp(argv[3],IMPORT_KEY_FROM_FILE))
	{
		NuClass->ImportSecPriFromFile(temp, argc - 4);
	}
	else if (!strcmp(argv[3],IMPORT_PUBKEY_FROM_FILE))
	{
		NuClass->ImportPublicFromFile(temp, argc - 4);
	}
	else if (!strcmp(argv[3],GET_KEYS_LIST))
	{
		char **pcKeyInfoList = NULL;
		CK_ULONG ulKeyNum = 0;
		NuClass->GetKeysInfoListByStringAttributes(temp, argc - 4,pcKeyInfoList,&ulKeyNum);
		if (NuClass->rvResult != CKR_OK)
		{
			printf("Error: 0x%8.8x\n",NuClass->rvResult);
			NuClass->~UserFunctionality();
			return -1;
		}
		if (ulKeyNum)
		{
			pcKeyInfoList = (char **) malloc (sizeof (char *) * ulKeyNum);
			for (CK_ULONG i = 0; i<ulKeyNum; i++)
			{
				pcKeyInfoList[i] = ( char *) malloc (256);
			}
			NuClass->GetKeysInfoListByStringAttributes(temp, argc - 4,pcKeyInfoList,&ulKeyNum);
			if (NuClass->rvResult != CKR_OK)
			{
				for (CK_ULONG i = 0; i<ulKeyNum; i++)
				{
					if (pcKeyInfoList[i]) free (pcKeyInfoList[i]);
				}
				if (pcKeyInfoList) free (pcKeyInfoList);
				printf("Error: 0x%8.8x\n",NuClass->rvResult);
				NuClass->~UserFunctionality();
				return -1;
			}
			printf ("Keys:\n");
			for (CK_ULONG i = 0; i<ulKeyNum; i++)
			{
				printf ("%s\n",pcKeyInfoList[i]);
			}
			for (CK_ULONG i = 0; i<ulKeyNum; i++)
			{
				if (pcKeyInfoList[i]) free (pcKeyInfoList[i]);
			}
			if (pcKeyInfoList) free (pcKeyInfoList);
		}
		else
		{
			printf ("No keys!\n");
		}
	}
	else if (!strcmp(argv[3],EXPORT_PUBLIC_KEY))
	{
		CK_BYTE *pbExportedKey = NULL;
		CK_ULONG ulExportedKeyLen = 0;
		NuClass->ExportPublicKeyByStringAttributes(temp, argc - 4, pbExportedKey, &ulExportedKeyLen);
		if (NuClass->rvResult == CKR_OK)
		{
			if (NULL == (pbExportedKey = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * ulExportedKeyLen)))
			{
				NuClass->rvResult = MEMORY_NOT_ALLOCATED;
			}
			else
			{
				NuClass->ExportPublicKeyByStringAttributes(temp, argc - 4, pbExportedKey, &ulExportedKeyLen);
				if (NuClass->rvResult == CKR_OK)
				{
					printf ("Exported key: \n");
					for (CK_ULONG i = 0; i<ulExportedKeyLen; i++)
					{
						printf ("%2.2x",pbExportedKey[i]);
						if (i%36 == 35) printf("\n");
						else if (i%4 == 3) printf(" ");
					}
					printf ("\n");
				}
			}
			if (pbExportedKey) free (pbExportedKey);
		}		
	}
	else if (!strcmp(argv[3],EXPORT_SEC_PRI_KEY))
	{
		CK_BYTE *pbExportedKey = NULL;
		CK_ULONG ulExportedKeyLen = 0;
		NuClass->ExportSecPriKeyByStringAttributes(temp, argc - 4, pbExportedKey, &ulExportedKeyLen);
		if (NuClass->rvResult == CKR_OK)
		{
			if (NULL == (pbExportedKey = (CK_BYTE_PTR) malloc (sizeof (CK_BYTE) * ulExportedKeyLen)))
			{
				NuClass->rvResult = MEMORY_NOT_ALLOCATED;
			}
			else
			{
				NuClass->ExportSecPriKeyByStringAttributes(temp, argc - 4, pbExportedKey, &ulExportedKeyLen);
				if (NuClass->rvResult == CKR_OK)
				{
					printf ("Exported key: \n");
					for (CK_ULONG i = 0; i<ulExportedKeyLen; i++)
					{
						printf ("%2.2x",pbExportedKey[i]);
						if (i%36 == 35) printf("\n");
						else if (i%4 == 3) printf(" ");
					}
					printf ("\n");
				}
			}
			if (pbExportedKey) free (pbExportedKey);
		}		
	}
	else
	{
		NuClass->rvResult = 0xFFFFFFFF;
	}
	printf("Result: 0x%8.8x\n",NuClass->rvResult);
//*/
	NuClass->~UserFunctionality();
	return 0;
};