#include "stdafx.h"

TEST_F(InitAndFormatTest, FormatWithPukTest) 
{
	CHAR pcBuffer[4096];
	DWORD dwBufferSize = 0;
	printf("Starting %s%s...\n",INIT_EXE_NAME,GET_DEVICE_LIST_CMD);
	MakeProcWork(INIT_EXE_NAME,GET_DEVICE_LIST_CMD,pcBuffer,&dwBufferSize);
	ASSERT_NE(0,dwBufferSize) << "Cannot exec func";
	printf("Succeeded! Result: \n%s\n",pcBuffer);

	//endl makes \t to the line; need to owerride with _:
	for (int i = 0; i<strlen(pcBuffer); i++)
		if (pcBuffer[i] == 13)
			pcBuffer[i] = ' ';

	//need to make it be by strings:
	char *ppcBufferLines[16];
	memset(ppcBufferLines,0,sizeof(char *)*16);
	DWORD dwNumOfLines = 0;
	MakeBufferBeStrings(pcBuffer,ppcBufferLines,&dwNumOfLines);
	ASSERT_NE(0,dwNumOfLines) << "Cannot parse result";

	char pcTempString[4096];
	memset(pcTempString,0,4096);
	sprintf(pcTempString,"No devices are connected ");
	for (DWORD i = 0; i<dwNumOfLines; i++)
	{
		//printf ("%s\n",ppcBufferLines[i]);
		if (!strncmp("Function",ppcBufferLines[i],strlen("Function")))
		{
			sprintf(pcTempString,"Function%s succeeded! ",GET_DEVICE_LIST_CMD);
			ASSERT_STREQ(ppcBufferLines[i],pcTempString) << "Cannot get info!!!";
		}
	}
	ASSERT_STRNE("No devices are connected ",ppcBufferLines[0]) << "Connect device and try again";

	//getting device id:
	char pcDeviceId[16];
	memset(pcDeviceId,0,16);
	int iCounter = 0;
	while (ppcBufferLines[0][iCounter] != ' ')
		iCounter++;
	iCounter++;
	for (int i = iCounter; i<strlen(ppcBufferLines[0]); i++)
		if (ppcBufferLines[0][i] == ' ')
			break;
		else
			pcDeviceId[i-iCounter] = ppcBufferLines[0][i];
	//trying to format device with PUK
	sprintf(pcTempString,"%s %s%s",FORMAT_CMD,pcDeviceId,WITH_PUK_CMP);
	printf("Starting %s%s...\n",INIT_EXE_NAME,pcTempString);
	MakeProcWork(INIT_EXE_NAME,pcTempString,pcBuffer,&dwBufferSize);
	ASSERT_NE(0,dwBufferSize) << "Cannot exec func";
	printf("Succeeded! Result: \n%s\n",pcBuffer);
}

