#include "stdafx.h"

void MakeProcWork(char *pcFileName, char *pcCommandLine, CHAR *pcOutputBuf, DWORD *dwOutputBufSize)
{
	HANDLE hProc_IN_Rd = NULL;
	HANDLE hProc_IN_Wr = NULL;
	HANDLE hProc_OUT_Rd = NULL;
	HANDLE hProc_OUT_Wr = NULL;
	SECURITY_ATTRIBUTES saAttr; 
	*dwOutputBufSize = 0;

	//filling security attributes
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
	saAttr.bInheritHandle = TRUE; 
	saAttr.lpSecurityDescriptor = NULL; 
	
	//creating pipe for input and output
	ASSERT_TRUE ( CreatePipe(&hProc_OUT_Rd, &hProc_OUT_Wr, &saAttr, 0) ) << "Cannot create pipe stdout"; 

	// Ensure the read handle to the pipe for STDOUT is not inherited.
	ASSERT_TRUE ( SetHandleInformation(hProc_OUT_Rd, HANDLE_FLAG_INHERIT, 0) ) << "Pipe is inherited"; 

	ASSERT_TRUE ( CreatePipe(&hProc_IN_Rd, &hProc_IN_Wr, &saAttr, 0)) << "Cannot create pipe stdin";

	// Ensure the write handle to the pipe for STDIN is not inherited. 
	ASSERT_TRUE ( SetHandleInformation(hProc_IN_Wr, HANDLE_FLAG_INHERIT, 0) )<< "Pipe is inherited";

	PROCESS_INFORMATION piProcInfo; 
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE; 

	//creating process
	// Set up members of the PROCESS_INFORMATION structure. 
	ZeroMemory( &piProcInfo, sizeof(PROCESS_INFORMATION) );
	// Set up members of the STARTUPINFO structure. 
	// This structure specifies the STDIN and STDOUT handles for redirection.
	ZeroMemory( &siStartInfo, sizeof(STARTUPINFO) );
	siStartInfo.cb = sizeof(STARTUPINFO); 
	siStartInfo.hStdError = hProc_OUT_Wr;
	siStartInfo.hStdOutput = hProc_OUT_Wr;
	siStartInfo.hStdInput = hProc_IN_Rd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
 
	// Create the child process. 
	bSuccess = CreateProcess(pcFileName, pcCommandLine, NULL, NULL, 
								TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo);

	// If an error occurs, exit the application. 
	ASSERT_TRUE ( bSuccess ) << "Cannot create process";

	// Close handles to the child process and its primary thread.
	// Some applications might keep these handles to monitor the status
	// of the child process, for example. 
	CloseHandle(piProcInfo.hProcess);
	CloseHandle(piProcInfo.hThread);
	//getting data from pipe
	DWORD dwRead = 0;
	CHAR chBuf[4096]; 
	CHAR *pcTempChBuf = chBuf;
	for (;;)
	{
		bSuccess = ReadFile( hProc_OUT_Rd, pcTempChBuf, 4096, &dwRead, NULL);
		if ((dwRead==0)||(!bSuccess))
			break;
		if ((dwRead == 1)&&(pcTempChBuf[0] == ' '))
		{
			*(pcTempChBuf - 2) = 0;
			break;
		}
		pcTempChBuf[dwRead] = '\n';
		pcTempChBuf += dwRead;
		WriteFile(hProc_OUT_Wr, " ", 1, &dwRead, NULL);
	}
	ASSERT_FALSE (pcTempChBuf == chBuf) << "Cannot read pipe";
	
	//deleting pipes
	CloseHandle(hProc_OUT_Wr);
	CloseHandle(hProc_OUT_Rd);
	CloseHandle(hProc_IN_Wr);
	CloseHandle(hProc_IN_Rd);
	
	//analizing results
	//printf("%s\n",chBuf);
	*dwOutputBufSize = strlen(chBuf)+1;
	if (pcOutputBuf)
	{
		memcpy(pcOutputBuf,chBuf,*dwOutputBufSize);
	}
};
void MakeBufferBeStrings(CHAR *pcBuffer, CHAR **ppcLines, DWORD *dwNumOfLines)
{
	*dwNumOfLines = 0;
	ppcLines[*dwNumOfLines] = pcBuffer;
	(*dwNumOfLines)++;
	for (int i = 0; i<strlen(pcBuffer); i++)
	{
		if (pcBuffer[i] == '\n')
		{
			if (pcBuffer[i+1]!=0)
				ppcLines[*dwNumOfLines] = &(pcBuffer[i+1]);
			(*dwNumOfLines)++;
			pcBuffer[i] = 0;
		}
	}
};