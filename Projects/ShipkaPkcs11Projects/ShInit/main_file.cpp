#include "cmd_functions.h"
#include "tests.h"
#include <iostream>
#include <bitset>

using namespace std;

int main(int argc, char **argv)
{
	CommandLineWork *clsCLW = new CommandLineWork();

	if (clsCLW->GetCommandFromCommandLine(argc, argv)==false)
		printf("Wrong input data! Terminating...\n");
		
	//Test_Init_GetInfo();
	//Test_Init_ChangePIN();
	//Test_Init_Unblock();
	//Test_Init_FormatWithoutPUK();
	//Test_Init_FormatWithPUK();
	return 0;
};
