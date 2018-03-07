#include "cmd_func.h"
using namespace std;

int main (int argc, char **argv)
{
	CmdFunctionsClassForEncSig *NuClass = new CmdFunctionsClassForEncSig();
	if (NuClass->rvResult != CKR_OK)
	{
		cout<<"Cannot init work with ShEncSig library"<<endl
			<<"Terminating..."<<endl;
		goto MAIN_FINALIZATION;
	}
	NuClass->GetCmdFromCmdLine(argc - 1, argv + 1);

MAIN_FINALIZATION:
	delete NuClass;
	return 0;
}