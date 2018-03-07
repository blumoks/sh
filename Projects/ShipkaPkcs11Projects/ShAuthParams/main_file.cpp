#include "cmd_functions.h"
#include <iostream>
#include <bitset>

using namespace std;

int main(int argc, char **argv)
{
	CommandLineWork *clsCLW = new CommandLineWork();
	if (clsCLW->GetCommandFromCommandLine(argc, argv)==false)
		return 1;
	//delete clsCLW;
	return 0;
}