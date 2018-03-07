#ifndef AUTH_CMD
#define AUTH_CMD
#include "ShAuthParams.h"

class CommandLineWork:public AuthParamsInit{
public:
	CommandLineWork();
	~CommandLineWork();
	
	bool GetCommandFromCommandLine(int argc, char **argv);
private:
	void PrintWorkResult(char *InFunction);
	void PrintDeviceInfo(CK_SLOT_ID ulSlotID);
	void PrintDeviceInfoEx(CK_SLOT_ID ulSlotID);
};

#endif