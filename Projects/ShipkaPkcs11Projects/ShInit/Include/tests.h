#pragma once
#include "cmd_functions.h"
#include "Init_y_Format.h"
#include <iostream>
#include <bitset>

CK_RV Test_Low_GetInfo();
CK_RV Test_Init_GetInfo();
CK_RV Test_Init_ChangePIN();
CK_RV Test_Init_Unblock();
CK_RV Test_Init_FormatWithPUK();
CK_RV Test_Init_FormatWithoutPUK();
