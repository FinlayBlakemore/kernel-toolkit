#pragma once

#define _DebugLogFunctionName printf("["); printf(__FUNCTION__); printf("] ");
#define DebugLog(Message, ...) _DebugLogFunctionName printf(Message, __VA_ARGS__);
#define DebugErrorLog() _DebugLogFunctionName printf("Error on line: %i\n", __LINE__)