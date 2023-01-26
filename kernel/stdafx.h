#pragma once
#pragma warning( disable : 4099 )

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <wdf.h>
#include <ntimage.h>
#include <intrin.h>

#include "Utils.h"
#include "CallbackHandler.h"

#define print(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, ##__VA_ARGS__) //dont use "\n"
