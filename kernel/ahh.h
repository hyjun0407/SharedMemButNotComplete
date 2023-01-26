#pragma once
#include <ntdef.h>
class sex
{
public:
	VOID NTAPI debugger_initialize();
	void DestroyThreadListEntry();
	void DestroyPspCidTableEntry(HANDLE ThreadID);
private:
};