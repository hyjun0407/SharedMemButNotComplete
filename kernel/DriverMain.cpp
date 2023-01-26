#include "stdafx.h"
#include "ahh.h"

UNICODE_STRING RegPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\ucflash");
PVOID SharedBuffer = 0;
UINT SharedPid = 0;
ULONG64 NewMaggicCode = DEFAULT_MAGGICCODE;
sex mew;
BOOL f = false;
/*switch (data.Type)
{
	CallbackHandler(WRITE);
	CallbackHandler(READ);
	CallbackHandler(PROTECT);
	CallbackHandler(ALLOC);
	CallbackHandler(FREE);
	CallbackHandler(MODULE);
	CallbackHandler(MAINBASE);
}*/
void NTAPI HookControl(void*) {
	//mew.DestroyThreadListEntry();
	//mew.DestroyPspCidTableEntry(PsGetCurrentThreadId());
	while (TRUE) {
		PEPROCESS process = NULL;
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)SharedPid, &process);
		if (NT_SUCCESS(status) && process) {
			REQUEST_DATA data;
			SIZE_T outSize = 0; //need to, if not == crash!
			if (NT_SUCCESS(MmCopyVirtualMemory(process, (void*)SharedBuffer, PsGetCurrentProcess(), &data, (SIZE_T)sizeof(REQUEST_DATA), KernelMode, &outSize))) {
				if (data.MaggicCode == NewMaggicCode) {
					if (data.isgo) {
						MmCopyVirtualMemory(PsGetCurrentProcess(), &f, process, data.isgoad, (SIZE_T)sizeof(BOOL), KernelMode, &outSize);
						PEPROCESS pProcess = NULL;
						REQUEST_MAINBASE args;
						RtlCopyMemory(&args, data.Arguments, sizeof(args));
						print("[+] dd: %d", args.ProcessId);
						print("[+] dcd: 0x%llX", args.OutAddress);
						//NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)args->ProcessId, &pProcess);
						//auto base = PsGetProcessSectionBaseAddress(pProcess);
						//RtlCopyMemory(args->OutAddress, &base, sizeof(base));
						//ObDereferenceObject(pProcess);
					}
				}
			}
		}

		else {
			SharedBuffer = (PVOID)Utils::Registry::ReadRegistry<LONG64>(RegPath, RTL_CONSTANT_STRING(L"xxx"));
			SharedPid = (UINT)Utils::Registry::ReadRegistry<LONG64>(RegPath, RTL_CONSTANT_STRING(L"xx"));
			print("[+] New SharedBuffer: 0x%llX", SharedBuffer);
			print("[+] New SharedPid: 0x%llX", SharedPid);
		}
	}

}

extern "C" NTSTATUS DriversMaain(
	PDRIVER_OBJECT  driver_object,
	PUNICODE_STRING registry_path
)
{
	// These are invalid for mapped drivers.
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);
	HANDLE thread_handle;
	SharedBuffer = (PVOID)Utils::Registry::ReadRegistry<LONG64>(RegPath, RTL_CONSTANT_STRING(L"xxx"));
	SharedPid = (UINT)Utils::Registry::ReadRegistry<LONG64>(RegPath, RTL_CONSTANT_STRING(L"xx"));
	const auto status = PsCreateSystemThread(
		&thread_handle,
		GENERIC_ALL,
		nullptr,
		nullptr,
		nullptr,
		HookControl,
		nullptr
	);
	if (!NT_SUCCESS(status))
	{
		return STATUS_UNSUCCESSFUL;
	}

	ZwClose(thread_handle);
	return STATUS_SUCCESS;
}