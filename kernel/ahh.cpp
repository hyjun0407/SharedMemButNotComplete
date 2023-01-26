#include "ahh.h"
#include <cstdint>
#include <ntifs.h>
#include <minwindef.h>
#include <ntimage.h>


typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS,
* PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void);

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;


typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

extern "C" __declspec(dllimport)
NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, PULONG ProtectSize, ULONG NewProtect, PULONG OldProtect);

extern "C" NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineNam);

extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

extern "C" NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);



extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

typedef struct _MEMORY_STRUCT
{
	BYTE type;
	LONG usermode_pid;
	LONG target_pid;
	ULONG64 base_address;
	void* address;
	LONG size;
	void* output;
	ULONG magic;
}MEMORY_STRUCT;
typedef unsigned long _DWORD, * PDWORD, * LPDWORD;
typedef unsigned short WORD, * PWORD, * LPWORD;
typedef unsigned __int64 _QWORD;
typedef struct _HANDLE_TABLE_ENTRY_INFO
{
	ULONG AuditMask;
} HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;

typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		PVOID Object;
		ULONG ObAttributes;
		PHANDLE_TABLE_ENTRY_INFO InfoTable;
		ULONG Value;
	};
	union
	{
		ULONG GrantedAccess;
		struct
		{
			WORD GrantedAccessIndex;
			WORD CreatorBackTraceIndex;
		};
		LONG NextFreeTableEntry;
	};
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;
typedef struct _DUMP_HEADER {
	ULONG Signature;
	ULONG ValidDump;
	ULONG MajorVersion;
	ULONG MinorVersion;
	ULONG_PTR DirectoryTableBase;
	ULONG_PTR PfnDataBase;
	PLIST_ENTRY PsLoadedModuleList;
	PLIST_ENTRY PsActiveProcessHead;
	ULONG MachineImageType;
	ULONG NumberProcessors;
	ULONG BugCheckCode;
	ULONG_PTR BugCheckParameter1;
	ULONG_PTR BugCheckParameter2;
	ULONG_PTR BugCheckParameter3;
	ULONG_PTR BugCheckParameter4;
	CHAR VersionUser[32];
#ifndef _WIN64
	ULONG PaeEnabled;
#endif// !_WIN64

	struct _KDDEBUGGER_DATA64* KdDebuggerDataBlock;
} DUMP_HEADER, * PDUMP_HEADER;
typedef struct _DBGKD_DEBUG_DATA_HEADER64

{

	LIST_ENTRY64    List;

	ULONG           OwnerTag;   //"KDBG"

	ULONG           Size;

}DBGKD_DEBUG_DATA_HEADER64, * PDBGKD_DEBUG_DATA_HEADER64;
typedef struct _KDDEBUGGER_DATA64 {
	DBGKD_DEBUG_DATA_HEADER64 Header;

	ULONG64 KernBase;

	ULONG64 BreakpointWithStatus; // address of breakpoint

	ULONG64 SavedContext;

	USHORT ThCallbackStack; // offset in thread data

	//
	// these values are offsets into that frame:
	//

	USHORT NextCallback; // saved pointer to next callback frame
	USHORT FramePointer; // saved frame pointer

	//
	// pad to a quad boundary
	//
	USHORT PaeEnabled;

	//
	// Address of the kernel callout routine.
	//

	ULONG64 KiCallUserMode; // kernel routine

	//
	// Address of the usermode entry point for callbacks.
	//

	ULONG64 KeUserCallbackDispatcher; // address in ntdll

	//
	// Addresses of various kernel data structures and lists
	// that are of interest to the kernel debugger.
	//

	ULONG64 PsLoadedModuleList;
	ULONG64 PsActiveProcessHead;
	ULONG64 PspCidTable;

	ULONG64 ExpSystemResourcesList;
	ULONG64 ExpPagedPoolDescriptor;
	ULONG64 ExpNumberOfPagedPools;

	ULONG64 KeTimeIncrement;
	ULONG64 KeBugCheckCallbackListHead;
	ULONG64 KiBugcheckData;

	ULONG64 IopErrorLogListHead;

	ULONG64 ObpRootDirectoryObject;
	ULONG64 ObpTypeObjectType;

	ULONG64 MmSystemCacheStart;
	ULONG64 MmSystemCacheEnd;
	ULONG64 MmSystemCacheWs;

	ULONG64 MmPfnDatabase;
	ULONG64 MmSystemPtesStart;
	ULONG64 MmSystemPtesEnd;
	ULONG64 MmSubsectionBase;
	ULONG64 MmNumberOfPagingFiles;

	ULONG64 MmLowestPhysicalPage;
	ULONG64 MmHighestPhysicalPage;
	ULONG64 MmNumberOfPhysicalPages;

	ULONG64 MmMaximumNonPagedPoolInBytes;
	ULONG64 MmNonPagedSystemStart;
	ULONG64 MmNonPagedPoolStart;
	ULONG64 MmNonPagedPoolEnd;

	ULONG64 MmPagedPoolStart;
	ULONG64 MmPagedPoolEnd;
	ULONG64 MmPagedPoolInformation;
	ULONG64 MmPageSize;

	ULONG64 MmSizeOfPagedPoolInBytes;

	ULONG64 MmTotalCommitLimit;
	ULONG64 MmTotalCommittedPages;
	ULONG64 MmSharedCommit;
	ULONG64 MmDriverCommit;
	ULONG64 MmProcessCommit;
	ULONG64 MmPagedPoolCommit;
	ULONG64 MmExtendedCommit;

	ULONG64 MmZeroedPageListHead;
	ULONG64 MmFreePageListHead;
	ULONG64 MmStandbyPageListHead;
	ULONG64 MmModifiedPageListHead;
	ULONG64 MmModifiedNoWritePageListHead;
	ULONG64 MmAvailablePages;
	ULONG64 MmResidentAvailablePages;

	ULONG64 PoolTrackTable;
	ULONG64 NonPagedPoolDescriptor;

	ULONG64 MmHighestUserAddress;
	ULONG64 MmSystemRangeStart;
	ULONG64 MmUserProbeAddress;

	ULONG64 KdPrintCircularBuffer;
	ULONG64 KdPrintCircularBufferEnd;
	ULONG64 KdPrintWritePointer;
	ULONG64 KdPrintRolloverCount;

	ULONG64 MmLoadedUserImageList;

	// NT 5.1 Addition

	ULONG64 NtBuildLab;
	ULONG64 KiNormalSystemCall;

	// NT 5.0 hotfix addition

	ULONG64 KiProcessorBlock;
	ULONG64 MmUnloadedDrivers;
	ULONG64 MmLastUnloadedDriver;
	ULONG64 MmTriageActionTaken;
	ULONG64 MmSpecialPoolTag;
	ULONG64 KernelVerifier;
	ULONG64 MmVerifierData;
	ULONG64 MmAllocatedNonPagedPool;
	ULONG64 MmPeakCommitment;
	ULONG64 MmTotalCommitLimitMaximum;
	ULONG64 CmNtCSDVersion;

	// NT 5.1 Addition

	ULONG64 MmPhysicalMemoryBlock;
	ULONG64 MmSessionBase;
	ULONG64 MmSessionSize;
	ULONG64 MmSystemParentTablePage;

	// Server 2003 addition

	ULONG64 MmVirtualTranslationBase;
	USHORT OffsetKThreadNextProcessor;
	USHORT OffsetKThreadTeb;
	USHORT OffsetKThreadKernelStack;
	USHORT OffsetKThreadInitialStack;

	USHORT OffsetKThreadApcProcess;
	USHORT OffsetKThreadState;
	USHORT OffsetKThreadBStore;
	USHORT OffsetKThreadBStoreLimit;

	USHORT SizeEProcess;
	USHORT OffsetEprocessPeb;
	USHORT OffsetEprocessParentCID;
	USHORT OffsetEprocessDirectoryTableBase;

	USHORT SizePrcb;
	USHORT OffsetPrcbDpcRoutine;
	USHORT OffsetPrcbCurrentThread;
	USHORT OffsetPrcbMhz;

	USHORT OffsetPrcbCpuType;
	USHORT OffsetPrcbVendorString;
	USHORT OffsetPrcbProcStateContext;
	USHORT OffsetPrcbNumber;

	USHORT SizeEThread;

	ULONG64 KdPrintCircularBufferPtr;
	ULONG64 KdPrintBufferSize;

	ULONG64 KeLoaderBlock;

	USHORT SizePcr;
	USHORT OffsetPcrSelfPcr;
	USHORT OffsetPcrCurrentPrcb;
	USHORT OffsetPcrContainedPrcb;

	USHORT OffsetPcrInitialBStore;
	USHORT OffsetPcrBStoreLimit;
	USHORT OffsetPcrInitialStack;
	USHORT OffsetPcrStackLimit;

	USHORT OffsetPrcbPcrPage;
	USHORT OffsetPrcbProcStateSpecialReg;
	USHORT GdtR0Code;
	USHORT GdtR0Data;

	USHORT GdtR0Pcr;
	USHORT GdtR3Code;
	USHORT GdtR3Data;
	USHORT GdtR3Teb;

	USHORT GdtLdt;
	USHORT GdtTss;
	USHORT Gdt64R3CmCode;
	USHORT Gdt64R3CmTeb;

	ULONG64 IopNumTriageDumpDataBlocks;
	ULONG64 IopTriageDumpDataBlocks;

	// Longhorn addition

	ULONG64 VfCrashDataBlock;
	ULONG64 MmBadPagesDetected;
	ULONG64 MmZeroedPageSingleBitErrorsDetected;

	// Windows 7 addition

	ULONG64 EtwpDebuggerData;
	USHORT OffsetPrcbContext;

	// Windows 8 addition

	USHORT OffsetPrcbMaxBreakpoints;
	USHORT OffsetPrcbMaxWatchpoints;

	ULONG OffsetKThreadStackLimit;
	ULONG OffsetKThreadStackBase;
	ULONG OffsetKThreadQueueListEntry;
	ULONG OffsetEThreadIrpList;

	USHORT OffsetPrcbIdleThread;
	USHORT OffsetPrcbNormalDpcState;
	USHORT OffsetPrcbDpcStack;
	USHORT OffsetPrcbIsrStack;

	USHORT SizeKDPC_STACK_FRAME;

	// Windows 8.1 Addition

	USHORT OffsetKPriQueueThreadListHead;
	USHORT OffsetKThreadWaitReason;

	// Windows 10 RS1 Addition

	USHORT Padding;
	ULONG64 PteBase;

	// Windows 10 RS5 Addition

	ULONG64 RetpolineStubFunctionTable;
	ULONG RetpolineStubFunctionTableSize;
	ULONG RetpolineStubOffset;
	ULONG RetpolineStubSize;
} KDDEBUGGER_DATA64, * PKDDEBUGGER_DATA64;
typedef struct _HANDLE_TRACE_DB_ENTRY
{
	CLIENT_ID ClientId;
	PVOID Handle;
	ULONG Type;
	VOID* StackTrace[16];
} HANDLE_TRACE_DB_ENTRY, * PHANDLE_TRACE_DB_ENTRY;
typedef struct _HANDLE_TRACE_DEBUG_INFO
{
	LONG RefCount;
	ULONG TableSize;
	ULONG BitMaskFlags;
	FAST_MUTEX CloseCompactionLock;
	ULONG CurrentStackIndex;
	HANDLE_TRACE_DB_ENTRY TraceDb[1];
} HANDLE_TRACE_DEBUG_INFO, * PHANDLE_TRACE_DEBUG_INFO;

typedef struct _HANDLE_TABLE
{
	ULONG TableCode;
	PEPROCESS QuotaProcess;
	PVOID UniqueProcessId;
	EX_PUSH_LOCK HandleLock;
	LIST_ENTRY HandleTableList;
	EX_PUSH_LOCK HandleContentionEvent;
	PHANDLE_TRACE_DEBUG_INFO DebugInfo;
	LONG ExtraInfoPages;
	ULONG Flags;
	ULONG StrictFIFO : 1;
	LONG FirstFreeHandle;
	PHANDLE_TABLE_ENTRY LastFreeHandleEntry;
	LONG HandleCount;
	ULONG NextHandleNeedingPool;
} HANDLE_TABLE, * PHANDLE_TABLE;

auto ThreadListHead1 = 0x5E0;
auto ThreadListEntry = 0x4E8;
typedef bool(__fastcall* fn_ExDestroyHandle)(PHANDLE_TABLE, HANDLE, PHANDLE_TABLE_ENTRY);
PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(const ULONG64* pHandleTable, const LONGLONG Handle)
{
	ULONGLONG v2; // rdx
	LONGLONG v3; // r8

	v2 = Handle & 0xFFFFFFFFFFFFFFFC;
	if (v2 >= *pHandleTable)
		return 0;
	v3 = *(pHandleTable + 1);
	if ((v3 & 3) == 1)
		return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<ULONG_PTR*>(v3 + 8 * (v2 >> 10) - 1) + 4 * (v2 & 0x3FF));
	if ((v3 & 3) != 0)
		return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<ULONG_PTR*>(*reinterpret_cast<ULONG_PTR*>(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF)) + 4 * (v2 & 0x3FF));
	return reinterpret_cast<PHANDLE_TABLE_ENTRY>(v3 + 4 * v2);
}
PVOID GetSystemBaseModule(const char* module_name)
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	if (!bytes) return 0;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x504D5448);

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status)) return 0;

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	PVOID module_base = 0, module_size = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (strcmp((char*)module[i].FullPathName, module_name) == 0)
		{
			module_base = module[i].ImageBase;
			module_size = (PVOID)module[i].ImageSize;
			break;
		}
	}

	if (modules) ExFreePoolWithTag(modules, 0);
	if (module_base <= 0) return 0;
	return module_base;
}
#ifndef _WIN64
#define KDDEBUGGER_DATA_OFFSET 0x1068
#else
#define KDDEBUGGER_DATA_OFFSET 0x2080
#endif 
extern "C"
{

	ULONG
		NTAPI
		KeCapturePersistentThreadState(
			IN PCONTEXT Context,
			IN PKTHREAD Thread,
			IN ULONG BugCheckCode,
			IN ULONG BugCheckParameter1,
			IN ULONG BugCheckParameter2,
			IN ULONG BugCheckParameter3,
			IN ULONG BugCheckParameter4,
			OUT PVOID VirtualAddress
		);

}
typedef struct _KDDEBUGGER_DATA_ADDITION64
{
	ULONG64   VfCrashDataBlock;
	ULONG64   MmBadPagesDetected;
	ULONG64   MmZeroedPageSingleBitErrorsDetected;
	ULONG64   EtwpDebuggerData;
	USHORT    OffsetPrcbContext;
	USHORT    OffsetPrcbMaxBreakpoints;
	USHORT    OffsetPrcbMaxWatchpoints;
	ULONG     OffsetKThreadStackLimit;
	ULONG     OffsetKThreadStackBase;
	ULONG     OffsetKThreadQueueListEntry;
	ULONG     OffsetEThreadIrpList;
	USHORT    OffsetPrcbIdleThread;
	USHORT    OffsetPrcbNormalDpcState;
	USHORT    OffsetPrcbDpcStack;
	USHORT    OffsetPrcbIsrStack;
	USHORT    SizeKDPC_STACK_FRAME;
	USHORT    OffsetKPriQueueThreadListHead;
	USHORT    OffsetKThreadWaitReason;
	USHORT    Padding;
	ULONG64   PteBase;
	ULONG64   RetpolineStubFunctionTable;
	ULONG     RetpolineStubFunctionTableSize;
	ULONG     RetpolineStubOffset;
	ULONG     RetpolineStubSize;
}KDDEBUGGER_DATA_ADDITION64, * PKDDEBUGGER_DATA_ADDITION64;

#ifndef _WIN64
#define DUMP_BLOCK_SIZE 0x20000
#else
#define DUMP_BLOCK_SIZE 0x40000
#endif 
KDDEBUGGER_DATA64 kd_block;
KDDEBUGGER_DATA_ADDITION64 kd_add_block;

VOID NTAPI sex::debugger_initialize()
{
	CONTEXT context = { 0 };
	PDUMP_HEADER dump_header = NULL;

	PKDDEBUGGER_DATA64 kd_debugger_data_block = NULL;
	PKDDEBUGGER_DATA_ADDITION64 kd_debugger_data_addition_block = NULL;

	context.ContextFlags = CONTEXT_FULL;
	RtlCaptureContext(&context);
	dump_header = (PDUMP_HEADER)ExAllocatePool(NonPagedPool, DUMP_BLOCK_SIZE);

	if (NULL != dump_header)
	{
		KeCapturePersistentThreadState(&context, NULL, 0, 0, 0, 0, 0, dump_header);
#pragma warning(disable : 4133)
		kd_debugger_data_block = (PKDDEBUGGER_DATA64)((PUCHAR)dump_header + KDDEBUGGER_DATA_OFFSET);
#pragma warning(default : 4133)
		RtlCopyMemory(&kd_block, kd_debugger_data_block, sizeof(KDDEBUGGER_DATA64));
		kd_debugger_data_addition_block = (PKDDEBUGGER_DATA_ADDITION64)(kd_debugger_data_block + 1);
		RtlCopyMemory(&kd_add_block, kd_debugger_data_addition_block, sizeof(KDDEBUGGER_DATA_ADDITION64));
		ExFreePoolWithTag(dump_header, 0);
	}
}
void sex::DestroyPspCidTableEntry(HANDLE ThreadID)
{
	if (kd_block.PspCidTable) {
		ULONG64* pHandleTable = reinterpret_cast<ULONG64*>(*(uint64_t*)kd_block.PspCidTable);
		PHANDLE_TABLE_ENTRY pCidEntry = NULL;
		pCidEntry = (PHANDLE_TABLE_ENTRY)ExpLookupHandleTableEntry(pHandleTable, reinterpret_cast<LONGLONG>(ThreadID));
		if (pCidEntry != NULL)
		{
			uint64_t aa = (uint64_t)GetSystemBaseModule("\\SystemRoot\\system32\\ntoskrnl.exe");
			if (aa != NULL) {
				aa = aa + 0x69A9B8;

				auto func = (fn_ExDestroyHandle)(aa);

				func(reinterpret_cast<PHANDLE_TABLE>(pHandleTable), ThreadID, pCidEntry);

				RtlZeroMemory(pCidEntry, 0x10);
			}
			else {
			}
		}
		else {
		}
	}
	else {
	}
}
void sex::DestroyThreadListEntry()
{
	PETHREAD CurrentThread = KeGetCurrentThread();
	auto CurrentProcess = IoGetCurrentProcess();
	PLIST_ENTRY ThreadListHead = 0;
	ThreadListHead = (PLIST_ENTRY)((ULONG64)CurrentProcess + ThreadListHead1);
	PLIST_ENTRY ThreadList = ThreadListHead;

	while ((ThreadList = ThreadList->Flink) != ThreadListHead)
	{
		PETHREAD Thread = (PETHREAD)((ULONG64)ThreadList - ThreadListEntry);
		if (Thread == CurrentThread)
		{
			RemoveEntryList(ThreadList);
			break;
		}
	}
}