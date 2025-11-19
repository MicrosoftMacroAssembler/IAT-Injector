#include "../../includes/includes.hpp"

typedef union _pte
{
	unsigned __int64 value;
	struct
	{
		unsigned __int64 present : 1;          // Must be 1, region invalid if 0.
		unsigned __int64 rw : 1;               // If 0, writes not allowed.
		unsigned __int64 user_supervisor : 1;  // If 0, user-mode accesses not allowed. 
		unsigned __int64 page_write : 1;        // Determines the memory type used to access the memory.
		unsigned __int64 page_cache : 1;       // Determines the memory type used to access the memory.
		unsigned __int64 accessed : 1;         // If 0, this entry has not been used for translation.
		unsigned __int64 dirty : 1;             // If 0, the memory backing this page has not been written to.
		unsigned __int64 page_access_type : 1;  // Determines the memory type used to access the memory.
		unsigned __int64 global : 1;            // If 1 and the PGE bit of CR4 is set, translations are global.
		unsigned __int64 ignored2 : 3;
		unsigned __int64 pfn : 36;             // The page frame number of the backing physical page.
		unsigned __int64 reserved : 4;
		unsigned __int64 ignored3 : 7;
		unsigned __int64 protect_key : 4;       // If the PKE bit of CR4 is set, determines the protection key.
		unsigned __int64 nx : 1;               // If 1, instruction fetches not allowed.
	};
} pte, * ppte;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
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

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _RTL_CRITICAL_SECTION {
	VOID* DebugInfo;
	LONG LockCount;
	LONG RecursionCount;
	PVOID OwningThread;
	PVOID LockSemaphore;
	ULONG SpinCount;
} RTL_CRITICAL_SECTION, * PRTL_CRITICAL_SECTION;

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
	ULONG SizeOfImage;  // in bytes
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;  // LDR_*
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef enum _SYSTEM_INFORMATION_CLASS {
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
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _KPRCB* PKPRCB;

typedef struct _KAFFINITY_EX {
	USHORT count;
	USHORT size;
	ULONG reserved;
	ULONGLONG bitmap[20];
} KAFFINITY_EX, * PKAFFINITY_EX;

#define MM_EXECUTE_READWRITE (6)

typedef struct _MMVAD_FLAGS {
	ULONG Lock : 1;
	ULONG LockContended : 1;
	ULONG DeleteInProgress : 1;
	ULONG NoChange : 1;
	ULONG VadType : 3;
	ULONG Protection : 5;
	ULONG PreferredNode : 6;
	ULONG PageSize : 2;
	ULONG PrivateMemory : 1;
} MMVAD_FLAGS, * PMMVAD_FLAGS;

typedef struct _MMVAD_SHORT {
	union {
		struct _MMVAD_SHORT* NextVad;
		RTL_BALANCED_NODE VadNode;
	};

	ULONG StartingVpn;
	ULONG EndingVpn;
	UCHAR StartingVpnHigh;
	UCHAR EndingVpnHigh;
	UCHAR CommitChargeHigh;
	UCHAR SpareNT64VadUChar;
	LONG ReferenceCount;
	EX_PUSH_LOCK PushLock;

	union {
		ULONG LongFlags;
	} u1;
} MMVAD, * PMMVAD;

typedef struct _POOL_TRACKER_BIG_PAGES {
	volatile ULONGLONG Va;                                                  //0x0
	ULONG Key;                                                              //0x8
	ULONG Pattern : 8;                                                        //0xc
	ULONG PoolType : 12;                                                      //0xc
	ULONG SlushSize : 12;                                                     //0xc
	ULONGLONG NumberOfBytes;                                                //0x10
} POOL_TRACKER_BIG_PAGES, *PPOOL_TRACKER_BIG_PAGES;

extern "C" {
	__declspec( dllimport ) NTSTATUS __stdcall ZwQuerySystemInformation( SYSTEM_INFORMATION_CLASS, void*, unsigned long, unsigned long* );
	__declspec( dllimport ) NTSTATUS __stdcall ZwProtectVirtualMemory( IN HANDLE, PVOID*, SIZE_T*, ULONG, PULONG );
	NTSTATUS __stdcall MmCopyVirtualMemory( PEPROCESS, void*, PEPROCESS, void*, unsigned long long, KPROCESSOR_MODE, unsigned long long* );
	__declspec( dllimport ) PPEB PsGetProcessPeb( PEPROCESS );
	__declspec( dllimport ) PVOID __stdcall RtlFindExportedRoutineByName( void*, PCCH );
	bool __fastcall KeInterlockedSetProcessorAffinityEx( uint8_t*, uint32_t );
	__declspec( dllimport ) VOID NTAPI KeInitializeAffinityEx( PKAFFINITY_EX );
	__declspec( dllimport ) VOID NTAPI KeAddProcessorAffinityEx( PKAFFINITY_EX, INT );
	__declspec( dllimport ) VOID NTAPI HalSendNMI( PKAFFINITY_EX );
	__declspec( dllimport ) PKPRCB NTAPI KeQueryPrcbAddress( __in ULONG );
}