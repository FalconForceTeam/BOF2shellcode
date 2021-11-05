#pragma once

#include <stdint.h>
#include "windows.h"

#include "wininet.h"

uint64_t getFunctionPtr(unsigned long, unsigned long);

// ----  KERNEL32 ----
#define HASH_KERNEL32 0x7040ee75
#define HASH_VirtualFree 0x668fcf2e
#define HASH_VirtualAlloc 0x382c0f97
#define HASH_LoadLibraryA 0x5fbff0fb
#define HASH_GetProcAddress 0xcf31bb1f
#define HASH_CreateProcessA 0xaeb52e19
#define HASH_CloseHandle 0x3870ca07
#define HASH_GetStdHandle 0xf178843c
#define HASH_WriteFile 0x663cecb0

typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR);
typedef BOOL(WINAPI* tVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef LPVOID(WINAPI* tVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef FARPROC(WINAPI* tGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* tCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* tCloseHandle)(HANDLE);
typedef HANDLE(WINAPI* tGetStdHandle)(DWORD);
typedef BOOL(WINAPI* tWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED );

// -- MSVCRT --
#define HASH_MSVCRT 0xff6c2f6e
#define HASH_printf 0x156b2bb8

typedef int(__CRTDECL* tprintf)(LPCSTR, ...);

// -- ADVAPI32 --
#define HASH_ADVAPI32 0x48b4de29

#define HASH_SetThreadToken 0x575b17ca
typedef BOOL(WINAPI* tSetThreadToken)(PHANDLE, HANDLE);

#define HASH_RevertToSelf 0x58cf32aa
typedef BOOL(WINAPI* tRevertToSelf)();

typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;
