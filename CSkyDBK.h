#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

#ifndef _WIN64
#error "Only win x64 is supported"
#endif


typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef NTSTATUS (__stdcall *tZwLoadDriver)(
	_In_ PUNICODE_STRING DriverServiceName
	);
typedef NTSTATUS (__stdcall *tZwUnloadDriver)(
	_In_ PUNICODE_STRING DriverServiceName
	);
typedef NTSTATUS(__stdcall *tRtlInitUnicodeString)(
	_Out_    PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR          SourceString
	);

class CSkyDBK
{
private:

	HANDLE m_hDBK;
	HANDLE m_hCheatEngine;
	HDESK m_hCheatEngineDesktop;

	const wchar_t *m_szDBKPath;
	const wchar_t *m_szCheatEnginePath;

	std::wstring m_szServiceName;
	std::wstring m_szProcessEventName;
	std::wstring m_szThreadEventName;

	tZwLoadDriver m_ZwLoadDriver;
	tZwUnloadDriver m_ZwUnloadDriver;
	tRtlInitUnicodeString m_RtlInitUnicodeString;

public:
	
	HANDLE LoadDriver();

	bool UnloadDriver();

	CSkyDBK(const wchar_t *szDBK, const wchar_t *szCE);

	~CSkyDBK();

	static std::wstring GetRandomWString(size_t len);

private:

	static HMODULE GetRemoteModule(const char *szModuleName, DWORD dwProcessId);

	static bool GetRemoteModuleExportDirectory32(HMODULE hRemote, PIMAGE_EXPORT_DIRECTORY ExportDirectory, PIMAGE_DOS_HEADER DosHeader, PIMAGE_NT_HEADERS32 NtHeaders, HANDLE hProcess);

	static PVOID GetRemoteFuncAddress32(const char *module, const char *func, HANDLE hProcess);
	
	BYTE *GetCreateFileShellcode(HANDLE _In_ hProcess, const wchar_t _In_ *szDriverPipe, PVOID _Out_ *allocatedMemory);

	bool LoadDBK();

	bool UnloadDBK();

	LSTATUS PrepareDriverRegEntry(const std::wstring& svcName, const std::wstring& path, bool cleanup = false);

	static bool AttemptDebugPrivilege(HANDLE h);


};