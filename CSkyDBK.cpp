#include "CSkyDBK.h"

std::wstring CSkyDBK::GetRandomWString(size_t len)
{
	std::wstring ustr = L"";

	const char begin1 = '\u0041';
	const char end1 = '\u005A';

	const char begin2 = '\u0061';
	const char end2 = '\u007A';

	const char begin3 = '\u0030';
	const char end3 = '\u0039';

	const char begin4 = '\u00A1';
	const char end4 = '\u00FF';

	for(auto i = 0; i < len; i++) {
		switch(rand() % 4)
		{
		default:
		case 0:
			ustr += begin1 + (rand() % (end1 - begin1));
			break;
		case 1:
			ustr += begin2 + (rand() % (end2 - begin2));
			break;
		case 2:
			ustr += begin3 + (rand() % (end3 - begin3));
			break;
		case 3:
			ustr += begin4 + (rand() % (end4 - begin4));
			break;
		}
	}

	return ustr;
}

HANDLE CSkyDBK::LoadDriver()
{
	if(!this->LoadDBK())
	{
		return INVALID_HANDLE_VALUE;
	}

	return this->m_hDBK;
}

bool CSkyDBK::UnloadDriver()
{
	return this->UnloadDBK();
}

CSkyDBK::CSkyDBK(const wchar_t * szDBK, const wchar_t * szCE)
{
	this->AttemptDebugPrivilege(GetCurrentProcess());

	this->m_szDBKPath = szDBK;
	this->m_szCheatEnginePath = szCE;
	this->m_hDBK = INVALID_HANDLE_VALUE;
	this->m_hCheatEngine = INVALID_HANDLE_VALUE;
	this->m_hCheatEngineDesktop = NULL;

	this->m_szProcessEventName = this->GetRandomWString(10 + (rand() % 15));
	this->m_szThreadEventName = this->GetRandomWString(10 + (rand() % 15));
	this->m_szServiceName = this->GetRandomWString(10 + (rand() % 15));

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	this->m_ZwLoadDriver = reinterpret_cast<tZwLoadDriver>(GetProcAddress(ntdll, "ZwLoadDriver"));
	this->m_ZwUnloadDriver = reinterpret_cast<tZwLoadDriver>(GetProcAddress(ntdll, "ZwUnloadDriver"));
	this->m_RtlInitUnicodeString = reinterpret_cast<tRtlInitUnicodeString>(GetProcAddress(ntdll, "RtlInitUnicodeString"));

	wchar_t currentPath[MAX_PATH + 1] = L"";
	GetCurrentDirectoryW(MAX_PATH, currentPath);
	
	STARTUPINFOW startupInfo = { 0 };
	PROCESS_INFORMATION processInfo = { 0 };

	startupInfo.cb = sizeof(startupInfo);

	//Hide MessageBox approach #2: Create a new Desktop for the new process

	//After all I should probably just run the process in suspended state
	//and patch the entry point

	std::wstring desktopName = this->GetRandomWString(10 + (rand() % 15));
	this->m_hCheatEngineDesktop = CreateDesktopW(desktopName.c_str(), NULL, NULL, 0, GENERIC_ALL, NULL);

	startupInfo.lpDesktop = const_cast<LPWSTR>(desktopName.c_str());

	CreateProcessW(const_cast<LPWSTR>(szCE), NULL, NULL, NULL, FALSE, 0, NULL, currentPath, &startupInfo, &processInfo);
	this->m_hCheatEngine = processInfo.hProcess;
	this->AttemptDebugPrivilege(this->m_hCheatEngine);


	//Hide MessageBox approach #1: hide the MessageBox as soon as we find it, that's pretty dirty and bad
	/*HWND msgBox = NULL;
	do
	{
		msgBox = FindWindowW(NULL, L"dbk32.sys unloaded"); //will be shown if the driver isn't loaded (most cases)
		if(!msgBox)
			msgBox = FindWindowW(NULL, L"driver error"); //will be shown when the driver is loaded via CE
		if(!msgBox)
			msgBox = FindWindowW(NULL, L"DBK32.sys unloader"); //some other error, rarely happens

		Sleep(50);

	} while(msgBox == NULL);

	ShowWindow(msgBox, SW_HIDE);*/
}

CSkyDBK::~CSkyDBK()
{
	if(this->m_hDBK != INVALID_HANDLE_VALUE)
	{
		this->UnloadDBK();
		this->m_hDBK = INVALID_HANDLE_VALUE;
	}

	if(this->m_hCheatEngine != INVALID_HANDLE_VALUE)
	{
		TerminateProcess(this->m_hCheatEngine, 0);
		this->m_hCheatEngine = INVALID_HANDLE_VALUE;
	}

	if(this->m_hCheatEngineDesktop != NULL)
	{
		CloseDesktop(this->m_hCheatEngineDesktop);
		this->m_hCheatEngineDesktop = NULL;
	}
}


HMODULE CSkyDBK::GetRemoteModule(const char *szModuleName, DWORD dwProcessId)
{
	if(!szModuleName || !dwProcessId) { return NULL; }
	
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcessId);
	if(hSnap == INVALID_HANDLE_VALUE) { return NULL; }
	
#if defined(MODULEENTRY32)
#define SKYDBK_REDEF_FUNCS
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#endif

	MODULEENTRY32 me;
	me.dwSize = sizeof(MODULEENTRY32);
	if(Module32First(hSnap, &me))
	{
		do 
		{
			if(!_stricmp(me.szModule, szModuleName))
			{
				CloseHandle(hSnap);
				return me.hModule;
			}
		} while(Module32Next(hSnap, &me));
	}
	CloseHandle(hSnap);

#ifdef SKYDBK_REDEF_FUNCS
#undef SKYDBK_REDEF_FUNCS
#define Module32First Module32FirstW
#define Module32Next Module32NextW
#define MODULEENTRY32 MODULEENTRY32W
#endif

	return NULL;
}

// https://github.com/EasyHook/EasyHook/blob/master/EasyHookDll/RemoteHook/thread.c#L710
bool CSkyDBK::GetRemoteModuleExportDirectory32(HMODULE hRemote, PIMAGE_EXPORT_DIRECTORY ExportDirectory, PIMAGE_DOS_HEADER DosHeader, PIMAGE_NT_HEADERS32 NtHeaders, HANDLE hProcess)
{
	if(!ExportDirectory)
		return false;

	memset(ExportDirectory, 0, sizeof(IMAGE_EXPORT_DIRECTORY));

	PUCHAR ucAllocatedPEHeader = new UCHAR[1000];

	if(!ReadProcessMemory(hProcess, (void*)hRemote, ucAllocatedPEHeader, (SIZE_T)1000, NULL))
		return false;

	PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)(ucAllocatedPEHeader + DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	for(int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++, pImageSectionHeader++) {
		if(!pImageSectionHeader)
			continue;

		if(_stricmp((char*)pImageSectionHeader->Name, ".edata") == 0) {
			if(!ReadProcessMemory(hProcess, (void*)pImageSectionHeader->VirtualAddress, ExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), NULL))
				continue;

			delete[] ucAllocatedPEHeader;
			return true;
		}

	}

	DWORD dwEATAddress = NtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;
	if(!dwEATAddress)
		return false;

	if(!ReadProcessMemory(hProcess, (void*)((DWORD)hRemote + dwEATAddress), ExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), NULL))
		return false;

	delete[] ucAllocatedPEHeader;
	return true;
}

// https://github.com/EasyHook/EasyHook/blob/master/EasyHookDll/RemoteHook/thread.c#L837
PVOID CSkyDBK::GetRemoteFuncAddress32(const char * module, const char * func, HANDLE hProcess)
{
	HMODULE hRemote = GetRemoteModule(module, GetProcessId(hProcess));

	if(!hRemote)
		return NULL;

	IMAGE_DOS_HEADER DosHeader;
	if(!ReadProcessMemory(hProcess, (void*)hRemote, &DosHeader, sizeof(IMAGE_DOS_HEADER), NULL) || DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	IMAGE_NT_HEADERS32 NtHeaders;
	void *dwNTHeaders = (PDWORD)((DWORD)hRemote + DosHeader.e_lfanew);
	if(!ReadProcessMemory(hProcess, dwNTHeaders, &NtHeaders, sizeof(IMAGE_NT_HEADERS32), NULL) || NtHeaders.Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_EXPORT_DIRECTORY EATDirectory;
	if(!GetRemoteModuleExportDirectory32(hRemote, &EATDirectory, &DosHeader, &NtHeaders, hProcess))
		return NULL;

	DWORD*    AddressOfFunctions = (DWORD*)malloc(EATDirectory.NumberOfFunctions * sizeof(DWORD));
	DWORD*    AddressOfNames = (DWORD*)malloc(EATDirectory.NumberOfNames * sizeof(DWORD));
	WORD*    AddressOfOrdinals = (WORD*)malloc(EATDirectory.NumberOfNames * sizeof(WORD));

	if(!ReadProcessMemory(hProcess, (void*)((DWORD)hRemote + (DWORD)EATDirectory.AddressOfFunctions), reinterpret_cast<PVOID>(AddressOfFunctions), EATDirectory.NumberOfFunctions * sizeof(DWORD), NULL)) {
		free(AddressOfFunctions);
		free(AddressOfNames);
		free(AddressOfOrdinals);
		return NULL;
	}

	if(!ReadProcessMemory(hProcess, (void*)((DWORD)hRemote + (DWORD)EATDirectory.AddressOfNames), reinterpret_cast<PVOID>(AddressOfNames), EATDirectory.NumberOfNames * sizeof(DWORD), NULL)) {
		free(AddressOfFunctions);
		free(AddressOfNames);
		free(AddressOfOrdinals);
		return NULL;
	}

	if(!ReadProcessMemory(hProcess, (void*)((DWORD)hRemote + (DWORD)EATDirectory.AddressOfNameOrdinals), reinterpret_cast<PVOID>(AddressOfOrdinals), EATDirectory.NumberOfNames * sizeof(WORD), NULL)) {
		free(AddressOfFunctions);
		free(AddressOfNames);
		free(AddressOfOrdinals);
		return NULL;
	}

	DWORD dwExportBase = ((DWORD)hRemote + NtHeaders.OptionalHeader.DataDirectory[0].VirtualAddress);
	DWORD dwExportSize = (dwExportBase + NtHeaders.OptionalHeader.DataDirectory[0].Size);

	for(DWORD i = 0; i < EATDirectory.NumberOfNames; ++i)
	{
		DWORD dwAddressOfFunction = ((DWORD)hRemote + (DWORD)AddressOfFunctions[i]);
		DWORD dwAddressOfName = ((DWORD)hRemote + (DWORD)AddressOfNames[i]);

		char pszFunctionName[256] = { 0 };

		if(!ReadProcessMemory(hProcess, (void*)dwAddressOfName, pszFunctionName, 256, NULL))
			continue;

		if(_stricmp(pszFunctionName, func) != 0)
			continue;

		if(dwAddressOfFunction >= dwExportBase && dwAddressOfFunction <= dwExportSize) {
			char pszRedirectName[256] = { 0 };

			if(!ReadProcessMemory(hProcess, (void*)dwAddressOfFunction, pszRedirectName, 256, NULL))
				continue;

			char pszModuleName[256] = { 0 };
			char pszFunctionRedi[256] = { 0 };

			int a = 0;
			for(; pszRedirectName[a] != '.'; a++)
				pszModuleName[a] = pszRedirectName[a];
			a++;
			pszModuleName[a] = '\0';

			int b = 0;
			for(; pszRedirectName[a] != '\0'; a++, b++)
				pszFunctionRedi[b] = pszRedirectName[a];
			b++;
			pszFunctionRedi[b] = '\0';

			strcat_s(pszModuleName, ".dll");

			free(AddressOfFunctions);
			free(AddressOfNames);
			free(AddressOfOrdinals);

			return GetRemoteFuncAddress32(pszModuleName, pszFunctionRedi, hProcess);
		}

		WORD OrdinalValue = (reinterpret_cast<WORD*>(AddressOfOrdinals))[i];

		if(OrdinalValue != i) {
			DWORD dwAddressOfRedirectedFunction = ((DWORD)hRemote + (DWORD)AddressOfFunctions[OrdinalValue]);
			DWORD dwAddressOfRedirectedName = ((DWORD)hRemote + (DWORD)AddressOfNames[OrdinalValue]);

			char pszRedirectedFunctionName[256] = { 0 };

			free(AddressOfFunctions);
			free(AddressOfNames);
			free(AddressOfOrdinals);

			if(!ReadProcessMemory(hProcess, (void*)dwAddressOfRedirectedName, pszRedirectedFunctionName, 256, NULL))
				return NULL;
			else
				return reinterpret_cast<PVOID>(dwAddressOfRedirectedFunction);
		}
		else {
			free(AddressOfFunctions);
			free(AddressOfNames);
			free(AddressOfOrdinals);

			return reinterpret_cast<PVOID>(dwAddressOfFunction);
		}
	}

	free(AddressOfFunctions);
	free(AddressOfNames);
	free(AddressOfOrdinals);

	return NULL;
}


BYTE * CSkyDBK::GetCreateFileShellcode(HANDLE _In_ hProcess, const wchar_t _In_ *szDriverPipe, PVOID _Out_ *allocatedMemory)
{
	static BYTE shellcode[] = {
		0x90,	//NOP
		0x90,	//NOP
		0x90,	//NOP
		0x90,	//NOP

		0xb8, 0xff, 0xff, 0xff, 0xff, //mov eax, 0xffffffff
		0x6a, 0x00,					  //push 0
		0x6a, 0x00,					  //push 0
		0x6a, 0x03,					  //push OPEN_EXISTING
		0x6a, 0x00,					  //push 0
		0x6a, 0x03,					  //push FILE_SHARE_READ | FILE_SHARE_WRITE
		0x68, 0x00, 0x00, 0x00, 0xc0, //push GENERIC_READ | GENERIC_WRITE
		0x68, 0xff, 0xff, 0xff, 0xff, //push 0xffffffff
		0xff, 0xd0,					  //call eax
		0xba, 0xff, 0xff, 0xff, 0xff, //mov edx, 0xffffffff
		0x89, 0x02,					  //mov [edx], eax
		0xc3,						  //ret
	};
	
	size_t pipeLen = wcslen(szDriverPipe);

	DWORD *shellcodeCreateFileW = reinterpret_cast<DWORD*>(&shellcode[0x5]);
	DWORD *shellcodePipename = reinterpret_cast<DWORD*>(&shellcode[0x19]);
	DWORD *shellcodeShellCodeStart = reinterpret_cast<DWORD*>(&shellcode[0x20]);

	void *ptrCreateFileW = this->GetRemoteFuncAddress32("kernel32.dll", "CreateFileW", hProcess);

	void *ptrAllocatedShellcode = VirtualAllocEx(hProcess, 0, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	void *ptrAllocatedPipeName = VirtualAllocEx(hProcess, 0, sizeof(wchar_t) * pipeLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	*shellcodeCreateFileW = reinterpret_cast<DWORD>(ptrCreateFileW);
	*shellcodePipename = reinterpret_cast<DWORD>(ptrAllocatedPipeName);
	*shellcodeShellCodeStart = reinterpret_cast<DWORD>(ptrAllocatedShellcode);

	WriteProcessMemory(hProcess, ptrAllocatedPipeName, szDriverPipe, sizeof(wchar_t) * pipeLen, NULL);
	WriteProcessMemory(hProcess, ptrAllocatedShellcode, shellcode, sizeof(shellcode), NULL);

	*allocatedMemory = ptrAllocatedShellcode;

	return shellcode;
}

bool CSkyDBK::LoadDBK()
{
	if(this->PrepareDriverRegEntry(this->m_szServiceName, this->m_szDBKPath) != 0)
	{
		return false;
	}

	std::wstring regPath = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + this->m_szServiceName;
	wprintf(L"%s\n", regPath.c_str());

	UNICODE_STRING Ustr = { 0 };
	this->m_RtlInitUnicodeString(&Ustr, regPath.c_str());
	
	printf("Loading driver\n");
	NTSTATUS result = this->m_ZwLoadDriver(&Ustr);
	if(result != 0)
	{
		printf("Failed: 0x%X\n", result);
		return false;
	}

	PVOID remoteShellcode = nullptr;
	DWORD dwThreadId = 0;
	HANDLE hThread = NULL, hCEHandle = NULL, hLocalHandle = NULL;
	BYTE *shellcode = this->GetCreateFileShellcode(this->m_hCheatEngine, (L"\\\\.\\" + this->m_szServiceName).c_str(), &remoteShellcode);

	printf("Creating thread...\n");
	hThread = CreateRemoteThread(this->m_hCheatEngine, NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteShellcode), NULL, NULL, &dwThreadId);
	WaitForSingleObject(hThread, INFINITE);
	ReadProcessMemory(this->m_hCheatEngine, remoteShellcode, &hCEHandle, 4, NULL);

	this->PrepareDriverRegEntry(this->m_szServiceName, this->m_szDBKPath, true);

	HANDLE ownProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

	printf("CE Handle: 0x%X\n", this->m_hCheatEngine);
	BOOL b = DuplicateHandle(this->m_hCheatEngine, hCEHandle, ownProcess, &hLocalHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);
	printf("DuplicateHandle: 0x%X\nLocal Handle: 0x%X\n", b, hLocalHandle);

	this->m_hDBK = hLocalHandle;
	
	TerminateProcess(this->m_hCheatEngine, 0);
	this->m_hCheatEngine = INVALID_HANDLE_VALUE;

	CloseDesktop(this->m_hCheatEngineDesktop);
	this->m_hCheatEngineDesktop = NULL;

	return true;
}

bool CSkyDBK::UnloadDBK()
{
	UNICODE_STRING Ustr = { 0 };

	std::wstring regPath = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + this->m_szServiceName;
	this->m_RtlInitUnicodeString(&Ustr, regPath.c_str());

	// Remove previously loaded instance, if any
	NTSTATUS status = this->m_ZwUnloadDriver(&Ustr);
	SHDeleteKeyW(HKEY_LOCAL_MACHINE, std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\" + this->m_szServiceName).c_str());

	if(status != 0)
	{
		return false;
	}

	return true;
}

//Credits: DarthTon
LSTATUS CSkyDBK::PrepareDriverRegEntry(const std::wstring& svcName, const std::wstring& path, bool cleanup /* = false */)
{
	HKEY key1, key2;
	DWORD dwType = 1;
	LSTATUS status = 0;
	WCHAR wszLocalPath[MAX_PATH] = { 0 };

	swprintf_s(wszLocalPath, ARRAYSIZE(wszLocalPath), L"\\??\\%s", path.c_str());

	status = RegOpenKeyW(HKEY_LOCAL_MACHINE, L"system\\CurrentControlSet\\Services", &key1);
	if(status)
		return status;

	status = RegCreateKeyW(key1, svcName.c_str(), &key2);
	if(status)
	{
		RegCloseKey(key1);
		return status;
	}

	if(!cleanup)
	{
		status = RegSetValueExW(
			key2, L"ImagePath", 0, REG_SZ,
			reinterpret_cast<const BYTE*>(wszLocalPath),
			static_cast<DWORD>(sizeof(WCHAR)* (wcslen(wszLocalPath) + 1))
			);

		if(status)
		{
			RegCloseKey(key2);
			RegCloseKey(key1);
			return status;
		}

		status = RegSetValueExW(key2, L"Type", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwType), sizeof(dwType));
		if(status)
		{
			RegCloseKey(key2);
			RegCloseKey(key1);
			return status;
		}
	}

	std::wstring A = L"\\Device\\" + this->m_szServiceName;
	std::wstring B = L"\\DosDevices\\" + this->m_szServiceName;
	std::wstring C = L"\\BaseNamedObjects\\" + this->m_szProcessEventName;
	std::wstring D = L"\\BaseNamedObjects\\" + this->m_szThreadEventName;
	
	if(!cleanup)
	{
		status = RegSetValueExW(key2, L"A", 0, REG_SZ, reinterpret_cast<const BYTE*>(A.c_str()), A.length() * sizeof(WCHAR));
		if(status)
		{
			RegCloseKey(key2);
			RegCloseKey(key1);
			return status;
		}

		status = RegSetValueExW(key2, L"B", 0, REG_SZ, reinterpret_cast<const BYTE*>(B.c_str()), B.length() * sizeof(WCHAR));
		if(status)
		{
			RegCloseKey(key2);
			RegCloseKey(key1);
			return status;
		}

		status = RegSetValueExW(key2, L"C", 0, REG_SZ, reinterpret_cast<const BYTE*>(C.c_str()), C.length() * sizeof(WCHAR));
		if(status)
		{
			RegCloseKey(key2);
			RegCloseKey(key1);
			return status;
		}

		status = RegSetValueExW(key2, L"D", 0, REG_SZ, reinterpret_cast<const BYTE*>(D.c_str()), D.length() * sizeof(WCHAR));
		if(status)
		{
			RegCloseKey(key2);
			RegCloseKey(key1);
			return status;
		}
	}
	else
	{
		RegDeleteValueW(key2, L"A");
		RegDeleteValueW(key2, L"B");
		RegDeleteValueW(key2, L"C");
		RegDeleteValueW(key2, L"D");
	}

	RegCloseKey(key2);
	RegCloseKey(key1);

	return status;
}

bool CSkyDBK::AttemptDebugPrivilege(HANDLE h)
{
	HANDLE hToken;
	bool res = false;

	if(OpenProcessToken(h, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		TOKEN_PRIVILEGES tp;

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		tp.Privileges[0].Luid.HighPart = 0;

		tp.Privileges[0].Luid.LowPart = 20; //Debug

		BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
		res = result == TRUE ? true : false;

		tp.Privileges[0].Luid.LowPart = 10; //Load Driver

		result = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
		res = res && (result == TRUE);

		CloseHandle(hToken);
	}

	return res;
}
