#pragma comment(lib, "Wtsapi32.lib")
#include <iostream>
#include <Windows.h>
#include <Wtsapi32.h>
#include <TlHelp32.h>
#include <tchar.h>

DWORD PID;
HANDLE Process = NULL;
PWTS_PROCESS_INFO_EX  process_p = NULL;
DWORD count_p;
HANDLE getPRocessAtPID(DWORD& PID);

LPVOID func_addr = NULL;


//Specify the path to DDL

char* PathToDLL = "C:/Users/ksingh/Documents/visual studio 2017/Projects/DLLINject/Debug/DLL.dll";
LPVOID addr_memory_region = NULL;
HANDLE RemoteThread = NULL;

BOOL Inject_SetDebugPrivilege(HANDLE Process);
int main()
{
	
	DWORD level = 1;

	if (!WTSEnumerateProcessesEx(WTS_CURRENT_SERVER_HANDLE, &level, WTS_ANY_SESSION, (LPSTR*)&process_p, &count_p))
	{
		std::cerr << "Fail to get processes " << std::endl;

		exit(0);
	}



	for (int i = 0; i < count_p; i++)
	{
		/*
		HANDLE temp_proc = getPRocessAtPID(process_p[i].ProcessId);
		PBOOL is64 = false;
		*/
		std::cout << process_p[i].ProcessId << " | ";
		std::cout << process_p[i].SessionId << " | ";
		std::cout << process_p[i].pUserSid << " | ";

		std::cout << process_p[i].PagefileUsage << " | ";
		/*
		if (!IsWow64Process(temp_proc, is64))
		{

		}
		else
		{
			if (is64)
			{
				std::cout << " CPU is 64 | ";
			}
			else
			{
				std::cout << " CPU is x86 | ";
			}

		}
		*/
		std::cout << process_p[i].pProcessName << std::endl;

		//CloseHandle(temp_proc);

	}

	std::cout << "Which process would you like to access PID: ";
	std::cin >> PID;
	std::cout << std::endl;


	Process = getPRocessAtPID(PID);
	if (!Inject_SetDebugPrivilege(Process))
		return 0;
	if (Process == NULL)
	{
		std::cerr << "Error Opening Process " << std::endl;
		return 0;
	}


	func_addr = GetProcAddress(GetModuleHandleA("Kernel32.dll"), TEXT("LoadLibraryA"));


	if (func_addr == NULL)
	{
		std::cerr << "Error Getting Function from Kernel32.dll " << std::endl;
		return 0;

	}


	// Allocate space on Target Process
	addr_memory_region = VirtualAllocEx(Process, 0, lstrlen(PathToDLL)+1,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);


	if (addr_memory_region == NULL)
	{
		std::cerr << "Error Allocating space :( " << std::endl;
		return 0;

	}

	if(!WriteProcessMemory(Process, addr_memory_region, PathToDLL, lstrlen(PathToDLL)+1, NULL))
	{
		std::cerr << "Write to process failed " << std::endl;
		return 0;


	}


	RemoteThread = CreateRemoteThread(Process, 0, 0,
		(LPTHREAD_START_ROUTINE)func_addr, addr_memory_region, 0, 0);

	// process above

	WaitForSingleObject(RemoteThread, INFINITE);


	VirtualFreeEx(Process, addr_memory_region, lstrlen(PathToDLL)+1, MEM_RELEASE);
	CloseHandle(RemoteThread);

	CloseHandle(Process);


	std::cout << "Injected" << std::endl;
	system("PAUSE");
	return 0;
}
HANDLE getPRocessAtPID(DWORD& PID)
{


	return OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

}

BOOL Inject_SetDebugPrivilege(HANDLE process)
{
	BOOL bRet = FALSE;
	HANDLE hToken = NULL;
	LUID luid = { 0 };

	if (OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		{
			TOKEN_PRIVILEGES tokenPriv = { 0 };
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luid;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

		}
	}

	return bRet;
}
