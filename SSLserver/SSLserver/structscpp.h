#pragma once

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>


#include <mutex>
#include <atomic>
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>


#include <wintrust.h>
#include <schannel.h>
#include <sspi.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Secur32.lib")
#pragma comment (lib, "crypt32.lib")





#define IO_BUFFER_SIZE  0x10000

struct players {
	char ip[20] = "a";
	short completionPort;
	float potition;
	int tableNumber;
	SOCKET ClientSocket;
	SOCKET SSLSocket;
	std::atomic<bool> PlayerBool;
	OVERLAPPED tcpOverlapped;
	DWORD Flags;
	WSABUF TcpRcvWsabuf;
	CHAR TcpRcvbuf[200];
	int TcpRcvbufLen = 200;
	DWORD sentBytes;
	DWORD BytesRECV;


	//negotiation variables
	int i;
	BOOL firstneg = TRUE;
	bool negotation = true;
	bool fail = false;
	int wsaRecv;
	WSABUF SSLTcpRcvWsabuf;


	
	TimeStamp            tsExpiry;
	SECURITY_STATUS      scRet;
	SecBufferDesc        InBuffer;
	SecBufferDesc        OutBuffer;
	SecBuffer            negInBuffers[2];
	SecBuffer            negOutBuffers[1];
	
	CtxtHandle     phContext;
	
	CHAR IoBuffer[IO_BUFFER_SIZE];
	DWORD cbIoBuffer = 0;
	SecPkgContext_StreamSizes Sizes;

	//messager variables
	PSecBuffer decryptresult;
	SecBufferDesc   Message;
	SecBuffer       recvBuffers[4];
	SecBufferDesc   MessageOut;
	SecBuffer       sendBuffers[4];

	
};