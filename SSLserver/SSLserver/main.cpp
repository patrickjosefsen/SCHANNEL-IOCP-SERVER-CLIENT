//--------------------------------------------------------------------
//  This is a server-side SSPI Windows Sockets program.
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS


#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include <iostream>

#include <wincrypt.h>
#include <wintrust.h>
#include <schannel.h>

#define SECURITY_WIN32
#include <security.h>
#include <sspi.h>
#include "structscpp.h"
#include "SSL.h"
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Secur32.lib")
#pragma comment (lib, "crypt32.lib")
WSADATA wsaData;
int iResult;

HANDLE CompletionPort;
SOCKET ListenSocket = INVALID_SOCKET;






players* Player = new players[3];

sockaddr_in local;
sockaddr_in localip;
DWORD Flags;
int iSendResult;

using namespace std;

void serverWorkerThread() {

	OVERLAPPED* pov = NULL;
	DWORD Flags = 0;
	DWORD BytesTransferred;
	ULONG_PTR playerID;
	DWORD sentBytes;
	bool kage = 0;
	WSABUF wsabuf;
	CHAR Buffer2[200];
	SSL ssl;
	
	int status;
	SECURITY_STATUS ss;

	
	
		ssl.initialize(3, Player);
	
	while (true) {


		

		pov = NULL;
		if (GetQueuedCompletionStatus(CompletionPort, &BytesTransferred, &playerID, &pov, INFINITE) == 0)

		{

			printf("GetQueuedCompletionStatus() failed with error %d\n", GetLastError());



		}

		else

			printf("GetQueuedCompletionStatus() is OK!\n");




		cout << BytesTransferred << endl;

		if (Player[playerID].negotation == true) {
			cout << "hello" << endl;

			if (ssl.SSPINegotiateLoop(playerID,
				BytesTransferred,
				
				
				Player) == TRUE) {


				Player[playerID].negotation = false;
				BytesTransferred = 0;
				playerID = 0;

				cout << "hello" << endl;
				ZeroMemory(&(Player[playerID].tcpOverlapped), sizeof(OVERLAPPED));
				Player[playerID].Flags = 0;
				if ((Player[playerID].wsaRecv = WSARecv(Player[playerID].SSLSocket, 
					&Player[playerID].SSLTcpRcvWsabuf, 1, &Player[playerID].BytesRECV, 
					&Player[playerID].Flags, &Player[playerID].tcpOverlapped, NULL)) == SOCKET_ERROR)

				{

					if (WSAGetLastError() != ERROR_IO_PENDING)

					{

						printf("WSARecv() failed with error %d\n", WSAGetLastError());


					}

				}

				else printf("WSARecv() is OK!\n");
				continue;
			}
			else {

				ZeroMemory(&(Player[playerID].tcpOverlapped), sizeof(OVERLAPPED));
				Player[playerID].Flags = 0;
				
				fprintf(stderr, "AcceptSecurityContext failed: 0x%08x\n", Player[playerID].scRet);
				

				if ((Player[playerID].wsaRecv = WSARecv(Player[playerID].SSLSocket, &Player[playerID].SSLTcpRcvWsabuf, 1, &Player[playerID].BytesRECV, &Player[playerID].Flags,
					&Player[playerID].tcpOverlapped, NULL)) == SOCKET_ERROR)

				{

					if (WSAGetLastError() != ERROR_IO_PENDING)

					{

						printf("WSARecv() failed with error %d\n", WSAGetLastError());


					}

				}
				continue;
			}
		}


		if (ssl.SSLrecv(playerID, Player)==SEC_E_OK){

			printf("\nMessage is: '%s'\n", Player[playerID].decryptresult->pvBuffer);
			if ((ss = ssl.SSLsend(playerID, Player, &status)) == SEC_E_OK) {
				cout << "data is send" << endl;
			}
		}
		


		/*

				if (WSASend(ClientSocket, &DataBuf, 1, &sentBytes, 0,

					NULL, NULL) == SOCKET_ERROR)

				{

					if (WSAGetLastError() != ERROR_IO_PENDING)

					{

						printf("WSASend() failed with error %d\n", WSAGetLastError());



					}

				}

				else

					printf("WSASend() is OK!\n");

		*/

	


	}

}

int __cdecl main(void)
{
	int i = 0;
	struct sockaddr_in saClient;
	int iClientSize = sizeof(saClient);



	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	CompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);



	//Now we populate the sockaddr_in structure
	local.sin_family = AF_INET; //Address family
	local.sin_addr.s_addr = INADDR_ANY; //Wild card IP address
	local.sin_port = htons((u_short)27013); //port to use




	// Create a SOCKET for connecting to server
	ListenSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket




	iResult = bind(ListenSocket, (sockaddr*)&local, sizeof(local));
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());

		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}



	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	
	thread t1(serverWorkerThread);
	t1.detach();

	DWORD iss = 0;
	char* localIP;


	while (TRUE)

	{

		Player[i].SSLSocket = WSAAccept(ListenSocket, (sockaddr*)&saClient, &iClientSize, NULL, 0);
		if (Player[i].SSLSocket == INVALID_SOCKET) {
			printf("accept failed with error: %d\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}

		localIP = inet_ntoa(saClient.sin_addr);
		cout << localIP << endl;

		if (CreateIoCompletionPort((HANDLE)Player[i].SSLSocket, CompletionPort, i, 0) == NULL)

		{

			printf("CreateIoCompletionPort() failed with error %d\n", GetLastError());

			return 1;

		}

		else

			printf("CreateIoCompletionPort() is OK!\n");






		Flags = 0;
		if ((Player[i].wsaRecv = WSARecv(Player[i].SSLSocket, &Player[i].SSLTcpRcvWsabuf, 1, &Player[i].BytesRECV, &Player[i].Flags, &Player[i].tcpOverlapped, NULL)) == SOCKET_ERROR)

		{

			if (WSAGetLastError() != ERROR_IO_PENDING)

			{

				printf("WSARecv() failed with error %d\n", WSAGetLastError());


			}

		}

		else printf("WSARecv() is OK!\n");

		

		i++;

	}








	

	// cleanup
	
	WSACleanup();

	return 0;
}