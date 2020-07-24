#pragma once
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
//  SspiExample.h
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>


#include <wincrypt.h>
#include <wintrust.h>
#include <schannel.h>

#define SECURITY_WIN32
#include <security.h>
#include <sspi.h>
#include "structscpp.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Secur32.lib")
#pragma comment (lib, "crypt32.lib")


#define MACHINE_NAME "localhost"


class SSL {
    
public:
    
  
    void getSchannelClientHandle();

    PCCERT_CONTEXT getServerCertificate();
    void initialize(int playerCount, players* Players);

    DWORD
        CreateCredentials(
            LPSTR pszUserName,              // in
            PCredHandle phCreds);
    BOOL
        SSPINegotiateLoop(
            int id,
            int bytetrans,
           
           
            players* Players);

    SECURITY_STATUS SSLsend(int id,
        players* Players,int* WSAstatuscode);

    SECURITY_STATUS SSLrecv(int id,
        players* Players);

    
    
    private:
        
        DWORD   dwProtocol = 0;
        HCERTSTORE  hMyCertStore = NULL;
        BOOL    fMachineStore = FALSE;
        CtxtHandle     phContext;
        PCCERT_CONTEXT serverCert;
        CredHandle Creds;
};