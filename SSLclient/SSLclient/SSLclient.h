#pragma once
#define SECURITY_WIN32 
#define _CRT_SECURE_NO_WARNINGS 
#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>
#include <wintrust.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Secur32.lib")
#pragma comment (lib, "Crypt32.lib")


class SSLclient {
public:
    SECURITY_STATUS rcvEN(SOCKET          Socket,         // in
        PCredHandle     phCreds,        // in
        CtxtHandle* phContext,      // in
        char*           recvbuf);
    SECURITY_STATUS sendEN(SOCKET          Socket,         // in
        PCredHandle     phCreds,        // in
        CtxtHandle* phContext,      // in
        char*           sendbuf);
    INT
        ConnectToServer(
            LPSTR    pszServerName, // in
            INT      iPortNumber,   // in
            SOCKET* pSocket);       // out
    


     SECURITY_STATUS
    CreateCredentials(
        PCredHandle phCreds);
    
    SECURITY_STATUS
        ClientHandshakeLoop(
            SOCKET          Socket,         // in
            PCredHandle     phCreds,        // in
            CtxtHandle* phContext,      // in, out
            BOOL            fDoInitialRead, // in
            SecBuffer* pExtraData);

    
        SECURITY_STATUS
        PerformClientHandshake(
            SOCKET          Socket,         // in
            PCredHandle     phCreds,        // in
            LPSTR           pszServerName,  // in
            CtxtHandle* phContext,      // out
            SecBuffer* pExtraData);     // out

        DWORD
            VerifyServerCertificate(
                PCCERT_CONTEXT  pServerCert,
                PSTR            pszServerName,
                DWORD           dwCertFlags);

        void
            DisplayConnectionInfo(
                CtxtHandle* phContext);
        void
        DisplayCertChain(
            PCCERT_CONTEXT  pServerCert,
            BOOL            fLocal);

        LONG
            DisconnectFromServer(
                SOCKET          Socket,
                PCredHandle     phCreds,
                CtxtHandle* phContext);

private:

    HCERTSTORE      hMyCertStore = 0;
    SCHANNEL_CRED  SchannelCred;
    DWORD   dwProtocol = 0;
    ALG_ID  aiKeyExch = 0;

    void
        DisplayWinVerifyTrustError(DWORD Status);
    
        void
        GetNewClientCredentials(
            CredHandle* phCreds,
            CtxtHandle* phContext);

    void
        PrintHexDump(DWORD length, PBYTE buffer);


};