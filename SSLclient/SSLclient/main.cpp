#include <iostream>

#include"SSLclient.h"

using namespace std;

int main() {
    SCHANNEL_CRED   SchannelCred;
    LPSTR   pszUserName = (LPSTR)"localhost";
    char arrayed[50] = "hello world";
    char* johnny = arrayed;
    char recvbuffer[50];
	SSLclient ssl;
    WSADATA WsaData;
    SOCKET  Socket = INVALID_SOCKET;

    CredHandle hClientCreds;
    CtxtHandle hContext;
    BOOL fCredsInitialized = FALSE;
    BOOL fContextInitialized = FALSE;

    SecBuffer  ExtraData;
    SECURITY_STATUS Status;

    PCCERT_CONTEXT pRemoteCertContext = NULL;

    INT i;
    INT iOption;
    PCHAR pszOption;

    //
    // Parse the command line.
    //




    //
    // Initialize the WinSock subsystem.
    //

    if (WSAStartup(0x0101, &WsaData) == SOCKET_ERROR)
    {
        printf("Error %d returned by WSAStartup\n", GetLastError());
        goto cleanup;
    }

    //
    // Create credentials.
    //
    std::cout << "kage" << endl;
    if (ssl.CreateCredentials(&hClientCreds))
    {
        printf("Error creating credentials\n");
        goto cleanup;
    }
    std::cout << "kage" << endl;
    fCredsInitialized = TRUE;


    //
    // Connect to server.
    //

    if (ssl.ConnectToServer(pszUserName, 27013, &Socket))
    {
        printf("Error connecting to server\n");
        goto cleanup;
    }


    //
    // Perform handshake
    //
    std::cout << "hello world" << std::endl;
    if (ssl.PerformClientHandshake(Socket,
        &hClientCreds,
        pszUserName,
        &hContext,
        &ExtraData))
    {
        printf("Error performing handshake\n");
        goto cleanup;
    }
    fContextInitialized = TRUE;


    //
    // Authenticate server's credentials.
    //

    // Get server's certificate.
    Status = QueryContextAttributes(&hContext,
        SECPKG_ATTR_REMOTE_CERT_CONTEXT,
        (PVOID)&pRemoteCertContext);
    if (Status != SEC_E_OK)
    {
        printf("Error 0x%x querying remote certificate\n", Status);
        goto cleanup;
    }

    // Display server certificate chain.
    ssl.DisplayCertChain(pRemoteCertContext, FALSE);

    // Attempt to validate server certificate.
    Status = ssl.VerifyServerCertificate(pRemoteCertContext,
        pszUserName,
        0);
    if (Status)
    {
        // The server certificate did not validate correctly. At this
        // point, we cannot tell if we are connecting to the correct 
        // server, or if we are connecting to a "man in the middle" 
        // attack server.

        // It is therefore best if we abort the connection.

        printf("**** Error 0x%x authenticating server credentials!\n", Status);
        //        goto cleanup;
    }

    // Free the server certificate context.
    CertFreeCertificateContext(pRemoteCertContext);
    pRemoteCertContext = NULL;


    //
    // Display connection info. 
    //

    ssl.DisplayConnectionInfo(&hContext);



    //
    // Read file from server.
    //
    ssl.sendEN(Socket, &hClientCreds, &hContext, johnny);
    ssl.rcvEN(Socket, &hClientCreds, &hContext, recvbuffer);

    cout << recvbuffer << endl;

    

    //
    // Send a close_notify alert to the server and
    // close down the connection.
    //

    if (ssl.DisconnectFromServer(Socket, &hClientCreds, &hContext))
    {
        printf("Error disconnecting from server\n");
        goto cleanup;
    }
    fContextInitialized = FALSE;
    Socket = INVALID_SOCKET;


cleanup:

    // Free the server certificate context.
    if (pRemoteCertContext)
    {
        CertFreeCertificateContext(pRemoteCertContext);
        pRemoteCertContext = NULL;
    }

    // Free SSPI context handle.
    if (fContextInitialized)
    {
        DeleteSecurityContext(&hContext);
        fContextInitialized = FALSE;
    }

    // Free SSPI credentials handle.
    if (fCredsInitialized)
    {
        FreeCredentialsHandle(&hClientCreds);
        fCredsInitialized = FALSE;
    }

    // Close socket.
    if (Socket != INVALID_SOCKET)
    {
        closesocket(Socket);
    }

    // Shutdown WinSock subsystem.
    WSACleanup();



    

    printf("Done\n");
	return 0;
}