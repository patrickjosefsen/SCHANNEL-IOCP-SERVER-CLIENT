

#include "SSLclient.h"



#define IO_BUFFER_SIZE  0x10000

INT
SSLclient::ConnectToServer(
    LPSTR    pszServerName, // in
    INT      iPortNumber,   // in
    SOCKET* pSocket)       // out
{
    SOCKET Socket;
    struct sockaddr_in sin;
    struct hostent* hp;

    Socket = socket(PF_INET, SOCK_STREAM, 0);
    if (Socket == INVALID_SOCKET)
    {
        printf("**** Error %d creating socket\n", WSAGetLastError());
        return WSAGetLastError();
    }



    sin.sin_family = AF_INET;
    sin.sin_port = htons((u_short)iPortNumber);

    if ((hp = gethostbyname(pszServerName)) == NULL)
    {
        printf("**** Error %d returned by gethostbyname\n", WSAGetLastError());
        return WSAGetLastError();
    }
    else
    {
        memcpy(&sin.sin_addr, hp->h_addr, 4);
    }


    if (connect(Socket, (struct sockaddr*) & sin, sizeof(sin)) == SOCKET_ERROR)
    {
        printf("**** Error %d connecting to \"%s\" (%s)\n",
            WSAGetLastError(),
            pszServerName,
            inet_ntoa(sin.sin_addr));
        closesocket(Socket);
        return WSAGetLastError();
    }



    *pSocket = Socket;

    return SEC_E_OK;
}



SECURITY_STATUS
SSLclient::CreateCredentials(
    
    PCredHandle phCreds)            // out
{
    SECURITY_STATUS SecStatus;
    TimeStamp Lifetime;
    CredHandle hCred;
    SCHANNEL_CRED credData;
    
    _SecPkgCred_SupportedAlgs algs;
 

    ZeroMemory(&credData, sizeof(credData));
    credData.dwVersion = SCHANNEL_CRED_VERSION;
    
    
    ALG_ID           rgbSupportedAlgs[4];
    rgbSupportedAlgs[0] = CALG_DH_EPHEM;
    rgbSupportedAlgs[1] = CALG_RSA_KEYX;
    rgbSupportedAlgs[2] = CALG_AES_128;
    rgbSupportedAlgs[3] = CALG_SHA_256;
    credData.cSupportedAlgs = 4;
    credData.palgSupportedAlgs = rgbSupportedAlgs;
    //credData.dwMinimumCipherStrength = -1;
    //credData.dwMaximumCipherStrength = -1;
    
    
    //-------------------------------------------------------
    // Specify the TLS V1.0 (client-side) security protocol.
    credData.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    credData.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;

    SecStatus = AcquireCredentialsHandle(
        NULL,                  // default principal
        (LPSTR)UNISP_NAME,            // name of the SSP
        SECPKG_CRED_OUTBOUND,  // client will use the credentials
        NULL,                  // use the current LOGON id
        &credData,             // protocol-specific data
        NULL,                  // default
        NULL,                  // default
        &hCred,                // receives the credential handle
        &Lifetime              // receives the credential time limit
    );
    printf("Client credentials status: 0x%x\n", SecStatus);
    // Return the handle to the caller.
    if (phCreds != NULL)
        *phCreds = hCred;

    SecStatus = QueryCredentialsAttributesA(&hCred, SECPKG_ATTR_SUPPORTED_ALGS, &algs);

    for (int i = 0; i < algs.cSupportedAlgs; i++) {
        fprintf(stderr, "alg: 0x%08x\n", algs.palgSupportedAlgs[i]);
    }

    


    return SecStatus;
}

SECURITY_STATUS
SSLclient::PerformClientHandshake(
    SOCKET          Socket,         // in
    PCredHandle     phCreds,        // in
    LPSTR           pszServerName,  // in
    CtxtHandle* phContext,      // out
    SecBuffer* pExtraData)     // out
{
    static TCHAR g_lpPackageName[1024];
    strcpy_s(g_lpPackageName, 1024 * sizeof(TCHAR), "localhost");
    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    SECURITY_STATUS scRet;
    DWORD           cbData;

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT |
        ISC_REQ_REPLAY_DETECT |
        ISC_REQ_CONFIDENTIALITY |
        ISC_RET_EXTENDED_ERROR |
        ISC_REQ_ALLOCATE_MEMORY |
        ISC_REQ_STREAM;


    //
    //  Initiate a ClientHello message and generate a token.
    //

    OutBuffers[0].pvBuffer = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer = 0;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    scRet = InitializeSecurityContextA(
        phCreds,
        NULL,
        g_lpPackageName,
        dwSSPIFlags,
        0,
        SECURITY_NATIVE_DREP,
        NULL,
        0,
        phContext,
        &OutBuffer,
        &dwSSPIOutFlags,
        &tsExpiry);

    if (scRet != SEC_I_CONTINUE_NEEDED)
    {
        printf("**** Error %d returned by InitializeSecurityContext (1)\n", scRet);
        return scRet;
    }

    std::cout << OutBuffers[0].cbBuffer << std::endl;
    std::cout << OutBuffers[0].pvBuffer << std::endl;
    // Send response to server if there is one.
    if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
    {
        cbData = send(Socket,
            (char*)OutBuffers[0].pvBuffer,
            OutBuffers[0].cbBuffer,
            0);
        if (cbData == SOCKET_ERROR || cbData == 0)
        {
            printf("**** Error %d sending data to server (1)\n", WSAGetLastError());
            FreeContextBuffer(OutBuffers[0].pvBuffer);
            DeleteSecurityContext(phContext);
            return SEC_E_INTERNAL_ERROR;
        }

        printf("%d bytes of handshake data sent\n", cbData);

        
            PrintHexDump(cbData, (PBYTE)OutBuffers[0].pvBuffer);
            printf("\n");
        

        // Free output buffer.
        FreeContextBuffer(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = NULL;
    }


    return ClientHandshakeLoop(Socket, phCreds, phContext, TRUE, pExtraData);
}


SECURITY_STATUS
SSLclient::ClientHandshakeLoop(
    SOCKET          Socket,         // in
    PCredHandle     phCreds,        // in
    CtxtHandle* phContext,      // in, out
    BOOL            fDoInitialRead, // in
    SecBuffer* pExtraData) {




    SecBufferDesc   InBuffer;
    SecBuffer       InBuffers[2];
    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    SECURITY_STATUS scRet;
    DWORD           cbData;

    PUCHAR           IoBuffer;
    DWORD           cbIoBuffer;
    BOOL            fDoRead;


    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT |
        ISC_REQ_REPLAY_DETECT |
        ISC_REQ_CONFIDENTIALITY |
        ISC_RET_EXTENDED_ERROR |
        ISC_REQ_ALLOCATE_MEMORY |
        ISC_REQ_STREAM;

    //
    // Allocate data buffer.
    //
    
    IoBuffer = (PUCHAR)LocalAlloc(LMEM_FIXED, IO_BUFFER_SIZE);
    if (IoBuffer == NULL)
    {
        printf("**** Out of memory (1)\n");
        return SEC_E_INTERNAL_ERROR;
    }
    
    cbIoBuffer = 0;

    fDoRead = fDoInitialRead;


    // 
    // Loop until the handshake is finished or an error occurs.
    //

    scRet = SEC_I_CONTINUE_NEEDED;

    while (scRet == SEC_I_CONTINUE_NEEDED ||
        scRet == SEC_E_INCOMPLETE_MESSAGE ||
        scRet == SEC_I_INCOMPLETE_CREDENTIALS)
    {

        //
        // Read data from server.
        //

        if (0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            if (fDoRead)
            {
                cbData = recv(Socket,
                    (char*)IoBuffer + cbIoBuffer,
                    IO_BUFFER_SIZE - cbIoBuffer,
                    0);
                if (cbData == SOCKET_ERROR)
                {
                    printf("**** Error %d reading data from server\n", WSAGetLastError());
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }
                else if (cbData == 0)
                {
                    printf("**** Server unexpectedly disconnected\n");
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }

                printf("%d bytes of handshake data received\n", cbData);

                
                    PrintHexDump(cbData, IoBuffer + cbIoBuffer);
                    printf("\n");
                

                cbIoBuffer += cbData;
            }
            else
            {
                fDoRead = TRUE;
            }
        }


        //
        // Set up the input buffers. Buffer 0 is used to pass in data
        // received from the server. Schannel will consume some or all
        // of this. Leftover data (if any) will be placed in buffer 1 and
        // given a buffer type of SECBUFFER_EXTRA.
        //

        InBuffers[0].pvBuffer = IoBuffer;
        InBuffers[0].cbBuffer = cbIoBuffer;
        InBuffers[0].BufferType = SECBUFFER_TOKEN;

        InBuffers[1].pvBuffer = NULL;
        InBuffers[1].cbBuffer = 0;
        InBuffers[1].BufferType = SECBUFFER_EMPTY;

        InBuffer.cBuffers = 2;
        InBuffer.pBuffers = InBuffers;
        InBuffer.ulVersion = SECBUFFER_VERSION;

        //
        // Set up the output buffers. These are initialized to NULL
        // so as to make it less likely we'll attempt to free random
        // garbage later.
        //

        OutBuffers[0].pvBuffer = NULL;
        OutBuffers[0].BufferType = SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer = 0;

        OutBuffer.cBuffers = 1;
        OutBuffer.pBuffers = OutBuffers;
        OutBuffer.ulVersion = SECBUFFER_VERSION;



        //
        // Call InitializeSecurityContext.
        //
        std::cout << "hello world" << std::endl;
        scRet = InitializeSecurityContextA(phCreds,
            phContext,
            NULL,
            dwSSPIFlags,
            0,
            SECURITY_NATIVE_DREP,
            &InBuffer,
            0,
            NULL,
            &OutBuffer,
            &dwSSPIOutFlags,
            &tsExpiry);

        //
        // If InitializeSecurityContext was successful (or if the error was 
        // one of the special extended ones), send the contends of the output
        // buffer to the server.
        //
        
        std::cout << "hello world" << std::endl;

        if (scRet == SEC_E_OK ||
            scRet == SEC_I_CONTINUE_NEEDED ||
            FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))
        {
            if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
            {
                std::cout << "hello world" << std::endl;
                std::cout << OutBuffers[0].cbBuffer << std::endl;
                std::cout << OutBuffers[0].pvBuffer << std::endl;
                cbData = send(Socket,
                    (char*)OutBuffers[0].pvBuffer,
                    OutBuffers[0].cbBuffer,
                    0);
                if (cbData == SOCKET_ERROR || cbData == 0)
                {
                    printf("**** Error %d sending data to server (2)\n",
                        WSAGetLastError());
                    FreeContextBuffer(OutBuffers[0].pvBuffer);
                    DeleteSecurityContext(phContext);
                    return SEC_E_INTERNAL_ERROR;
                }

                printf("%d bytes of handshake data sent\n", cbData);

                
                    PrintHexDump(cbData, (PBYTE)OutBuffers[0].pvBuffer);
                    printf("\n");
                

                // Free output buffer.
                FreeContextBuffer(OutBuffers[0].pvBuffer);
                OutBuffers[0].pvBuffer = NULL;
            }
        }


        //
        // If InitializeSecurityContext returned SEC_E_INCOMPLETE_MESSAGE,
        // then we need to read more data from the server and try again.
        //

        if (scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            continue;
        }


        //
        // If InitializeSecurityContext returned SEC_E_OK, then the 
        // handshake completed successfully.
        //

        if (scRet == SEC_E_OK)
        {
            //
            // If the "extra" buffer contains data, this is encrypted application
            // protocol layer stuff. It needs to be saved. The application layer
            // will later decrypt it with DecryptMessage.
            //

            printf("Handshake was successful\n");

            if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
            {
                pExtraData->pvBuffer = LocalAlloc(LMEM_FIXED,
                    InBuffers[1].cbBuffer);
                if (pExtraData->pvBuffer == NULL)
                {
                    printf("**** Out of memory (2)\n");
                    return SEC_E_INTERNAL_ERROR;
                }

                MoveMemory(pExtraData->pvBuffer,
                    IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                    InBuffers[1].cbBuffer);

                pExtraData->cbBuffer = InBuffers[1].cbBuffer;
                pExtraData->BufferType = SECBUFFER_TOKEN;

                printf("%d bytes of app data was bundled with handshake data\n",
                    pExtraData->cbBuffer);
            }
            else
            {
                pExtraData->pvBuffer = NULL;
                pExtraData->cbBuffer = 0;
                pExtraData->BufferType = SECBUFFER_EMPTY;
            }

            //
            // Bail out to quit
            //

            break;
        }


        //
        // Check for fatal error.
        //

        if (FAILED(scRet))
        {
            printf("**** Error 0x%x returned by InitializeSecurityContext (2)\n", scRet);
            break;
        }


        //
        // If InitializeSecurityContext returned SEC_I_INCOMPLETE_CREDENTIALS,
        // then the server just requested client authentication. 
        //

        if (scRet == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            //
            // Busted. The server has requested client authentication and
            // the credential we supplied didn't contain a client certificate.
            //

            // 
            // This function will read the list of trusted certificate
            // authorities ("issuers") that was received from the server
            // and attempt to find a suitable client certificate that
            // was issued by one of these. If this function is successful, 
            // then we will connect using the new certificate. Otherwise,
            // we will attempt to connect anonymously (using our current
            // credentials).
            //

            GetNewClientCredentials(phCreds, phContext);

            // Go around again.
            fDoRead = FALSE;
            scRet = SEC_I_CONTINUE_NEEDED;
            continue;
        }


        //
        // Copy any leftover data from the "extra" buffer, and go around
        // again.
        //

        if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
        {
            MoveMemory(IoBuffer,
                IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                InBuffers[1].cbBuffer);

            cbIoBuffer = InBuffers[1].cbBuffer;
        }
        else
        {
            cbIoBuffer = 0;
        }
    }

    // Delete the security context in the case of a fatal error.
    if (FAILED(scRet))
    {
        DeleteSecurityContext(phContext);
    }

    LocalFree(IoBuffer);

    return scRet;
}




void
SSLclient::GetNewClientCredentials(
    CredHandle* phCreds,
    CtxtHandle* phContext)
{
    CredHandle hCreds;
    SecPkgContext_IssuerListInfoEx IssuerListInfo;
    PCCERT_CHAIN_CONTEXT pChainContext;
    CERT_CHAIN_FIND_BY_ISSUER_PARA FindByIssuerPara;
    PCCERT_CONTEXT  pCertContext;
    TimeStamp       tsExpiry;
    SECURITY_STATUS Status;
    static TCHAR      lpPackageName[1024];

    //
    // Read list of trusted issuers from schannel.
    //

    Status = QueryContextAttributes(phContext,
        SECPKG_ATTR_ISSUER_LIST_EX,
        (PVOID)&IssuerListInfo);
    if (Status != SEC_E_OK)
    {
        printf("Error 0x%x querying issuer list info\n", Status);
        return;
    }

    //
    // Enumerate the client certificates.
    //
    strcpy_s(lpPackageName, 1024 * sizeof(TCHAR), "Pattis ssl");
    ZeroMemory(&FindByIssuerPara, sizeof(FindByIssuerPara));

    FindByIssuerPara.cbSize = sizeof(FindByIssuerPara);
    FindByIssuerPara.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
    FindByIssuerPara.dwKeySpec = 0;
    FindByIssuerPara.cIssuer = IssuerListInfo.cIssuers;
    FindByIssuerPara.rgIssuer = IssuerListInfo.aIssuers;

    pChainContext = NULL;
    
    while (TRUE)
    {
        // Find a certificate chain.
        pChainContext = CertFindChainInStore(hMyCertStore,
            X509_ASN_ENCODING,
            0,
            CERT_CHAIN_FIND_BY_ISSUER,
            &FindByIssuerPara,
            pChainContext);
        if (pChainContext == NULL)
        {
            printf("Error 0x%x finding cert chain\n", GetLastError());
            break;
        }
        printf("\ncertificate chain found\n");

        // Get pointer to leaf certificate context.
        pCertContext = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;

        // Create schannel credential.
        SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
        SchannelCred.cCreds = 1;
        SchannelCred.paCred = &pCertContext;

        Status = AcquireCredentialsHandleA(
            NULL,                   // Name of principal
            lpPackageName,           // Name of package
            SECPKG_CRED_OUTBOUND,   // Flags indicating use
            NULL,                   // Pointer to logon ID
            &SchannelCred,          // Package specific data
            NULL,                   // Pointer to GetKey() func
            NULL,                   // Value to pass to GetKey()
            &hCreds,                // (out) Cred Handle
            &tsExpiry);             // (out) Lifetime (optional)
        if (Status != SEC_E_OK)
        {
            printf("**** Error 0x%x returned by AcquireCredentialsHandle\n", Status);
            continue;
        }
        printf("\nnew schannel credential created\n");

        // Destroy the old credentials.
        FreeCredentialsHandle(phCreds);

        *phCreds = hCreds;

        //
        // As you can see, this sample code maintains a single credential
        // handle, replacing it as necessary. This is a little unusual.
        //
        // Many applications maintain a global credential handle that's
        // anonymous (that is, it doesn't contain a client certificate),
        // which is used to connect to all servers. If a particular server
        // should require client authentication, then a new credential 
        // is created for use when connecting to that server. The global
        // anonymous credential is retained for future connections to
        // other servers.
        //
        // Maintaining a single anonymous credential that's used whenever
        // possible is most efficient, since creating new credentials all
        // the time is rather expensive.
        //

        break;
    }
}

SECURITY_STATUS SSLclient::rcvEN(SOCKET          Socket,         // in
    PCredHandle     phCreds,        // in
    CtxtHandle* phContext,      // in
    char* recvbuf) {
    SecPkgContext_StreamSizes Sizes;
    SECURITY_STATUS scRet;
    SecBufferDesc   Message;
    SecBuffer       Buffers[4];
    SecBuffer* pDataBuffer;
    SecBuffer* pExtraBuffer;
    SecBuffer       ExtraBuffer;

    PBYTE pbIoBuffer;
    DWORD cbIoBuffer;
    DWORD cbIoBufferLength;
    PBYTE pbMessage;
    DWORD cbMessage;

    DWORD cbData;
    INT   i;

    //
// Read stream encryption properties.
//

    scRet = QueryContextAttributes(phContext,
        SECPKG_ATTR_STREAM_SIZES,
        &Sizes);
    if (scRet != SEC_E_OK)
    {
        printf("**** Error 0x%x reading SECPKG_ATTR_STREAM_SIZES\n", scRet);
        return scRet;
    }

    printf("\nHeader: %d, Trailer: %d, MaxMessage: %d\n",
        Sizes.cbHeader,
        Sizes.cbTrailer,
        Sizes.cbMaximumMessage);

    //
    // Allocate a working buffer. The plaintext sent to EncryptMessage
    // should never be more than 'Sizes.cbMaximumMessage', so a buffer 
    // size of this plus the header and trailer sizes should be safe enough.
    // 

    cbIoBufferLength = Sizes.cbHeader +
        Sizes.cbMaximumMessage +
        Sizes.cbTrailer;

    pbIoBuffer = (PBYTE)LocalAlloc(LMEM_FIXED, cbIoBufferLength);
    if (pbIoBuffer == NULL)
    {
        printf("**** Out of memory (2)\n");
        return SEC_E_INTERNAL_ERROR;
    }


    //

    // Build the HTTP request offset into the data buffer by "header size"
    // bytes. This enables Schannel to perform the encryption in place,
    // which is a significant performance win.
    pbMessage = pbIoBuffer + Sizes.cbHeader;

    cbIoBuffer = 0;

    while (true) {
        if (0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            cbData = recv(Socket,
                (char*)pbIoBuffer + cbIoBuffer,
                cbIoBufferLength - cbIoBuffer,
                0);
            if (cbData == SOCKET_ERROR)
            {
                printf("**** Error %d reading data from server\n", WSAGetLastError());
                scRet = SEC_E_INTERNAL_ERROR;
                return SEC_E_INTERNAL_ERROR;
            }
            else if (cbData == 0)
            {
                // Server disconnected.
                if (cbIoBuffer)
                {
                    printf("**** Server unexpectedly disconnected\n");
                    scRet = SEC_E_INTERNAL_ERROR;
                    return scRet;
                }

            }
            else
            {
                printf("%d bytes of (encrypted) application data received\n", cbData);


                PrintHexDump(cbData, pbIoBuffer + cbIoBuffer);
                printf("\n");


                cbIoBuffer += cbData;
            }
        }

        // 
        // Attempt to decrypt the received data.
        //

        Buffers[0].pvBuffer = pbIoBuffer;
        Buffers[0].cbBuffer = cbIoBuffer;
        Buffers[0].BufferType = SECBUFFER_DATA;

        Buffers[1].BufferType = SECBUFFER_EMPTY;
        Buffers[2].BufferType = SECBUFFER_EMPTY;
        Buffers[3].BufferType = SECBUFFER_EMPTY;

        Message.ulVersion = SECBUFFER_VERSION;
        Message.cBuffers = 4;
        Message.pBuffers = Buffers;

        scRet = DecryptMessage(phContext, &Message, 0, NULL);

        if (scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            // The input buffer contains only a fragment of an
            // encrypted record. Loop around and read some more
            // data.
            continue;
        }

        // Server signalled end of session
        if (scRet == SEC_I_CONTEXT_EXPIRED)
            break;
    }
    if (scRet != SEC_E_OK &&
        scRet != SEC_I_RENEGOTIATE &&
        scRet != SEC_I_CONTEXT_EXPIRED)
    {
        printf("**** Error 0x%x returned by DecryptMessage\n", scRet);
        return scRet;
    }

    // Locate data and (optional) extra buffers.
    pDataBuffer = NULL;
    pExtraBuffer = NULL;
    for (i = 1; i < 4; i++)
    {

        if (pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA)
        {
            pDataBuffer = &Buffers[i];
            
            printf("Buffers[%d].BufferType = SECBUFFER_DATA\n", i);
        }
        if (pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA)
        {
            pExtraBuffer = &Buffers[i];
        }
    }
    *recvbuf = pDataBuffer->cbBuffer;
    // Display or otherwise process the decrypted data.
    if (pDataBuffer)
    {
        printf("Decrypted data: %d bytes\n", pDataBuffer->cbBuffer);

        
        
            PrintHexDump(pDataBuffer->cbBuffer, (PBYTE)pDataBuffer->pvBuffer);
            printf("\n");
        
    }
    
    // Move any "extra" data to the input buffer.
    if (pExtraBuffer)
    {
        MoveMemory(pbIoBuffer, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
        cbIoBuffer = pExtraBuffer->cbBuffer;
    }
    else
    {
        cbIoBuffer = 0;
    }

    if (scRet == SEC_I_RENEGOTIATE)
    {
        // The server wants to perform another handshake
        // sequence.

        printf("Server requested renegotiate!\n");

        scRet = ClientHandshakeLoop(Socket,
            phCreds,
            phContext,
            FALSE,
            &ExtraBuffer);
        if (scRet != SEC_E_OK)
        {
            return scRet;
        }

        // Move any "extra" data to the input buffer.
        if (ExtraBuffer.pvBuffer)
        {
            MoveMemory(pbIoBuffer, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
            cbIoBuffer = ExtraBuffer.cbBuffer;
        }
    
}

return SEC_E_OK;
    

}
SECURITY_STATUS SSLclient::sendEN(SOCKET          Socket,         // in
    PCredHandle     phCreds,        // in
    CtxtHandle* phContext,      // in
    char* sendbuf) {
    SecPkgContext_StreamSizes Sizes;
    SECURITY_STATUS scRet;
    SecBufferDesc   Message;
    SecBuffer       Buffers[4];
    SecBuffer* pDataBuffer;
    SecBuffer* pExtraBuffer;
    SecBuffer       ExtraBuffer;

    PBYTE pbIoBuffer;
    DWORD cbIoBuffer;
    DWORD cbIoBufferLength;
    PBYTE pbMessage;
    DWORD cbMessage;

    DWORD cbData;
    INT   i;
    //
// Read stream encryption properties.
//

    scRet = QueryContextAttributes(phContext,
        SECPKG_ATTR_STREAM_SIZES,
        &Sizes);
    if (scRet != SEC_E_OK)
    {
        printf("**** Error 0x%x reading SECPKG_ATTR_STREAM_SIZES\n", scRet);
        return scRet;
    }

    printf("\nHeader: %d, Trailer: %d, MaxMessage: %d\n",
        Sizes.cbHeader,
        Sizes.cbTrailer,
        Sizes.cbMaximumMessage);

    //
    // Allocate a working buffer. The plaintext sent to EncryptMessage
    // should never be more than 'Sizes.cbMaximumMessage', so a buffer 
    // size of this plus the header and trailer sizes should be safe enough.
    // 

    cbIoBufferLength = Sizes.cbHeader +
        Sizes.cbMaximumMessage +
        Sizes.cbTrailer;

    pbIoBuffer = (PBYTE)LocalAlloc(LMEM_FIXED, cbIoBufferLength);
    if (pbIoBuffer == NULL)
    {
        printf("**** Out of memory (2)\n");
        return SEC_E_INTERNAL_ERROR;
    }


    //
    // Build an HTTP request to send to the server.
    //

    // Remove the trailing backslash from the filename, should one exist.
 

    // Build the HTTP request offset into the data buffer by "header size"
    // bytes. This enables Schannel to perform the encryption in place,
    // which is a significant performance win.
    pbMessage = pbIoBuffer + Sizes.cbHeader;

    // Build HTTP request. Note that I'm assuming that this is less than
    // the maximum message size. If it weren't, it would have to be broken up.
    sprintf((char*)pbMessage,
        sendbuf);
    printf("\her skal send besked stå tydeligt: %s\n", pbMessage);

    cbMessage = (DWORD)strlen((char*)pbMessage);

    printf("Sending plaintext: %d bytes\n", cbMessage);

    
        PrintHexDump(cbMessage, pbMessage);
        printf("\n");
    

    Buffers[0].pvBuffer = pbIoBuffer;
    Buffers[0].cbBuffer = Sizes.cbHeader;
    Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

    Buffers[1].pvBuffer = pbMessage;
    Buffers[1].cbBuffer = cbMessage;
    Buffers[1].BufferType = SECBUFFER_DATA;

    Buffers[2].pvBuffer = pbMessage + cbMessage;
    Buffers[2].cbBuffer = Sizes.cbTrailer;
    Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

    Buffers[3].BufferType = SECBUFFER_EMPTY;

    Message.ulVersion = SECBUFFER_VERSION;
    Message.cBuffers = 4;
    Message.pBuffers = Buffers;

    scRet = EncryptMessage(phContext, 0, &Message, 0);

    if (FAILED(scRet))
    {
        printf("**** Error 0x%x returned by EncryptMessage\n", scRet);
        return scRet;
    }


    // 
    // Send the encrypted data to the server.
    //
    
    cbData = send(Socket,
        (char*)pbIoBuffer,
        Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer,
        0);
    if (cbData == SOCKET_ERROR || cbData == 0)
    {
        printf("**** Error %d sending data to server (3)\n",
            WSAGetLastError());
        DeleteSecurityContext(phContext);
        return SEC_E_INTERNAL_ERROR;
    }

    printf("%d bytes of application data sent\n", cbData);

    
        PrintHexDump(cbData, pbIoBuffer);
        printf("\n");
    
}

void
SSLclient::DisplayWinVerifyTrustError(DWORD Status)
{
    LPSTR pszName = NULL;

    switch (Status)
    {
    case CERT_E_EXPIRED:                pszName =(LPSTR) "CERT_E_EXPIRED";                 break;
    case CERT_E_VALIDITYPERIODNESTING:  pszName = (LPSTR)"CERT_E_VALIDITYPERIODNESTING";   break;
    case CERT_E_ROLE:                   pszName = (LPSTR)"CERT_E_ROLE";                    break;
    case CERT_E_PATHLENCONST:           pszName = (LPSTR)"CERT_E_PATHLENCONST";            break;
    case CERT_E_CRITICAL:               pszName = (LPSTR)"CERT_E_CRITICAL";                break;
    case CERT_E_PURPOSE:                pszName = (LPSTR)"CERT_E_PURPOSE";                 break;
    case CERT_E_ISSUERCHAINING:         pszName = (LPSTR)"CERT_E_ISSUERCHAINING";          break;
    case CERT_E_MALFORMED:              pszName = (LPSTR)"CERT_E_MALFORMED";               break;
    case CERT_E_UNTRUSTEDROOT:          pszName = (LPSTR)"CERT_E_UNTRUSTEDROOT";           break;
    case CERT_E_CHAINING:               pszName = (LPSTR)"CERT_E_CHAINING";                break;
    case TRUST_E_FAIL:                  pszName = (LPSTR)"TRUST_E_FAIL";                   break;
    case CERT_E_REVOKED:                pszName = (LPSTR)"CERT_E_REVOKED";                 break;
    case CERT_E_UNTRUSTEDTESTROOT:      pszName = (LPSTR)"CERT_E_UNTRUSTEDTESTROOT";       break;
    case CERT_E_REVOCATION_FAILURE:     pszName = (LPSTR)"CERT_E_REVOCATION_FAILURE";      break;
    case CERT_E_CN_NO_MATCH:            pszName = (LPSTR)"CERT_E_CN_NO_MATCH";             break;
    case CERT_E_WRONG_USAGE:            pszName = (LPSTR)"CERT_E_WRONG_USAGE";             break;
    default:                            pszName = (LPSTR)"(unknown)";                      break;
    }

    printf("Error 0x%x (%s) returned by CertVerifyCertificateChainPolicy!\n",
        Status, pszName);
}

DWORD
SSLclient::VerifyServerCertificate(
    PCCERT_CONTEXT  pServerCert,
    PSTR            pszServerName,
    DWORD           dwCertFlags)
{
    HTTPSPolicyCallbackData  polHttps;
    CERT_CHAIN_POLICY_PARA   PolicyPara;
    CERT_CHAIN_POLICY_STATUS PolicyStatus;
    CERT_CHAIN_PARA          ChainPara;
    PCCERT_CHAIN_CONTEXT     pChainContext = NULL;

    LPSTR rgszUsages[] = { (char*)szOID_PKIX_KP_SERVER_AUTH,
                            (char*)szOID_SERVER_GATED_CRYPTO,
                            (char*)szOID_SGC_NETSCAPE };
    DWORD cUsages = sizeof(rgszUsages) / sizeof(LPSTR);

    PWSTR   pwszServerName = NULL;
    DWORD   cchServerName;
    DWORD   Status;

    if (pServerCert == NULL)
    {
        Status = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }


    //
    // Convert server name to unicode.
    //

    if (pszServerName == NULL || strlen(pszServerName) == 0)
    {
        Status = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }

    cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, NULL, 0);
    pwszServerName = (PWSTR)LocalAlloc(LMEM_FIXED, cchServerName * sizeof(WCHAR));
    if (pwszServerName == NULL)
    {
        Status = SEC_E_INSUFFICIENT_MEMORY;
        goto cleanup;
    }
    cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, pwszServerName, cchServerName);
    if (cchServerName == 0)
    {
        Status = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }


    //
    // Build certificate chain.
    //

    ZeroMemory(&ChainPara, sizeof(ChainPara));
    ChainPara.cbSize = sizeof(ChainPara);
    ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    ChainPara.RequestedUsage.Usage.cUsageIdentifier = cUsages;
    ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = rgszUsages;

    if (!CertGetCertificateChain(
        NULL,
        pServerCert,
        NULL,
        pServerCert->hCertStore,
        &ChainPara,
        0,
        NULL,
        &pChainContext))
    {
        Status = GetLastError();
        printf("Error 0x%x returned by CertGetCertificateChain!\n", Status);
        goto cleanup;
    }


    //
    // Validate certificate chain.
    // 

    ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
    polHttps.cbStruct = sizeof(HTTPSPolicyCallbackData);
    polHttps.dwAuthType = AUTHTYPE_SERVER;
    polHttps.fdwChecks = dwCertFlags;
    polHttps.pwszServerName = pwszServerName;

    memset(&PolicyPara, 0, sizeof(PolicyPara));
    PolicyPara.cbSize = sizeof(PolicyPara);
    PolicyPara.pvExtraPolicyPara = &polHttps;

    memset(&PolicyStatus, 0, sizeof(PolicyStatus));
    PolicyStatus.cbSize = sizeof(PolicyStatus);

    if (!CertVerifyCertificateChainPolicy(
        CERT_CHAIN_POLICY_SSL,
        pChainContext,
        &PolicyPara,
        &PolicyStatus))
    {
        Status = GetLastError();
        printf("Error 0x%x returned by CertVerifyCertificateChainPolicy!\n", Status);
        goto cleanup;
    }

    if (PolicyStatus.dwError)
    {
        Status = PolicyStatus.dwError;
        DisplayWinVerifyTrustError(Status);
        goto cleanup;
    }


    Status = SEC_E_OK;

cleanup:

    if (pChainContext)
    {
        CertFreeCertificateChain(pChainContext);
    }

    if (pwszServerName)
    {
        LocalFree(pwszServerName);
    }

    return Status;
}



void
SSLclient::PrintHexDump(DWORD length, PBYTE buffer)
{
    DWORD i, count, index;
    CHAR rgbDigits[] = "0123456789abcdef";
    CHAR rgbLine[100];
    char cbLine;

    for (index = 0; length; length -= count, buffer += count, index += count)
    {
        count = (length > 16) ? 16 : length;

        sprintf(rgbLine, "%4.4x  ", index);
        cbLine = 6;

        for (i = 0; i < count; i++)
        {
            rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
            rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
            if (i == 7)
            {
                rgbLine[cbLine++] = ':';
            }
            else
            {
                rgbLine[cbLine++] = ' ';
            }
        }
        for (; i < 16; i++)
        {
            rgbLine[cbLine++] = ' ';
            rgbLine[cbLine++] = ' ';
            rgbLine[cbLine++] = ' ';
        }

        rgbLine[cbLine++] = ' ';

        for (i = 0; i < count; i++)
        {
            if (buffer[i] < 32 || buffer[i] > 126 || buffer[i] == '%')
            {
                rgbLine[cbLine++] = '.';
            }
            else
            {
                rgbLine[cbLine++] = buffer[i];
            }
        }

        rgbLine[cbLine++] = 0;
        printf("%s\n", rgbLine);
    }
}

void
SSLclient::DisplayCertChain(
    PCCERT_CONTEXT  pServerCert,
    BOOL            fLocal)
{
    CHAR szName[1000];
    PCCERT_CONTEXT pCurrentCert;
    PCCERT_CONTEXT pIssuerCert;
    DWORD dwVerificationFlags;

    printf("\n");

    // display leaf name
    if (!CertNameToStr(pServerCert->dwCertEncodingType,
        &pServerCert->pCertInfo->Subject,
        CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
        szName, sizeof(szName)))
    {
        printf("**** Error 0x%x building subject name\n", GetLastError());
    }
    if (fLocal)
    {
        printf("Client subject: %s\n", szName);
    }
    else
    {
        printf("Server subject: %s\n", szName);
    }
    if (!CertNameToStr(pServerCert->dwCertEncodingType,
        &pServerCert->pCertInfo->Issuer,
        CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
        szName, sizeof(szName)))
    {
        printf("**** Error 0x%x building issuer name\n", GetLastError());
    }
    if (fLocal)
    {
        printf("Client issuer: %s\n", szName);
    }
    else
    {
        printf("Server issuer: %s\n\n", szName);
    }


    // display certificate chain
    pCurrentCert = pServerCert;
    while (pCurrentCert != NULL)
    {
        dwVerificationFlags = 0;
        pIssuerCert = CertGetIssuerCertificateFromStore(pServerCert->hCertStore,
            pCurrentCert,
            NULL,
            &dwVerificationFlags);
        if (pIssuerCert == NULL)
        {
            if (pCurrentCert != pServerCert)
            {
                CertFreeCertificateContext(pCurrentCert);
            }
            break;
        }

        if (!CertNameToStr(pIssuerCert->dwCertEncodingType,
            &pIssuerCert->pCertInfo->Subject,
            CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
            szName, sizeof(szName)))
        {
            printf("**** Error 0x%x building subject name\n", GetLastError());
        }
        printf("CA subject: %s\n", szName);
        if (!CertNameToStr(pIssuerCert->dwCertEncodingType,
            &pIssuerCert->pCertInfo->Issuer,
            CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
            szName, sizeof(szName)))
        {
            printf("**** Error 0x%x building issuer name\n", GetLastError());
        }
        printf("CA issuer: %s\n\n", szName);

        if (pCurrentCert != pServerCert)
        {
            CertFreeCertificateContext(pCurrentCert);
        }
        pCurrentCert = pIssuerCert;
        pIssuerCert = NULL;
    }
}
void
SSLclient::DisplayConnectionInfo(
    CtxtHandle* phContext)
{
    SECURITY_STATUS Status;
    SecPkgContext_ConnectionInfo ConnectionInfo;

    Status = QueryContextAttributes(phContext,
        SECPKG_ATTR_CONNECTION_INFO,
        (PVOID)&ConnectionInfo);
    if (Status != SEC_E_OK)
    {
        printf("Error 0x%x querying connection info\n", Status);
        return;
    }

    printf("\n");

    switch (ConnectionInfo.dwProtocol)
    {
    case SP_PROT_TLS1_CLIENT:
        printf("Protocol: TLS1\n");
        break;

    case SP_PROT_SSL3_CLIENT:
        printf("Protocol: SSL3\n");
        break;

    case SP_PROT_PCT1_CLIENT:
        printf("Protocol: PCT\n");
        break;

    case SP_PROT_SSL2_CLIENT:
        printf("Protocol: SSL2\n");
        break;

    default:
        printf("Protocol: 0x%x\n", ConnectionInfo.dwProtocol);
    }

    switch (ConnectionInfo.aiCipher)
    {
    case CALG_RC4:
        printf("Cipher: RC4\n");
        break;

    case CALG_3DES:
        printf("Cipher: Triple DES\n");
        break;

    case CALG_RC2:
        printf("Cipher: RC2\n");
        break;

    case CALG_DES:
    case CALG_CYLINK_MEK:
        printf("Cipher: DES\n");
        break;

    case CALG_SKIPJACK:
        printf("Cipher: Skipjack\n");
        break;

    default:
        printf("Cipher: 0x%x\n", ConnectionInfo.aiCipher);
    }

    printf("Cipher strength: %d\n", ConnectionInfo.dwCipherStrength);

    switch (ConnectionInfo.aiHash)
    {
    case CALG_MD5:
        printf("Hash: MD5\n");
        break;

    case CALG_SHA:
        printf("Hash: SHA\n");
        break;

    default:
        printf("Hash: 0x%x\n", ConnectionInfo.aiHash);
    }

    printf("Hash strength: %d\n", ConnectionInfo.dwHashStrength);

    switch (ConnectionInfo.aiExch)
    {
    case CALG_RSA_KEYX:
    case CALG_RSA_SIGN:
        printf("Key exchange: RSA\n");
        break;

    case CALG_KEA_KEYX:
        printf("Key exchange: KEA\n");
        break;

    case CALG_DH_EPHEM:
        printf("Key exchange: DH Ephemeral\n");
        break;

    default:
        printf("Key exchange: 0x%x\n", ConnectionInfo.aiExch);
    }

    printf("Key exchange strength: %d\n", ConnectionInfo.dwExchStrength);
}

LONG
SSLclient::DisconnectFromServer(
    SOCKET          Socket,
    PCredHandle     phCreds,
    CtxtHandle* phContext)
{
    DWORD           dwType;
    PBYTE           pbMessage;
    DWORD           cbMessage;
    DWORD           cbData;

    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    DWORD           Status;

    //
    // Notify schannel that we are about to close the connection.
    //

    dwType = SCHANNEL_SHUTDOWN;

    OutBuffers[0].pvBuffer = &dwType;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer = sizeof(dwType);

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    Status = ApplyControlToken(phContext, &OutBuffer);

    if (FAILED(Status))
    {
        printf("**** Error 0x%x returned by ApplyControlToken\n", Status);
        goto cleanup;
    }

    //
    // Build an SSL close notify message.
    //

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT |
        ISC_REQ_REPLAY_DETECT |
        ISC_REQ_CONFIDENTIALITY |
        ISC_RET_EXTENDED_ERROR |
        ISC_REQ_ALLOCATE_MEMORY |
        ISC_REQ_STREAM;

    OutBuffers[0].pvBuffer = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer = 0;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    Status = InitializeSecurityContextA(
        phCreds,
        phContext,
        NULL,
        dwSSPIFlags,
        0,
        SECURITY_NATIVE_DREP,
        NULL,
        0,
        phContext,
        &OutBuffer,
        &dwSSPIOutFlags,
        &tsExpiry);

    if (FAILED(Status))
    {
        printf("**** Error 0x%x returned by InitializeSecurityContext\n", Status);
        goto cleanup;
    }

    pbMessage = (PBYTE)OutBuffers[0].pvBuffer;
    cbMessage = OutBuffers[0].cbBuffer;


    //
    // Send the close notify message to the server.
    //

    if (pbMessage != NULL && cbMessage != 0)
    {
        cbData = send(Socket, (char*)pbMessage, cbMessage, 0);
        if (cbData == SOCKET_ERROR || cbData == 0)
        {
            Status = WSAGetLastError();
            printf("**** Error %d sending close notify\n", Status);
            goto cleanup;
        }

        printf("Sending Close Notify\n");
        printf("%d bytes of handshake data sent\n", cbData);

            PrintHexDump(cbData, pbMessage);
            printf("\n");
        

        // Free output buffer.
        FreeContextBuffer(pbMessage);
    }


cleanup:

    // Free the security context.
    DeleteSecurityContext(phContext);

    // Close the socket.
    closesocket(Socket);

    return Status;
}