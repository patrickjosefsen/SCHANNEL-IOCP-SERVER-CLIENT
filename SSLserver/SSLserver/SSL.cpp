#include "SSL.h"


BOOL
SSL::SSPINegotiateLoop(
    int id,
    int bytetrans,
    
    
    
    
    
    players* Players)
{


    DWORD sendec;
    

    

    DWORD                dwSSPIFlags, dwSSPIOutFlags;
   
    

    dwSSPIFlags = ASC_REQ_SEQUENCE_DETECT |
        ASC_REQ_REPLAY_DETECT |
        ASC_REQ_CONFIDENTIALITY |
        ASC_REQ_EXTENDED_ERROR |
        ASC_REQ_ALLOCATE_MEMORY |
        ASC_REQ_STREAM;

    if (Players[id].firstneg) {
        

        Players[id].OutBuffer.cBuffers = 1;
        Players[id].OutBuffer.pBuffers = Players[id].negOutBuffers;
        Players[id].OutBuffer.ulVersion = SECBUFFER_VERSION;
        Players[id].scRet = SEC_I_CONTINUE_NEEDED;
        
        
    }


    //
    //  set OutBuffer for InitializeSecurityContext call
    //

 


    Players[id].cbIoBuffer += bytetrans;
    //Players[id].cbIoBuffer += Players[id].wsaRecv; //skal tjekkes
   

    





        //
        // InBuffers[1] is for getting extra data that
        //  SSPI/SCHANNEL doesn't proccess on this
        //  run around the loop.
        //
        
        Players[id].negInBuffers[0].pvBuffer = Players[id].IoBuffer;
        Players[id].negInBuffers[0].cbBuffer = Players[id].cbIoBuffer;
        Players[id].negInBuffers[0].BufferType = SECBUFFER_TOKEN;

        Players[id].negInBuffers[1].pvBuffer = NULL;
        Players[id].negInBuffers[1].cbBuffer = 0;
        Players[id].negInBuffers[1].BufferType = SECBUFFER_EMPTY;

        Players[id].InBuffer.cBuffers = 2;
        Players[id].InBuffer.pBuffers = Players[id].negInBuffers;//SKAL TJEKKES POITER LAVET OM
        Players[id].InBuffer.ulVersion = SECBUFFER_VERSION;


        //
        // Initialize these so if we fail, pvBuffer contains NULL,
        // so we don't try to free random garbage at the quit
        //

        Players[id].negOutBuffers[0].pvBuffer = NULL;
        Players[id].negOutBuffers[0].BufferType = SECBUFFER_TOKEN;
        Players[id].negOutBuffers[0].cbBuffer = 0;
        
        
        if (Players[id].firstneg) {
            Players[id].scRet = AcceptSecurityContext(
                &Creds,
                NULL,
                &Players[id].InBuffer,
                dwSSPIFlags,
                SECURITY_NATIVE_DREP,
                &Players[id].phContext,
                &Players[id].OutBuffer,
                &dwSSPIOutFlags,
                &Players[id].tsExpiry);
            
            Players[id].firstneg = FALSE;
            fprintf(stderr, "AcceptSecurityContext failed: 0x%08x\n", Players[id].scRet);
            
         
        }
        else
        {
            Players[id].scRet = AcceptSecurityContext(
                &Creds,
                &Players[id].phContext,
                &Players[id].InBuffer,
                dwSSPIFlags,
                SECURITY_NATIVE_DREP,
                NULL,
                &Players[id].OutBuffer,
                &dwSSPIOutFlags,
                &Players[id].tsExpiry);
            fprintf(stderr, "AcceptSecurityContext failed: 0x%08x\n", Players[id].scRet);
        }
       ;
       
        
        
        


        if (Players[id].scRet == SEC_E_OK ||
            Players[id].scRet == SEC_I_CONTINUE_NEEDED ||
            (FAILED(Players[id].scRet) && (0 != (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))))
        {
            if (Players[id].negOutBuffers[0].cbBuffer != 0 &&
                Players[id].negOutBuffers[0].pvBuffer != NULL)
            {
                //
                // Send response to server if there is one
                //
                
                sendec = send(Players[id].SSLSocket,
                    (char*)Players[id].negOutBuffers[0].pvBuffer,
                    Players[id].negOutBuffers[0].cbBuffer,
                    0);
                    
               

                FreeContextBuffer(Players[id].negOutBuffers[0].pvBuffer);
                Players[id].negOutBuffers[0].pvBuffer = NULL;
            }
        }


        if (Players[id].scRet == SEC_E_OK)
        {
            std::cout << "jeg når sec e ok" << std::endl;

            if (Players[id].negInBuffers[1].BufferType == SECBUFFER_EXTRA)
            {

                memcpy(Players[id].IoBuffer,
                    (LPBYTE)(Players[id].IoBuffer + (Players[id].cbIoBuffer - Players[id].negInBuffers[1].cbBuffer)),
                    Players[id].negInBuffers[1].cbBuffer);
                Players[id].cbIoBuffer = Players[id].negInBuffers[1].cbBuffer;
            }
            else
            {
                Players[id].cbIoBuffer = 0;
            }
            Players[id].scRet = QueryContextAttributes(&Players[id].phContext, SECPKG_ATTR_STREAM_SIZES, &Players[id].Sizes);


            if (Players[id].scRet != SEC_E_OK)
            {
                printf("Couldn't get Sizes\n");
               
            }
   

            return TRUE;
        }
        else if (FAILED(Players[id].scRet) && (Players[id].scRet != SEC_E_INCOMPLETE_MESSAGE))
        {

            Players[id].fail = true;
            //Clean socket up
            return FALSE;

        }



        if (Players[id].scRet != SEC_E_INCOMPLETE_MESSAGE &&
            Players[id].scRet != SEC_I_INCOMPLETE_CREDENTIALS)
        {


            if (Players[id].negInBuffers[1].BufferType == SECBUFFER_EXTRA)
            {



                memcpy(Players[id].IoBuffer,
                    (LPBYTE)(Players[id].IoBuffer + (Players[id].cbIoBuffer - Players[id].negInBuffers[1].cbBuffer)),
                    Players[id].negInBuffers[1].cbBuffer);
                Players[id].cbIoBuffer = Players[id].negInBuffers[1].cbBuffer;
                return FALSE;
            }
            else
            {
                //
                // prepare for next receive
                //

                Players[id].cbIoBuffer = 0;
                return FALSE;
            }
        }
    
   
    return FALSE;
}


void SSL::initialize(int playerCount, players* Players) {
    getSchannelClientHandle();
    for (int i = 0; i < playerCount; i++) {

        Players[i].cbIoBuffer = 0;
        Players[i].SSLTcpRcvWsabuf.len = IO_BUFFER_SIZE;
        Players[i].SSLTcpRcvWsabuf.buf = Players[i].IoBuffer + Players[i].cbIoBuffer;
        Players[i].Message.ulVersion = SECBUFFER_VERSION;
        Players[i].Message.cBuffers = 4;
        Players[i].Message.pBuffers = Players[i].recvBuffers;

        Players[i].recvBuffers[0].BufferType = SECBUFFER_EMPTY;
        Players[i].recvBuffers[1].BufferType = SECBUFFER_EMPTY;
        Players[i].recvBuffers[2].BufferType = SECBUFFER_EMPTY;
        Players[i].recvBuffers[3].BufferType = SECBUFFER_EMPTY;

        Players[i].MessageOut.ulVersion = SECBUFFER_VERSION;
        Players[i].MessageOut.cBuffers = 4;
        Players[i].MessageOut.pBuffers = Players[i].sendBuffers;

        Players[i].sendBuffers[0].BufferType = SECBUFFER_EMPTY;
        Players[i].sendBuffers[1].BufferType = SECBUFFER_EMPTY;
        Players[i].sendBuffers[2].BufferType = SECBUFFER_EMPTY;
        Players[i].sendBuffers[3].BufferType = SECBUFFER_EMPTY;
    }
    
}

SECURITY_STATUS SSL::SSLsend(int id, players* Players,int *WSAstatuscode) {
    //kan se send og recv buffer måske skal være det samme efter som de er forbundet med i
    
    Players[id].sendBuffers[0].pvBuffer = Players[id].IoBuffer;
    Players[id].sendBuffers[0].cbBuffer = Players[id].Sizes.cbHeader;
    Players[id].sendBuffers[0].BufferType = SECBUFFER_STREAM_HEADER;

    Players[id].sendBuffers[1].pvBuffer = Players[id].IoBuffer + Players[id].Sizes.cbHeader;
    Players[id].sendBuffers[1].cbBuffer = Players[id].i;
    Players[id].sendBuffers[1].BufferType = SECBUFFER_DATA;

    Players[id].sendBuffers[2].pvBuffer = Players[id].IoBuffer + Players[id].Sizes.cbHeader + Players[id].i;
    Players[id].sendBuffers[2].cbBuffer = Players[id].Sizes.cbTrailer;
    Players[id].sendBuffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

    Players[id].sendBuffers[3].BufferType = SECBUFFER_EMPTY;

    Players[id].scRet = EncryptMessage(&Players[id].phContext, 0, &Players[id].Message, 0);

    if (FAILED(Players[id].scRet))
    {
        return Players[id].scRet;
    }
    *WSAstatuscode = send(Players[id].SSLSocket,
        Players[id].IoBuffer,
        Players[id].sendBuffers[0].cbBuffer + Players[id].sendBuffers[1].cbBuffer + Players[id].sendBuffers[2].cbBuffer,
        0);
}

SECURITY_STATUS SSL::SSLrecv(int id, players* Players) {
    Players[id].recvBuffers[0].pvBuffer = Players[id].IoBuffer;
    Players[id].recvBuffers[0].cbBuffer = Players[id].cbIoBuffer;
    Players[id].recvBuffers[0].BufferType = SECBUFFER_DATA;

    Players[id].recvBuffers[1].BufferType = SECBUFFER_EMPTY;
    Players[id].recvBuffers[2].BufferType = SECBUFFER_EMPTY;
    Players[id].recvBuffers[3].BufferType = SECBUFFER_EMPTY;

    Players[id].scRet = DecryptMessage(&Players[id].phContext, &Players[id].Message, 0, NULL);//det kan forkomme at der skal pre decryptikate før hver besked
    Players[id].cbIoBuffer += Players[id].wsaRecv;
    if (Players[id].scRet == SEC_E_INCOMPLETE_MESSAGE) {
        return Players[id].scRet;
    }
    if (Players[id].scRet == SEC_E_OK) {
        Players[id].decryptresult = NULL;
        for (Players[id].i = 1; Players[id].i < 4; Players[id].i++)
        {
            if (Players[id].recvBuffers[Players[id].i].BufferType == SECBUFFER_DATA)
            {
                Players[id].decryptresult = &Players[id].recvBuffers[Players[id].i];
                break;
            }
        }
    }

    return Players[id].scRet;

 //det færdige resultat er i pDataBuffer->pvBuffer

}





void SSL::getSchannelClientHandle()
{
    SECURITY_STATUS SecStatus;
    TimeStamp Lifetime;
    CredHandle hCred;
    SCHANNEL_CRED credData;
   
    _SecPkgCred_SupportedAlgs algs;

    PCCERT_CONTEXT serverCert= NULL; // server-side certificate
  //-------------------------------------------------------
  // Get the server certificate. 

    HCERTSTORE hMyCertStore = NULL;
    

    //-------------------------------------------------------
    // Open the My store, also called the personal store.
    // This call to CertOpenStore opens the Local_Machine My 
    // store as opposed to the Current_User's My store.

    hMyCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
        X509_ASN_ENCODING,
        NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
        L"MY");

    if (hMyCertStore == NULL)
    {
        printf("Error opening MY store for server.\n");
        
    }
    //-------------------------------------------------------
    // Search for a certificate with some specified
    // string in it. This example attempts to find
    // a certificate with the string "example server" in
    // its subject string. Substitute an appropriate string
    // to find a certificate for a specific user.

    serverCert = CertFindCertificateInStore(hMyCertStore,
        X509_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR_A,
        MACHINE_NAME, // use appropriate subject name
        NULL
    );

    if (serverCert == NULL)
    {
        printf("Error retrieving server certificate.");
        
    }
    /*
    if (hMyCertStore)
    {
        CertCloseStore(hMyCertStore, 0);
    }
    */

    

    // getServerCertificate is a placeholder function.
    

    ZeroMemory(&credData, sizeof(credData));
    credData.dwVersion = SCHANNEL_CRED_VERSION;
    //credData.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK | SCH_USE_STRONG_CRYPTO;
    credData.cCreds = 1;
    credData.paCred = &serverCert;
    //credData.dwCredFormat = SCH_CRED_FORMAT_CERT_HASH;
   
    
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
    credData.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
    
    
    SecStatus = AcquireCredentialsHandle(
        NULL,                  // default principal
        (LPSTR)UNISP_NAME,            // name of the SSP
        SECPKG_CRED_INBOUND,  // client will use the credentials
        NULL,                  // use the current LOGON id
        &credData,             // protocol-specific data
        NULL,                  // default
        NULL,                  // default
        &hCred,                // receives the credential handle
        &Lifetime              // receives the credential time limit
    );
    printf("Client credentials status: 0x%x\n", SecStatus);
    // Return the handle to the caller.
    
        Creds = hCred;

        SecStatus = QueryCredentialsAttributesA(&hCred, SECPKG_ATTR_SUPPORTED_ALGS, &algs);

        for (int i = 0; i < algs.cSupportedAlgs; i++) {
            fprintf(stderr, "alg: 0x%08x\n", algs.palgSupportedAlgs[i]);
        }
    return;
    //-------------------------------------------------------
    // When you have finished with this handle,
    // free the handle by calling the 
    // FreeCredentialsHandle function.
}