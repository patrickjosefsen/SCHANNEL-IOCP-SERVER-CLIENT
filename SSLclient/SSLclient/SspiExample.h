#pragma once
#include <sspi.h>
#include <windows.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Secur32.lib")


BOOL SendMsg(SOCKET s, PBYTE pBuf, DWORD cbBuf);
BOOL ReceiveMsg(SOCKET s, PBYTE pBuf, DWORD cbBuf, DWORD* pcbRead);
BOOL SendBytes(SOCKET s, PBYTE pBuf, DWORD cbBuf);
BOOL ReceiveBytes(SOCKET s, PBYTE pBuf, DWORD cbBuf, DWORD* pcbRead);
void cleanup();

BOOL GenClientContext(
    BYTE* pIn,
    DWORD       cbIn,
    BYTE* pOut,
    DWORD* pcbOut,
    SecBuffer* pExtraData,
    BOOL* pfDone,
    BOOL* dontSend,
    CHAR* pszTarget,
    CredHandle* hCred,
    struct _SecHandle* hcText
);

BOOL GenServerContext(
    BYTE* pIn,
    DWORD cbIn,
    BYTE* pOut,
    DWORD* pcbOut,
    BOOL* pfDone,
    BOOL  fNewCredential
);

BOOL EncryptThis(
    PBYTE pMessage,
    ULONG cbMessage,
    BYTE** ppOutput,
    LPDWORD pcbOutput,
    ULONG securityTrailer
);

PBYTE DecryptThis(
    PBYTE achData,
    LPDWORD pcbMessage,
    struct _SecHandle* hCtxt,
    ULONG   cbSecurityTrailer
);

BOOL
SignThis(
    PBYTE pMessage,
    ULONG cbMessage,
    BYTE** ppOutput,
    LPDWORD pcbOutput
);

PBYTE VerifyThis(
    PBYTE pBuffer,
    LPDWORD pcbMessage,
    struct _SecHandle* hCtxt,
    ULONG   cbMaxSignature
);

void PrintHexDump(DWORD length, PBYTE buffer);

BOOL ConnectAuthSocket(
    SOCKET* s,
    CredHandle* hCred,
    struct _SecHandle* hcText
);

BOOL CloseAuthSocket(SOCKET s);

BOOL DoAuthentication(SOCKET s);

void MyHandleError(std::string s);