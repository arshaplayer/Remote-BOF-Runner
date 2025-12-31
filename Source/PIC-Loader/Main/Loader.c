/*
 * Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <windows.h>
#include <string.h>
#include <stdarg.h>
#include "TCG.h"
#include "IPC.h"

WINBASEAPI LPVOID  WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI VOID    WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI VOID    WINAPI KERNEL32$ExitProcess(UINT uExitCode);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
WINBASEAPI DWORD   WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI int     WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

WINUSERAPI HWND WINAPI USER32$CreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
WINUSERAPI BOOL WINAPI USER32$DestroyWindow(HWND hWnd);

WINBASEAPI int    WINAPI MSVCRT$strcmp(const char *str1, const char *str2);
WINBASEAPI int    WINAPI MSVCRT$vsnprintf(char *str, size_t size, const char *format, va_list ap);
WINBASEAPI int 	  WINAPI MSVCRT$sprintf(char *str, const char *format, ...);
WINBASEAPI void * WINAPI MSVCRT$memcpy(void *dest, const void *src, size_t n);

/*
 * This is our opt-in Dynamic Function Resolution resolver. It turns MODULE$Function into pointers.
 * See dfr "resolve" in loader.spec
 */
FARPROC resolve(DWORD modHash, DWORD funcHash) {
	HANDLE hModule = findModuleByHash(modHash);
	return findFunctionByHash(hModule, funcHash);
}

/*
 * This is our opt-in function to help fix ptrs in x86 PIC. See fixptrs _caller" in loader.spec
 */
#ifdef WIN_X86
__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)WIN_GET_CALLER(); }
#endif

/*
 * find RW slackspace at the end of a .rdata section
 */
#define FLAG(x, y) ( ((x) & (y)) == (y) )
 
char * findDataCave(char * dllBase, int length) {
    DLLDATA                 data;
    DWORD                   numberOfSections;
    IMAGE_SECTION_HEADER  * sectionHdr       = NULL;
    IMAGE_SECTION_HEADER  * sectionNxt       = NULL;
 
    /* parse our DLL! */
    ParseDLL(dllBase, &data);
 
    /* loop through our sections */
    numberOfSections = data.NtHeaders->FileHeader.NumberOfSections;
    sectionHdr       = (IMAGE_SECTION_HEADER *)PTR_OFFSET(data.OptionalHeader, data.NtHeaders->FileHeader.SizeOfOptionalHeader);
    for (int x = 0; (x + 1) < numberOfSections; x++) {
        /* look for our RW section! */
        if (FLAG(sectionHdr->Characteristics, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA)) {
            /* let's look at our next section, we need it to get the right size of the code cave */
            sectionNxt      = sectionHdr + 1;
 
            /* calculate the size, based on section headers */
            DWORD size      = sectionNxt->VirtualAddress - sectionHdr->VirtualAddress;
 
            /* calculate the size of our code cave */
            DWORD cavesize  = size - sectionHdr->SizeOfRawData;
 
            /* if we fit, return it */
            if (length < cavesize)
                return dllBase + (sectionNxt->VirtualAddress - cavesize);
        }
 
        /* advance to our next section */
        sectionHdr++;
    }
 
    return NULL;
}
 
/*
 * This is our opt-in fixbss function. The method here is to look for slack R/W space within various
 * loaded modules and use that for our .bss section. This is not compatible with multiple PICs being
 * resident in the same process space using this method--but it does do the job of giving us global
 * variables in our PIC.
 */
 
char * getBSS(DWORD length) {
    /* try in our module */
    HANDLE hModule = KERNEL32$GetModuleHandleA(NULL);
    char * ptr     = findDataCave(hModule, length);
 
    if (ptr != NULL)
        return ptr;
 
    /* try in kernel32 */
    hModule = KERNEL32$GetModuleHandleA("kernel32.dll");
    ptr     = findDataCave(hModule, length);
    if (ptr != NULL)
        return ptr;
 
    /* it's really bad news if we get here... ka-rash! */
    return NULL;
}

/*
 * Initialize UI context for .NET compatibility
 * This forces initialization of message queue and window structures
 * which are necessary for .NET processes to function properly
 */
void InitializeUIContext() {
	LoadLibraryA("user32.dll");
	HWND hwnd = USER32$CreateWindowExA(WS_EX_NOACTIVATE, "Static", "", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);
	if (hwnd) {
		USER32$DestroyWindow(hwnd);
	}
}

/*
 * This is the Crystal Palace convention for getting ahold of data linked with this loader.
 */
char __BOFDATA__[0] __attribute__((section("bof")));
char __BOFARGS__[0] __attribute__((section("bof_args")));

char * findAppendedBof() {
	return (char *)&__BOFDATA__;
}

char * findAppendedBofArgs() {
	return (char *)&__BOFARGS__;
}

typedef void (*BOF_ENTRY)(char* args, int len);

/* Global IPC client instance for BeaconOutput and BeaconPrintf */
IpcInstance* g_ipc;

/* Convert ANSI string to wchar_t in place within allocated buffer */
char * ConvertAnsiToWideInBuffer(char * ansi_buffer, int ansi_len) {
	/* Extract the size header from ANSI data (first 4 bytes) */
	int * ansi_size_ptr = (int*)ansi_buffer;
	int ansi_data_size = *ansi_size_ptr;  /* Size of the actual ANSI string */
	
	/* The actual ANSI string data starts at offset +4 */
	char * ansi_string = ansi_buffer + 4;
	
	/* Allocate space for: [DWORD size header] + [wchar_t data] */
	/* Size in bytes of wchar_t data = ansi_data_size * 2 */
	int wide_data_size = ansi_data_size * 2;
	int total_alloc = 4 + wide_data_size;  /* 4 bytes for header + data */
	
	char * wide_buffer = (char*)KERNEL32$VirtualAlloc(NULL, total_alloc + 2, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	
	if (!wide_buffer) {
		return NULL;
	}
	
	/* Write the new size header in bytes (for wchar_t data) */
	int * wide_size_ptr = (int*)wide_buffer;
	*wide_size_ptr = wide_data_size;
	
	/* Convert ANSI string to wchar_t at offset +4 */
	wchar_t * wide_string = (wchar_t*)(wide_buffer + 4);
	int wide_len = KERNEL32$MultiByteToWideChar(CP_ACP, 0, (LPCCH)ansi_string, ansi_data_size, wide_string, ansi_data_size + 1);
	
	if (wide_len <= 0) {
		KERNEL32$VirtualFree(wide_buffer, 0, MEM_RELEASE);
		return NULL;
	}
	
	wide_string[wide_len] = 0;  /* Null terminate */
	
	return wide_buffer;
}

/* Initialize the global IPC client */
BOOL InitializeBeaconIPC() {
	HANDLE ipcClientHandle = InitializeIpcClient("Remote-BOF-Runner-Pipe", NULL);
	if (!ipcClientHandle || ipcClientHandle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	
	g_ipc = (IpcInstance*)KERNEL32$VirtualAlloc(NULL, sizeof(IpcInstance), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	if (!g_ipc) {
		return FALSE;
	}
	
	g_ipc->h_channel = ipcClientHandle;
	return TRUE;
}

/* Close the global IPC client */
void CloseBeaconIPC() {
	if (g_ipc) {
		CloseIpcClient(g_ipc);
		KERNEL32$VirtualFree(g_ipc, 0, MEM_RELEASE);
		g_ipc = NULL;
	}
}

void BeaconOutput(int type, const char * data, int len) {
	if (!data || len <= 0 || !g_ipc) {
		return;
	}

	/* Fragment size: IPC_BUFFER_SIZE - length of MESSAGE_DELIMITER */
	int fragmentSize = IPC_BUFFER_SIZE - sizeof(MESSAGE_DELIMITER);
	int offset = 0;
	
	while (offset < len) {
		int chunkLen = len - offset;
		if (chunkLen > fragmentSize) {
			chunkLen = fragmentSize;
		}
		
		/* Create fragment buffer */
		char fragment[IPC_BUFFER_SIZE] = { 0 };
		for (int i = 0; i < chunkLen; i++) {
			fragment[i] = data[offset + i];
		}
		
		AddIpcMessage(g_ipc, fragment);

		offset += chunkLen;
	}
}

void BeaconPrintf(int type, const char * fmt, ...) {
	va_list args;
	char buffer[1024] = { 0 };
	int len;
	
	/* Format the string with variable arguments */
	va_start(args, fmt);
	len = MSVCRT$vsnprintf(buffer, sizeof(buffer) - 1, fmt, args);
	va_end(args);
	
	/* Send the formatted output via BeaconOutput if successful */
	if (len > 0) {
		BeaconOutput(type, buffer, len);
	}
}

/* data API */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} datap;

void BeaconDataParse(datap * parser, char * buffer, int size) {
	if (parser == NULL)
		return;

	parser->original = buffer;
	parser->buffer   = buffer;
	parser->length   = size;
	parser->size     = size;
}

char * BeaconDataPtr(datap * parser, int size) {
	char * ptr = parser->buffer;
	parser->buffer += size;
	parser->length -= size;
	return ptr;
}

int BeaconDataInt(datap * parser) {
	int value = 0;

	if (parser->length < 4)
		return 0;

	MSVCRT$memcpy(&value, parser->buffer, 4);

	parser->buffer += 4;
	parser->length -= 4;

	return value;
}

short BeaconDataShort(datap * parser) {
	short value = 0;

	if (parser->length < 2)
		return 0;

	MSVCRT$memcpy(&value, parser->buffer, 2);

	parser->buffer += 2;
	parser->length -= 2;

	return value;
}

int BeaconDataLength(datap * parser) {
	return parser->length;
}

char * BeaconDataExtract(datap * parser, int * size) {
	int length = 0;
	char * data = NULL;

	if (parser->length < 4) {
		if (size != NULL)
			*size = 0;
		return NULL;
	}

	MSVCRT$memcpy(&length, parser->buffer, 4);

	parser->buffer += 4;

	data = parser->buffer;
	if (data == NULL) {
		if (size != NULL)
			*size = 0;
		return NULL;
	}

	parser->length -= 4;
	parser->length -= length;
	parser->buffer += length;

	if (size != NULL)
		*size = length;

	return data;
}

HMODULE WINAPI _LoadLibraryA(LPCSTR lpLibFileName) {
	if(MSVCRT$strcmp(lpLibFileName, "BEACON") == 0) {
		return (HMODULE)0xBEEFCAFE;
	} else {
		return LoadLibraryA(lpLibFileName);
	}
}

FARPROC WINAPI _GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	if(hModule == (HMODULE)0xBEEFCAFE) {
		if(MSVCRT$strcmp(lpProcName, "BeaconOutput") == 0) {
			return (FARPROC)BeaconOutput;
		}

		if(MSVCRT$strcmp(lpProcName, "BeaconPrintf") == 0) {
			return (FARPROC)BeaconPrintf;
		}

		if(MSVCRT$strcmp(lpProcName, "BeaconDataParse") == 0) {
			return (FARPROC)BeaconDataParse;
		}

		if(MSVCRT$strcmp(lpProcName, "BeaconDataPtr") == 0) {
			return (FARPROC)BeaconDataPtr;
		}

		if(MSVCRT$strcmp(lpProcName, "BeaconDataInt") == 0) {
			return (FARPROC)BeaconDataInt;
		}

		if(MSVCRT$strcmp(lpProcName, "BeaconDataShort") == 0) {
			return (FARPROC)BeaconDataShort;
		}

		if(MSVCRT$strcmp(lpProcName, "BeaconDataLength") == 0) {
			return (FARPROC)BeaconDataLength;
		}

		if(MSVCRT$strcmp(lpProcName, "BeaconDataExtract") == 0) {
			return (FARPROC)BeaconDataExtract;
		}
	}

    FARPROC result = __resolve_hook(ror13hash(lpProcName));
    if (result != NULL)
        return result;
 
    return GetProcAddress(hModule, lpProcName);
}

/*
 * Our PICO loader, have fun, go nuts!
 */
void go() {
	char        * dstCode;
	char        * dstData;
	char        * src;
	IMPORTFUNCS   funcs;

	/* Force UI context initialization for .NET compatibility */
	InitializeUIContext();

	/* find our DLL appended to this PIC */
	src = findAppendedBof();

	/* allocate memory for our PICO */
	dstCode = KERNEL32$VirtualAlloc( NULL, PicoCodeSize(src), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE );
	dstData = KERNEL32$VirtualAlloc( NULL, PicoDataSize(src), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_READWRITE );

	/* setup our IMPORTFUNCS data structure */
	funcs.GetProcAddress = _GetProcAddress;
	funcs.LoadLibraryA   = _LoadLibraryA;

	/* load our pico into our destination address, thanks! */
	PicoLoad(&funcs, src, dstCode, dstData);

	/* Initialize IPC client before executing the PICO */
	if (!InitializeBeaconIPC()) {
		KERNEL32$ExitProcess(1);
	}

	/* Get BOF arguments from appended section */
	char * bof_args = findAppendedBofArgs();
	char * args_to_pass = NULL;
	int bof_args_len = 0;
	
	/* If there are arguments, skip outer headers and pass the inner Beacon data */
	if (bof_args != NULL) {
		int * size_ptr = (int*)bof_args;
		int outer_size = *size_ptr;
		
		if (outer_size > 0) {
			/* Skip both the preplen header (4 bytes) and the inner Packer header (4 bytes) */
			args_to_pass = bof_args + 8;
			bof_args_len = outer_size - 4;
		}
	}

	/* execute our pico with BOF arguments */
	((BOF_ENTRY)PicoEntryPoint(src, dstCode)) (args_to_pass, bof_args_len);

	/* Close IPC client after execution */
	CloseBeaconIPC();

	KERNEL32$ExitProcess(0);
}
