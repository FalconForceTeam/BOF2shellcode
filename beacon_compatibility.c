/*
 * Cobalt Strike 4.X BOF compatibility layer
 * -----------------------------------------
 * The whole point of these files are to allow beacon object files built for CS
 * to run fine inside of other tools without recompiling.
 *
 * Built off of the beacon.h file provided to build for CS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include "APIResolve.h"
#include "ministdlib.h"

#ifdef _WIN32
#include <windows.h>

#include "beacon_compatibility.h"

#define DEFAULTPROCESSNAME "rundll32.exe"
#ifdef _WIN64
#define X86PATH "SysWOW64"
#define X64PATH "System32"
#else
#define X86PATH "System32"
#define X64PATH "sysnative"
#endif


 /* Data Parsing */
uint32_t swap_endianess(uint32_t indata) {
    uint32_t testint = 0xaabbccdd;
    uint32_t outint = indata;
    if (((unsigned char*)&testint)[0] == 0xdd) {
        ((unsigned char*)&outint)[0] = ((unsigned char*)&indata)[3];
        ((unsigned char*)&outint)[1] = ((unsigned char*)&indata)[2];
        ((unsigned char*)&outint)[2] = ((unsigned char*)&indata)[1];
        ((unsigned char*)&outint)[3] = ((unsigned char*)&indata)[0];
    }
    return outint;
}

char* beacon_compatibility_output = NULL;
int beacon_compatibility_size = 0;
int beacon_compatibility_offset = 0;

void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (parser == NULL) {
        return;
    }
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size - 4;
    parser->size = size - 4;
    parser->buffer += 4;
    return;
}

int BeaconDataInt(datap* parser) {
    int32_t fourbyteint = 0;
    if (parser->length < 4) {
        return 0;
    }
    _memcpy(&fourbyteint, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return (int)fourbyteint;
}

short BeaconDataShort(datap* parser) {
    int16_t retvalue = 0;
    if (parser->length < 2) {
        return 0;
    }
   _memcpy(&retvalue, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return (short)retvalue;
}

int BeaconDataLength(datap* parser) {
    return parser->length;
}

char* BeaconDataExtract(datap* parser, int* size) {
    uint32_t length = 0;
    char* outdata = NULL;
    /*Length prefixed binary blob, going to assume uint32_t for this.*/
    if (parser->length < 4) {
        return NULL;
    }
   _memcpy(&length, parser->buffer, 4);
    parser->buffer += 4;

    outdata = parser->buffer;
    if (outdata == NULL) {
        return NULL;
    }
    parser->length -= 4;
    parser->length -= length;
    parser->buffer += length;
    if (size != NULL && outdata != NULL) {
        *size = length;
    }
    return outdata;
}

/* format API */

void BeaconFormatAlloc(formatp* format, int maxsz) {
    // TODO implement this again
    // if (format == NULL) {
    //     return;
    // }
    // format->original = calloc(maxsz, 1);
    // format->buffer = format->original;
    // format->length = 0;
    // format->size = maxsz;
    return;
}

void BeaconFormatReset(formatp* format) {
    _memset(format->original, 0, format->size);
    format->buffer = format->original;
    format->length = format->size;
    return;
}

void BeaconFormatFree(formatp* format) {
    // TODO reimplement
    // if (format == NULL) {
    //     return;
    // }
    // if (format->original) {
    //     free(format->original);
    //     format->original = NULL;
    // }
    // format->buffer = NULL;
    // format->length = 0;
    // format->size = 0;
    return;
}

void BeaconFormatAppend(formatp* format, char* text, int len) {
   _memcpy(format->buffer, text, len);
    format->buffer += len;
    format->length += len;
    return;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    // TODO reimplement
    tprintf _printf = (tprintf)getFunctionPtr(HASH_MSVCRT, HASH_printf);
    va_list args;
    va_start(args, fmt);
    _printf(fmt, args);
    va_end(args);

    // /*Take format string, and sprintf it into here*/
    // va_list args;
    // int length = 0;

    // va_start(args, fmt);
    // length = vsnprintf(NULL, 0, fmt, args);
    // va_end(args);
    // if (format->length + length > format->size) {
    //     return;
    // }

    // va_start(args, fmt);
    // (void)vsnprintf(format->buffer, length, fmt, args);
    // va_end(args);
    // format->length += length;
    // format->buffer += length;
    return;
}


char* BeaconFormatToString(formatp* format, int* size) {
    *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp* format, int value) {
    uint32_t indata = value;
    uint32_t outdata = 0;
    if (format->length + 4 > format->size) {
        return;
    }
    outdata = swap_endianess(indata);
   _memcpy(format->buffer, &outdata, 4);
    format->length += 4;
    format->buffer += 4;
    return;
}

/* Main output functions */

void BeaconPrintf(int type, char* fmt, ...) {
    tprintf _printf = (tprintf)getFunctionPtr(HASH_MSVCRT, HASH_printf);
    va_list args;
    va_start(args, fmt);
    _printf(fmt, args);
    va_end(args);
    return;
}

void BeaconOutput(int type, char* data, int len) {
    _puts(data);
    return;
}

/* Token Functions */

BOOL BeaconUseToken(HANDLE token) {
    /* Probably needs to handle DuplicateTokenEx too */
    tSetThreadToken _SetThreadToken = (tSetThreadToken)getFunctionPtr(HASH_ADVAPI32, HASH_SetThreadToken);
    _SetThreadToken(NULL, token);
    return TRUE;
}

void BeaconRevertToken(void) {
    tRevertToSelf _RevertToSelf = (tRevertToSelf)getFunctionPtr(HASH_ADVAPI32, HASH_RevertToSelf);
    if (!_RevertToSelf()) {
#ifdef DEBUG
        printf("RevertToSelf Failed!\n");
#endif
    }
    return;
}

BOOL BeaconIsAdmin(void) {
    /* Leaving this to be implemented by people needing it */
#ifdef DEBUG
    printf("BeaconIsAdmin Called\n");
#endif
    return FALSE;
}

/* Injection/spawning related stuffs
 *
 * These functions are basic place holders, and if implemented into something
 * real should be just calling internal functions for your tools. */
void BeaconGetSpawnTo(BOOL x86, char* buffer, int length) {
    // TODO re-implement
    return;
    // char* tempBufferPath = NULL;
    // if (buffer == NULL) {
    //     return;
    // }
    // if (x86) {
    //     tempBufferPath = "C:\\Windows\\"X86PATH"\\"DEFAULTPROCESSNAME;
    //     if (_strlen(tempBufferPath) > length) {
    //         return;
    //     }
    //     _memcpy(buffer, tempBufferPath, _strlen(tempBufferPath));
    // }
    // else {
    //     tempBufferPath = "C:\\Windows\\"X64PATH"\\"DEFAULTPROCESSNAME;
    //     if (_strlen(tempBufferPath) > length) {
    //         return;
    //     }
    //     _memcpy(buffer, tempBufferPath, _strlen(tempBufferPath));

    // }
    // return;
}

BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * sInfo, PROCESS_INFORMATION * pInfo) {
    // TODO re-implement
    return TRUE;
    // tCreateProcessA _CreateProcessA = (tCreateProcessA)getFunctionPtr(HASH_ADVAPI32, HASH_CreateProcessA);

    // BOOL bSuccess = FALSE;
    // if (x86) {
    //     bSuccess = _CreateProcessA(NULL, (char*)"C:\\Windows\\"X86PATH"\\"DEFAULTPROCESSNAME, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
    // }
    // else {
    //     bSuccess = _CreateProcessA(NULL, (char*)"C:\\Windows\\"X64PATH"\\"DEFAULTPROCESSNAME, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
    // }
    // return bSuccess;
}

void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char * arg, int a_len) {
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len) {
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo) {
    tCloseHandle _CloseHandle = (tCloseHandle)getFunctionPtr(HASH_ADVAPI32, HASH_CreateProcessA);
    
    (void)_CloseHandle(pInfo->hThread);
    (void)_CloseHandle(pInfo->hProcess);
    return;
}

BOOL toWideChar(char* src, wchar_t* dst, int max) {
    /* Leaving this to be implemented by people needing/wanting it */
    return FALSE;
}

char* BeaconGetOutputData(int *outsize) {
    // TODO reimplement
    return NULL;
    // char* outdata = beacon_compatibility_output;
    // *outsize = beacon_compatibility_size;
    // beacon_compatibility_output = NULL;
    // beacon_compatibility_size = 0;
    // beacon_compatibility_offset = 0;
    // return outdata;
}

#endif
