/*
 * COFF Loader Project
 * -------------------
 * This is a re-implementation of a COFF loader, with a BOF compatibility layer
 * it's meant to provide functional example of loading a COFF file in memory
 * and maybe be useful.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "APIResolve.h"
#include "ministdlib.h"

#if defined(_WIN32)
#include <windows.h>
#include "beacon_compatibility.h"
#endif

#include "COFFLoader.h"

 /* Enable or disable debug output if testing or adding new relocation types */
#ifdef DEBUG
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(x, ...)
#endif

/* Defining symbols for the OS version, will try to define anything that is
 * different between the arch versions by specifying them here. */
#if defined(__x86_64__) || defined(_WIN64)
#define PREPENDSYMBOLVALUE "__imp_"
#else
#define PREPENDSYMBOLVALUE "__imp__"
#endif

static unsigned long
djb2(char* str)
{
	unsigned long hash = 5381;
	int c;

	while ((c = *str++))
		hash = ((hash << 5) + hash) + c;

	return hash;
}


#ifdef EXEVERSION
unsigned char* unhexlify(unsigned char* value, int *outlen) {
    unsigned char* retval = NULL;
    char byteval[3] = { 0 };
    int counter = 0;
    int counter2 = 0;
    char character = 0;
    if (value == NULL) {
        return NULL;
    }
    DEBUG_PRINT("Unhexlify Strlen: %lu\n", (long unsigned int)_strlen((char*)value));
    if (value == NULL || _strlen((char*)value) % 2 != 0) {
        DEBUG_PRINT("Either value is NULL, or the hexlified string isn't valid\n");
        goto errcase;
    }

    retval = calloc(_strlen((char*)value) + 1, 1);
    if (retval == NULL) {
        goto errcase;
    }

    counter2 = 0;
    for (counter = 0; counter < _strlen((char*)value); counter += 2) {
        _memcpy(byteval, value + counter, 2);
        character = strtol(byteval, NULL, 16);
        _memcpy(retval + counter2, &character, 1);
        counter2++;
    }
    *outlen = counter2;

errcase:
    return retval;
}



/* Helper to just get the contents of a file, used for testing. Real
 * implementations of this in an agent would use the tasking from the
 * C2 server for this */
unsigned char* getContents(char* filepath, uint32_t* outsize) {
    FILE *fin = NULL;
    uint32_t fsize = 0;
    uint32_t readsize = 0;
    unsigned char* buffer = NULL;
    unsigned char* tempbuffer = NULL;

    fin = fopen(filepath, "rb");
    if (fin == NULL) {
        return NULL;
    }
    fseek(fin, 0, SEEK_END);
    fsize = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    tempbuffer = calloc(fsize, 1);
    if (tempbuffer == NULL) {
        return NULL;
    }
    _memset(tempbuffer, 0, fsize);
    readsize = fread(tempbuffer, 1, fsize, fin);

    fclose(fin);
    buffer = calloc(readsize, 1);
    if (buffer == NULL) {
        return NULL;
    }
    _memset(buffer, 0, readsize);
    _memcpy(buffer, tempbuffer, readsize - 1);
    free(tempbuffer);
    *outsize = fsize;
    return buffer;
}
#endif

/* Helper function to process a symbol string, determine what function and
 * library its from, and return the right function pointer. Will need to
 * implement in the loading of the beacon internal functions, or any other
 * internal functions you want to have available. */
void* process_symbol(char* symbolstring) {
    void* functionaddress = NULL;
    char localcopy[1024] = { 0 };
    char* locallib = NULL;
    char* localfunc = NULL;
    static unsigned long funchash = 0;    
#if defined(_WIN32)    
    HMODULE llHandle = NULL;
#endif

   _memcpy(localcopy, symbolstring, _strlen(symbolstring));
    char msg1[] = {'_','_','i','m','p','_','B','e','a','c','o','n', 0x00};
    char msg2[] = {'_','_','i','m','p','_','t','o','W','i','d','e','C','h','a','r', 0x00};
    char msg3[] = {'_','_','i','m','p','_', 0x00};
    if (_strncmp(symbolstring, msg1, _strlen(msg1)) == 0 || _strncmp(symbolstring, msg2, _strlen(msg2)) == 0) {
        localfunc = symbolstring + 6;  // _strlen(PREPENDSYMBOLVALUE);
        funchash = djb2(localfunc);
        DEBUG_PRINT("\t\tInternalFunction: %s\n", localfunc);
        /* TODO: Get internal symbol here and set to functionaddress, then
         * return the pointer to the internal function*/
#if defined(_WIN32)
        if (funchash == 0xe2494ba2) { return  (unsigned char*)BeaconDataParse; };
        if (funchash == 0xaf1afdd2) { return  (unsigned char*)BeaconDataInt; };
        if (funchash == 0xe2835ef7) { return  (unsigned char*)BeaconDataShort; };
        if (funchash == 0x22641d29) { return  (unsigned char*)BeaconDataLength; };
        if (funchash == 0x80d46722) { return  (unsigned char*)BeaconDataExtract; };
        if (funchash == 0x4caae0e1) { return  (unsigned char*)BeaconFormatAlloc; };
        if (funchash == 0x4ddac759) { return  (unsigned char*)BeaconFormatReset; };
        if (funchash == 0x7e749f38) { return  (unsigned char*)BeaconFormatFree; };
        if (funchash == 0xe25167ce) { return  (unsigned char*)BeaconFormatAppend; };
        if (funchash == 0x56f4aa9) { return  (unsigned char*)BeaconFormatPrintf; };
        if (funchash == 0xb59f4df0) { return  (unsigned char*)BeaconFormatToString; };
        if (funchash == 0x3a229cc1) { return  (unsigned char*)BeaconFormatInt; };
        if (funchash == 0x700d8660) { return  (unsigned char*)BeaconPrintf; };
        if (funchash == 0x6df4b81e) { return  (unsigned char*)BeaconOutput; };
        if (funchash == 0x889e48bb) { return  (unsigned char*)BeaconUseToken; };
        if (funchash == 0xf2744ba6) { return  (unsigned char*)BeaconRevertToken; };
        if (funchash == 0x566264d2) { return  (unsigned char*)BeaconIsAdmin; };
        if (funchash == 0x1e7c9fb9) { return  (unsigned char*)BeaconGetSpawnTo; };
        if (funchash == 0xd6c57438) { return  (unsigned char*)BeaconSpawnTemporaryProcess; };
        if (funchash == 0xea75b09) { return  (unsigned char*)BeaconInjectProcess; };
        if (funchash == 0x9e22498c) { return  (unsigned char*)BeaconInjectTemporaryProcess; };
        if (funchash == 0xcee62b74) { return  (unsigned char*)BeaconCleanupProcess; };
        if (funchash == 0x59fcf3cf) { return  (unsigned char*)toWideChar; };
#endif
    }
    else if (_strncmp(symbolstring, msg3, _strlen(msg3)) == 0) {
        DEBUG_PRINT("\t\tYep its an external symbol\n");
        locallib = localcopy + 6; // _strlen(PREPENDSYMBOLVALUE);
        int i;
        // Extract localfunc as part before first $
        for (i=0; i< _strlen(locallib); i++) {
            if (locallib[i] == '$') {
                locallib[i] = '\x00'; // Change first $ to zero byte to end the string here
                localfunc = locallib + i + 1;
                break;
            }
        }
        for (i=0; i< _strlen(localfunc); i++) {
            if (localfunc[i] == '$' || localfunc[i] == '@' ) {
                localfunc[i] = '\x00'; // Change first $/@ to zero byte to end the string here
                break;
            }
        }

        DEBUG_PRINT("\t\tLibrary: %s\n", locallib);
        DEBUG_PRINT("\t\tFunction: %s\n", localfunc);
        /* Resolve the symbols here, and set the functionpointervalue */
#if defined(_WIN32)
        tLoadLibraryA _LoadLibraryA = (tLoadLibraryA)getFunctionPtr(HASH_KERNEL32, HASH_LoadLibraryA);
        llHandle = _LoadLibraryA(locallib);
        DEBUG_PRINT("\t\tHandle: 0x%lx\n", llHandle);
        tGetProcAddress _GetProcAddress = (tGetProcAddress)getFunctionPtr(HASH_KERNEL32, HASH_GetProcAddress);
        functionaddress = _GetProcAddress(llHandle, localfunc);
        DEBUG_PRINT("\t\tProcAddress: 0x%p\n", functionaddress);
#endif
    }
    return functionaddress;
}

/* Just a generic runner for testing, this is pretty much just a reference
 * implementation, return values will need to be checked, more relocation
 * types need to be handled, and needs to have different arguments for use
 * in any agent. */
int RunCOFF(unsigned char* coff_data, uint32_t filesize, unsigned char* argumentdata, int argumentSize) {
    coff_file_header_t *coff_header_ptr = NULL;
    coff_sect_t *coff_sect_ptr = NULL;
    coff_reloc_t *coff_reloc_ptr = NULL;
    coff_sym_t * coff_sym_ptr = NULL;
    int retcode = 0;
    int counter = 0;
    int reloccount = 0;
    int tempcounter = 0;
    uint32_t symptr = 0;
#ifdef _WIN32
    void* funcptrlocation = NULL;
    int32_t offsetvalue = 0;
#endif
    char functionname[] = {'g','o', 0x00};
    char* entryfuncname = functionname;
#if defined(__x86_64__) || defined(_WIN64)
#ifdef _WIN32
    uint64_t longoffsetvalue = 0;
#endif
#else
#endif

#ifdef _WIN32
    /* NOTE: I just picked a size, look to see what is max/normal. */
    char* sectionMapping[25] = { 0 };
    tVirtualFree _VirtualFree = (tVirtualFree)getFunctionPtr(HASH_KERNEL32, HASH_VirtualFree);
    tVirtualAlloc _VirtualAlloc = (tVirtualAlloc)getFunctionPtr(HASH_KERNEL32, HASH_VirtualAlloc);

#ifdef DEBUG
    int sectionSize[25] = { 0 };
#endif
    void(*foo)(char* in, unsigned long datalen);
    char* functionMapping = NULL;
    int functionMappingCount = 0;
#endif

    if (coff_data == NULL) {
        DEBUG_PRINT("Can't execute NULL\n");
        return 1;
    }
    coff_header_ptr = (coff_file_header_t*)coff_data;
    DEBUG_PRINT("Machine 0x%X\n", coff_header_ptr->Machine);
    DEBUG_PRINT("Number of sections: %d\n", coff_header_ptr->NumberOfSections);
    DEBUG_PRINT("TimeDateStamp : %X\n", coff_header_ptr->TimeDateStamp);
    DEBUG_PRINT("PointerToSymbolTable : 0x%X\n", coff_header_ptr->PointerToSymbolTable);
    DEBUG_PRINT("NumberOfSymbols: %d\n", coff_header_ptr->NumberOfSymbols);
    DEBUG_PRINT("OptionalHeaderSize: %d\n", coff_header_ptr->SizeOfOptionalHeader);
    DEBUG_PRINT("Characteristics: %d\n", coff_header_ptr->Characteristics);
    DEBUG_PRINT("\n");
    coff_sym_ptr = (coff_sym_t*)(coff_data + coff_header_ptr->PointerToSymbolTable);

    /* Handle the allocation and copying of the sections we're going to use
     * for right now I'm just VirtualAlloc'ing memory, this can be changed to
     * other methods, but leaving that up to the person implementing it. */
    for (counter = 0; counter < coff_header_ptr->NumberOfSections; counter++) {
        coff_sect_ptr = (coff_sect_t*)(coff_data + sizeof(coff_file_header_t) + (sizeof(coff_sect_t) * counter));
        DEBUG_PRINT("Name: %s\n", coff_sect_ptr->Name);
        DEBUG_PRINT("VirtualSize: 0x%X\n", coff_sect_ptr->VirtualSize);
        DEBUG_PRINT("VirtualAddress: 0x%X\n", coff_sect_ptr->VirtualAddress);
        DEBUG_PRINT("SizeOfRawData: 0x%X\n", coff_sect_ptr->SizeOfRawData);
        DEBUG_PRINT("PointerToRelocations: 0x%X\n", coff_sect_ptr->PointerToRelocations);
        DEBUG_PRINT("PointerToRawData: 0x%X\n", coff_sect_ptr->PointerToRawData);
        DEBUG_PRINT("NumberOfRelocations: %d\n", coff_sect_ptr->NumberOfRelocations);
        /* NOTE: When changing the memory loading information of the loader,
         * you'll want to use this field and the defines from the Section
         * Flags table of Microsofts page, some defined in COFFLoader.h */
        DEBUG_PRINT("Characteristics: %x\n", coff_sect_ptr->Characteristics);
#ifdef _WIN32
        DEBUG_PRINT("Allocating 0x%x bytes\n", coff_sect_ptr->VirtualSize);
        /* NOTE: Might want to allocate as PAGE_READWRITE and VirtualProtect
         * before execution to either PAGE_READWRITE or PAGE_EXECUTE_READ
         * depending on the Section Characteristics. Parse them all again
         * before running and set the memory permissions. */
        sectionMapping[counter] = _VirtualAlloc(NULL, coff_sect_ptr->SizeOfRawData, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
#ifdef DEBUG
        sectionSize[counter] = coff_sect_ptr->SizeOfRawData;
#endif
        if (sectionMapping[counter] == NULL) {
            DEBUG_PRINT("Failed to allocate memory\n");
        }
        DEBUG_PRINT("Allocated section %d at %p\n", counter, sectionMapping[counter]);
       _memcpy(sectionMapping[counter], coff_data + coff_sect_ptr->PointerToRawData, coff_sect_ptr->SizeOfRawData);
#endif
    }

    /* Allocate and setup the GOT for functions, same here as above. */
#ifdef _WIN32
#ifdef _WIN64
    functionMapping = _VirtualAlloc(NULL, 2048, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
#else
    functionMapping = _VirtualAlloc(NULL, 2048, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
#endif
#endif

    /* Start parsing the relocations, and *hopefully* handle them correctly. */
    for (counter = 0; counter < coff_header_ptr->NumberOfSections; counter++) {
        DEBUG_PRINT("Doing Relocations of section: %d\n", counter);
        coff_sect_ptr = (coff_sect_t*)(coff_data + sizeof(coff_file_header_t) + (sizeof(coff_sect_t) * counter));
        coff_reloc_ptr = (coff_reloc_t*)(coff_data + coff_sect_ptr->PointerToRelocations);
        for (reloccount = 0; reloccount < coff_sect_ptr->NumberOfRelocations; reloccount++) {
            DEBUG_PRINT("\tVirtualAddress: 0x%X\n", coff_reloc_ptr->VirtualAddress);
            DEBUG_PRINT("\tSymbolTableIndex: 0x%X\n", coff_reloc_ptr->SymbolTableIndex);
            DEBUG_PRINT("\tType: 0x%X\n", coff_reloc_ptr->Type);
            if (coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name[0] != 0) {
                symptr = coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.value[1];
                DEBUG_PRINT("\tSymPtr: 0x%X\n", symptr);
                DEBUG_PRINT("\tSymName: %s\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name);
                DEBUG_PRINT("\tSectionNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber);

                /* This is the code for relative offsets in other sections of the COFF file. */
#ifdef _WIN32
#ifdef _WIN64
            /* Type == 1 relocation is the 64-bit VA of the relocation target */
                if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR64) {
                   _memcpy(&longoffsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(uint64_t));
                    DEBUG_PRINT("\tReadin longOffsetValue : 0x%llX\n", longoffsetvalue);
                    longoffsetvalue = (uint64_t)(sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] + (uint64_t)longoffsetvalue);
                    DEBUG_PRINT("\tModified longOffsetValue : 0x%llX Base Address: %p\n", longoffsetvalue, sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1]);
                   _memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &longoffsetvalue, sizeof(uint64_t));
                }
                /* This is Type == 3 relocation code */
                else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR32NB) {
                   _memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                    DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetvalue);
                    DEBUG_PRINT("\t\tReferenced Section: 0x%X\n", sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] + offsetvalue);
                    DEBUG_PRINT("\t\tEnd of Relocation Bytes: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4);
                    if (((char*)(sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] + offsetvalue) - (char*)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > 0xffffffff) {
                        DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                        retcode = 1;
                        goto cleanup;
                    }
                    offsetvalue = ((char*)(sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] + offsetvalue) - (char*)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    DEBUG_PRINT("\tOffsetValue : 0x%0X\n", offsetvalue);
                    DEBUG_PRINT("\t\tSetting 0x%X to %X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue);
                   _memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                }
                /* This is Type == 4 relocation code, needed to make global variables to work correctly */
                else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32) {
                   _memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                    DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);
                    if ((sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > 0xffffffff) {
                        DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                        retcode = 1;
                        goto cleanup;
                    }
                    offsetvalue += (sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    DEBUG_PRINT("\t\tRelative address: 0x%X\n", offsetvalue);
                   _memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                }
                else {
                    DEBUG_PRINT("No code for relocation type: %d\n", coff_reloc_ptr->Type);
                }
#else
             /* This is Type == IMAGE_REL_I386_DIR32 relocation code */
               _memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetvalue);
                offsetvalue = (uint32_t)(sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1]) + offsetvalue;
               _memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
#endif //WIN64 statement close
#endif //WIN32 statement close
            }
            else {
                symptr = coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.value[1];
                DEBUG_PRINT("\tSymPtr: 0x%X\n", symptr);
                DEBUG_PRINT("\tSymVal: %s\n", ((char*)(coff_sym_ptr + coff_header_ptr->NumberOfSymbols)) + symptr);
                DEBUG_PRINT("\tSectionNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber);

                /* This is the code to handle functions themselves, so using a makeshift Global Offset Table for it */
#ifdef _WIN32
                funcptrlocation = process_symbol(((char*)(coff_sym_ptr + coff_header_ptr->NumberOfSymbols)) + symptr);
                if (funcptrlocation == NULL) {
                    DEBUG_PRINT("Failed to resolve symbol\n");
                    retcode = 1;
                    goto cleanup;
                }
#ifdef _WIN64
                if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32 && funcptrlocation != NULL) {
                    /* This is Type == 4 relocation code */
                    DEBUG_PRINT("Doing function relocation\n");
                    if (((functionMapping + (functionMappingCount * 8)) - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > 0xffffffff) {
                        DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                        retcode = 1;
                        goto cleanup;
                    }
                   _memcpy(functionMapping + (functionMappingCount * 8), &funcptrlocation, sizeof(uint64_t));
                    offsetvalue = (int32_t)((functionMapping + (functionMappingCount * 8)) - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    DEBUG_PRINT("\t\tRelative address : 0x%x\n", offsetvalue);
                   _memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                    functionMappingCount++;
                }
                else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32) {
                    /* This shouldn't be needed here, but incase there's a defined symbol
                     * that somehow doesn't have a function, try to resolve it here.*/
                   _memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                    if ((sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > 0xffffffff) {
                        DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                        retcode = 1;
                        goto cleanup;
                    }
                    DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);
                    offsetvalue += (sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1] - (sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                    DEBUG_PRINT("\t\tRelative address: 0x%X\n", offsetvalue);
                   _memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                }
                else {
                    DEBUG_PRINT("No code for relocation type: %d\n", coff_reloc_ptr->Type);
                }
#else
                /* This is Type == IMAGE_REL_I386_DIR32 relocation code */
               _memcpy(functionMapping + (functionMappingCount * 4), &funcptrlocation, sizeof(uint32_t));
                offsetvalue = (int32_t)(functionMapping + (functionMappingCount * 4));
               _memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
                functionMappingCount++;
#endif
#endif
            }
            DEBUG_PRINT("\tValueNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value);
            DEBUG_PRINT("\tSectionNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber);
            coff_reloc_ptr = (coff_reloc_t*)(((char*)coff_reloc_ptr) + sizeof(coff_reloc_t));
            DEBUG_PRINT("\n");
        }
        DEBUG_PRINT("\n");
    }

    /* Some debugging code to see what the sections look like in memory */
#if DEBUG
#ifdef _WIN32
    for (tempcounter = 0; tempcounter < 10; tempcounter++) {
        DEBUG_PRINT("Section: %d\n", tempcounter);
        if (sectionMapping[tempcounter] != NULL) {
            DEBUG_PRINT("\t");
            for (counter = 0; counter < sectionSize[tempcounter]; counter++) {
                DEBUG_PRINT("%02X ", (uint8_t)(sectionMapping[tempcounter][counter]));
            }
            DEBUG_PRINT("\n");
        }
    }
#endif
#endif

    DEBUG_PRINT("Symbols:\n");
    for (tempcounter = 0; tempcounter < coff_header_ptr->NumberOfSymbols; tempcounter++) {
        DEBUG_PRINT("\t%s: Section: %d, Value: 0x%X\n", coff_sym_ptr[tempcounter].first.Name, coff_sym_ptr[tempcounter].SectionNumber, coff_sym_ptr[tempcounter].Value);
        if (_strcmp(coff_sym_ptr[tempcounter].first.Name, entryfuncname) == 0) {
            DEBUG_PRINT("\t\tFound entry!\n");
#ifdef _WIN32
            /* So for some reason VS 2017 doesn't like this, but char* casting works, so just going to do that */
#ifdef _MSC_VER
            foo = (char*)(sectionMapping[coff_sym_ptr[tempcounter].SectionNumber - 1] + coff_sym_ptr[tempcounter].Value);
#else
            foo = (void(*)(char *, unsigned long))(sectionMapping[coff_sym_ptr[tempcounter].SectionNumber - 1] + coff_sym_ptr[tempcounter].Value);
#endif
            //sectionMapping[coff_sym_ptr[tempcounter].SectionNumber-1][coff_sym_ptr[tempcounter].Value+7] = '\xcc';
            DEBUG_PRINT("Trying to run: %p\n", foo);
            foo((char*)argumentdata, argumentSize);
#endif
        }
    }
    DEBUG_PRINT("Back\n");

    /* Cleanup the allocated memory */
#ifdef _WIN32
    cleanup :
            for (tempcounter = 0; tempcounter < 25; tempcounter++) {
                if (sectionMapping[tempcounter]) {
                    _VirtualFree(sectionMapping[tempcounter], 0, MEM_RELEASE);
                }
            }
            _VirtualFree(functionMapping, 0, MEM_RELEASE);
#endif
            DEBUG_PRINT("Returning\n");
            return retcode;
}

#ifdef COFF_STANDALONE
#ifdef EXEVERSION
int main(int argc, char* argv[]) {
#else
int go(void) {
#endif
    char* coff_data = NULL;
    unsigned char* arguments = NULL;
    int argumentSize = 0;
#ifdef _WIN32
#endif
    uint32_t filesize = 0;
    int checkcode = 0;
    tprintf _printf = (tprintf)getFunctionPtr(HASH_MSVCRT, HASH_printf);

    #ifdef EXEVERSION
    if (argc < 2) {
        _printf("ERROR: %s /path/to/object/file.o (arguments)\n", argv[0]);
        return 1;
    }

    coff_data = (char*)getContents(argv[2], &filesize);
    if (coff_data == NULL) {
        return 1;
    }
    _printf("Got contents of COFF file\n");
    arguments = unhexlify((unsigned char*)argv[3], &argumentSize);
    #else
        unsigned char* seek_offset = (unsigned char*) go;
        // Find the magic header 0xe9e63f1c in memory
        while (1) {
            if (seek_offset[0] == 0x1c && seek_offset[1] == 0x3f && seek_offset[2] == 0xe6 && seek_offset[3] == 0xe9) {
                break;
            }
            seek_offset += 1;
        }
        filesize = *(uint32_t*)(seek_offset+4);
        coff_data = seek_offset+8;
    #endif

    char msg[] = {'R','u','n','n','i','n','g','/','P','a','r','s','i','n','g',' ','t','h','e',' ','C','O','F','F',' ','f','i','l','e',0x0a, 0x00};
    _printf(msg);
    checkcode = RunCOFF((unsigned char*)coff_data, filesize, arguments, argumentSize);
    if (checkcode == 0) {
#ifdef _WIN32
        char msg2[] = {'R','a','n','/','p','a','r','s','e','d',' ','t','h','e',' ','c','o','f','f',0x0a, 0x00};
        _printf(msg2);
#endif
    }
    else {
        char msg3[] = {'F','a','i','l','e','d',' ','t','o',' ','r','u','n','/','p','a','r','s','e',' ','t','h','e',' ','C','O','F','F',' ','f','i','l','e',0x0a, 0x00};
        _printf(msg3);
    }

    return 0;
}

#endif
