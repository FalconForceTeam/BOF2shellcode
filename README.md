# BOF2Shellcode
POC tool to convert a Cobalt Strike BOF into raw shellcode.

## Introduction

This code was written as part of a blog tutorial on how to convert an existing C tool, in this case
[@trustedsec's COFFLoader](https://github.com/trustedsec/COFFLoader) into a raw shellcode.

It uses techniques based on [@thefLink's C-To-Shellcode-Examples repository](https://github.com/thefLink/C-To-Shellcode-Examples/).

## Usage

First run make to build the `bofloader.bin` file.

After that the `bof2shellcode.py` script can be used to convert a BOF into raw shellcode.

## Usage Examples

### Converting the tasklist BOF to shellcode and executing it:
```
% python3 bof2shellcode.py -i tasklist.x64.o -o tasklist.x64.bin
Writing tasklist.x64.bin

load_sc.exe tasklist.x64.bin | c:\msys64\usr\bin\head.exe
Name                              ProcessId  ParentProcessId  SessionId CommandLine
System Idle Process                       0                0          0 (NULL)
System                                    4                0          0 (NULL)
Registry                                 92                4          0 (NULL)
smss.exe                                348                4          0 (NULL)
csrss.exe                               464              456          0 (NULL)
wininit.exe                             536              456          0 (NULL)
csrss.exe                               544              528          1 (NULL)
winlogon.exe                            628              528          1 (NULL)
services.exe                            636              536          0 (NULL)
```

## Notes

This is purely a POC, it is missing some implementations of Beacon related functions, for example BeaconPrintf has been replace by a simple printf call that writes to stdout.

## Credits

Note that the code in this repository is heavily based on [@trustedsec's COFFLoader](https://github.com/trustedsec/COFFLoader) and [@thefLink's C-To-Shellcode-Examples repository](https://github.com/thefLink/C-To-Shellcode-Examples/).