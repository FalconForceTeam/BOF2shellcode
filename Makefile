
all: bof bofshellcode

bof:
	x86_64-w64-mingw32-gcc -Wall -DCOFF_STANDALONE -DEXEVERSION ministdlib.c ApiResolve.c beacon_compatibility.c COFFLoader.c -o COFFLoader64.exe

bofshellcode:
	x86_64-w64-mingw32-gcc -Wall -DCOFF_STANDALONE -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 ministdlib.c ApiResolve.c beacon_compatibility.c COFFLoader.c -c -o COFFLoader64.o -Wl,--no-seh
