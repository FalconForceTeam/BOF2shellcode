
all: bof bofshellcode

bof:
	x86_64-w64-mingw32-gcc -Wall -DCOFF_STANDALONE beacon_compatibility.c COFFLoader.c -o COFFLoader64.exe

bofshellcode:
	x86_64-w64-mingw32-gcc -Wall -DCOFF_STANDALONE -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 beacon_compatibility.c COFFLoader.c -o COFFLoader64.exe -Wl,--no-seh
