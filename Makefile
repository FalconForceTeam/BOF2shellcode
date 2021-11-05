
all: bof bofshellcode

bof:
	x86_64-w64-mingw32-gcc -Wall -DCOFF_STANDALONE -DEXEVERSION ministdlib.c ApiResolve.c beacon_compatibility.c COFFLoader.c -o COFFLoader64.exe

bofshellcode:
	nasm -f win64 adjuststack.asm -o adjuststack.o
	x86_64-w64-mingw32-gcc -Wall -DCOFF_STANDALONE -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 ministdlib.c -c -o ministdlib.o -Wl,--no-seh -g2
	x86_64-w64-mingw32-gcc -Wall -DCOFF_STANDALONE -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 ApiResolve.c -c -o ApiResolve.o -Wl,--no-seh -g2
	x86_64-w64-mingw32-gcc -Wall -DCOFF_STANDALONE -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 beacon_compatibility.c -c -o beacon_compatibility.o -Wl,--no-seh -g2
	x86_64-w64-mingw32-gcc -Wall -DCOFF_STANDALONE -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 COFFLoader.c -c -o COFFLoader.o -Wl,--no-seh -g2
	x86_64-w64-mingw32-ld -s adjuststack.o ministdlib.o ApiResolve.o beacon_compatibility.o COFFLoader.o -o bofloader.exe
	x86_64-w64-mingw32-objcopy bofloader.exe --dump-section .text=bofloader.bin