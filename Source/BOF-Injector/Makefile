CC=i686-w64-mingw32-gcc
CC_64=x86_64-w64-mingw32-gcc

all: bin/injector.x86.o bin/injector.x64.o

bin:
	mkdir Bin

#
# x86 targets
#
bin/injector.x86.o: bin
	$(CC) -DWIN_X86 -shared -masm=intel -Wall -Wno-pointer-arith -c Main/main.c -o Bin/injector.x86.o

#
# x64 targets
#
bin/injector.x64.o: bin
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c Main/main.c -o Bin/injector.x64.o

#
# Other targets
#
clean:
	rm -f Bin/*