gcc -m64 -c main.c syscall_process.c -shared
nasm -f win64 -o syscall_process_stubs.std.x64.o ./syscall_process_stubs.std.x64.nasm
gcc *.o -o temp.exe -lntdll
gcc *.o -o temp.exe -lntdll
temp.exe