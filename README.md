# UNIX_PTRACE
Use PTRACE to implement an instruction-level debugger
### disassemble:
1.address, eg:```0x4000b0```
2.raw instruction, eg:```b8 04 00 00 00```
3.mnemonic, eg:```mov```
4.operands of the instruction, eg:```eax, 4```
### 1. Si
```
bash$ ./sdb ./hello64
0x0000004000b0: b8 04 00 00 00                  	mov       eax, 4
0x0000004000b5: bb 01 00 00 00                  	mov       ebx, 1
0x0000004000ba: b9 d4 00 60 00                  	mov       ecx, 0x6000d4
0x0000004000bf: ba 0e 00 00 00                  	mov       edx, 0xe
0x0000004000c4: cd 80                           	int       0x80
(sdb) si
0x0000004000b5: bb 01 00 00 00                  	mov       ebx, 1
0x0000004000ba: b9 d4 00 60 00                  	mov       ecx, 0x6000d4
0x0000004000bf: ba 0e 00 00 00                  	mov       edx, 0xe
0x0000004000c4: cd 80                           	int       0x80
0x0000004000c6: b8 01 00 00 00                  	mov       eax, 1
```
### 2. Cont
```
bash$ ./sdb ./hello64
0x0000004000b0: b8 04 00 00 00                  	mov       eax, 4
0x0000004000b5: bb 01 00 00 00                  	mov       ebx, 1
0x0000004000ba: b9 d4 00 60 00                  	mov       ecx, 0x6000d4
0x0000004000bf: ba 0e 00 00 00                  	mov       edx, 0xe
0x0000004000c4: cd 80                           	int       0x80
(sdb) si
0x0000004000b5: bb 01 00 00 00                  	mov       ebx, 1
0x0000004000ba: b9 d4 00 60 00                  	mov       ecx, 0x6000d4
0x0000004000bf: ba 0e 00 00 00                  	mov       edx, 0xe
0x0000004000c4: cd 80                           	int       0x80
0x0000004000c6: b8 01 00 00 00                  	mov       eax, 1
(sdb) cont
hello, world!
** the target program terminated.
```
### 3. Breakpoint
```
bash$ ./sdb ./hello64
0x0000004000b0: b8 04 00 00 00                  	mov       eax, 4
0x0000004000b5: bb 01 00 00 00                  	mov       ebx, 1
0x0000004000ba: b9 d4 00 60 00                  	mov       ecx, 0x6000d4
0x0000004000bf: ba 0e 00 00 00                  	mov       edx, 0xe
0x0000004000c4: cd 80                           	int       0x80
(sdb) break 0x4000ba
** set a breakpoint at 0x0000004000ba
(sdb) si
0x0000004000b5: bb 01 00 00 00                  	mov       ebx, 1
0x0000004000ba: b9 d4 00 60 00                  	mov       ecx, 0x6000d4
0x0000004000bf: ba 0e 00 00 00                  	mov       edx, 0xe
0x0000004000c4: cd 80                           	int       0x80
0x0000004000c6: b8 01 00 00 00                  	mov       eax, 1
(sdb) si
** hit a breakpoint 0x0000004000ba.
0x0000004000ba: b9 d4 00 60 00                  	mov       ecx, 0x6000d4
0x0000004000bf: ba 0e 00 00 00                  	mov       edx, 0xe
0x0000004000c4: cd 80                           	int       0x80
0x0000004000c6: b8 01 00 00 00                  	mov       eax, 1
0x0000004000cb: bb 00 00 00 00                  	mov       ebx, 0
```
### 4. Timetravel
> use anchor command set a checkpoint and use timetravel command to restore the process status
```
bash$ ./sdb ./hello64
0x0000004000b0: b8 04 00 00 00                  	mov       eax, 4
0x0000004000b5: bb 01 00 00 00                  	mov       ebx, 1
0x0000004000ba: b9 d4 00 60 00                  	mov       ecx, 0x6000d4
0x0000004000bf: ba 0e 00 00 00                  	mov       edx, 0xe
0x0000004000c4: cd 80                           	int       0x80
(sdb) anchor
** dropped an anchor
(sdb) break 0x4000cb
** set a breakpoint at 0x0000004000cb
(sdb) cont
hello, world!
** hit a breakpoint 0x0000004000cb.
0x0000004000cb: bb 00 00 00 00                  	mov       ebx, 0
0x0000004000d0: cd 80                           	int       0x80
0x0000004000d2: c3                              	ret
** the address is out of the range of the text section.
(sdb) timetravel
** go back to the anchor point
0x0000004000b0: b8 04 00 00 00                  	mov       eax, 4
0x0000004000b5: bb 01 00 00 00                  	mov       ebx, 1
0x0000004000ba: b9 d4 00 60 00                  	mov       ecx, 0x6000d4
0x0000004000bf: ba 0e 00 00 00                  	mov       edx, 0xe
0x0000004000c4: cd 80                           	int       0x80
(sdb) cont
hello, world!
** hit a breakpoint 0x0000004000cb.
0x0000004000cb: bb 00 00 00 00                  	mov       ebx, 0
0x0000004000d0: cd 80                           	int       0x80
0x0000004000d2: c3                              	ret
** the address is out of the range of the text section.
```
## Example
1. ```./sdb ./hello```
```
0x000000401000: f3 0f 1e fa                     	endbr64
0x000000401004: 55                              	push      rbp
0x000000401005: 48 89 e5                        	mov       rbp, rsp
0x000000401008: ba 0e 00 00 00                  	mov       edx, 0xe
0x00000040100d: 48 8d 05 ec 0f 00 00            	lea       rax, [rip + 0xfec]
(sdb) cont
hello world!
** the target program terminated.
```
2. ```./sdb ./hello```
```
0x000000401000: f3 0f 1e fa                     	endbr64
0x000000401004: 55                              	push      rbp
0x000000401005: 48 89 e5                        	mov       rbp, rsp
0x000000401008: ba 0e 00 00 00                  	mov       edx, 0xe
0x00000040100d: 48 8d 05 ec 0f 00 00            	lea       rax, [rip + 0xfec]
(sdb) break 0x401030
** set a breakpoint at 0x000000401030
(sdb) break 0x40103b
** set a breakpoint at 0x00000040103b
(sdb) cont
** hit a breakpoint 0x000000401030.
0x000000401030: 0f 05                           	syscall
0x000000401032: c3                              	ret
0x000000401033: b8 00 00 00 00                  	mov       eax, 0
0x000000401038: 0f 05                           	syscall
0x00000040103a: c3                              	ret
(sdb) cont
hello world!
** hit a breakpoint 0x00000040103b.
0x00000040103b: b8 3c 00 00 00                  	mov       eax, 0x3c
0x000000401040: 0f 05                           	syscall
** the address is out of the range of the text section.
(sdb) si
0x000000401040: 0f 05                           	syscall
** the address is out of the range of the text section.
(sdb) si
** the target program terminated.
```
3. ```./sdb ./guess```
```
0x00000040108b: f3 0f 1e fa                     	endbr64
0x00000040108f: 55                              	push      rbp
0x000000401090: 48 89 e5                        	mov       rbp, rsp
0x000000401093: 48 83 ec 10                     	sub       rsp, 0x10
0x000000401097: ba 12 00 00 00                  	mov       edx, 0x12
(sdb) break 0x4010bf
** set a breakpoint at 0x0000004010bf
(sdb) break 0x40111e
** set a breakpoint at 0x00000040111e
(sdb) cont
guess a number > ** hit a breakpoint 0x0000004010bf.
0x0000004010bf: bf 00 00 00 00                  	mov       edi, 0
0x0000004010c4: e8 67 00 00 00                  	call      0x401130
0x0000004010c9: 48 89 45 f8                     	mov       qword ptr [rbp - 8], rax
0x0000004010cd: 48 8d 05 3e 0f 00 00            	lea       rax, [rip + 0xf3e]
0x0000004010d4: 48 89 c6                        	mov       rsi, rax
(sdb) anchor
** dropped an anchor
(sdb) cont
iii

no no no
** hit a breakpoint 0x00000040111e.
0x00000040111e: bf 00 00 00 00                  	mov       edi, 0
0x000000401123: e8 10 00 00 00                  	call      0x401138
0x000000401128: b8 01 00 00 00                  	mov       eax, 1
0x00000040112d: 0f 05                           	syscall
0x00000040112f: c3                              	ret
(sdb) timetravel
** go back to the anchor point
** hit a breakpoint 0x0000004010bf.
0x0000004010bf: bf 00 00 00 00                  	mov       edi, 0
0x0000004010c4: e8 67 00 00 00                  	call      0x401130
0x0000004010c9: 48 89 45 f8                     	mov       qword ptr [rbp - 8], rax
0x0000004010cd: 48 8d 05 3e 0f 00 00            	lea       rax, [rip + 0xf3e]
0x0000004010d4: 48 89 c6                        	mov       rsi, rax
(sdb) cont
42

yes
** hit a breakpoint 0x00000040111e.
0x00000040111e: bf 00 00 00 00                  	mov       edi, 0
0x000000401123: e8 10 00 00 00                  	call      0x401138
0x000000401128: b8 01 00 00 00                  	mov       eax, 1
0x00000040112d: 0f 05                           	syscall
0x00000040112f: c3                              	ret
(sdb) cont
** the target program terminated.
```
