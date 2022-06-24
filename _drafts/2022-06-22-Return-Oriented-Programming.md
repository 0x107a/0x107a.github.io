---
title: "Return Oriented Programming"
categories:
  - pwn
tags:
  - pwn
---

Within this post, I will be explaining the concept of return oriented programming, as well as
the various techniques that leverage it. This post assumes no prior knowledge other than
familiarity with the x86 architecture and ability to use a debugger.

I will also be detailing various esoteric exploitation techniques that utilize return oriented
programming, as well as some additional use cases; such as binary polymorphism.

This post will generally be oriented around the x86_64 architecture, but the same concepts will
apply to other architectures & addressing modes.

## x86 Call Stack

If you feel comfortable with the following concepts being explained, feel free to move forward
to whichever section of the post you like.


### Stack Alignment

This will be important later on, as when developing an exploit, we will also have to account
for the alignment of the stack.

### Calling Conventions
## Return Oriented Programming
## Ret2win
## ROP syscall
## Ret2plt
### GOT and PLT
## Return to CSU
## Stack Pivoting
## Frame Faking
## Return to DL Resolve
## Sigreturn Oriented Programming
## Blind Return Oriented Programming
## Jump Oriented Programming
## Data Oriented Attacks
## Polymorphism via Return Oriented Programming
## Conclusion

