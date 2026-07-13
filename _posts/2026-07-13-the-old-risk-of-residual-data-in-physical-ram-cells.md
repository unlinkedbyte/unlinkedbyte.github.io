---
layout: post
title: "The old risk of residual data in physical RAM cells"
date: 2026-07-13
categories: [research, labs]
tags: [x86, assembly, memory, kernel]
---

Hi there. If you have made it this far, I doubt introductions are even necessary. I have simply decided to write this blog post for the reasons you have probably already seen in the repository, even though I never thought I would actually make one.

Today, I was messing around in my lab with the classic LiveCD from Jon Erickson's *Hacking: The Art of Exploitation*, analyzing a basic `for` loop in 32-bit x86 assembly, when a fundamental question crossed my mind—something that, while learning C, I hadn't considered yet or had simply overlooked.

### Memory Mapping in 32-bit Systems
Before getting into the meat of the matter, it is worth noting a bit of context. Back in the day, on 32-bit systems, it was very common to see stack pointers starting with `0xbf...`. This was because user space was allocated in the highest memory ranges of the architecture (in the stack).

In modern 64-bit systems, this behavior has completely changed due to an immense address space and security mitigations like **ASLR** (Address Space Layout Randomization), which randomizes the base address of the stack on every execution.

However, operating within the predictable memory map of this LiveCD allowed me to observe that specific detail I mentioned earlier, which I had overlooked until now: **the reality of uninitialized variables**.

### What is "Garbage" in Memory, Really?
In the K&R book (*The C Programming Language*) itself, they tell you that uninitialized variables contain "garbage". Following the book's pace and analyzing the code with **GDB**, right before the program initialized the loop variable `i`, we could see through the debugger what data those physical cells of RAM contained that hadn't been overwritten yet.

> **Note:** We must keep in mind that when we delete something, it is not physically erased; only the "label" or pointer pointing to it is removed.

Seeing what was left in that memory area is exactly when the big question arises: **Can we manipulate instructions, directives, or create a program to trick the system and retrieve the information we want? Specifically, sensitive information.**

### From Theory to Real Danger: Information Disclosure
At first glance, seeing random numbers in a debugger looks like an innocent technical quirk. In cybersecurity, however, this is the root of a critical family of vulnerabilities: ***Information Disclosure*** or ***Information Leakage* via uninitialized memory**.

To picture this easily, imagine a web server written in C:

1. **Function A:** A user logs in. Their secret password is processed and temporarily sits in the *stack frame*. When the function exits, the bytes of the password remain physically recorded in the RAM transistors, because freeing memory on the stack only means moving the `ESP`/`RSP` pointer, not wiping the actual content.
2. **Function B:** A second later, another user requests to view their public profile. If the developer made a small programming mistake and forgot to initialize a local variable or a buffer on the stack, Function B will reuse and occupy the exact same memory space previously used by Function A due to the constant recycling of the stack to save space.
3. **The Outcome:** The inherited "garbage" read by the second user ends up leaking the first user's password. This can lead to a complete disaster.

And to visualize this recycling process layout more clearly, here is a quick ASCII text diagram of how the stack pointer behaves during these transitions:


[ HIGH MEMORY ADDRESSES ] (0xffffffff)
           |
           v   +---------------------------------------+

               | ... System / OS Memory ...            |
               +---------------------------------------+ <--- ESP (Initial state)

               |                                       |
               |  [ STEP 1: Function A Executes ]      |
               |  - Stack Frame A is created           |
               |  - Local variable 'password' stores   |
               |    plaintext data: "Secret123"        |  | Stack grows
               |                                       |  | DOWNWARDS
               +---------------------------------------+  v towards low memory

               |                                       |
               |  [ STEP 2: Function A Returns ]       |
               |  - ESP moves back UP (shrinks)        |
               |  - Memory is NOT wiped/cleared        |
               |  - "Secret123" physical data remains  |
               |                                       |
               +---------------------------------------+ <--- ESP (Returned/Idle)

               |                                       |
               |  [ STEP 3: Function B Executes ]      |
               |  - Stack Frame B is created           |
               |  - It reuses the exact same memory    |
               |    space left behind by Function A    |
               |  - Uninitialized buffer reads the     |
               |    existing garbage: "Secret123"      |
               |                                       |
               +---------------------------------------+ <--- ESP (Max Frame B)

               | ... Rest of Stack / Process Memory ...|
               +---------------------------------------+
           ^
           |
[ LOW MEMORY ADDRESSES ] (0x00000000)



### The Boundary: Kernel Isolation and Virtual Memory
Seeing this on the LiveCD triggered a logical question: could my program declare a massive amount of variables or a giant array to try and spy on the stack garbage of other active processes, like Firefox?

The answer is a **resounding no**, thanks to two pillars of the operating system:
* **Virtual Memory**
* The isolated illusion managed by the **MMU** (Memory Management Unit) and the kernel. (concepts that would easily yield enough material for another post, even if it is just what each thing consists of)

When your process requests new memory pages, the operating system intercepts the request and **zeroes out those pages** before handing them over to you. This limits the danger of stack garbage strictly to data that your own process has already touched before.

### The Critical Scenario: The Kernel Stack and Modern Mitigations
However, the game changes completely in the **Kernel Stack** (the internal stack used by Linux when executing a *syscall* in kernel space). If a kernel function suffers from this bug and leaves a variable uninitialized, it could leak internal physical memory addresses, breaking critical protections like **KASLR** (Kernel ASLR) and serving as a stepping stone for privilege escalation exploits.

In modern systems, the Linux kernel implements automatic mitigations at the compiler level to eradicate this attack vector entirely:
* **GCC Compiler Flags:** Such as `-ftrivial-auto-var-init=zero`.
* **Kernel Configurations:** Such as `CONFIG_INIT_STACK_ALL_ZERO=y`.

These directives force the hardware to zero out absolutely every single variable on the stack as soon as it is created, sacrificing a minimal amount of performance in exchange for security.

But here, on this old 32-bit LiveCD, those protections do not exist. The memory is stripped bare, and watching how the system works without filters is absolutely fascinating and addictive.

