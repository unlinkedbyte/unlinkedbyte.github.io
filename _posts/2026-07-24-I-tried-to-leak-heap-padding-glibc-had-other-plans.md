---
layout: post
title: "I Tried to Leak Heap Padding. glibc Had Other Plans."
date: 2026-07-24
categories: [research, labs]
tags: [x86, memory, alignment, heap, glibc]
---

###A small experiment with compiler padding, heap reuse, tcache metadata, and residual data


Hi there. Today, I was back at it again with Jon Erickson's LiveCD, pushing my boundaries with GDB and analyzing compiled binaries. While researching how memory structures behave under the hood, I noticed something interesting: a structural quirk that reminded me of a class of information disclosure vulnerabilities, often involving heap padding or leftover data in reused memory.

At first glance, unused bytes inside a heap allocation may appear to originate from a single source. In reality, they are produced by several independent layers--including the compiler, the ABI, and the allocator—each introducing its own form of padding, alignment, or metadata.

The original idea came from thinking about how data alignment and CPU efficiency affect the way structures are laid out in memory. As I followed that question deeper, the experiment gradually turned into an exploration of the different layers involved in a heap allocation--from compiler-inserted padding to glibc's chunk layout and internal metadata.

Distinguishing between these layers is essential when studying information disclosure vulnerabilities.

### Two Layers of Memory Management: Pages and Heap Chunks
To understand how data slips through the cracks, we need to look at how Linux manages RAM. The memory architecture relies on two different entities working in unison:

1. **The Kernel & MMU:** They handle memory at a macro level, dividing physical RAM into fixed blocks called **Pages** (typically 4096 bytes). 
2. **The `glibc` Allocator (`malloc`):** Since asking the Kernel for memory pages is slow, `glibc` requests large chunks upfront and chops them into smaller pieces when a developer calls `malloc()`. 

But glibc doesn't manage memory arbitrarily. Alignment requirements also influence how heap chunks are laid out and sized.

### Why Alignment Creates Padding
The compiler inserts padding so that fields satisfy their required alignment constraints. For maximum efficiency on x86_64 architectures, individual data variables are aligned to their natural boundaries. If you define a data structure (as you will see in the PoC) containing a char id[5] followed by an integer, the compiler doesn't pack them tightly. To ensure the 4-byte integer is aligned correctly in memory, the compiler automatically injects 3 bytes of internal padding between them, rounding the fields up to a 12-byte structure. *The padding had not occurred when it was simply a static array of 5 bytes, because a character array only requires 1-byte alignment.* 

*(Note: In my initial draft, the structure only contained a static char id[5] array. Since character arrays only require a 1-byte alignment constraint, the compiler didn't inject any padding at all, resulting in a strict 5-byte structure. To properly demonstrate the compiler-level padding layer, we must introduce a subsequent field with stricter alignment constraints, such as an integer).*


However, padding and alignment happen at three different layers with different constraints:
1. **Compiler-level Padding:** The compiler follows the alignment requirements imposed by the target ABI. In this structure, int `int` is typically 4-byte aligned, so the compiler inserts 3 bytes of padding after the 5-byte array.
2. **Allocator-level extra space (Heap Slack Space):** Enforced by `glibc`. On modern 64-bit glibc systems, malloc typically returns 16-byte aligned addresses.
3. **The chunk headers:** Every time you request memory, `glibc` doesn't just allocate your data; it prepends a 16-byte header containing metadata (like the chunk size and flags) to manage the Heap's state.

Across these layers, unused or allocator-managed bytes can exist outside the data the program explicitly initializes. These bytes are not all the same, and distinguishing them is essential when studying information disclosure.

And here lies the security problem: User space allocators avoid clearing reused heap memory because doing so would impose a measurable performance cost. So, depending on the allocator implementation and the allocation path, parts of the returned chunk may still contain residual bytes from previous allocations. 


Example:

```text
[ 5B: id ("USR01") ]  [3B: Padding] [ 4B: int x ] [ 12 Bytes: Heap Slack Space ]

|                    |             |             |                             |
|====================|=============|=============|=============================|
| 0x55 0x53 0x52...  |  0x00 0x00  |  0x00 0x00  | 0x41 0x41 0x41 ... 0x41     |
|====================|=============|=============|=============================|
^----------------------------------^-------------------------------------------^
Bytes 0-11: C object (struct LeakyStruct)
Bytes 12-15: allocator/tcache-managed area on reuse
Bytes 16-23: extra usable bytes outside the C object
```

*(Why 24 bytes if we said 16 bytes are for the chunk headers? I explain this at the end of the post).*


### Offense vs. Defense: Exploiting the Alignment
Can an attacker hide malware inside this Heap slack space? **A resounding no**. The Heap is highly dynamic; a subsequent allocation may reuse the same chunk and overwrite the data. For persistence or stealth in RAM, attackers rely on complex techniques like *Process Injection* or *Reflective DLL Injection* to hijack stable memory spaces.

However, for **Information Disclosure**, this hidden space is a crucial stepping stone for advanced reverse engineers:

* **Bypassing ASLR:** If a previously freed object contained a code pointer, those residual bytes might remain trapped inside the padding of a newly allocated, low-privileged buffer. If that buffer is sent over the network or read by a user, the internal memory map is exposed, potentially bypassing ASLR.
* **Kernel Infoleaks:** Similar information disclosure vulnerabilities have historically affected the Linux kernel when partially initialized structures were copied back to user space without clearing their padding bytes.


## The Proof of Concept (PoC)

*Note: since I am currently in my third month of learning and am still building my understanding of C structures (structs) and heap internals, I used external research and AI assistance while developing this PoC. I wanted a practical tool to help validate the reasoning behind this experiment.*

To see this in action: 

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h> // REQUIRED for malloc_usable_size()

struct LeakyStruct {
  char id[5]; 
  int x;
  // 3 bytes of compiler-inserted padding are added
  // between id and x to align the int field
};

void simulate_prior_sensitive_data() {
  // Request the exact same size to ensure we hit the same bin/tcache chunk
  char *dirty = (char *)malloc(sizeof(struct LeakyStruct));
  if (dirty) {
      // Query the actual physical chunk size to taint the entire block
      size_t real_chunk_size = malloc_usable_size(dirty);
      memset(dirty, 0x41, real_chunk_size); // Fill the whole chunk with 'A's (0x41)
      free(dirty);             
  }
}

int main() {
    simulate_prior_sensitive_data();

    // Reuses the exact same physical chunk from the tcache
    struct LeakyStruct *my_chunk = (struct LeakyStruct *)malloc(sizeof(struct LeakyStruct));
    if (!my_chunk) return 1;
    
    // Initialize only the 5 official bytes of our structure.
    memcpy(my_chunk->id, "USR01", 5);

    // Query glibc for the number of bytes available in the allocated chunk
    size_t total_usable = malloc_usable_size(my_chunk);

    unsigned char *raw_bytes = (unsigned char *)my_chunk;
    
    printf("[+] Official struct size (Compiler): %zu bytes\n", sizeof(struct LeakyStruct));
    printf("[+] Usable bytes reported by glibc: %zu bytes\n", total_usable);   
    printf("[+] Raw memory block contents:\n");
    
    // The bytes beyond sizeof(struct LeakyStruct) are not part of the C object.
    // This experiment inspects the additional bytes reported as usable by glibc.
    for (size_t i = 0; i < total_usable; i++) {
        printf("Byte %02zu: 0x%02X (%c)", i, raw_bytes[i], 
               raw_bytes[i] >= 32 && raw_bytes[i] <= 126 ? raw_bytes[i] : '.');
        
        if (i < 5) printf(" <-- Official User Data\n");
        else if (i < 8) printf(" <-- Compiler Struct Padding (Cleared by high bits of next ptr)\n");
        else if (i < 16) printf(" <-- Uninitialized fields & Metadata (Overwritten by tcache anti-double-free key)\n");
        else printf(" <-- GENUINE HEAP SLACK SPACE (Residual data from a previous allocation!)\n");
    }

    free(my_chunk);
    return 0;
}


```

## Representative output

```text
[+] Official struct size (Compiler): 12 bytes
[+] Usable bytes reported by glibc: 24 bytes
[+] Raw memory block contents:
Byte 00: 0x55 (U) <-- Official User Data
Byte 01: 0x53 (S) <-- Official User Data
Byte 02: 0x52 (R) <-- Official User Data
Byte 03: 0x30 (0) <-- Official User Data
Byte 04: 0x31 (1) <-- Official User Data
Byte 05: 0x00 (.) <-- Compiler Struct Padding (Cleared by high bits of tcache pointer)
Byte 06: 0x00 (.) <-- Compiler Struct Padding (Cleared by high bits of tcache pointer)
Byte 07: 0x00 (.) <-- Compiler Struct Padding (Cleared by high bits of tcache pointer)
Byte 08: 0x00 (.) <-- Uninitialized 'int x' (Overwritten by tcache anti-double-free key)
Byte 09: 0x00 (.) <-- Uninitialized 'int x' (Overwritten by tcache anti-double-free key)
Byte 10: 0x00 (.) <-- Uninitialized 'int x' (Overwritten by tcache anti-double-free key)
Byte 11: 0x00 (.) <-- Uninitialized 'int x' (Overwritten by tcache anti-double-free key)
Byte 12: 0x00 (.) <-- tcache_entry metadata (Overwritten by tcache anti-double-free key)
Byte 13: 0x00 (.) <-- tcache_entry metadata (Overwritten by tcache anti-double-free key)
Byte 14: 0x00 (.) <-- tcache_entry metadata (Overwritten by tcache anti-double-free key)
Byte 15: 0x00 (.) <-- tcache_entry metadata (Overwritten by tcache anti-double-free key)
Byte 16: 0x41 (A) <-- GENUINE HEAP SLACK SPACE (Residual data from a previous allocation!)
Byte 17: 0x41 (A) <-- GENUINE HEAP SLACK SPACE (Residual data from a previous allocation!)
Byte 18: 0x41 (A) <-- GENUINE HEAP SLACK SPACE (Residual data from a previous allocation!)
Byte 19: 0x41 (A) <-- GENUINE HEAP SLACK SPACE (Residual data from a previous allocation!)
Byte 20: 0x41 (A) <-- GENUINE HEAP SLACK SPACE (Residual data from a previous allocation!)
Byte 21: 0x41 (A) <-- GENUINE HEAP SLACK SPACE (Residual data from a previous allocation!)
Byte 22: 0x41 (A) <-- GENUINE HEAP SLACK SPACE (Residual data from a previous allocation!)
Byte 23: 0x41 (A) <-- GENUINE HEAP SLACK SPACE (Residual data from a previous allocation!)

```
**Visual Overview**

glibc chunk

+------------------------+
| chunk metadata         |
| (allocator-managed)    |
+------------------------+
| struct object          |
| id[5]                  |
| compiler padding       |
| int x                  |
+------------------------+
| extra usable bytes     |
| outside the C object   |
+------------------------+

The last region is not part of struct LeakyStruct, even though malloc_usable_size() may report it as usable space. 


*(Note: Depending on your system's exact `glibc` version, the very first bytes of a reused chunk might temporarily hold tcache management pointers right after `free()`. However, since our structure's user data immediately overwrites those first bytes, the remaining "slack space" at the end remains untouched, preserving our leaked `0x41` bytes).*

## Analysis & Reality Check: When glibc Gets in the Way
When executing this PoC on a modern linux system (glibc >= 2.32), we run into a fascinating surprise: instead of seeing the entire block filled with our previously sprayed `0x41` bytes, the middle section is wiped with zeroes. 

**Why does this happen?**
Because modern glibc implements native security mitigations to prevent Double Free exploits. When a chunk is sent to the `tcache`, the allocator writes hidden internal metadata--specifically, a `next` pointer obfuscated via safe-linking (bytes 0-7) and a security `key` (bytes 8-15). When the chunk is reallocated, `glibc` explicitly zeros out the `key` field to sanitize its state. Additionally, on the 64-bit user-space mappings used in this experiment, the high bytes of the stored pointer value are zero, which is why the compiler padding appears as zeroes in this particular run. 

However, because our 12-byte structure (5 bytes from the id array, 3 padding bytes, and 4 bytes from the integer) is smaller than the total space allocated by glibc due to its strict 16-byte alignment constraints, the security mechanism leaves a gap. The final 8 bytes of the block (bytes 16 to 23) represent the genuine heap slack space in this particular allocation layout. Since no tcache metadata overwrites this tail end, it remains completely untouched, successfully exposing the residual 0x41 bytes left by the previous allocation.
 
*(Note: As discussed in the previous post, the linux kernel zeroes out pages before handling them to a new process to avoid inter-process spying. Therefore, this information disclosure vector occurs strictly within the boundaries of the same process or inside the kernel subsystem itself).*

### Under the Hood: The 24-Byte Mystery (Space Reclamation Mechanics)
On the system I tested, malloc_usable_size() reported 24 usable bytes for a 12-byte allocation. This can look surprising at first: why does glibc provide 24 bytes when the requested object is only 12 bytes? And why not 32, which might seem more intuitive at first thinking about the alignment?

The answer lies in the way glibc lays out and manages heap chunks. The allocator maintains metadata around chunks, and some fields that are part of the overall chunk layout are treated differently depending on whether neighboring chunks are in use.

This means that the relationship between the requested size, the physical chunk size, and the number reported by malloc_usable_size() is not simply "requested bytes + fixed header."

In this experiment, the important point is that glibc reports 24 usable bytes, while the C object itself remains only 12 bytes.

##Final Thoughts

What started as a simple question about data alignment and CPU efficiency turned into something much more interesting.

I initially wanted to understand why a structure could contain bytes that I hadn't explicitly written. But following those bytes led me through several different layers of the system: compiler padding, ABI alignment, heap allocation, chunk layout, tcache metadata, and finally the extra bytes that glibc reported as usable.

The most interesting part was not finding a vulnerability. In fact, this experiment does not demonstrate a standalone vulnerability by itself. What it demonstrates is how easy it is to lose sight of what a program actually owns when looking at memory at different abstraction levels.

A 12-byte C structure can exist inside a larger heap allocation. The allocator can manage metadata that the program never sees. Freed memory can be reused. Security mechanisms can overwrite some of the old contents while leaving other bytes untouched. And what initially looks like "padding" can turn out to have several completely different origins.

That was the real lesson for me: when looking at memory, it is not enough to ask what bytes are here? You also have to ask who owns them, who wrote them, and at which layer are they being interpreted?

This experiment started by looking for potential logical gaps where memory alignment, driven in part by CPU efficiency, might leave bytes outside the data explicitly initialized by a program.

It ended with glibc.
