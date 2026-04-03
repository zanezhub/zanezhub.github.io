---
title: Reverse Challenge - Silent Lock
date: 2026-03-31 00:00:00 -0600
categories: [reverse engineer, crackmes.one, CTF]
tags: [blog, reverse engineer, crackmes.one, CTF]
---

This challenge was done by `Ploxied`. You can find it [here](https://crackmes.one/crackme/69ab07567b3cc38c80464e59), please give a try. Thanks to `Ploxied` for creating the challenge.

# Weird functions
I found these interesting, I had to use [Intel's documentation](https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html) to find these, none of them are C functions. It seems like these were added using inline assembly or importing their specific header file that implements them in C.

* `_mm_cmpgt_epi8`: Compare packed signed 8-bit integers in a and b for greater-than, and store the results in dst.
```c
__m128i _mm_cmpgt_epi8 (__m128i a, __m128i b)
#include <emmintrin.h>
Instruction: pcmpgtb xmm, xmm
CPUID Flags: SSE2
```

* `_mm_unpacklo_epi8`:  Unpack and interleave 8-bit integers from the low half of a and b, and store the results in dst.
```c
__m128i _mm_unpacklo_epi8 (__m128i a, __m128i b)
#include <emmintrin.h>
Instruction: punpcklbw xmm, xmm
CPUID Flags: SSE2
```

* `_mm_unpackhi_epi8`: Unpack and interleave 8-bit integers from the high half of a and b, and store the results in dst.
```c
__m128i _mm_unpackhi_epi8 (__m128i a, __m128i b)
#include <emmintrin.h>
Instruction: punpckhbw xmm, xmm
CPUID Flags: SSE2
```

* `_mm_cmpgt_epi16`: Compare packed signed 16-bit integers in a and b for greater-than, and store the results in dst.
```c
__m128i _mm_cmpgt_epi16 (__m128i a, __m128i b)
#include <emmintrin.h>
Instruction: pcmpgtw xmm, xmm
CPUID Flags: SSE2
```

* `_mm_unpackhi_epi16`: Unpack and interleave 16-bit integers from the high half of a and b, and store the results in dst.
```c
__m128i _mm_unpackhi_epi16 (__m128i a, __m128i b)
#include <emmintrin.h>
Instruction: punpckhwd xmm, xmm
CPUID Flags: SSE2
```

* `__paddd_xmmdq_memdq`: This one seems to be `PADD` in the assembly instructions. 

This instruction adds the dwords of the source to the dwords of the destination and writes the results to the MMX register. When the result is too large to be represented in a packed dword (overflow), the result wraps around and the lower 32 bits are writen to the destination register.
https://asm.inightmare.org/opcodelst/index.php?op=PADDD

* `_mm_add_epi32`: Add packed 32-bit integers in a and b, and store the results in dst.
```c
__m128i _mm_add_epi32 (__m128i a, __m128i b)
#include <emmintrin.h>
Instruction: paddd xmm, xmm
CPUID Flags: SSE2
```

* `_mm_unpacklo_epi16`: Unpack and interleave 16-bit integers from the low half of a and b, and store the results in dst.
```c
__m128i _mm_unpacklo_epi16 (__m128i a, __m128i b)
#include <emmintrin.h>
Instruction: punpcklwd xmm, xmm
CPUID Flags: SSE2
```

* `_mm_bsrli_si128`: Shift a right by imm8 bytes while shifting in zeros, and store the results in dst.
```c
__m128i _mm_bsrli_si128 (__m128i a, int imm8)
#include <emmintrin.h>
Instruction: psrldq xmm, imm8
CPUID Flags: SSE2
```
The use of these functions gives us the following Pseudo C code:
![](assets/img/posts/reverse-ch-5/weird-asm.png)

This big `if` statement is doing some transformations on the string `PWD!!^-12345-!XD`. The functions are used for transformations.

The string looks funny, so it catches my attention and I see it is being used a lot in the transformation. In this dissasembly snippet we can see that the string is moved into `xmm1` using `movdqa`. This is later used alongside `xmm0` to `xor` and store the result in `xmm0`.

The whole `if` only runs if the `count` is equal to 16, this is the same length as the string `PWD!!^-12345-!XD`.

![](assets/img/posts/reverse-ch-5/use-password.png)

In the `main` function, this variable is later filled with zeros, most likely because it is trying to stop you from extracting the decrypted strings at runtime.
```c
__builtin_memset(&password, 0, 0x10);  
```

In the function `0x1400017c0` that contains the main logic behind the encryption also takes strings that have a length of `27`, and `8`.
# Anti Debugging
## IsDebuggerPresent() & ud2
The challenge also mentions that some anti debugging tricks will be used. The most common and well known example is the function `IsDebuggerPresent()`, even if it's your first time learning about this function you could probably guess what this is meant to do.

In this code snippet
```c
if (!IsDebuggerPresent())
    return (uint64_t)return_val;

trap(6);
```

If no debugger is present then it returns one of the values that was computed in this function and continues with the intended workflow for the binary, if there is a debugger present then it calls the function `trap(6)`.

This is the `ud2` assembly instruction.
> UD2 is an x86 assembly instruction that simulates an invalid opcode and mostly used for testing purposes, but not only. Indeed it can be used by malware authors for example to disturbe the decompilation process of the malware.

## SetUnhandledExceptionFilter()
There's also this other function, that is used in this code snippet.

> After calling this function, if an exception occurs in a process that is not being debugged, and the exception makes it to the unhandled exception filter, that filter will call the exception filter function specified by the `lpTopLevelExceptionFilter` parameter.

```nasm
sub     rsp, 0x28
lea     rcx, [rel sub_140001700]
call    qword [rel SetUnhandledExceptionFilter]
call    qword [rel IsDebuggerPresent]
test    eax, eax
je      0x14000172d

ud2     
Does not return

add     rsp, 0x28
retn    __return_addr
```

The second instruction `lea rcx, [rel sub_140001700]`, is just a way to obfuscate the value of `0xffffffff`. The function just returns the value.
```nasm
mov     eax, 0xffffffff
retn     __return_addr
```

And then calls the function `SetUnhandledExceptionFilter` with the value.

```nasm
call    qword [rel SetUnhandledExceptionFilter]
call    qword [rel IsDebuggerPresent]
```

> Return from `UnhandledExceptionFilter` and continue execution from the point of the exception. Note that the filter function is free to modify the continuation state by modifying the exception information supplied through its `LPEXCEPTION_POINTERS` parameter.

# Links
Thanks for the help with these topics
* [Anti-Decompiling instructions](https://0x09.dev/posts/undifined_but_simple_anti_decompiler/)
* [UD2 Assembly instructions](https://mudongliang.github.io/x86/html/file_module_x86_id_318.html)
* [IsDebuggerPresent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent)
* [SetUnhandledExceptionFilter](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter)
* [Anti-Debug: Assembly instructions](https://anti-debug.checkpoint.com/techniques/assembly.html)
* [Anti-Debug: Exceptions](https://anti-debug.checkpoint.com/techniques/exceptions.html)
* [Anti-Debug with Trap Flag Register](https://leons.im/posts/anti-debug-with-trap-flag-register/)
