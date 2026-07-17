---
title: Reverse Challenge - MCM 3.0 Rework
date: 2026-02-26 10:00:00 -0600
categories: [reverse engineer, crackmes.one, CTF]
tags: [blog, reverse engineer, crackmes.one, CTF]
---

![](assets/img/posts/reverse-ch-3/challenge.png)

We can see that he packed binary is inside `.rdata`.
![Packed](assets/img/posts/reverse-ch-3/01.png)

![Packed-Sections](assets/img/posts/reverse-ch-3/02.png)

Capa
```text
PS C:\Users\zanez\Desktop\Crackmes.one\mcm 3 rework > capa .\CrackMe_packed.exe -vvv
md5                     35fec8b1ad8856f9083a332e0d6b9259
sha1                    6fbd870ed2213bc6f5ca1668bcc0e1c432c371c1
sha256                  2baf205890340e7ff50119748da85692548e8132de714ce652e8ae9270685982
path                    C:/Users/zanez/Desktop/Crackmes.one/mcm 3 rework/CrackMe_packed.exe
timestamp               2026-02-26 15:06:43.493157
capa version            9.2.1
os                      windows
format                  pe
arch                    amd64
analysis                static
extractor               VivisectFeatureExtractor
base address            0x140000000
rules                   C:/Users/zanez/AppData/Local/Temp/_MEI27882/rules
function count          226
library function count  143
total feature count     15350

encode data using XOR
namespace  data-manipulation/encoding/xor
scope      basic block
matches    0x140001070

query environment variable
namespace  host-interaction/environment-variable
scope      function
matches    0x140007E00

set environment variable
namespace  host-interaction/environment-variable
scope      function
matches    0x14000B934

get common file path
namespace  host-interaction/file-system
scope      function
matches    0x140001000

delete file
namespace  host-interaction/file-system/delete
scope      function
matches    0x140001000

enumerate files on Windows
namespace  host-interaction/file-system/files/list
scope      function
matches    0x140006A78

write file on Windows (3 matches)
namespace  host-interaction/file-system/write
scope      function
matches    0x140001000
           0x14000BDDC
           0x14000C728

create process on Windows
namespace  host-interaction/process/create
scope      basic block
matches    0x1400011BD

terminate process
namespace  host-interaction/process/terminate
scope      function
matches    0x140004CC0

link function at runtime on Windows (3 matches)
namespace  linking/runtime-linking
scope      instruction
matches    0x140004D2B
           0x1400094F6
           0x1400094F6

enumerate PE sections
namespace  load-code/pe
scope      function
matches    0x14000D930

parse PE header (4 matches)
namespace  load-code/pe
scope      function
matches    0x140001908
           0x140004BDC
           0x140004DC4
           0x14000D9D0
```

# sub_14000d930 - Enumerate PE sections
![code-snippet](assets/img/posts/reverse-ch-3/03.png)

The arguments are arg1 and arg2:
arg1: &__dos_header
arg2: arg1 - &__dos_header

In that function `sub_14000d980(int64_t arg1)`.
![code-snippet-2](assets/img/posts/reverse-ch-3/04.png)

> _ValidateImageBase is a function used in Windows PE (Portable Executable) file handling, specifically within startup or runtime relocation routines, to verify if a PE image (DLL or EXE) is correctly loaded at a particular memory address. 


which comes from 
```c
if (*(uint32_t*)arg1 == 0xe06d7363 && sub_14000d980(&data_14004dba0))
```

And data `data_14004dba0` comes from `.rdata`:
```c
void* data_14004dba0 = sub_140001f64
```

![](assets/img/posts/reverse-ch-3/05.png)


# main
So this is the main functiono, here we can see some windows api call functions like `VirtualAlloc` and int he next is the decryption of the `.rdata` stuff

![decrypt](assets/img/posts/reverse-ch-3/06.png)

the number `0x7ff6a2e8f360` is the start of the `rdata`, this number is high because I rebased the source code to match the x64dbg code.

![decrypt](assets/img/posts/reverse-ch-3/07.png)

the code does some iteration using a math shit whatever the fufck and saves it in payload, which was the allocated buffer for the next step.

here the file is created without any info, and we can see that it tries to create a unique filename using the `GetTickCount()` function and XORing it with `0x4a3b2c1d`

![](assets/img/posts/reverse-ch-3/08.png)

then it writes the payload to the file that was created

![](assets/img/posts/reverse-ch-3/09.png)

then it executes it and deletes it from the system

![](assets/img/posts/reverse-ch-3/10.png)

## x64dbg
I put a break point before the code executes the next step, and search for the name that used for the file

![](assets/img/posts/reverse-ch-3/11.png)

The file is wct4AA43DF1.tmp

so the time was 0x9F11EC and to deicmal 10,424,812, those are milisecs because the gettickcount Retrieves the number of milliseconds that have elapsed since the system was started,

so to minutes is ~173.7469 minutes

which is ~ 2 hours 53 minutes 45 seconds

that is the next step

![](assets/img/posts/reverse-ch-3/12.png)


it looks like this was not corrupted so i guess its okeay

```text
PS C:\Users\zanez\Desktop\Crackmes.one\mcm 3 rework > capa .\wct4AA43DF1.bin -vvv
md5                     932726ac637f18c85efa162a46e77289
sha1                    538c961fa195c21b034cca324a351d26e5e3e8a7
sha256                  9e1397b54c973f0508b7f18f3de8cbcd9538931582fab445b08dbb0ec913e068
path                    C:/Users/zanez/Desktop/Crackmes.one/mcm 3 rework/wct4AA43DF1.bin
timestamp               2026-02-26 18:43:32.717123
capa version            9.2.1
os                      windows
format                  pe
arch                    amd64
analysis                static
extractor               VivisectFeatureExtractor
base address            0x140000000
rules                   C:/Users/zanez/AppData/Local/Temp/_MEI55762/rules
function count          493
library function count  288
total feature count     32523

check for PEB BeingDebugged flag (2 matches)
namespace  anti-analysis/anti-debugging/debugger-detection
scope      basic block
matches    0x140011B3F
           0x14001250D

check for PEB NtGlobalFlag flag
namespace  anti-analysis/anti-debugging/debugger-detection
scope      function
matches    0x140011C20

check for software breakpoints
namespace  anti-analysis/anti-debugging/debugger-detection
scope      function
matches    0x140011C20

execute anti-debugging instructions (3 matches)
namespace  anti-analysis/anti-debugging/debugger-detection
scope      function
matches    0x1400119F0
           0x140011C20
           0x1400148C0

get geographical location (4 matches)
namespace  collection
scope      function
matches    0x140028AA4
           0x140032FD4
           0x140033088
           0x1400331CC

hash data with CRC32
namespace  data-manipulation/checksum/crc32
scope      function
matches    0x140011C20

encode data using XOR (31 matches)
namespace  data-manipulation/encoding/xor
scope      basic block
matches    0x1400118D0
           0x140011A60
           0x1400121E1
           0x140012360
           0x140012470
           0x140012590
           0x140012620
           0x140012740
           0x1400127C0
           0x140012870
           0x1400128F0
           0x1400129B0
           0x140012A30
           0x140012B40
           0x140012BC0
           0x140012ED0
           0x140012F50
           0x140012FE0
           0x1400130E0
           0x140013170
           0x140013250
           0x1400132E0
           0x140013450
           0x1400134E0
           0x140013640
           0x1400136C0
           0x140013790
           0x140013820
           0x140014970
           0x140014B30
           0x140014C30

encrypt data using RC4 PRGA (2 matches)
namespace  data-manipulation/encryption/rc4
scope      function
matches    0x140011860
           0x1400119F0

hash data using djb2
namespace  data-manipulation/hashing/djb2
scope      function
matches    0x140011860

hash data using fnv (22 matches)
namespace    data-manipulation/hashing/fnv
description  can be any Fowler-Noll-Vo (FNV) hash variant, including FNV-1, FNV-1a, FNV-0
scope        function
matches      0x140010310
             0x1400106F0
             0x140010840
             0x140010990
             0x140010AE0
             0x140011C20
             0x1400138B0
             0x140013A00
             0x140013B50
             0x140013CA0
             0x140013DF0
             0x140013F40
             0x140014090
             0x1400141E0
             0x140014330
             0x140014480
             0x140014620
             0x1400148C0
             0x140016AD0
             0x140016C20
             0x140016D70
             0x140017660

query environment variable
namespace  host-interaction/environment-variable
scope      function
matches    0x14002FE84

set environment variable
namespace  host-interaction/environment-variable
scope      function
matches    0x140034514

enumerate files on Windows
namespace  host-interaction/file-system/files/list
scope      function
matches    0x14002EE24

get file size
namespace  host-interaction/file-system/meta
scope      function
matches    0x14002B624

read file on Windows (4 matches)
namespace  host-interaction/file-system/read
scope      function
matches    0x14001B6AC
           0x14002B2A8
           0x14002B778
           0x14002B974

write file on Windows (2 matches)
namespace  host-interaction/file-system/write
scope      function
matches    0x14002A1A8
           0x14002AAF4

check OS version
namespace  host-interaction/os/version
scope      function
matches    0x140011C20

get process filename (2 matches)
namespace    host-interaction/process
description  Retrieves the current process' filename. In the example sample, this was part of a sandbox evasion
             technique that computed and verified the checksum of the sample's filename.
scope        basic block
matches      0x1400131B5
             0x140014620

terminate process
namespace  host-interaction/process/terminate
scope      function
matches    0x140025124

access PEB ldr_data (36 matches)
namespace  linking/runtime-linking
scope      basic block
matches    0x140010310
           0x140010432
           0x14001058D
           0x1400106F0
           0x140010840
           0x140010990
           0x140010AE0
           0x140011860
           0x140012550
           0x1400126EB
           0x14001282D
           0x140012977
           0x140012B01
           0x140012E9B
           0x1400130A2
           0x1400131B5
           0x14001341D
           0x140013607
           0x140013755
           0x1400138B0
           0x1400138B0
           0x140013A00
           0x140013B50
           0x140013CA0
           0x140013DF0
           0x140013F40
           0x140014090
           0x1400141E0
           0x140014330
           0x140014480
           0x140014620
           0x140014753
           0x140016AD0
           0x140016C20
           0x140016D70
           0x140017660

link function at runtime on Windows (3 matches)
namespace  linking/runtime-linking
scope      instruction
matches    0x14002518F
           0x140028852
           0x140028852

enumerate PE sections
namespace  load-code/pe
scope      function
matches    0x140035410

parse PE header (4 matches)
namespace  load-code/pe
scope      function
matches    0x14001D0DC
           0x140025040
           0x140025228
           0x1400354B0

resolve function by parsing PE exports (2 matches)
namespace  load-code/pe
scope      function
matches    0x140011860
           0x140011C20
```

so, whatever ie executed the unpacked code and it worked....
![unpacked-run](assets/img/posts/reverse-ch-3/13.png)

we can see that it creates a new instance of itself and then runs , and it looks like that is where everything happens

it also has string encryption, because i tried to look for string `[-] FAILED. ACCESS DENIED.` and nothing showed up

it somehow worked? lol

![unpacked-run](assets/img/posts/reverse-ch-3/14.png)

i think that you can quickly put anything here and it will work

## debug the unpacked code

![anti-dbg-1](assets/img/posts/reverse-ch-3/15.png)

![anti-dbg-2](assets/img/posts/reverse-ch-3/16.png)

```nasm
movsxd rax,ecx                 
inc ecx                        
xor byte ptr ss:[rsp+rax+20],5A
movsxd rax,ecx                 
cmp byte ptr ss:[rsp+rax+20],0 
jne wct4aa43df1.7FF703641A60   
```

| Encoded | XOR 5A | ASCII |
| ------- | ------ | ----- |
| 05      | 5F     | `_`   |
| 12      | 48     | `H`   |
| 1F      | 45     | `E`   |
| 1B      | 41     | `A`   |
| 0A      | 50     | `P`   |
| 05      | 5F     | `_`   |
| 0E      | 54     | `T`   |
| 08      | 52     | `R`   |
| 1B      | 41     | `A`   |
| 19      | 43     | `C`   |
| 1F      | 45     | `E`   |
| 05      | 5F     | `_`   |
| 1C      | 46     | `F`   |
| 16      | 4C     | `L`   |
| 1B      | 41     | `A`   |
| 1D      | 47     | `G`   |
| 09      | 53     | `S`   |

Seeing `_HEAP_TRACE_FLAGS` in decoded strings is a strong anti-analysis signal.

fuck it, just modify the RIP to the next instruction and jump over that shit
