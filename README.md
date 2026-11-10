# Ordinal Hash Obfuscation Pass
Built for LLVM 19.1 - Windows x64 <br> <br>

Within obfuscation you will see certain people removing constants within conditions using hashes. This is nearly always only an equivalence comparison. <br>
```c
if (runtimehash(val) == 0xdeadbeef)
``` 
Instead of 

```c
if (val == 0xcafebabe)
``` 
You see how the value is hidden when you hash? <br>
The issue is this only works for equivalence, Prior to this release no one has handled greater than or less than as hashes will not retain ordinality. <br>
```c
if (val > 1000)
``` 
Turns into
```c
//Obfuscation time:
tag[i, v] = H(salt, i, v, rel)
//Runtime
if (LookUpTable(H(runtimeval)) > 0) // if runtimeval isn't 1000 then this simply falls through. If it is it will find the table
``` 

Luckily this amazing paper was released a couple years ago which works PERFECTLY as we can simply use runtime as K to turn it into a full blown hashing algorithm rather than an encryption algorithm, Weaponising it with AES-NI for maximum effect. <br> <br> 
Credits to: Nathan Chenette, Kevin Lewi, Stephen A. Weis, and David J. Wu;  For their paper [Practical Order-Revealing Encryption with Limited Leakage](https://eprint.iacr.org/2015/1125). <br>
Then since we know the runtime value, we can build individual per instance encryption look ups using the runtime K, to prevent any leaking at all. Hardening it entirely. <br>
We also use bilinear mapping from: <br>
Kevin Lewi and David J. Wu - [Order-Revealing Encryption: New Constructions, Applications, and Lower Bounds](https://eprint.iacr.org/2016/612)

## The Methodology
We take every ```<``` ```>``` ```<=``` ```>=``` condition where the value is runtime known. <br>
We then break them into tables of 4 bit chunks, using AES-NI with the runtime known value as K to make it runtime dependent (an actual hash)<br>
We look up the runtime value in the table, if runtime value is none of these, then it falls through all conditions, if it is found, we have the real value's table look up. <br>
This means without the runtime value/ known result, it will never leak the value of the condition, The only thing an attacker sees is a table AESed to the runtime value. <br>
This is the EASIEST way to put it, as you can imagine, that means a lot of overhead is required to research the tables, itterate them, hash over 192 table instances per condition <br>
If you want a more in depth explanation, All the articles are cited above. <br> <br>
Before:
```c
  if ( v5 <= 1 )
  {
    ++v5;
    goto LABEL_5;
  }
  ```
  After:

```c
 v805 = v813 ^ 0x80000000;
  v738 = v805 >> 28;
  v739 = qword_1403AA3E0[v738];
  _XMM2 = _mm_xor_si128((__m128i)((v738 << 48) | 0x2C98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v738 << 48) | 0x2C98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v738 << 48) | 0x2C98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v738 << 48) | 0x2C98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) == v739 )
    goto LABEL_86;
  _XMM2 = _mm_xor_si128((__m128i)((v738 << 48) | 0x2D98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v738 << 48) | 0x2D98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v738 << 48) | 0x2D98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v738 << 48) | 0x2D98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) != v739 )
    goto LABEL_88;
  v736 = HIBYTE(v805) & 0xF;
  v737 = qword_1403AA3E0[v736 + 16];
  _XMM2 = _mm_xor_si128((__m128i)((v736 << 48) | 0x1002C98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v736 << 48) | 0x1002C98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v736 << 48) | 0x1002C98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v736 << 48) | 0x1002C98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) == v737 )
    goto LABEL_86;
  _XMM2 = _mm_xor_si128((__m128i)((v736 << 48) ^ 0x1002D98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v736 << 48) ^ 0x1002D98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v736 << 48) ^ 0x1002D98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v736 << 48) ^ 0x1002D98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) != v737 )
    goto LABEL_88;
  v734 = (v805 >> 20) & 0xF;
  v735 = qword_1403AA3E0[v734 + 32];
  _XMM2 = _mm_xor_si128((__m128i)((v734 << 48) | 0x2002C98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v734 << 48) | 0x2002C98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v734 << 48) | 0x2002C98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v734 << 48) | 0x2002C98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) == v735 )
    goto LABEL_86;
  _XMM2 = _mm_xor_si128((__m128i)((v734 << 48) ^ 0x2002D98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v734 << 48) ^ 0x2002D98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v734 << 48) ^ 0x2002D98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v734 << 48) ^ 0x2002D98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) != v735 )
    goto LABEL_88;
  v732 = HIWORD(v805) & 0xF;
  v733 = qword_1403AA3E0[v732 + 48];
  _XMM2 = _mm_xor_si128((__m128i)((v732 << 48) | 0x3002C98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v732 << 48) | 0x3002C98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v732 << 48) | 0x3002C98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v732 << 48) | 0x3002C98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) == v733 )
    goto LABEL_86;
  _XMM2 = _mm_xor_si128((__m128i)((v732 << 48) ^ 0x3002D98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v732 << 48) ^ 0x3002D98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v732 << 48) ^ 0x3002D98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v732 << 48) ^ 0x3002D98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) != v733 )
    goto LABEL_88;
  v730 = (unsigned __int16)v813 >> 12;
  v731 = qword_1403AA3E0[v730 + 64];
  _XMM2 = _mm_xor_si128((__m128i)((v730 << 48) | 0x4002C98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v730 << 48) | 0x4002C98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v730 << 48) | 0x4002C98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v730 << 48) | 0x4002C98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) == v731 )
    goto LABEL_86;
  _XMM2 = _mm_xor_si128((__m128i)((v730 << 48) ^ 0x4002D98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v730 << 48) ^ 0x4002D98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v730 << 48) ^ 0x4002D98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v730 << 48) ^ 0x4002D98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) != v731 )
    goto LABEL_88;
  v728 = (v805 >> 8) & 0xF;
  v729 = qword_1403AA3E0[v728 + 80];
  _XMM2 = _mm_xor_si128((__m128i)((v728 << 48) | 0x5002C98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v728 << 48) | 0x5002C98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v728 << 48) | 0x5002C98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v728 << 48) | 0x5002C98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) == v729 )
    goto LABEL_86;
  _XMM2 = _mm_xor_si128((__m128i)((v728 << 48) ^ 0x5002D98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v728 << 48) ^ 0x5002D98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v728 << 48) ^ 0x5002D98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v728 << 48) ^ 0x5002D98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) != v729 )
    goto LABEL_88;
  v726 = (unsigned __int8)v813 >> 4;
  v727 = qword_1403AA3E0[v726 + 96];
  _XMM2 = _mm_xor_si128((__m128i)((v726 << 48) | 0x6002C98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v726 << 48) | 0x6002C98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v726 << 48) | 0x6002C98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v726 << 48) | 0x6002C98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) == v727 )
    goto LABEL_86;
  _XMM2 = _mm_xor_si128((__m128i)((v726 << 48) ^ 0x6002D98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v726 << 48) ^ 0x6002D98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v726 << 48) ^ 0x6002D98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v726 << 48) ^ 0x6002D98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) != v727 )
    goto LABEL_88;
  v724 = v813 & 0xF;
  v725 = qword_1403AA3E0[v724 + 112];
  _XMM2 = _mm_xor_si128((__m128i)((v724 << 48) | 0x7002C98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v724 << 48) | 0x7002C98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v724 << 48) | 0x7002C98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v724 << 48) | 0x7002C98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) == v725 )
  {
LABEL_86:
    v804 = -1;
    goto LABEL_10;
  }
  _XMM2 = _mm_xor_si128((__m128i)((v724 << 48) ^ 0x7002D98000047E5uLL), (__m128i)xmmword_14038E840);
  _XMM0 = xmmword_14038E850;
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v724 << 48) ^ 0x7002D98000047E5uLL), (__m128i)xmmword_14038E860);
  __asm { aesenc  xmm0, xmm2 }
  _XMM2 = _mm_xor_si128((__m128i)((v724 << 48) ^ 0x7002D98000047E5uLL), (__m128i)xmmword_14038E870);
  __asm { aesenc  xmm0, xmm2 }
  _XMM1 = _mm_xor_si128((__m128i)((v724 << 48) ^ 0x7002D98000047E5uLL), (__m128i)xmmword_14038E880);
  __asm { aesenclast xmm0, xmm1 }
  if ( ((unsigned __int64)_XMM0 ^ 0x341000051FDLL) == v725 )
  {
    v804 = 0;
    goto LABEL_10;
  }
LABEL_88:
  v804 = 1;
LABEL_10:
  if ( v804 <= 0 )
  {
    ++v813;
    goto LABEL_12;
  }
  ```
## Annotations
```c
__attribute__((annotate("noobfus")))
``` 
* Excludes a function from the pass

## How To Build
* Download [LLVM 19.1](https://github.com/llvm/llvm-project/releases/tag/llvmorg-19.1.0)
* Download [VCPKG](https://github.com/microsoft/vcpkg)
* VCPKG install asmjit
* Open build.bat in a text editor.
* Find the LLVM 19.1 references in the command line, Change them to your file path.
* Find the VCPKG references in the command line, Change them to your file path.
* Run the build script
* Build your application with the ``` -load-pass-plugin ``` Param to the FunctionPass.dll
