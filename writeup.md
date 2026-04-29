# Rev Wandering - CTF Writeup

This challenge took me nearly two days to solve . We are given a `vm` binary along with a `Dockerfile` .

## Initial Setup and Execution

Listing the files in the directory and examining the `Dockerfile` :

```bash
$ ls rev_wandering/
compose.yaml  Dockerfile  flag.txt  run.sh  vm

$ cat Dockerfile
FROM debian:bookworm-slim

RUN apt-get update  && apt-get install -y --no-install-recommends socat  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY vm /app/vm
COPY run.sh /app/run.sh
COPY flag.txt /flag.txt

RUN chmod +x /app/vm /app/run.sh

EXPOSE 1337
ENTRYPOINT ["socat", "-T", "60", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/app/run.sh,stderr"]
```

The `Dockerfile` runs a `run.sh` script, so let's examine it :

```bash
$ cat run.sh                     
#!/bin/sh
set -eu

VM_BIN="/app/vm"
if [ ! -x "$VM_BIN" ]; then
  VM_BIN="$(dirname "$0")/vm"
fi

while true; do
  "$VM_BIN" || true
done
```

It contains an infinite loop that keeps running our VM if it crashes or terminates . 

Next, we build and run the Docker image :

```bash
$ sudo docker build -t vm:v1 rev_wandering && sudo docker run -p 1337:1337 vm:v1
```

Now that we have the VM running, let's try to communicate with it via `nc` :

```bash
$ nc localhost 1337                 
sa
sad
as
da
sd
as
das
d
1 1
incorrect!
aa 2
24 4 
21 21
aa a
2 2
incorrect!
2 2
2 2
incorrect!
a
```

As observed, after supplying some inputs, it outputs "incorrect!" .

## Basic Dynamic and Static Analysis

Let's run the standard `file` command :

```bash
$ file ./vm                     
vm: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped
```

It is a stripped x64 binary .

Next, running the `strings` command reveals what kind of text data is inside the VM :

```bash
$ strings ./vm
.
.
.
%d%c%d
/flag.txt
incorrect!
Failed initialization
9*3$"
.
.
.
```

After some digging, I found these interesting strings . The first one is likely a format string argument for `scanf`, suggesting the VM might be expecting a mathematical operation, which we will verify using a disassembler .

Before that, running `ltrace` or `strace` helps us see what is happening dynamically :

```bash
$ ltrace ./vm
setvbuf(0x7fdd00a315c0, nil, 2, 0)          = 0
malloc(2504)                                = 0x563dbab95010
memcpy(0x563dbab95010, "éÕ¥"I@"éñÃ¥/_Ã¥µ«l®Á¥"..., 2504) = 0x563dbab95010
calloc(4198432, 1)                          = 0x7fdd00442010
time(nil)                                   = 1777314516
getpid()                                    = 143257
__isoc99_scanf(0x563db8d4c000, 0x7ffc36d63e70, 0x7ffc36d63e6f, 0x7ffc36d63e74) 1 1
__isoc99_scanf(0x563db8d4c000, 0x7ffc36d63e70, 0x7ffc36d63e6f, 0x7ffc36d63e74) 1 1

puts("incorrect!"incorrect!
)                          = 11
free(0x7fdd00442010)                        = <void>
free(0x563dbab95010)                        = <void>
+++ exited (status 0) +++
```

This output looks messy but is highly informative . The binary allocates 2504 bytes and copies data into it, indicating it is likely loading the VM from memory .

## Deep Dive with IDA Pro

Now, let's run the binary through a disassembler (`ida ./vm`) and examine the `main` function using the IDA decompiler :

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int v3; // r13d
  __int64 v4; // rax
  void *v5; // rbp
  __int64 v6; // rax
  void *v7; // r12
  _QWORD v9[5]; // [rsp+0h] [rbp-28h] BYREF

  v3 = 1;
  v9[1] = __readfsqword(0x28u);
  setvbuf(stdout, 0, 2, 0);
  v4 = sub_1C30(v9);
  if ( v4 )
  {
    v5 = (void *)v4;
    v6 = sub_13A0(v4, v9[0]);
    v7 = (void *)v6;
    if ( v6 )
    {
      v3 = 0;
      sub_1630(v6);
      free(v7);
      free(v5);
    }
    else
    {
      free(v5);
      puts("Failed initialization");
    }
  }
  return v3;
}
```

The `main` function calls multiple subroutines, starting with `sub_13A0` which takes `v9` as an argument . The variable `v9` is defined as an array of `_QWORD` (64-bit), but the stack canary appearing as the second element of the array is simply decompiler confusion . Changing the type of `v9` to just `_QWORD` fixes this issue :

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int v3; // r13d
  void *v4; // rax
  void *v5; // rbp
  _QWORD *v6; // rax
  void *v7; // r12
  __int64 v9; // [rsp+0h] [rbp-28h] BYREF
  unsigned __int64 v10; // [rsp+8h] [rbp-20h]

  v3 = 1;
  v10 = __readfsqword(0x28u);
  setvbuf(stdout, 0, 2, 0);
  v4 = sub_1C30(&v9);
  if ( v4 )
  {
    v5 = v4;
    v6 = sub_13A0((__int64)v4, v9);
    v7 = v6;
    if ( v6 )
    {
      v3 = 0;
      sub_1630(v6);
      free(v7);
      free(v5);
    }
    else
    {
      free(v5);
      puts("Failed initialization");
    }
  }
  return v3;
}
```

Now, IDA correctly shows every variable separately . 

### VM Loading (`sub_1C30`)

Let's examine the `sub_1C30` function, which takes the address of `v9` as a parameter and stores the result in `a1` :

```c
void *__fastcall sub_1C30(_QWORD *a1)
{
  void *v1; // r8
  unsigned int v2; // ebx
  __int64 v3; // rbp
  void *v4; // rax
  void *v5; // rax

  v1 = 0;
  v2 = n;
  if ( (n & 7) == 0 )
  {
    v3 = (unsigned int)n >> 3;
    v4 = malloc(8 * v3);
    v1 = v4;
    if ( v4 )
    {
      v5 = memcpy(v4, &unk_4020, v2);
      *a1 = v3;
      return v5;
    }
  }
  return v1;
}
```

This function allocates memory and copies data into it, effectively loading the VM from memory and storing it in `v4` . It also takes the passed pointer (pointing to `v9`) and stores the size of the allocated memory divided by 8 (since right-shifting by 3 is equivalent to dividing by 2^3) . 

We can rename `v2` to `vm_size`, `v5` to `vm_data`, and `v3` to `size_divided_by_8` . This is probably the number of instructions our VM will execute . Let's tentatively rename this function to `load_vm?` and continue investigating .

### VM Initialization (`sub_13A0`)

If the VM loads correctly, another function executes, taking `vm_data` (`v4`) and `size_divided_by_8` (`v9`) as parameters . This function allocates a huge memory chunk and saves the pointer to `vm_data` in the first 8 bytes . The `size_divided_by_8` is saved in the second 8 bytes . 

It sets a flag at an offset of 1030, initializes a seed, XORs values to generate a random number, stores it at offset 1031, and returns the pointer . The best name for this is `init_vm` :

```c
_QWORD *__fastcall sub_13A0(__int64 a1, __int64 a2)
{
  _QWORD *v2; // rax
  _QWORD *v3; // r12
  int v4; // ebx
  int v5; // eax
  unsigned int v6; // edx
  bool v7; // zf
  int v8; // eax

  v2 = calloc(0x401020u, 1u);
  v3 = v2;
  if ( v2 )
  {
    v2[1] = a2;
    *v2 = a1;
    *((_DWORD *)v2 + 1030) = -1;
    v4 = time(0);
    v5 = v4 ^ getpid();
    v6 = v5 ^ 0xA5C3F1E9;
    v7 = v5 == -1513885207;
    v8 = 1;
    if ( !v7 )
      v8 = v6;
    *((_DWORD *)v3 + 1031) = v8;
  }
  return v3;
}
```

Let's rename the `v6` variable to `vm?` .

### The VM Execution Brain (`sub_1630`)

If initialization is successful, `sub_1630` is called . Let's examine it :

```c
void __fastcall sub_1630(__int64 *a1)
{
  unsigned __int64 v1; // rcx
  __int64 v3; // rsi
  // allocating other variables...
  .
  .
  .
  v1 = a1[2];
  if ( a1[1] > v1 )
  {
    do
    {
      v3 = *a1;
      a1[2] = v1 + 1;
      v4 = sub_1410(*(unsigned int *)(v3 + 8 * v1));
      v7 = (unsigned int)sub_1470(*(unsigned int *)(v5 + 4), v3, v6, v5, v4);
      switch ( v10 )
      {
        case 2:
          v57 = *((_DWORD *)a1 + 1030);
          v1 = v9;
          if ( v57 <= 1022 )
          {
            v58 = v57 + 1;
            *((_DWORD *)a1 + 1030) = v58;
            *((_DWORD *)a1 + v58 + 6) = v7;
          }
          break;
      .
      .
      .
      }
    }
    while ( v8 > v1 );
  }
}
```

This massive function acts as the heart or brain of the VM, containing a switch statement and extensive logic . It takes the VM as input (renaming `a1` to `vm`), stores a value into `v1`, and compares the second 64-bit value (`size_divided_by_8`) . It is highly probable that `v1` acts as an Instruction Pointer (IP register) .

Analyzing the first lines of the `do-while` loop :
```c
v3 = *a1;
a1[2] = v1 + 1;
v4 = sub_1410(*(unsigned int *)(v3 + 8 * v1));
v7 = (unsigned int)sub_1470(*(unsigned int *)(v5 + 4), v3, v6, v5, v4);
```

It dereferences `a1`, stores the value in `v3`, and increments `a1[2]` (the IP) by 1 . The `v3` pointer now points to the actual instructions, making `instructions_adr` a suitable name . The function `sub_1410` fetches the instruction from memory by indexing `v3 + 8 * v1` (which maps to `instructions_adr + 8 * IP`) . This observation confirms each instruction is 8 bytes long .

### Instruction Decoding (`sub_1410` and `sub_1470`)

Let's examine `sub_1410` :

```c
unsigned __int64 __fastcall sub_1410(unsigned int a1)
{
  return (16 * HIWORD(a1) + 4 * (unsigned __int8)a1 + a1 * (2 * HIWORD(a1) + 1))
       ^ ((16 * HIWORD(a1)
         + 4 * (unsigned __int8)a1
         + a1 * (unsigned __int64)(2 * HIWORD(a1) + 1)
         + (((unsigned __int8)(a1 ^ BYTE1(a1)) + a1 * (unsigned __int64)((4 * (unsigned __int16)(a1 >> 8)) & 0x3FC | 2u)) << 32)) >> 32);
}
```

This heavily obfuscated function is likely fetching or decoding instructions; we can name it `decode_instruction?` . The companion function `sub_1470` performs further XORing and bit manipulation :

```c
__int64 __fastcall sub_1470(int a1)
{
  unsigned int v1; // edi
  int v2; // eax
  int v3; // ecx
  unsigned int v4; // edx
  int v5; // ecx
  unsigned int v6; // eax
  int v7; // edx
  unsigned int v8; // esi

  v1 = a1 ^ 0xA5C3F1E9;
  v2 = 4;
  v3 = 2;
  do
  {
    v4 = v1 >> v3;
    v3 *= 2;
    v1 ^= v4;
    --v2;
  }
  while ( v2 );
  v5 = 3;
  v6 = ((v1 ^ (32 * v1)) << 10) ^ v1 ^ (32 * v1) ^ ((((v1 ^ (32 * v1)) << 10) ^ v1 ^ (32 * v1)) << 20);
  v7 = 4;
  do
  {
    v8 = v6 >> v5;
    v5 *= 2;
    v6 ^= v8;
    --v7;
  }
  while ( v7 );
  return (v6 << 7) ^ v6 ^ (((v6 << 7) ^ v6) << 14) ^ (((v6 << 7) ^ v6 ^ (((v6 << 7) ^ v6) << 14)) << 28);
}
```

Since it is difficult to read manually, we continue our investigation to gather more context .

## Reconstructing the VM Struct

Based on the gathered information, let's build a C struct representing the VM :

```c
typedef struct {
  uint64_t *instructions_adr;
  uint64_t num_of_instructions;
  uint64_t IP;

  //gap(2480 bytes)
} vm; //sizeof(vm) = 2504
```

Looking closely at `case 2` in the switch statement :

```c
case 2:
  v55 = *((_DWORD *)vm + 1030);
  v1 = v7;
  if ( v55 <= 1022 )
  {
    v56 = v55 + 1;
    *((_DWORD *)vm + 1030) = v56;
    *((_DWORD *)vm + v56 + 6) = v5;
  }
  break;
```

This code increments offset 1030 in the VM and stores the return value into `*((_DWORD *)vm + v56 + 6)` . Given standard low-level architecture, this mimics a `push` instruction . It stores a value (`*((_DWORD *)vm + 1030) = v56`) and increments the pointer (`v56 = v55 + 1`) .

The actual stack resides at `((_DWORD *)vm + v56 + 6)`, meaning it starts 6 `DWORD`s (24 bytes) after the start of the VM memory block . The variable `v56` serves as the Stack Pointer (SP), holding 4-byte values . Because of the condition `if ( v55 <= 1022 )`, we know its total capacity is 1022 items .

Updating the VM struct with these findings yields :

```c
typedef struct {
  uint64_t *instructions_adr;
  uint64_t num_of_instructions;
  uint64_t IP;
  uint32_t stack[1022];
  //gap(8 bytes)
  uint32_t SP;
  .
  .  
} vm; //sizeof(vm) = 4198432 bytes (based on the calloc function)
```

Rewriting `case 2` using our struct makes the underlying logic clear :

```c
case 2:
  SP = vm->SP;
  IP = v7;
  if ( SP <= 1022 )
  {
    v56 = SP + 1;
    vm->SP = v56;
    vm->stack[v56] = v5;
  }
  break;
```

The line `v1 = v7` is a decompiler artifact assigning the instruction number to itself . From here, analyzing the remainder of the VM instructions would follow the same struct-mapping process .

"I got tired i'll complete it soon"
