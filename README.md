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

Password: `0x31 0x3d 0x6a 0x6b 0x67 0x7a 0x3c`

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

Password: `0x3b 0x2b 0x22 0x6d 0x31 0x7a 0x64 0x51`

## Hanoi

#### Exploit: Overflowing a the checksum

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

Password: `AAAAAAAAAAAAAAAA1`

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

Password: `AAAAAAAAAAAAAAAAFD`
