---
title: Reverse Challenge - Razkom v1.1
date: 2026-02-23 23:50:00 -0600
categories: [reverse engineer, crackmes.one, CTF]
tags: [blog, reverse engineer, crackmes.one, CTF]
---

Here's the [challenge](https://crackmes.one/crackme/69968b7589af4192123d7aad). Thanks to RAZKOM for the challenge :)

This will be considered solved when we get the key that decrypts that secrect message.

![Challenge](assets/img/posts/reverse-ch-2/challenge.png)

There's a few setup functions that are used for printing messages and to read from the standard input when the binary is executed.

I renamed them to `mw_printf` and `mw_get_input`. These are not that useful, nothing important was done on any of these functions:
![Setup-Functions](assets/img/posts/reverse-ch-2/01.png)

The input string that is being read from the standard input is stored at `rsp+0x20`. After that I see 5 variables that are lated used in an `if` statement. All of these are of type `char`.

![Weird-Variables](assets/img/posts/reverse-ch-2/02.png)

This is very strange, I don't see anything useful in the Pseudo C code I have. So I will have to use disassembly.

Now I can see the following code. Keep in mind that the `-` characters were not showing up like this. I had to change the display of that specific part. The characters were showing up like this `0x2d`.

![Assembly](assets/img/posts/reverse-ch-2/03.png)

With this information I can also see the following:

```c
0x14000136a   char string;    rsp+0x20
0x1400013ac   char var_65;    rsp+0x23    
0x1400013ac   char var_61;    rsp+0x27    
0x1400013ac   char var_5d;    rsp+0x2b    
0x1400013ac   char var_59;    rsp+0x2f    
0x1400013ac   char var_55;    rsp+0x33    
```

This means that the input string starts at `rsp+0x20`, and all the weird variables are close to the input string. So this makes me think that the variables are singles characters of the input string. This was later confimed by an `if` statement that was checking for the existence of the character `-`.

![Check-for-char](assets/img/posts/reverse-ch-2/04.png)

This statement just checks for the string to be 23 characters long. It also check every few characters if a character at a position is equal to `-`. Take for example the following string.

```
X       X       X       -       X       X       X       -
0       1       2       3       4       5       6       7
0x20    0x21    0x22    0x23    0x24    0x25    0x26    0x27
```

So all the variables mentioned are 3 characters apart, so keeping in mind all these factors we can imagine that the string should have a structure like this:

```
XXX-XXX-XXX-XXX-XXX-XXX
```

If the previous is true then the string is then sent to the function `0x1400010e0`. I renamed this function to `mw_verification`.

## mw_verification
This function does not look as good as it looks now. To be more exact the changes I made were on the following code snippets:

I took this:
```c
int32_t var_0 = (int32_t)arg1[2];
```

To this:
```c
int32_t char3 = (int32_t)string[2];
```

At the end I changed the comparasion to their respective ASCII equivalent.
```c
% 0x1a + 0x41 == char3 && (uint8_t)char3 == 'R')
```

![](assets/img/posts/reverse-ch-2/05.png)


In the `if` statement I can see that there's some chars in the string that are checked to see if that specific character is equal to something, in this case `R`. This needs to be true for the string to be correct. 

```c
if(((int32_t)string[1] + (int32_t)*(uint8_t*)string)
% 0x1a + 0x41 == char3 && (uint8_t)char3 == 'R')
```

After adding all the characters, here's the result of the string I got:

```
XXX-XXX-XXX-XXX-XXX-XXX
XXR-XXA-XXZ-XXK-XXO-XXM
```

The characters added are only the last character before a new group starts. The two previous characters are used to get the last character in the group. So by using the last character we can know the last two values. Take for example the following code snippet:

```c
if(((int32_t)string[1] + (int32_t)*(uint8_t*)string)
% 0x1a + 0x41 == char3 && (uint8_t)char3 == 'R')
```

The first and second character of the string are used in the computation to verify the two previous chars are valid, then it checks for the last character. 

I made this python script to bruteforce the characters used. We can see that it uses the same algorithm and just prints out the values that are correct. I can change the character in each run.
```python
import sys
for char1 in range(65, 91):
    for char2 in range(65, 91):
        if ((char2 + char1) % 0x1a + 0x41 == ord('Z')):
            print(chr(char2), chr(char1), '... Z')
            sys.exit(0)
```

After checking for all the characters I got the final key. I used that exact key to decrypt the final message. And with all of that I consider it solved.

```
RAR-AAA-ZAZ-KAK-OAO-MAM
```

![](assets/img/posts/reverse-ch-2/solved.png)