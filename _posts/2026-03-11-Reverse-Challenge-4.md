---
title: Reverse Challenge - Nexus! (Lite)
date: 2026-03-11 10:00:00 -0600
categories: [reverse engineer, crackmes.one, CTF]
tags: [blog, reverse engineer, crackmes.one, CTF]
---

In this post I will try to explain how I reverse engineered the challenge to get the master key from the binary. Here's the [challenge](https://crackmes.one/crackme/694af49f0c16072f40f5a379) (thanks to sally1337 for the challenge) if you want to try for yourself before reading or if you want to follow this post.

This one is pretty straight forward. It's very easy to identify the password using some of the tools we have preinstalled on **FlareVM**.

I went straight to the `main` function that was marked by Binary Ninja:

![](assets/img/posts/reverse-ch-4/01.png)

As you can see it's not that long. It has some other functions in the function. I take a quick look at each function that is present inside of main and find the function `sub_140001c70` that I later renamed to `mw_logic`.

![](assets/img/posts/reverse-ch-4/02.png)

I can see more plain text strings in the function. Some of these are just the the strings that are printed when you first start the program, the way they are called to be printed are kinda weird, but I renamed some functions that are used for these purpose.

You can also see the use of the Windows API `IsDebuggerPresent()`. This function is used to detect debuggers, if a debugger is detected by the function then it assings the value `1` to the variable I renamed `debug`. This exact variable is used multiple times in the function for the same purpose. If a debugger is detected then it avoids executing the real logic of the binary to verify the input string.

![](assets/img/posts/reverse-ch-4/03.png)

Now the next thing that catches my eye is a while loop that seems to take the input from the command line. I guessed this because of the string `Enter Master Key: `, indicating input should be provided by the user, so I start looking after that string for any signs that may look like encoding or encryption.

![](assets/img/posts/reverse-ch-4/04.png)

![](assets/img/posts/reverse-ch-4/05.png)

I see another debug check and the string `[*] Validating...`. Which is printed before checking for the password, with thi information we can guess that the next function is used to check if the password is correct.

I check the function `sub_1400020a0`. And in this function is just the strings that will be printed if you put the correct password

![](assets/img/posts/reverse-ch-4/06.png)

With this we can also guess that the only argument this function takes is the password. And in the past function we were analyzing the function `sub_1400020a0` or how I decided to name it `mw_correct` is called with the `arg1`. We rename the variables and I get this:

```cpp
class std::basic_ostream<char,struct std::char_traits<char> >* mw_logic(int64_t* password) {
    ...
}
```

The only place where this function is called is in `main`. So we go back to that function and see this, which makes a little bit more sense now.

![](assets/img/posts/reverse-ch-4/07.png)

We can see the use of the variable `password` and the string `NEXUS-MASTER-KEY-2025`. These are used in a function that seems to transform them into something else, but I decide to try the string I found as input and...

![](assets/img/posts/reverse-ch-4/solved.png)

We get the password.
