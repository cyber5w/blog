---
layout: post
title: Malware Analysis - How to bypass Anti-Debugging Tricks - part 1
---

Today, we will show how to bypass Anti-Debugging trick of our simple malware written in C/C++. There are different characteristics that serve as indicators that a malware analyst is conducting a manual inspection of the malicious application. Malware authors can avoid this by checking for these characteristics, which also impede the analyst's ability to reverse-engineer the malware code.     

### IsDebuggerPresent

For example anti-debugging techniques identify whether a program is being executed under the influence of a debugger. The function `IsDebuggerPresent()` is enabled via the kernel32.dll library. This function is frequently employed in malicious software to complicate reverse engineering, as it alters the program's flow when examined in a user-mode debugger, such as x32dbg, which is the most widely used anti-debugging method in Windows:    

```cpp
BOOL IsDebuggerPresent();
```

`IsDebuggerPresent` function basically checks `BeingDebugged` flag in the `PEB`:    

```cpp
// "ask" the OS if any debugger is present
if (IsDebuggerPresent()) {
  printf("attached debugger detected :(\n");
  return -2;
}
```

### Ok, how to bypass it? Practical example

Let's look an example. We will use a [sample]({{ site.baseurl }}/images/4/hack.exe.7z) of simple malware that uses this trick and use the [x32dbg or x64dbg](https://x64dbg.com/) debugger for Windows.    

First of all, let's try to debug it with debugger:      

![debug]({{ site.baseurl }}/images/4/2024-01-01_11-18.png)    

![debug]({{ site.baseurl }}/images/4/2024-01-01_11-20.png)    

After several steps we got a message and the malware stops its activity:    

![debug]({{ site.baseurl }}/images/4/2024-01-01_11-21.png)    

To bypass it, restart debugging, go to the `Symbols` tab:    

![debug]({{ site.baseurl }}/images/4/2024-01-01_11-25.png)    

and find `kernel32.dll`:    

![debug]({{ site.baseurl }}/images/4/2024-01-01_11-25_1.png)    

Find `IsDebuggerPresent`:    

![debug]({{ site.baseurl }}/images/4/2024-01-01_11-29.png)    

and press `F2` for setting Breakpoint:    

![debug]({{ site.baseurl }}/images/4/2024-01-01_11-30.png)    

At the next step, restart program in the debugger. While running the program, await the program halt for this operation code:    

![debug]({{ site.baseurl }}/images/4/2024-01-01_11-36.png)    

Step over (Press `F8`, This allows you to execute an entire subroutine or repeat instruction without stepping through it instruction by instruction), until you return to the given code.    

![debug]({{ site.baseurl }}/images/4/2024-01-01_11-46.png)    

Be cautious that the output of `IsDebuggerPresent` is saved in `eax` if you search for something like `test eax,eax` followed by `je jnz` or similar.

![debug]({{ site.baseurl }}/images/4/2024-01-01_11-51.png)    

That is straightforward logic: the debugger detection alerted if the return value is `1` and is stored in `eax`. To evade `IsDebuggerPresent` detection, replace `je` with `jmp` press the space keyboard and `jmp` assembly. (process of patching):    

![debug]({{ site.baseurl }}/images/4/2024-01-01_11-59.png)    

1 - replace `je` to `jmp` instruction
2 - x32dbg say that instruction is successfully changed.    

At the final step we must save patched application:    

![debug]({{ site.baseurl }}/images/4/2024-01-01_12-01.png)    

![debug]({{ site.baseurl }}/images/4/2024-01-01_12-02.png)    

![debug]({{ site.baseurl }}/images/4/2024-01-01_12-02_1.png)    

Save it to file `hack2.exe`. Let's check correctness of our patch. Open debugger and attach `hack2.exe`:    

![debug]({{ site.baseurl }}/images/4/2024-01-01_12-04.png)    

![debug]({{ site.baseurl }}/images/4/2024-01-01_12-04_1.png)    

Malware sample is successfully executed in the debugger and as we can see, we bypass `IsDebuggerPresent` Anti-debugging trick!    

We hope this post spreads awareness to the blue teamers of this interesting and useful technique, and adds a weapon to the Malware Analyst's arsenal. Also this post is useful for entry level cybersec specialists.     

### References

[IsDebuggerPresent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent)     
[x64dbg](https://x64dbg.com/)    

Thanks for your time happy hacking and good bye!   
*PS. All drawings and screenshots are Cyber 5W*    
