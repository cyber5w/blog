---
layout: post
title:  Manually Unpacking Malware
image: "/images/unpack/cover.png"
description: "A Walkthrough of one of the most used unpacking techniques"
tags: [Malware-Analysis, Reverse-Engineering] 
---

# Objectives

In this blog post, we will go through a famous packing technique which is the use of VirualAlloc and VirtualProtect to decrypt data in memory and execute it, and how to unpack it manually, we are going to apply it to **Death Ransomware** malware

# Introduction

What is packed malware?

packed malware refers to malicious software that has been compressed and/or encrypted to obfuscate its code and make it more difficult to detect by antivirus or other security solutions.


# Static Analysis

Let's open the sample in DIE to see if it is packed or not

DIE is a tool that detects if the malware is packed or not. It does this by measuring the entropy of the file, which is a measure of randomness. If the data in a file is more random, it usually means that the file is packed.

When the entropy of a file is greater than 7, it generally indicates that the file is likely compressed or encrypted.

![](/images/unpack/image1.jpg)

Yeah It's packed

Let's see its imports in IDA

![](/images/unpack/image2.jpg)

**Virtual Alloc**, **Virtual protect** are not listed, but I think that the malware resolves them dynamically

As we can see the sample resolves **Virtual protect**

**VirtualAlloc** and **VirtualProtect** are two Windows API functions commonly used by the malware to unpack itself.

Malware uses **VirtualAlloc** to allocate memory for the unpacked malware code then uses **VirtualProtect** to change the protection to mark the memory allocated as executable, writable, or both to be able to execute the dynamically unpacked code.

![](/images/unpack/image3.jpg)

Let's open our sample into x64dbg

I'll put a breakpoint in **VirtualAlloc**

Press ctrl+g and write in the search bar "VirtualAlloc" and click ok.

To put a breakpoint in **VirtualAlloc** we need to click on the circle on the left side of the **VirtualAlloc** instruction 

Let's run the sample until we hit the breakpoint

![](/images/unpack/image4.jpg)

Let's go to the return of the function and step over it and follow **EAX** In a dump.

After stepping over some code there is some data written into the dump

![](/images/unpack/image5.jpg)

Let's run the debugger to hit the second **VirtualAlloc** function and do the same thing we did above.

After some stepping over we can see a loop. I'll put a breakpoint at the end of it.

![](/images/unpack/image6.jpg)

Let's run the malware

![](/images/unpack/image7.jpg)

A **PE** file is being written in the dump.

This is the final result

![](/images/unpack/image8.jpg)

Let's follow this in the memory map and dump it into a file

![](/images/unpack/image9.jpg)
![](/images/unpack/image10.jpg)

Let's see the dumped file in IDA

![](/images/unpack/image11.jpg)

The malware is successfully unpacked

{% highlight text %}
SHA256:ab828f0e0555f88e3005387cb523f221a1933bbd7db4f05902a1e5cc289e7ba4
{% endhighlight %}

This blog is authored by **Mostafa Farghaly(M4lcode)**.
