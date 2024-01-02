---
layout: post
title: Memory Forensics - Practical example, detect process injection
---

At times, following a system compromise, it becomes crucial to retrieve forensically significant data. RAM, being volatile, has a transient nature. With each system reboot, the memory in RAM is cleared. Consequently, if a computer is breached and subsequently restarted, substantial information detailing the sequence of events leading to the system compromise may be lost.    

![mem]({{ site.baseurl }}/images/5/2024-01-02_13-37.png)    

Today we will show in practice how to detect process injection via memory forensics. 

First of all, let's say we have a malware [sample]({{ site.baseurl }}/images/5/hack.exe.7z). For simulating process injection, just execute `notepad.exe` and run it in the victim's machine (Windows 7 x64 VM in my case):    

```powershell
.\hack.exe <notepad.exe PID>
```

![mem]({{ site.baseurl }}/images/5/2024-01-02_11-04.png)    

As you can see, everything is work perfectly. Shellcode successfully injected.    

Additionally, following the execution of our malicious operation, we proceeded to download [winpmem](https://winpmem.velocidex.com/) onto the targeted Windows 7 x64 machine. Subsequently, execute:    

```powershell
>.\winpmem_v3.3.rc3.exe --output mem.raw
```

### Analyse memory image

For analysing memory image we use Volatility3 framework. First of all obtaining the OS. Acquiring details about the operating system from the memory dump is a straightforward process. You can utilize the `windows.info.Info` plugin to retrieve information about the captured memory dump:    

```bash
python3 ./volatility3/vol.py -f ./mem.raw windows.info.Info
```

![mem]({{ site.baseurl }}/images/5/2024-01-02_11-16.png)    

![mem]({{ site.baseurl }}/images/5/2024-01-02_11-15.png)    

Following that, the `windows.pslist.PsList` plugin had been used to examine the processes that were active on the compromised computer during the memory capture:    

```bash
python3 ./volatility3/vol.py -f ./mem.raw windows.pslist.PsList
```

![mem]({{ site.baseurl }}/images/5/2024-01-02_11-16_1.png)    

![mem]({{ site.baseurl }}/images/5/2024-01-02_11-18.png)    

Looking at the list, `PID 1363` is `notepad.exe`, which is our victim process. Let's go to find injected code to this process. For finding hidden and injected code, just run:    

```bash
python3 ./volatility3/vol.py -f ./mem.raw windows.malfind.Malfind
```

![mem]({{ site.baseurl }}/images/5/2024-01-02_11-19.png)    

What do we see here? We see that several memory areas of different processes have the `PAGE_EXECUTE_READWRITE` property, which mean it's executable and readable. 

Note that, certain detection tools and antivirus engines have the capability to identify this memory area due to its unusual nature. It becomes conspicuous as the process requires memory that possesses simultaneous attributes of being readable, writable, and executable.    

![mem]({{ site.baseurl }}/images/5/2024-01-02_11-20.png)    

As you can see, we found memory section where `hack.exe` injected payload `fc 48 81....` to `notepad.exe`.    

![mem]({{ site.baseurl }}/images/5/2024-01-02_11-19_1.png)    

Ok, dump the process memory with `windows.memmap.Memmap` plugin:    

```powershell
python3 ./volatility3/vol.py -f ./mem.raw --output-dir ./dump/ windows.memmap.Memmap --pid 1968 --dump
```

![mem]({{ site.baseurl }}/images/5/2024-01-02_12-02.png)    

Finally, if we search our bytes `fc 48 81 e4`:    

![mem]({{ site.baseurl }}/images/5/2024-01-02_12-40.png)    

we found our payload bytes.    

We hope this post spreads awareness to the blue teamers of this interesting and useful tools, and can be good start for Digital Forensics path. Of course, also this post is useful for entry level cybersec specialists.     

### References

[https://github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)    
[https://github.com/Velocidex/WinPmem](https://github.com/Velocidex/WinPmem)    
[Cyber5W Intro to forensics](https://academy.cyber5w.com/collections/intro-to-forensics)    

Thanks for your time happy hacking and good bye!   
*PS. All drawings and screenshots are Cyber 5W*    


