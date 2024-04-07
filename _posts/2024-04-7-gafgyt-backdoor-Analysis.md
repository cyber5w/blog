---
layout: post
title:  "Gafgyt Backdoor Analysis"
image: "/images/gafgyt/cover.png"
description: "Analysis of Gafgyt Backdoor"
tags: [Malware-Analysis, Reverse-Engineering] 
---
Experience Level required: Begineer 

# Objectives

In this report, we will conduct a comprehensive analysis of Gafgyt, which is an ELF malware. Our aim is to examine the malware's capabilities and determine its functions:
- DDoS Attack Capabilities
- Communication with Command and Control (C&C) Server
- Evade detection
- Network Setup and Configuration
- Process Manipulation


# Overview

Gafgyt malware, which is also known as Bashlite has targeted millions of vulnerable IoT devices in the last few years. Gafgyt is a Linux-based botnet.It receives commands from C2 server to perform multiple types of TCP and UDP DoS attacks

According to [Kaspersky](https://threats.kaspersky.com/) Gafgyt family is used for DDoS attacks and consists of ELF files controlled by C&C servers.

![](/images/gafgyt/image41.jpg)

It targets vulnerable Internet of Things (IoT) devices like Huawei routers, Realtek routers, and ASUS devices, which it then uses to launch large-scale distributed denial-of-service (DDoS) attacks.

# Static Analysis

Let's see the sample in VirusTotal

![](/images/gafgyt/image1.jpg)

Gafgyt contacts with URLs, domains, and potentially malicious IP addresses.

![](/images/gafgyt/image2.jpg)

Let's see its strings

{% highlight text %}
strings a9662b56d8409b4c022c5b3d3f0bcf00ea353220960191e3fe3cc239b874b3aa.elf
{% endhighlight %}

There are some interesting strings:

User agents for various browsers and devices

![](/images/gafgyt/image4.jpg)

**SendHTTP** can be used to send HTTP requests. 

Malware could use HTTP requests to communicate with command and control servers, download additional payloads, exfiltrate data, or perform other malicious activities over the internet.

![](/images/gafgyt/image5.jpg)

Let's see if the sample is packed or not. I'll use DIE

![](/images/gafgyt/image8.jpg)

DIE says that it's packed, but it's not always correct.

Let's see its functions

{% highlight text %}
gdb a9662b56d8409b4c022c5b3d3f0bcf00ea353220960191e3fe3cc239b874b3aa.elf
(gdb) info functions
{% endhighlight %}

![](/images/gafgyt/image6.jpg)

There are intriguing functions

# Behavioral Analysis
Let's run the sample to see what IPs the malware communicates with.

![](/images/gafgyt/image7.jpg)

I think we got the malware C2 server IP

{% highlight text %}
91.92.244.11:19302
{% endhighlight %}

Virus Total says that this ip address is malicious

![](/images/gafgyt/image40.jpg)

# Code Analysis

Let's open the sample in IDA

![](/images/gafgyt/image9.jpg)


## Network reconnaissance.

Next we have a function named by **getOurIP**. Let's see it.

![](/images/gafgyt/image12.jpg)

This function creates a UDP socket which is a communication endpoint that enables malware to send and receive data using the User Datagram Protocol (UDP). 

After that, it establishes a connection to Google DNS (8.8.8.8). This connection has a two-fold purpose: firstly, it serves as a means to ensure that the malware can successfully create outgoing network connections, and secondly, it allows the malware to send DNS queries, which can be used for various purposes.

Next, it retrieves the local socket's address and port by querying the operating system. Knowing the local IP address and port is crucial for the malware to identify the network interface through which it is communicating and to determine how other devices on the network can reach it.

Then it finds the default gateway, which is the network device responsible for transmitting traffic destined for external networks. By determining the default gateway, the malware gains information about the network topology and the path outgoing traffic takes to reach destinations outside the local network.

Finally, it extracts the default gateway's MAC address. By obtaining the MAC address of the default gateway, the malware gains additional information about the network infrastructure, which could be used for various purposes such as network reconnaissance or creating spoofed packets.

## Process Manipulation

Next the malwares creates a child process. The parent waits for the child to exit to exit also. Meanwhile the first child creates a second child process that will be the daemon process.

![](/images/gafgyt/image13.jpg)

The malware sets up the daemon process. First, the process is detached from the controlling terminal, its working directory is changed to the root directory, and a signal handler is set up to ignore the SIGPIPE signal.

![](/images/gafgyt/image14.jpg)

This is a setup process for a daemon process that has been created by malware. It ensures that the daemon process can operate independently without relying on any specific terminal or directory. Additionally, it handles certain signals to prevent unexpected terminations.


The next function sets up a socket connection with a server which is done by the following:

1. Specify the server's address and port number that the client wants to connect to.

2. Create a socket and initiate the connection request to the server.

3. Once the connection is established, data can be exchanged between the client and the server.

![](/images/gafgyt/image15.jpg)


## Information Gathering Functions:

**getArch()** function returns "x86_32", indicating that the system architecture is 32-bit x86. The result of this function is assigned to the variable **Arch** for later use in the malware's operation.

![](/images/gafgyt/image18.jpg)

Next we have **getPortz()**

![](/images/gafgyt/image16.jpg)

This function checks for the presence of certain executables (python, python3, perl, and telnetd) and returns the port number associated with SSH (22) if any of them are found. If none are found or if Telnet is not available, it returns "Unknown Port". The return value is assigned to "Portz".

**inet_ntoa(ourIP)** takes an IPv4 address in binary form (ourIP) and converts it into a string representation in standard dotted-decimal notation. This notation separates the four octets of the IPv4 address with periods, resulting in a human-readable IP address format.

For example, if ourIP is represented in binary form as "11000000101010000000101000000001", the function would convert it to the string "192.168.10.1" in dotted-decimal notation.

![](/images/gafgyt/image19.jpg)

## System Configuration

**UpdateNameSrvs** update the DNS resolver configuration file /etc/resolv.conf with Google's public DNS server addresses (8.8.8.8 and 8.8.4.4).

![](/images/gafgyt/image21.jpg)

**RemoveTempDirs** removes temporary directories and files, as well as terminate certain processes.

Processes to be terminated:

{% highlight text %}
badbox
busybox
perl
python
{% endhighlight %}

![](/images/gafgyt/image22.jpg)

It may be part of the malware's strategy to evade detection, remove competing malware, or ensure system stability for its own operation.

## Communication 

This function sends a formatted message over the socket **mainCommSock**. It includes the IP address stored in **v9**, the port stored in **Portz**, and the architecture stored in **Arch**. The text is displayed in bright magenta color.

![](/images/gafgyt/image20.jpg)

Then we have a loop that is responsible for handling communication with clients. It likely listens for incoming connections, receives commands from clients, processes these commands, and manages child processes as needed.

![](/images/gafgyt/image23.jpg)
![](/images/gafgyt/image24.jpg)

Now let's go to the last call **processCmd**

This part deals with network communication, specifically handling TCP and UDP connections.

![](/images/gafgyt/image25.jpg)
![](/images/gafgyt/image26.jpg)

## C&C Commands

TCP Command

- This command calls **ftcp** function that crafts and sends TCP packets with specified TCP flags set according to the provided a5 parameter.

UDP Command

- This command calls **SendUDP** function that crafts and sends UDP packets with a randomized sequence of payload data.

VSE Command

- This command calls **vseattack** function that sends the payload over the network, randomizes the destination IP address and computes and updates the checksum for the packet.

STDV3 Command

- This command calls **SendSTDV** function that generates a series of random hexadecimal values that  are accumulated and concatenated to form a payload. The payload is then presumably sent over the network using the socket.

UDPBYPASS Command

- This command calls **vseattack** and **astd** functions, **astd** sends data through the socket and connects to an address and it checks if a certain amount of time has passed since the start of the function and exits if so.

JUNK Command 

- This command calls **ajunk** function that manages multiple sockets, performs I/O operations, and handles errors in a networked environment.

LAYER3 Command 

- This command calls **aLAYER3** function that continuously sends data packets over a network while monitoring the elapsed time, and it terminates when the specified time limit is reached.

HOME Command

- This command calls **SendUDP** and **astd** functions

HOLD Command

- This command calls **ahold** function that manages network connections, including socket creation, data transmission, and reception, while also monitoring the elapsed time and terminating when necessary.

FORTNITE Command

- This command calls **rtcp** function that sends TCP packets to random IP addresses within a specified time frame or packet count. It may be used for network stress testing or other network-related tasks.

R6 Command

- This command calls **RandHex** function that generate a long hexadecimal values.

ARK Command

- This command calls **RandHex** function

NULLROUTE Command

- This command calls **atcp** function that constructs an IP packet and sends the constructed packets.

VPN-BETA Command

- This command calls **rtcp** and **vpnattack** functions, **vpnattack** performs a DoS attack against a target host.

OVH-BETA Command

- This command calls **atcp** and **SendSTDV** functions

HANDSHAKE Command

- This command calls **atcp** and **ftcp** functions

XMAS Command

- This command calls **rtcp** function

SSH-KILL Command

- This command calls **rtcp** and **aLAYER3** functions

KILLALLV7 Command

- This command calls **rtcp**, **ftcp**, **atcp** and **astd** functions

CRUSH Command

- This command calls **atcp** and **SendSTDV** functions

STOMP Command

- This command calls **audp**, **atcp**, and **SendSTD_HEX** functions

  - **audp** is designed to flood a target host with network packets, either using UDP or TCP protocol, depending on the specified protocol type.
  - **SendSTD_HEX** sends hexadecimal data over a socket. 

HEX Command

- This command calls **astd** function

HTTP Command

- This command calls **SendHTTP** function that sends HTTP requests using the provided HTTP method, target host, URI, and a randomly selected user agent to a server

STOP Command

- This command calls **kill** function that sends a kill signal to the process identified by the PID.

CLEAN Command

- This command removes temporary directories and files, as well as terminate certain processes and sends HTTP requests based on input parameters.

## User Agents

<details>
  <summary>Click to expand</summary>
  
  <!-- Your long string goes here -->
Opera/9.25 (Windows NT 5.1; U; lt)<br>
Opera/9.24 (X11; Linux i686; U; en)<br>
Opera/9.24 (X11; SunOS i86pc; U; en)<br>
Opera/9.25 (Macintosh; Intel Mac OS X; U; en)<br>
Opera/9.25 (Macintosh; PPC Mac OS X; U; en)<br>
Opera/9.25 (OpenSolaris; U; en)<br>
Opera/9.25 (Windows NT 4.0; U; en)<br>
Opera/9.25 (Windows NT 5.0; U; cs)<br>
Opera/9.25 (Windows NT 5.0; U; de)<br>
Opera/9.25 (Windows NT 5.0; U; en)<br>
Opera/9.25 (Windows NT 5.1; U; MEGAUPLOAD 1.0; pt-br)<br>
Opera/9.25 (Windows NT 5.1; U; de)<br>
Opera/9.25 (Windows NT 5.1; U; en)<br>
Opera/9.24 (X11; Linux i686; U; de)<br>
Opera/9.25 (Windows NT 5.1; U; ru)<br>
Opera/9.25 (Windows NT 5.1; U; zh-cn)<br>
Opera/9.25 (Windows NT 5.2; U; de)<br>
Opera/9.25 (Windows NT 5.2; U; en)<br>
Opera/9.25 (Windows NT 6.0; U; MEGAUPLOAD 1.0; ru)<br>
Opera/9.25 (Windows NT 6.0; U; SV1; MEGAUPLOAD 2.0; ru)<br>
Opera/9.25 (Windows NT 6.0; U; de)<br>
Opera/9.25 (Windows NT 6.0; U; en)<br>
Opera/9.25 (Windows NT 6.0; U; en-US)<br>
Opera/9.25 (Windows NT 6.0; U; ru)<br>
Opera/9.25 (Windows NT 6.0; U; sv)<br>
Opera/9.25 (X11; Linux i686; U; en)<br>
Opera/9.23 (Windows NT 5.1; U; zh-cn)<br>
Opera/9.23 (Windows ME; U; de)<br>
Opera/9.23 (Windows NT 5.0; U; de)<br>
Opera/9.23 (Windows NT 5.0; U; en)<br>
Opera/9.23 (Windows NT 5.1; U; SV1; MEGAUPLOAD 1.0; ru)<br>
Opera/9.23 (Windows NT 5.1; U; da)<br>
Opera/9.23 (Windows NT 5.1; U; de)<br>
Opera/9.23 (Windows NT 5.1; U; en)<br>
Opera/9.23 (Windows NT 5.1; U; fi)<br>
Opera/9.23 (Windows NT 5.1; U; it)<br>
Opera/9.23 (Windows NT 5.1; U; ja)<br>
Opera/9.23 (Windows NT 5.1; U; pt)<br>
Opera/9.23 (Windows NT 5.1; U; ru)<br>
Opera/9.25 (X11; Linux i686; U; fr)<br>
Opera/9.23 (Windows NT 5.2; U; en)<br>
Opera/9.23 (Windows NT 6.0; U; de)<br>
Opera/9.23 (X11; Linux i686; U; en)<br>
Opera/9.23 (X11; Linux i686; U; es-es)<br>
Opera/9.23 (X11; Linux x86_64; U; en)<br>
Opera/9.24 (Macintosh; PPC Mac OS X; U; en)<br>
Opera/9.24 (Windows NT 5.0; U; ru)<br>
Opera/9.24 (Windows NT 5.1; U; de)<br>
Opera/9.24 (Windows NT 5.1; U; ru)<br>
Opera/9.24 (Windows NT 5.1; U; tr)<br>
Opera/9.24 (Windows NT 6.0; U; de)<br>
Opera/9.24 (X11; FreeBSD 5 i386; U; de)<br>
Opera/9.50 (Windows NT 5.1; U; en)<br>
Opera/9.30 (Nintendo Wii; U; ; 2047-7;pt-br)<br>
Opera/9.30 (Nintendo Wii; U; ; 2071; Wii Shop Channel/1.0; en)<br>
Opera/9.30 (Nintendo Wii; U; ; 3642; de)<br>
Opera/9.5 (Windows NT 5.1; U; fr)<br>
Opera/9.5 (Windows NT 6.0; U; en)<br>
Opera/9.5 (X11; U; pt)<br>
Opera/9.50 (J2ME/MIDP; Opera Mini/4.0.10031/230; U; en)<br>
Opera/9.50 (J2ME/MIDP; Opera Mini/4.0.10031/298; U; en)<br>
Opera/9.50 (J2ME/MIDP; Opera Mini/4.1.10781/298; U; en)<br>
Opera/9.50 (Macintosh; Intel Mac OS X; U; de)<br>
Opera/9.50 (Macintosh; Intel Mac OS X; U; en)<br>
Opera/9.50 (Windows NT 5.1; U; de)<br>
Opera/9.30 (Nintendo Wii; U; ; 2047-7;es)<br>
Opera/9.50 (Windows NT 5.1; U; es-ES)<br>
Opera/9.50 (Windows NT 5.1; U; it)<br>
Opera/9.50 (Windows NT 5.1; U; nl)<br>
Opera/9.50 (Windows NT 5.1; U; nn)<br>
Opera/9.50 (Windows NT 5.1; U; ru)<br>
Opera/9.50 (Windows NT 5.2; U; it)<br>
Opera/9.50 (Windows NT 6.0; U; de)<br>
Opera/9.50 (Windows NT 6.0; U; en)<br>
Opera/9.50 (X11; Linux i686; U; en)<br>
Opera/9.50 (X11; Linux i686; U; es-ES)<br>
Opera/9.50 (X11; Linux ppc; U; en)<br>
Opera/9.50 (X11; Linux x86_64; U; nb)<br>
Opera/9.26 (Windows; U; pl)<br>
Opera/9.25 (X11; Linux i686; U; fr-ca)<br>
Opera/9.25 (compatible; U; en)<br>
Opera/9.26 (Macintosh; PPC Mac OS X; U; en)<br>
Opera/9.26 (Windows 98; U; de)<br>
Opera/9.26 (Windows NT 5.1; U; MEGAUPLOAD 2.0; en)<br>
Opera/9.26 (Windows NT 5.1; U; de)<br>
Opera/9.26 (Windows NT 5.1; U; en)<br>
Opera/9.26 (Windows NT 5.1; U; nl)<br>
Opera/9.26 (Windows NT 5.1; U; pl)<br>
Opera/9.26 (Windows NT 5.1; U; ru)<br>
Opera/9.26 (Windows NT 5.1; U; zh-cn)<br>
Opera/9.26 (Windows NT 6.0; U; de)<br>
Opera/9.23 (Nintendo Wii; U; ; 1038-58; Wii Internet Channel/1.0; en)<br>
Opera/9.27 (Macintosh; Intel Mac OS X; U; sv)<br>
Opera/9.27 (Windows NT 5.1; U; de)<br>
Opera/9.27 (Windows NT 5.1; U; ja)<br>
Opera/9.27 (Windows NT 5.2; U; en)<br>
Opera/9.27 (Windows NT 6.0; U; de)<br>
Opera/9.27 (X11; Linux i686; U; en)<br>
Opera/9.27 (X11; Linux i686; U; fr)<br>
Opera/9.30 (Nintendo Wii; U; ; 2047-7; de)<br>
Opera/9.30 (Nintendo Wii; U; ; 2047-7; en)<br>
Opera/9.30 (Nintendo Wii; U; ; 2047-7; fr)<br>
Opera/9.30 (Nintendo Wii; U; ; 2047-7;en)<br>
Opera/9.10 (X11; Linux x86_64; U; en)<br>
Opera/9.10 (Windows NT 5.1; U; pl) Presto/9.9.9<br>
Opera/9.10 (Windows NT 5.1; U; pt)<br>
Opera/9.10 (Windows NT 5.1; U; sv)<br>
Opera/9.10 (Windows NT 5.1; U; zh-tw)<br>
Opera/9.10 (Windows NT 5.2; U; de)<br>
Opera/9.10 (Windows NT 5.2; U; en)<br>
Opera/9.10 (Windows NT 6.0; U; en)<br>
Opera/9.10 (Windows NT 6.0; U; it-IT)<br>
Opera/9.10 (X11; Linux i386; U; en)<br>
Opera/9.10 (X11; Linux i686; U; en)<br>
Opera/9.10 (X11; Linux i686; U; kubuntu;pl)<br>
Opera/9.10 (X11; Linux i686; U; pl)<br>
Opera/9.10 (Windows NT 5.1; U; pl)<br>
Opera/9.10 (X11; Linux; U; en)<br>
Opera/9.12 (Windows NT 5.0; U)<br>
Opera/9.12 (Windows NT 5.0; U; ru)<br>
Opera/9.12 (X11; Linux i686; U; en) (Ubuntu)<br>
Opera/9.141 (Windows NT 6.0; U; nl) Presto/171.831.131 Version/801.361<br>
Opera/9.20 (Windows NT 5.1; U; MEGAUPLOAD=1.0; es-es)<br>
Opera/9.20 (Windows NT 5.1; U; de)<br>
Opera/9.20 (Windows NT 5.1; U; en)<br>
Opera/9.20 (Windows NT 5.1; U; es-AR)<br>
Opera/9.20 (Windows NT 5.1; U; es-es)<br>
Opera/9.20 (Windows NT 5.1; U; it)<br>
Opera/9.20 (Windows NT 5.1; U; nb)<br>
Opera/9.02 (X11; Linux i686; U; en)<br>
Opera/9.02 (Windows NT 5.1; U; fi)<br>
Opera/9.02 (Windows NT 5.1; U; ja)<br>
Opera/9.02 (Windows NT 5.1; U; nb)<br>
Opera/9.02 (Windows NT 5.1; U; pl)<br>
Opera/9.02 (Windows NT 5.1; U; pt-br)<br>
Opera/9.02 (Windows NT 5.1; U; ru)<br>
Opera/9.02 (Windows NT 5.1; U; zh-cn)<br>
Opera/9.02 (Windows NT 5.2; U; de)<br>
Opera/9.02 (Windows NT 5.2; U; en)<br>
Opera/9.02 (Windows XP; U; ru)<br>
Opera/9.02 (Windows; U; nl)<br>
Opera/9.02 (X11; Linux i686; U; de)<br>
Opera/9.20 (Windows NT 5.1; U; zh-tw)<br>
Opera/9.02 (X11; Linux i686; U; hu)<br>
Opera/9.02 (X11; Linux i686; U; pl)<br>
Opera/9.10 (Nintendo Wii; U; ; 1621; en)<br>
Opera/9.10 (Windows NT 5.1; U; MEGAUPLOAD 1.0; pl)<br>
Opera/9.10 (Windows NT 5.1; U; de)<br>
Opera/9.10 (Windows NT 5.1; U; en)<br>
Opera/9.10 (Windows NT 5.1; U; es-es)<br>
Opera/9.10 (Windows NT 5.1; U; fi)<br>
Opera/9.10 (Windows NT 5.1; U; hu)<br>
Opera/9.10 (Windows NT 5.1; U; it)<br>
Opera/9.10 (Windows NT 5.1; U; nl)<br>
Opera/9.22 (Windows NT 5.1; U; de)<br>
Opera/9.21 (Windows NT 5.1; U; pt-br)<br>
Opera/9.21 (Windows NT 5.1; U; ru)<br>
Opera/9.21 (Windows NT 5.2; U; en)<br>
Opera/9.21 (Windows NT 6.0; U; en)<br>
Opera/9.21 (Windows NT 6.0; U; en)Opera/9.21 (Windows NT 5.1; U; en)Opera/9.20 (X11; Linux i686; U; ru)Opera/9.20 (Windows NT 5.2; U; en)Opera/9.20 (Windows NT 5.1; U; it)<br>
Opera/9.21 (Windows NT 6.0; U; nb)<br>
Opera/9.21 (X11; Linux i686; U; de)<br>
Opera/9.21 (X11; Linux i686; U; en)<br>
Opera/9.21 (X11; Linux i686; U; es-es)<br>
Opera/9.21 (X11; Linux x86_64; U; en)<br>
Opera/9.22 (Windows NT 5.1; U; SV1; MEGAUPLOAD 1.0; ru)<br>
Opera/9.22 (Windows NT 5.1; U; SV1; MEGAUPLOAD 2.0; ru)<br>
Opera/9.21 (Windows NT 5.1; U; pl)<br>
Opera/9.22 (Windows NT 5.1; U; en)<br>
Opera/9.22 (Windows NT 5.1; U; fr)<br>
Opera/9.22 (Windows NT 5.1; U; pl)<br>
Opera/9.22 (Windows NT 5.2; U; SV1; Alexa Toolbar; pl)<br>
Opera/9.22 (Windows NT 6.0; U; en)<br>
Opera/9.22 (Windows NT 6.0; U; ru)<br>
Opera/9.22 (X11; Linux i686; U; de)<br>
Opera/9.22 (X11; Linux i686; U; en)<br>
Opera/9.22 (X11; OpenBSD i386; U; en)<br>
Opera/9.23 (Mac OS X; fr)<br>
Opera/9.23 (Mac OS X; ru)<br>
Opera/9.23 (Macintosh; Intel Mac OS X; U; ja)<br>
Opera/9.20 (X11; Linux x86_64; U; en)<br>
Opera/9.20 (Windows NT 5.2; U; en)<br>
Opera/9.20 (Windows NT 6.0; U; de)<br>
Opera/9.20 (Windows NT 6.0; U; en)<br>
Opera/9.20 (Windows NT 6.0; U; en),<br>
Opera/9.20 (Windows NT 6.0; U; es-es)<br>
Opera/9.20 (X11; Linux i586; U; en)<br>
Opera/9.20 (X11; Linux i686; U; en)<br>
Opera/9.20 (X11; Linux i686; U; es-es)<br>
Opera/9.20 (X11; Linux i686; U; pl)<br>
Opera/9.20 (X11; Linux i686; U; ru)<br>
Opera/9.20 (X11; Linux i686; U; tr)<br>
Opera/9.20 (X11; Linux ppc; U; en)<br>
Opera/9.50 (X11; Linux x86_64; U; pl)<br>
Opera/9.20(Windows NT 5.1; U; en)<br>
Opera/9.21 (Macintosh; Intel Mac OS X; U; en)<br>
Opera/9.21 (Macintosh; PPC Mac OS X; U; en)<br>
Opera/9.21 (Windows 98; U; en)<br>
Opera/9.21 (Windows NT 5.0; U; de)<br>
Opera/9.21 (Windows NT 5.1; U; MEGAUPLOAD 1.0; en)<br>
Opera/9.21 (Windows NT 5.1; U; SV1; MEGAUPLOAD 1.0; ru)<br>
Opera/9.21 (Windows NT 5.1; U; de)<br>
Opera/9.21 (Windows NT 5.1; U; en)<br>
Opera/9.21 (Windows NT 5.1; U; fr)<br>
Opera/9.21 (Windows NT 5.1; U; nl)<br>
Opera/9.64 (Windows NT 6.0; U; zh-cn) Presto/2.1.1<br>
Opera/9.63 (X11; Linux x86_64; U; cs) Presto/2.1.1<br>
Opera/9.63 (X11; Linux x86_64; U; ru) Presto/2.1.1<br>
Opera/9.63 (X11; U; nb)<br>
Opera/9.64 (Macintosh; Intel Mac OS X; U; de) Presto/2.1.1<br>
Opera/9.64 (Macintosh; Intel Mac OS X; U; en) Presto/2.1.1<br>
Opera/9.64 (Windows NT 5.0; U; de) Presto/2.1.1<br>
Opera/9.64 (Windows NT 5.1; U; de) Presto/2.1.1<br>
Opera/9.64 (Windows NT 5.1; U; en) Presto/2.1.1<br>
Opera/9.64 (Windows NT 6.0; U; de) Presto/2.1.1<br>
Opera/9.64 (Windows NT 6.0; U; en) Presto/2.1.1<br>
Opera/9.64 (Windows NT 6.0; U; pl) Presto/2.1.1<br>
Opera/9.64 (Windows NT 6.0; U; pt) Presto/2.1.1<br>
Opera/9.63 (X11; Linux i686; U; ru) Presto/2.1.1<br>
Opera/9.64 (Windows NT 6.1; U; MRA 5.5 (build 02842); ru) Presto/2.1.1<br>
Opera/9.64 (Windows NT 6.1; U; de) Presto/2.1.1<br>
Opera/9.64 (X11; Linux i686; U; Linux Mint; it) Presto/2.1.1<br>
Opera/9.64 (X11; Linux i686; U; Linux Mint; nb) Presto/2.1.1<br>
Opera/9.64 (X11; Linux i686; U; da) Presto/2.1.1<br>
Opera/9.64 (X11; Linux i686; U; de) Presto/2.1.1<br>
Opera/9.64 (X11; Linux i686; U; en) Presto/2.1.1<br>
Opera/9.64 (X11; Linux i686; U; nb) Presto/2.1.1<br>
Opera/9.64 (X11; Linux i686; U; pl) Presto/2.1.1<br>
Opera/9.64 (X11; Linux i686; U; sv) Presto/2.1.1<br>
Opera/9.64 (X11; Linux i686; U; tr) Presto/2.1.1<br>
Opera/9.64 (X11; Linux x86_64; U; cs) Presto/2.1.1<br>
Opera/9.63 (Windows NT 6.0; U; pl) Presto/2.1.1<br>
Opera/9.62 (X11; Linux x86_64; U; ru) Presto/2.1.1<br>
Opera/9.63 (Macintosh; Intel Mac OS X; U; de) Presto/2.1.1<br>
Opera/9.63 (Windows NT 5.1; U; de) Presto/2.1.1<br>
Opera/9.63 (Windows NT 5.1; U; en) Presto/2.1.1<br>
Opera/9.63 (Windows NT 5.1; U; pt-BR) Presto/2.1.1<br>
Opera/9.63 (Windows NT 5.2; U; de) Presto/2.1.1<br>
Opera/9.63 (Windows NT 5.2; U; en) Presto/2.1.1<br>
Opera/9.63 (Windows NT 6.0; U; cs) Presto/2.1.1<br>
Opera/9.63 (Windows NT 6.0; U; de) Presto/2.1.1<br>
Opera/9.63 (Windows NT 6.0; U; en) Presto/2.1.1<br>
Opera/9.63 (Windows NT 6.0; U; fr) Presto/2.1.1<br>
Opera/9.63 (Windows NT 6.0; U; nb) Presto/2.1.1<br>
Opera/9.64 (X11; Linux x86_64; U; de) Presto/2.1.1<br>
Opera/9.63 (Windows NT 6.1; U; de) Presto/2.1.1<br>
Opera/9.63 (Windows NT 6.1; U; en) Presto/2.1.1<br>
Opera/9.63 (Windows NT 6.1; U; hu) Presto/2.1.1<br>
Opera/9.63 (X11; FreeBSD 7.1-RELEASE i386; U; en) Presto/2.1.1<br>
Opera/9.63 (X11; Linux i686)<br>
Opera/9.63 (X11; Linux i686; U; de) Presto/2.1.1<br>
Opera/9.63 (X11; Linux i686; U; en)<br>
Opera/9.63 (X11; Linux i686; U; en) Presto/2.1.1<br>
Opera/9.63 (X11; Linux i686; U; en-GB) Presto/2.1.1<br>
Opera/9.63 (X11; Linux i686; U; nb) Presto/2.1.1<br>
Opera/9.63 (X11; Linux i686; U; ru)<br>
Opera/9.80 (S60; SymbOS; Opera Mobi/499; U; en-GB) Presto/2.4.18 Version/10.00<br>
Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; en) Presto/2.9.168 Version/11.52<br>
Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52<br>
Opera/9.80 (Macintosh; Intel Mac OS X 10.7.2; U; ru) Presto/2.10.229 Version/11.60<br>
Opera/9.80 (Macintosh; Intel Mac OS X 10.7.3; U; en) Presto/2.10.229 Version/11.62<br>
Opera/9.80 (Macintosh; Intel Mac OS X 10.7.4; U; en) Presto/2.10.229 Version/11.62<br>
Opera/9.80 (Macintosh; Intel Mac OS X 10.7.4; U; ru) Presto/2.10.289 Version/12.00<br>
Opera/9.80 (Macintosh; Intel Mac OS X 10.9.5; U; en) Presto/2.10.229 Version/11.64<br>
Opera/9.80 (Macintosh; Intel Mac OS X; U; de) Presto/2.2.15 Version/10.10<br>
Opera/9.80 (Macintosh; Intel Mac OS X; U; en) Presto/2.2.15 Version/10.00<br>
Opera/9.80 (Macintosh; Intel Mac OS X; U; nl) Presto/2.6.30 Version/10.61<br>
Opera/9.80 (Macintosh; PPC Mac OS X; U; de) Presto/2.2.15 Version/10.10<br>
Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10<br>
Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; en) Presto/2.9.168 Version/11.51<br>
Opera/9.80 (S60; SymbOS; Opera Tablet/9174; U; en) Presto/2.7.81 Version/10.5<br>
Opera/9.80 (Windows 98; U; de) Presto/2.2.15 Version/10.10<br>
Opera/9.80 (Windows 98; U; de) Presto/2.6.30 Version/10.61<br>
Opera/9.80 (Windows NT 5.0; U; en) Presto/2.2.15 Version/10.20<br>
Opera/9.80 (Windows NT 5.1) Presto/2.12.388 Version/12.10<br>
Opera/9.80 (Windows NT 5.1) Presto/2.12.388 Version/12.11<br>
Opera/9.80 (Windows NT 5.1) Presto/2.12.388 Version/12.12<br>
Opera/9.80 (Windows NT 5.1) Presto/2.12.388 Version/12.14<br>
Opera/9.80 (Windows NT 5.1) Presto/2.12.388 Version/12.15<br>
Opera/9.80 (Windows NT 5.1) Presto/2.12.388 Version/12.16<br>
Opera/9.80 (Windows NT 5.1) Presto/2.12.388 Version/12.17<br>
Opera/9.80 (Windows NT 5.1; DepositFiles/FileManager 0.9.9.206 YB/5.0.3) Presto/2.12.388 Version/12.14<br>
Opera/9.80 (Android 3.2.1; Linux; Opera Tablet/ADR-1205181138; U; en-GB) Presto/2.10.254 Version/12.00<br>
Opera/9.64 (X11; Linux x86_64; U; en) Presto/2.1.1<br>
Opera/9.64 (X11; Linux x86_64; U; en-GB) Presto/2.1.1<br>
Opera/9.64 (X11; Linux x86_64; U; hr) Presto/2.1.1<br>
Opera/9.64 (X11; Linux x86_64; U; pl) Presto/2.1.1<br>
Opera/9.64(Windows NT 5.1; U; en) Presto/2.1.1<br>
Opera/9.70 (Linux i686 ; U;  ; en) Presto/2.2.1<br>
Opera/9.70 (Linux i686 ; U; ; en) Presto/2.2.1<br>
Opera/9.70 (Linux i686 ; U; en) Presto/2.2.0<br>
Opera/9.70 (Linux i686 ; U; en) Presto/2.2.1<br>
Opera/9.70 (Linux i686 ; U; en-us) Presto/2.2.0<br>
Opera/9.70 (Linux i686 ; U; zh-cn) Presto/2.2.0<br>
Opera/9.70 (Linux ppc64 ; U; en) Presto/2.2.1<br>
Opera/9.62 (X11; Linux x86_64; U; en_GB, en_US) Presto/2.1.1<br>
Opera/9.80 (Android 4.0.4; Linux; Opera Mobi/ADR-1301080958) Presto/2.11.355 Version/12.10<br>
Opera/9.80 (Android 4.1.2; Linux; Opera Mobi/ADR-1305251841) Presto/2.11.355 Version/12.10<br>
Opera/9.80 (J2ME/MIDP; Opera Mini/4.1.15082/22.414; U; en) Presto/2.5.25 Version/10.54<br>
Opera/9.80 (J2ME/MIDP; Opera Mini/5.0.16823/1428; U; en) Presto/2.2.0<br>
Opera/9.80 (J2ME/MIDP; Opera Mini/5.1.22296/22.414; U; en) Presto/2.5.25 Version/10.54<br>
Opera/9.80 (J2ME/MIDP; Opera Mini/6.0.24093/24.741; U; en) Presto/2.5.25 Version/10.54<br>
Opera/9.80 (J2ME/MIDP; Opera Mini/6.5.26955/26.1283; U; en) Presto/2.8.119 Version/10.54<br>
Opera/9.80 (J2ME/MIDP; Opera Mini/7.28870/27.1530; U; en)<br>
Opera/9.80 (Linux armv6l ; U; CE-HTML/1.0 NETTV/3.0.1;; en) Presto/2.6.33 Version/10.60<br>
Opera/9.80 (Linux i686; U; en) Presto/2.5.22 Version/10.51<br>
Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; de) Presto/2.9.168 Version/11.52<br>
Opera/9.52 (X11; Linux ppc; U; de)<br>
Opera/9.52 (Windows NT 5.0; U; en)<br>
Opera/9.52 (Windows NT 5.1; U; de)<br>
Opera/9.52 (Windows NT 5.1; U; en)<br>
Opera/9.52 (Windows NT 5.2; U; ru)<br>
Opera/9.52 (Windows NT 6.0; U; Opera/9.52 (X11; Linux x86_64; U); en)<br>
Opera/9.52 (Windows NT 6.0; U; de)<br>
Opera/9.52 (Windows NT 6.0; U; en)<br>
Opera/9.52 (Windows NT 6.0; U; fr)<br>
Opera/9.52 (Windows NT 6.0; U; ru)<br>
Opera/9.52 (X11; Linux i686; U; cs)<br>
Opera/9.52 (X11; Linux i686; U; en)<br>
Opera/9.52 (X11; Linux i686; U; fr)<br>
Opera/9.52 (Macintosh; PPC Mac OS X; U; ja)<br>
Opera/9.52 (X11; Linux x86_64; U)<br>
Opera/9.52 (X11; Linux x86_64; U; en)<br>
Opera/9.52 (X11; Linux x86_64; U; ru)<br>
Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.13337/504; U; en) Presto/2.2.0<br>
Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.13918/488; U; en) Presto/2.2.0<br>
Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15<br>
Opera/9.60 (Windows NT 5.0; U; en) Presto/2.1.1<br>
Opera/9.60 (Windows NT 5.1; U; de) Presto/2.1.1<br>
Opera/9.60 (Windows NT 5.1; U; en) Presto/2.1.1<br>
Opera/9.60 (Windows NT 5.1; U; en-GB) Presto/2.1.1<br>
Opera/9.60 (Windows NT 5.1; U; es-ES) Presto/2.1.1<br>
Opera/9.60 (Windows NT 5.1; U; sv) Presto/2.1.1<br>
Opera/9.51 (Windows NT 6.0; U; es)<br>
Opera/9.51 (Macintosh; Intel Mac OS X; U; en)<br>
Opera/9.51 (Windows NT 5.1; U; da)<br>
Opera/9.51 (Windows NT 5.1; U; de)<br>
Opera/9.51 (Windows NT 5.1; U; en)<br>
Opera/9.51 (Windows NT 5.1; U; en-GB)<br>
Opera/9.51 (Windows NT 5.1; U; es-AR)<br>
Opera/9.51 (Windows NT 5.1; U; es-LA)<br>
Opera/9.51 (Windows NT 5.1; U; fr)<br>
Opera/9.51 (Windows NT 5.1; U; nn)<br>
Opera/9.51 (Windows NT 5.2; U; en)<br>
Opera/9.51 (Windows NT 6.0; U; de)<br>
Opera/9.51 (Windows NT 6.0; U; en)<br>
Opera/9.60 (Windows NT 5.1; U; tr) Presto/2.1.1<br>
Opera/9.51 (Windows NT 6.0; U; sv)<br>
Opera/9.51 (Windows NT 6.1; U; ru)<br>
Opera/9.51 (X11; Linux i686; U; Linux Mint; en)<br>
Opera/9.51 (X11; Linux i686; U; de)<br>
Opera/9.51 (X11; Linux i686; U; fr)<br>
Opera/9.51 (X11; Linux x86_64; U; de)<br>
Opera/9.51 (X11; Linux x86_64; U; en)<br>
Opera/9.51 Beta (Microsoft Windows; PPC; Opera Mobi/1718; U; en)<br>
Opera/9.52 (Macintosh; Intel Mac OS X; U; pt)<br>
Opera/9.52 (Macintosh; Intel Mac OS X; U; pt-BR)<br>
Opera/9.52 (Macintosh; PPC Mac OS X; U; fr)<br>
Opera/9.62 (Windows NT 6.0; U; de) Presto/2.1.1<br>
Opera/9.61 (X11; Linux i686; U; pl) Presto/2.1.1<br>
Opera/9.61 (X11; Linux i686; U; ru) Presto/2.1.1<br>
Opera/9.61 (X11; Linux x86_64; U; en) Presto/2.1.1<br>
Opera/9.61 (X11; Linux x86_64; U; fr) Presto/2.1.1<br>
Opera/9.62 (Windows NT 5.1; U; de) Presto/2.1.1<br>
Opera/9.62 (Windows NT 5.1; U; pl) Presto/2.1.1<br>
Opera/9.62 (Windows NT 5.1; U; pt-BR) Presto/2.1.1<br>
Opera/9.62 (Windows NT 5.1; U; ru) Presto/2.1.1<br>
Opera/9.62 (Windows NT 5.1; U; tr) Presto/2.1.1<br>
Opera/9.62 (Windows NT 5.1; U; zh-cn) Presto/2.1.1<br>
Opera/9.62 (Windows NT 5.1; U; zh-tw) Presto/2.1.1<br>
Opera/9.62 (Windows NT 5.2; U; en) Presto/2.1.1<br>
Opera/9.61 (X11; Linux i686; U; en) Presto/2.1.1<br>
Opera/9.62 (Windows NT 6.0; U; en) Presto/2.1.1<br>
Opera/9.62 (Windows NT 6.0; U; en-GB) Presto/2.1.1<br>
Opera/9.62 (Windows NT 6.0; U; nb) Presto/2.1.1<br>
Opera/9.62 (Windows NT 6.0; U; pl) Presto/2.1.1<br>
Opera/9.62 (Windows NT 6.1; U; de) Presto/2.1.1<br>
Opera/9.62 (Windows NT 6.1; U; en) Presto/2.1.1<br>
Opera/9.62 (X11; Linux i686; U; Linux Mint; en) Presto/2.1.1<br>
Opera/9.62 (X11; Linux i686; U; de) Presto/2.1.1<br>
Opera/9.62 (X11; Linux i686; U; en) Presto/2.1.1<br>
Opera/9.62 (X11; Linux i686; U; fi) Presto/2.1.1<br>
Opera/9.62 (X11; Linux i686; U; it) Presto/2.1.1<br>
Opera/9.62 (X11; Linux i686; U; pt-BR) Presto/2.1.1<br>
Opera/9.61 (Windows NT 5.1; U; en-GB) Presto/2.1.1<br>
Opera/9.60 (Windows NT 6.0; U; bg) Presto/2.1.1<br>
Opera/9.60 (Windows NT 6.0; U; de) Presto/2.1.1<br>
Opera/9.60 (Windows NT 6.0; U; pl) Presto/2.1.1<br>
Opera/9.60 (Windows NT 6.0; U; ru) Presto/2.1.1<br>
Opera/9.60 (Windows NT 6.0; U; uk) Presto/2.1.1<br>
Opera/9.60 (X11; Linux i686; U; en-GB) Presto/2.1.1<br>
Opera/9.60 (X11; Linux i686; U; ru) Presto/2.1.1<br>
Opera/9.60 (X11; Linux x86_64; U)<br>
Opera/9.61 (Macintosh; Intel Mac OS X; U; de) Presto/2.1.1<br>
Opera/9.61 (Windows NT 5.1; U; cs) Presto/2.1.1<br>
Opera/9.61 (Windows NT 5.1; U; de) Presto/2.1.1<br>
Opera/9.61 (Windows NT 5.1; U; en) Presto/2.1.1<br>
Opera/9.02 (Windows NT 5.1; U; en)<br>
Opera/9.61 (Windows NT 5.1; U; fr) Presto/2.1.1<br>
Opera/9.61 (Windows NT 5.1; U; ru) Presto/2.1.1<br>
Opera/9.61 (Windows NT 5.1; U; zh-cn) Presto/2.1.1<br>
Opera/9.61 (Windows NT 5.1; U; zh-tw) Presto/2.1.1<br>
Opera/9.61 (Windows NT 5.2; U; de) Presto/2.1.1<br>
Opera/9.61 (Windows NT 5.2; U; en) Presto/2.1.1<br>
Opera/9.61 (Windows NT 6.0; U; en) Presto/2.1.1<br>
Opera/9.61 (Windows NT 6.0; U; http://lucideer.com; en-GB) Presto/2.1.1<br>
Opera/9.61 (Windows NT 6.0; U; pt-BR) Presto/2.1.1<br>
Opera/9.61 (Windows NT 6.0; U; ru) Presto/2.1.1<br>
Opera/9.61 (X11; Linux i686; U; de) Presto/2.1.1<br>
Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0<br>
NokiaN-Gage/1.0 SymbianOS/6.1 Series60/1.2 Profile/MIDP-1.0 Configuration/CLDC-1.0<br>
NokiaN70-1/5.0737.3.0.1 Series60/2.8 Profile/MIDP-2.0 Configuration/CLDC-1.1/UC Browser7.8.0.95/27/352<br>
NokiaN80-3/1.0552.0.7Series60/3.0Profile/MIDP-2.0Configuration/CLDC-1.1<br>
NokiaN90-1/3.0545.5.1 Series60/2.8 Profile/MIDP-2.0 Configuration/CLDC-1.1<br>
Opera 6.0[en]Nokia/Series-9300<br>
Opera 9.4 (Windows NT 5.3; U; en)<br>
Opera 9.4 (Windows NT 6.1; U; en)<br>
Opera 9.7 (Windows NT 5.2; U; en)<br>
Opera/10.00 (Windows NT 5.1; U; en) Presto/2.2.0<br>
Opera/10.00 (Windows NT 6.0; U; en) Presto/2.2.0<br>
Opera/10.00 (Windows NT 6.1; U; de) Presto/2.2.2<br>
Opera/10.00 (X11; Linux i686 ; U; en) Presto/2.2.0<br>
NokiaC3-00/5.0 (04.60) Profile/MIDP-2.1 Configuration/CLDC-1.1 Mozilla/5.0 AppleWebKit/420+ (KHTML, like Gecko) Safari/420+<br>
Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0,<br>
Opera/10.50 (Windows NT 6.1; U; en-GB) Presto/2.2.2<br>
Opera/10.60 (Windows NT 5.1; U; cs) Presto/2.6.30 Version/10.60<br>
Opera/10.60 (Windows NT 5.1; U; en-US) Presto/2.6.30 Version/10.60<br>
Opera/10.60 (Windows NT 5.1; U; zh-cn) Presto/2.6.30 Version/10.60<br>
Opera/12.0(Windows NT 5.1;U;en)Presto/22.9.168 Version/12.00<br>
Opera/12.0(Windows NT 5.2;U;en)Presto/22.9.168 Version/12.00<br>
Opera/12.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.02<br>
Opera/15.51 (X11; Linux i386; U; de)<br>
Opera/2.0.3920 (J2ME/MIDP; Opera Mini; en; U; ssr)<br>
Opera/4.02 (Windows 98; U) [en]<br>
Opera/5.0 (SunOS 5.8 sun4m; U) [en]<br>
Nokia5140/2.0 (3.10) Profile/MIDP-2.0 Configuration/CLDC-1.1<br>
Mozilla/7.0 (not compatible; MSIE 4.2; Linux LE 0.016; libwww-FM/2.14)<br>
Mozilla/8.0 (X11; Ubuntu; Linux x86_64; rv:15.0.1) Gecko/Chameleon Firefox/15.0.1<br>
Mozilla/8.0 (compatible; MSIE 9.0; Windows NT 8.2)<br>
Mozilla/9.0 (Windows; U; Windows 9; en; rv:1.9.1.7) Gecko/20091221 Firefox/2344.0.2<br>
Nokia2700c-2/2.0 (07.80) Profile/MIDP-2.1 Configuration/CLDC-1.1 nokia2700c-2/UC Browser7.7.1.88/69/444 UNTRUSTED/1.0<br>
Nokia2700c-2/2.0 (09.80) Profile/MIDP-2.1 Configuration/CLDC-1.1 UCWEB/2.0(Java; U; MIDP-2.0; en-US; nokia2700c-2) U2/1.0.0 UCBrowser/8.8.1.252 U2/1.0.0 Mobile<br>
Nokia2760/2.0 (06.82) Profile/MIDP-2.1 Configuration/CLDC-1.1<br>
Nokia3120Classic/2.0 (06.20) Profile/MIDP-2.1 Configuration/CLDC-1.1<br>
Nokia3200/1.0 (5.29) Profile/MIDP-1.0 Configuration/CLDC-1.0 UP.Link/6.3.1.13.0<br>
Nokia3510i/1.0 (04.44) Profile/MIDP-1.0 Configuration/CLDC-1.0<br>
Nokia3650/1.0 SymbianOS/6.1 Series60/1.2 Profile/MIDP-1.0 Configuration/CLDC-1.0<br>
Nokia5130c-2/2.0 (07.97) Profile/MIDP-2.1 Configuration/CLDC-1.1 nokia5130c-2/UC Browser7.5.1.77/69/351 UNTRUSTED/1.0<br>
Opera/5.0 (SunOS 5.8 sun4u; U)  [en]<br>
Nokia6212 classic/2.0 (06.20) Profile/MIDP-2.1 Configuration/CLDC-1.1<br>
Nokia6230/2.0+(04.43)+Profile/MIDP-2.0+Configuration/CLDC-1.1+UP.Link/6.3.0.0.0<br>
Nokia6600/1.0 (5.27.0) SymbianOS/7.0s Series60/2.0 Profile/MIDP-2.0 Configuration/CLDC-1<br>
Nokia6630/1.0 (2.3.129) SymbianOS/8.0 Series60/2.6 Profile/MIDP-2.0 Configuration/CLDC-1.1<br>
Nokia6680/1.0 (4.04.07) SymbianOS/8.0 Series60/2.6 Profile/MIDP-2.0 Configuration/CLDC-1.1<br>
Nokia6800/2.0 (4.17) Profile/MIDP-1.0 Configuration/CLDC-1.0 UP.Link/5.1.2.9<br>
Nokia7250/1.0 (3.14) Profile/MIDP-1.0 Configuration/CLDC-1.0<br>
Nokia7250I/1.0 (3.22) Profile/MIDP-1.0 Configuration/CLDC-1.0<br>
Nokia7610/2.0 (5.0509.0) SymbianOS/7.0s Series60/2.1 Profile/MIDP-2.0 Configuration/CLDC-1.0<br>
Nokia7610/2.0 (7.0642.0) SymbianOS/7.0s Series60/2.1 Profile/MIDP-2.0 Configuration/CLDC-1.0/UC Browser7.9.1.120/27/351/UCWEB<br>
Nokia8310/1.0 (05.11) UP.Link/6.5.0.0.06.5.0.0.06.5.0.0.06.5.0.0.0<br>
Opera/6.05 (Windows 2000; U)  [ja]<br>
Opera/6.03 (Windows NT 4.0; U)  [en]<br>
Opera/6.04 (Windows 2000; U)  [de]<br>
Opera/6.04 (Windows 2000; U)  [en]<br>
Opera/6.04 (Windows 98; U)  [en-GB]<br>
Opera/6.04 (Windows NT 4.0; U)  [de]<br>
Opera/6.04 (Windows NT 4.0; U)  [en]<br>
Opera/6.04 (Windows XP; U)  [de]<br>
Opera/6.04 (Windows XP; U)  [en]<br>
Opera/6.05 (Windows 2000; U)  [de]<br>
Opera/6.05 (Windows 2000; U)  [en]<br>
Opera/6.05 (Windows 2000; U)  [fr]<br>
Opera/6.05 (Windows 2000; U)  [it]<br>
Opera/6.03 (Windows 98; U) [en]<br>
Opera/6.05 (Windows 2000; U)  [oc]<br>
Opera/6.05 (Windows 98; U)  [de]<br>
Opera/6.05 (Windows 98; U)  [en]<br>
Opera/6.05 (Windows 98; U)  [fr]<br>
Opera/6.05 (Windows ME; U)  [de]<br>
Opera/6.05 (Windows ME; U)  [fr]<br>
Opera/6.05 (Windows NT 4.0; U)  [de]<br>
Opera/6.05 (Windows NT 4.0; U)  [fr]<br>
Opera/6.05 (Windows NT 4.0; U)  [ro]<br>
Opera/6.05 (Windows XP; U)  [de]<br>
Opera/6.05 (Windows XP; U)  [en]<br>
Opera/6.05 (Windows XP; U) [en]<br>
Opera/6.0 (Windows 2000; U) [fr]<br>
Opera/5.0 (Ubuntu; U; Windows NT 6.1; es; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13<br>
Opera/5.02 (Macintosh; U; id)<br>
Opera/5.02 (Windows 98; U)  [en]<br>
Opera/5.02 (Windows NT 5.0; U) [en]<br>
Opera/5.11 (Windows 98; U)  [en]<br>
Opera/5.11 (Windows 98; U) [en]<br>
Opera/5.12 (Windows 98; U)  [en]<br>
Opera/5.12 (Windows 98; U) [en]<br>
Opera/5.12 (Windows NT 5.1; U)  [de]<br>
Opera/6.0 (Macintosh; PPC Mac OS X; U)<br>
Opera/6.0 (Windows 2000; U)  [de]<br>
Opera/6.0 (Windows 2000; U)  [fr]<br>
Mozilla/7.0 (compatible; MSIE 10.0; Linux 2.6.26.-1-amd64) Lobo/0.98.3<br>
Opera/6.0 (Windows ME; U)  [de]<br>
Opera/6.0 (Windows XP; U)  [de]<br>
Opera/6.01 (Windows 2000; U)  [de]<br>
Opera/6.01 (Windows 2000; U)  [en]<br>
Opera/6.01 (Windows 98; U)  [de]<br>
Opera/6.01 (Windows 98; U)  [en]<br>
Opera/6.01 (Windows XP; U)  [de]<br>
Opera/6.01 (X11; U; nn)<br>
Opera/6.02 (Windows NT 4.0; U)  [de]<br>
Opera/6.03 (Linux 2.4.18-18.7.x i686; U)  [en]<br>
Opera/6.03 (Windows 2000; U)  [en]<br>
Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0<br>
Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 (KHTML, like Gecko) NX/3.0.4.2.12 NintendoBrowser/4.3.1.11264.US<br>
Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0<br>
Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)<br>
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00<br>
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00<br>
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00<br>
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; cn) Opera 11.00<br>
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00<br>
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36<br>
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FSL 7.0.6.01001)<br>
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FSL 7.0.7.01001)<br>
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FSL 7.0.5.01003)<br>
Mozilla/5.0 (iPad; U; CPU OS 5_1 like Mac OS X) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B367 Safari/531.21.10 UCBrowser/3.4.3.532<br>
Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.9.2.8) Gecko/20100723 Ubuntu/10.04 (lucid) Firefox/3.6.8<br>
Mozilla/5.0 (Windows NT 5.1; rv:13.0) Gecko/20100101 Firefox/13.0.1<br>
Mozilla/5.0 (Windows NT 6.1; WOW64; rv:11.0) Gecko/20100101 Firefox/11.0<br>
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.0.3705)<br>
Mozilla/5.0 (Windows NT 6.1; WOW64; rv:13.0) Gecko/20100101 Firefox/13.0.1<br>
Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)<br>
Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)<br>
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)<br>
Opera/9.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.01<br>
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)<br>
Mozilla/5.0 (Windows NT 5.1; rv:5.0.1) Gecko/20100101 Firefox/5.0.1<br>
Mozilla/5.0 (Windows NT 6.1; rv:5.0) Gecko/20100101 Firefox/5.02<br>
Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36<br>
FAST-WebCrawler/3.6 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)<br>
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)<br>
TheSuBot/0.2 (www.thesubot.de)<br>
Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16<br>
BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)<br>
Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201<br>
FAST-WebCrawler/3.7 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)<br>
Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1<br>
zspider/0.9-dev http://feedback.redkolibri.com/<br>
Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)<br>
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)<br>
Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51<br>
Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1<br>
Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3<br>
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194ABaiduspider+(+http://www.baidu.com/search/spider.htm)<br>
Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko<br>
Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko/20090327 Galeon/2.0.7<br>
Opera/9.80 (J2ME/MIDP; Opera Mini/5.0 (Windows; U; Windows NT 5.1; en) AppleWebKit/886; U; en) Presto/2.4.15<br>
Mozilla/5.0 (Android; Linux armv7l; rv:9.0) Gecko/20111216 Firefox/9.0 Fennec/9.0<br>
Mozilla/5.0 (iPhone; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10<br>
Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3)<br>
Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)<br>
Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5<br>
Opera/9.80 (Windows NT 5.1; U; en) Presto/2.10.229 Version/11.60<br>
Mozilla/6.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.27 Safari/532.0<br>
Mozilla/6.0 (Macintosh; I; Intel Mac OS X 11_7_9; de-LI; rv:1.9b4) Gecko/2012010317 Firefox/10.0a4<br>
Mozilla/6.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:2.0.0.0) Gecko/20061028 Firefox/3.0<br>
Mozilla/6.0 (Windows NT 6.1) Firefox/18.0<br>
Mozilla/6.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2062.122 Safari/537.36 OPR/24.0.1558.64<br>
Mozilla/6.0 (Windows NT 6.1; WOW64; rv:19.0.2) Firefox/19.0.2<br>
Mozilla/6.0 (Windows NT 6.2; WOW64; rv:16.0.1) Gecko/20121011 Firefox/16.0.1<br>
Mozilla/6.0 (Windows NT 6.2; WOW64; rv:18.0.1) Gecko/20121011 Firefox/18.0.1<br>
Mozilla/6.0 (Windows NT 6.5; rv:42.0) Gecko/20150302 Firefox/42.0<br>
Mozilla/6.0 (Windows; U; Windows NT 6.0; en-US) Gecko/2009032609 (KHTML, like Gecko) Chrome/2.0.172.6 Safari/530.7<br>
Mozilla/6.0 (Windows; U; Windows NT 6.0; en-US) Gecko/2009032609 Chrome/2.0.172.6 Safari/530.7<br>
Mozilla/6.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.0.8) Gecko/2009032609 Firefox/3.0.8<br>
Mozilla/6.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.0.8) Gecko/2009032609 Firefox/3.0.8 (.NET CLR 3.5.30729)<br>
Mozilla/6.0 (Future Star Technologies Corp. Star-Blade OS; U; en-US) iNet Browser 2.5<br>
Mozilla/6.0 (Windows; U; Windows NT 7.0; en-US; rv:1.9.0.8) Gecko/2009032609 Firefox/3.0.9 (.NET CLR 3.5.30729)<br>
Mozilla/6.0 (Windows; U; Windows NT 7.2; de;) Gecko/20083526 Firefox/2.0.0.5<br>
Mozilla/6.0 (X11; Linux x64_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.1.2403.125 Safari/537.36<br>
Mozilla/6.0 (X11; U; Linux x86_64; en-US; rv:2.9.0.3) Gecko/2009022510 FreeBSD/ Sunrise/4.0.1/like Safari<br>
Mozilla/6.0 (compatible)<br>
Mozilla/6.0 (compatible; KnuddelsForum-Welt.de; Version 8.2)<br>
Mozilla/6.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.0<br>
Mozilla/6.0 (compatible; MSIE 7.0a1; Windows NT 5.2; SV1)<br>
Mozilla/6.0 (compatible; MSIE 8.0; Windows 7)<br>
Mozilla/6.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/6.0; IAVC60-00000000; IAVC60-00000000; IAV80-00000000) Firefox/16.0.1<br>
Mozilla/6.8 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.7.4727.644 Safari/537.36<br>
Mozilla/7.0 (Windows NT 7.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.4.2311.135 Safari/537.36<br>
Mozilla/5.0 (Linux; Android 6.0.1; MI 4W Build/MMB29M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36<br>
Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 5.0) Opera 7.02 Bork-edition [en]<br>
Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36<br>
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36<br>
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36<br>
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36<br>
Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36<br>
Mozilla/5.0 (Linux; Android 6.0.1; Le X821 Build/FGXOSOP5801910121S) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.85 Mobile Safari/537.36<br>
Mozilla/5.0 (Linux; Android 6.0.1; Lenovo K33a48) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.83 Mobile Safari/537.36<br>
Mozilla/5.0 (Linux; Android 6.0.1; Lenovo TB-X103F Build/LenovoTB-X103F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36<br>
Mozilla/5.0 (Linux; Android 6.0.1; Lenovo TB-X103F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.83 Safari/537.36<br>
Mozilla/5.0 (Linux; Android 6.0.1; Lenovo TB-X103F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36<br>
Mozilla/5.0 (Linux; Android 6.0.1; M6SPlus Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.100 Mobile Safari/537.36<br>
Opera/6.11 (FreeBSD 4.7-RELEASE i386; U)  [en]<br>
Mozilla/5.0 (Linux; Android 6.0.1; MI 5 Build/MXB48T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.91 Mobile Safari/537.36<br>
Mozilla/5.0 (Linux; Android 6.0.1; MI 5s Plus Build/MXB48T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Mobile Safari/537.36<br>
Mozilla/5.0 (Linux; Android 6.0.1; OPPO A57 Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/63.0.3239.83 Mobile Safari/537.36 T7/11.0 baiduboxapp/11.0.0.11 (Baidu; P1 6.0.1)<br>
Mozilla/5.0 (Linux; Android 6.0.1; OPPO A57t Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/55.0.2883.91 Mobile Safari/537.36 rabbit/1.0 baiduboxapp/7.1 (Baidu; P1 6.0.1)<br>
Mozilla/5.0 (Linux; Android 6.0.1; OPPO A57t Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/63.0.3239.83 Mobile Safari/537.36 T7/11.5 baiduboxapp/11.5.0.10 (Baidu; P1 6.0.1)<br>
Mozilla/5.0 (Linux; Android 6.0.1; OPPO R9s Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/63.0.3239.83 Mobile Safari/537.36 T7/11.1 baiduboxapp/11.1.5.10 (Baidu; P1 6.0.1)<br>
Mozilla/5.0 (Linux; Android 6.0.1; OPPO R9s Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/63.0.3239.83 Mobile Safari/537.36 T7/11.7 baiduboxapp/11.7.0.10 (Baidu; P1 6.0.1)<br>
Mozilla/5.0 (Linux; Android 6.0.1; OPPO R9s Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/63.0.3239.83 Mobile Safari/537.36 T7/11.8 baiduboxapp/11.8.0.10 (Baidu; P1 6.0.1)<br>
Mozilla/5.0 (Linux; Android 6.0.1; OPPO R9sk Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/63.0.3239.83 Mobile Safari/537.36 T7/10.12 baiduboxapp/10.12.0.12 (Baidu; P1 6.0.1)<br>
Mozilla/5.0 (Linux; Android 6.0.1; OPPO R9sk Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/63.0.3239.83 Mobile Safari/537.36 T7/11.8 baiduboxapp/11.8.0.10 (Baidu; P1 6.0.1)<br>
Mozilla/5.0 (Linux; Android 6.0.1; OPPO R9st Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/63.0.3239.83 Mobile Safari/537.36 T7/11.8 baiduboxapp/11.8.0.10 (Baidu; P1 6.0.1)<br>
Opera/8.54 (Windows 98; U; en)<br>
Opera/8.52 (Windows NT 5.0; U; en)<br>
Opera/8.52 (Windows NT 5.1; U; en)<br>
Opera/8.52 (Windows NT 5.1; U; ru)<br>
Opera/8.52 (X11; Linux i386; U; de)<br>
Opera/8.52 (X11; Linux i686; U; en)<br>
Opera/8.52 (X11; Linux x86_64; U; en)<br>
Opera/8.53 (Windows 98; U; en)<br>
Opera/8.53 (Windows NT 5.0; U; en)<br>
Opera/8.53 (Windows NT 5.1; U; de)<br>
Opera/8.53 (Windows NT 5.1; U; en)<br>
Opera/8.53 (Windows NT 5.1; U; pt)<br>
Opera/8.53 (Windows NT 5.2; U; en)<br>
Opera/8.52 (Windows ME; U; en)<br>
Opera/8.54 (Windows NT 4.0; U; zh-cn)<br>
Opera/8.54 (Windows NT 5.0; U; de)<br>
Opera/8.54 (Windows NT 5.0; U; en)<br>
Opera/8.54 (Windows NT 5.1; U; de)<br>
Opera/8.54 (Windows NT 5.1; U; en)<br>
Opera/8.54 (Windows NT 5.1; U; pl)<br>
Opera/8.54 (Windows NT 5.1; U; ru)<br>
Opera/8.54 (X11; Linux i686; U; de)<br>
Opera/8.54 (X11; Linux i686; U; pl)<br>
Opera/9.0 (WinGogi; U; en)<br>
Opera/9.0 (Windows NT 5.0; U; en)<br>
Opera/9.0 (Windows NT 5.1; U; en)<br>
Opera/8.51 (Windows 98; U; en)<br>
Opera/8.50 (Windows NT 4.0; U; zh-cn)<br>
Opera/8.50 (Windows NT 5.0; U; de)<br>
Opera/8.50 (Windows NT 5.0; U; en)<br>
Opera/8.50 (Windows NT 5.0; U; fr)<br>
Opera/8.50 (Windows NT 5.1; U; de)<br>
Opera/8.50 (Windows NT 5.1; U; en)<br>
Opera/8.50 (Windows NT 5.1; U; es-ES)<br>
Opera/8.50 (Windows NT 5.1; U; fr)<br>
Opera/8.50 (Windows NT 5.1; U; pl)<br>
Opera/8.50 (Windows NT 5.1; U; ru)<br>
Opera/8.51 (FreeBSD 5.1; U; en)<br>
Opera/8.51 (Macintosh; PPC Mac OS X; U; de)<br>
Opera/9.00 (Macintosh; PPC Mac OS X; U; en)<br>
Opera/8.51 (Windows NT 5.0; U; en)<br>
Opera/8.51 (Windows NT 5.1; U; de)<br>
Opera/8.51 (Windows NT 5.1; U; en)<br>
Opera/8.51 (Windows NT 5.1; U; en;VWP-online.de)<br>
Opera/8.51 (Windows NT 5.1; U; fr)<br>
Opera/8.51 (Windows NT 5.1; U; nb)<br>
Opera/8.51 (Windows NT 5.1; U; pl)<br>
Opera/8.51 (X11; Linux i386; U; de)<br>
Opera/8.51 (X11; Linux i686; U; en)<br>
Opera/8.51 (X11; Linux x86_64; U; en)<br>
Opera/8.51 (X11; U; Linux i686; en-US; rv:1.8)<br>
Opera/9.01 (Windows NT 5.1; U; pl)<br>
Opera/9.01 (Macintosh; PPC Mac OS X; U; en)<br>
Opera/9.01 (Macintosh; PPC Mac OS X; U; it)<br>
Opera/9.01 (Windows NT 5.0; U; de)<br>
Opera/9.01 (Windows NT 5.0; U; en)<br>
Opera/9.01 (Windows NT 5.1)<br>
Opera/9.01 (Windows NT 5.1; U; bg)<br>
Opera/9.01 (Windows NT 5.1; U; cs)<br>
Opera/9.01 (Windows NT 5.1; U; da)<br>
Opera/9.01 (Windows NT 5.1; U; de)<br>
Opera/9.01 (Windows NT 5.1; U; en)<br>
Opera/9.01 (Windows NT 5.1; U; es-es)<br>
Opera/9.01 (Windows NT 5.1; U; ja)<br>
Opera/9.00 (X11; Linux i686; U; pl)<br>
Opera/9.01 (Windows NT 5.1; U; ru)<br>
Opera/9.01 (Windows NT 5.2; U; en)<br>
Opera/9.01 (Windows NT 5.2; U; ru)<br>
Opera/9.01 (X11; FreeBSD 6 i386; U; en)<br>
Opera/9.01 (X11; FreeBSD 6 i386; U;pl)<br>
Opera/9.01 (X11; Linux i686; U; en)<br>
Opera/9.01 (X11; OpenBSD i386; U; en)<br>
Opera/9.01 (X11; U; fr)<br>
Opera/9.02 (Windows NT 5.0; U; en)<br>
Opera/9.02 (Windows NT 5.0; U; pl)<br>
Opera/9.02 (Windows NT 5.0; U; sv)<br>
Opera/9.02 (Windows NT 5.1; U; de)<br>
Opera/9.00 (Windows NT 5.1; U; it)<br>
Opera/9.00 (Macintosh; PPC Mac OS X; U; es)<br>
Opera/9.00 (Nintendo Wii; U; ; 1038-58; Wii Internet Channel/1.0; en)<br>
Opera/9.00 (Nintendo Wii; U; ; 1309-9; en)<br>
Opera/9.00 (Wii; U; ; 1038-58; Wii Shop Channel/1.0; en)<br>
Opera/9.00 (Windows NT 4.0; U; en)<br>
Opera/9.00 (Windows NT 5.0; U; en)<br>
Opera/9.00 (Windows NT 5.1; U; da)<br>
Opera/9.00 (Windows NT 5.1; U; de)<br>
Opera/9.00 (Windows NT 5.1; U; en)<br>
Opera/9.00 (Windows NT 5.1; U; es-es)<br>
Opera/9.00 (Windows NT 5.1; U; fi)<br>
Opera/9.00 (Windows NT 5.1; U; fr)<br>
Opera/8.50 (Windows ME; U; en)<br>
Opera/9.00 (Windows NT 5.1; U; ja)<br>
Opera/9.00 (Windows NT 5.1; U; nl)<br>
Opera/9.00 (Windows NT 5.1; U; pl)<br>
Opera/9.00 (Windows NT 5.1; U; ru)<br>
Opera/9.00 (Windows NT 5.2; U; en)<br>
Opera/9.00 (Windows NT 5.2; U; pl)<br>
Opera/9.00 (Windows NT 5.2; U; ru)<br>
Opera/9.00 (Windows NT 6.0; U; en)<br>
Opera/9.00 (Windows; U)<br>
Opera/9.00 (X11; Linux i686; U; de)<br>
Opera/9.00 (X11; Linux i686; U; en)<br>
Opera/7.11 (Windows NT 5.1; U)  [en]<br>
Opera/7.03 (Windows NT 5.1; U)  [de]<br>
Opera/7.03 (Windows NT 5.1; U)  [en]<br>
Opera/7.10 (Linux Debian;en-US)<br>
Opera/7.10 (Windows NT 4.0; U)  [de]<br>
Opera/7.10 (Windows NT 5.0; U)  [en]<br>
Opera/7.10 (Windows NT 5.1; U)  [en]<br>
Opera/7.11 (Linux 2.6.0-test4 i686; U)  [en]<br>
Opera/7.11 (Windows 98; U)  [de]<br>
Opera/7.11 (Windows 98; U)  [en]<br>
Opera/7.11 (Windows NT 5.0; U)  [de]<br>
Opera/7.11 (Windows NT 5.0; U)  [en]<br>
Opera/7.11 (Windows NT 5.1; U)  [de]<br>
Opera/7.03 (Windows NT 5.0; U) [en]<br>
Opera/7.11 (Windows NT 5.1; U)  [pl]<br>
Opera/7.11 (Windows NT 5.1; U) [en]<br>
Opera/7.20 (Windows NT 5.1; U)  [en]<br>
Opera/7.21 (Windows NT 5.1; U)  [en]<br>
Opera/7.22 (Windows NT 5.1; U)  [de]<br>
Opera/7.23 (Windows 98; U) [en]<br>
Opera/7.23 (Windows NT 5.0; U)  [en]<br>
Opera/7.23 (Windows NT 5.0; U)  [fr]<br>
Opera/7.23 (Windows NT 5.0; U) [en]<br>
Opera/7.23 (Windows NT 5.1; U; sv)<br>
Opera/7.23 (Windows NT 6.0; U)  [zh-cn]<br>
Opera/7.50 (Windows NT 5.1; U)  [en]<br>
Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)<br>
Opera/6.11 (Linux 2.4.10-4GB i686; U)  [en]<br>
Opera/6.11 (Linux 2.4.18-4GB i686; U)  [en]<br>
Opera/6.11 (Linux 2.4.18-bf2.4 i686; U)  [en]<br>
Opera/6.12 (Linux 2.4.18-14cpq i686; U)  [en]<br>
Opera/6.12 (Linux 2.4.20-4GB i686; U)  [en]<br>
Opera/7.0 (SunOS 5.8 sun4m; U) [en]<br>
Opera/7.0 (Windows 2000; U)  [de]<br>
Opera/7.0 (Windows 2000; U)  [en]<br>
Opera/7.0 (Windows 98; U)  [en]<br>
Opera/7.0 (Windows NT 4.0; U)  [de]<br>
Opera/7.0 (Windows NT 4.0; U)  [en]<br>
Opera/7.0 (Windows NT 5.1; U)  [en]<br>
Opera/7.50 (Windows NT 5.1; U) [en]<br>
Opera/7.01 (Windows 98; U)  [en]<br>
Opera/7.01 (Windows 98; U)  [fr]<br>
Opera/7.01 (Windows NT 5.0; U)  [en]<br>
Opera/7.01 (Windows NT 5.1; U)  [en]<br>
Opera/7.02 (Windows 98; U)  [en]<br>
Opera/7.02 (Windows NT 5.1; U)  [fr]<br>
Opera/7.03 (Windows 98; U)  [de]<br>
Opera/7.03 (Windows 98; U)  [en]<br>
Opera/7.03 (Windows NT 4.0; U)  [en]<br>
Opera/7.03 (Windows NT 5.0; U)  [de]<br>
Opera/7.03 (Windows NT 5.0; U)  [en]<br>
Opera/8.01 (Windows NT 5.1)<br>
Opera/8.0 (X11; Linux i686; U; cs)<br>
Opera/8.0.1 (J2ME/MIDP; Opera Mini/3.1.9427/1724; en; U; ssr)<br>
Opera/8.00 (Windows NT 5.1; U; en)<br>
Opera/8.01 (J2ME/MIDP; Opera Mini/1.0.1479/HiFi; SonyEricsson P900; no; U; ssr)<br>
Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4062; en; U; ssr)<br>
Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4509/1316; fi; U; ssr)<br>
Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4509/1558; en; U; ssr)<br>
Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4719; en; U; ssr)<br>
Opera/8.01 (J2ME/MIDP; Opera Mini/3.0.6306/1528; en; U; ssr)<br>
Opera/8.01 (Macintosh; PPC Mac OS X; U; en)<br>
Opera/8.01 (Macintosh; U; PPC Mac OS; en)<br>
Opera/8.01 (Windows NT 5.0; U; de)<br>
Opera/8.0 (Windows NT 5.1; U; en)<br>
Opera/8.01 (Windows NT 5.1; U; de)<br>
Opera/8.01 (Windows NT 5.1; U; en)<br>
Opera/8.01 (Windows NT 5.1; U; fr)<br>
Opera/8.01 (Windows NT 5.1; U; pl)<br>
Opera/8.02 (Qt embedded; Linux armv4ll; U) [en] SONY/COM1<br>
Opera/8.02 (Windows NT 5.1; U; de)<br>
Opera/8.02 (Windows NT 5.1; U; en)<br>
Opera/8.02 (Windows NT 5.1; U; ru)<br>
Opera/8.10 (Windows NT 5.1; U; en)<br>
Opera/8.5 (X11; Linux i686; U; cs)<br>
Opera/8.50 (Windows 98; U; en)<br>
Opera/8.50 (Windows 98; U; ru)<br>
Opera/7.53 (X11; Linux i686; U) [en_US]<br>
Opera/7.50 (Windows XP; U)<br>
Opera/7.51 (Linux) [en]<br>
Opera/7.51 (Windows NT 5.0; U) [en]<br>
Opera/7.51 (Windows NT 5.1; U) [en]<br>
Opera/7.51 (Windows NT 5.1; U) [ru]<br>
Opera/7.51 (Windows NT 5.2; U) [ch]<br>
Opera/7.51 (Windows NT 6.0; U) [zw]<br>
Opera/7.51 (Windows NT 6.1; U) [ua]<br>
Opera/7.51 (X11; SunOS sun4u; U) [de]<br>
Opera/7.52 (Windows NT 5.1; U)  [en]<br>
Opera/7.52 (Windows NT 5.1; U) [en]<br>
Opera/7.53 (Windows NT 5.1; U)  [en]<br>
Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36<br>
Opera/7.54 (Ubuntu; U) [pl]<br>
Opera/7.54 (Windows 98; U)  [de]<br>
Opera/7.54 (Windows NT 5.0; U)  [de]<br>
Opera/7.54 (Windows NT 5.0; U)  [en]<br>
Opera/7.54 (Windows NT 5.1; U)  [de]<br>
Opera/7.54 (Windows NT 5.1; U)  [en]<br>
Opera/7.54 (Windows NT 5.1; U)  [it]<br>
Opera/7.54 (Windows NT 5.1; U) [en]<br>
Opera/7.54 (Windows NT 5.1; U) [pl]<br>
Opera/7.54 (X11; Linux i686; U)  [en]<br>
Opera/7.60 (Windows NT 5.2; U) [en] (IBM EVV/3.0/EAK01AG9/LE)<br>

</details>


# Summary

Gafgyt is a type of malware that waits for command and control (C&C) instructions to execute distributed denial of service (DDoS) attacks.

# IOCs

```
C2 Server :
  91.92.244.11:19302
Sha256:
  a9662b56d8409b4c022c5b3d3f0bcf00ea353220960191e3fe3cc239b874b3aa
```


# References

- https://threats.kaspersky.com/en/threat/Backdoor.Linux.Gafgyt/#:~:text=This%20family%20consists%20of%20malicious,used%20to%20perform%20DDoS%20attacks.
- https://securityscorecard.com/wp-content/uploads/2024/01/Report-A-Detailed-Analysis-Of-The-Gafgyt-Malware-Targeting-IoT-Devices.pdf
- https://threatpost.com/gafgyt-botnet-ddos-mirai/165424/


This report is authored by Mostafa Farghaly(M4lcode).




