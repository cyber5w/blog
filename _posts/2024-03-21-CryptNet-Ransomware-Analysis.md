---
layout: post
title:  "CryptNet Ransomware Detailed Analysis"
image: "/images/cryptnet/cover.png"
description: "Detailed analysis of CryptNet Ransomware"
tags: [Malware-Analysis, Reverse-Engineering] 
---
Experience Level required: Intermediate 

# Objectives
In this report, we will analyze the CryptNet Ransomware, starting with deobfuscating the sample and proceeding through the ransomware's techniques:
- Obfuscated strings
- encrypted strings
- AES & RSA Encryption algorithms

# Overview
CryptNet is a NET ransomware that has been advertised as a new ransomware-as-a-service in underground forums since at least April 2023. Its Threat group performs double extortion attacks by combining data exfiltration with file encryption.

![](/images/cryptnet/image31.jpg)

The CryptNet codebase appears to be related to the Chaos ransomware. The similarities in the code include:
- Encryption methods
- Ability to disable backup services, and delete shadow copies.

According to [RAKESH KRISHNAN](https://twitter.com/RakeshKrish12/status/1645673225618182144) CryptNET threat group are looking on criminal forums for pentesters with experience in Active Directory Network.

![](/images/cryptnet/image32.jpg)


#  Sample Overview

Let's see the sample in Virus Total

![](/images/cryptnet/image29.jpg)

54 of 70 security vendors detected this file as malicious.

It's a .Net executable.

![](/images/cryptnet/image30.jpg)

Let's see the sample in DIE to check the entropy.

![](/images/cryptnet/image27.jpg)

The sample is not packed.

Let's see the strings in Pestudio.

![](/images/cryptnet/image28.jpg)

There are many encrypted strings, we need to deobfuscate them.

# Code Analysis

## Deobfuscating the sample

Let's open the sample in dnspy

As we see the sample is obfuscated

![](/images/cryptnet/image1.jpg)
![](/images/cryptnet/image2.jpg)

I'll use the **NETReactorSlayer** tool to deobfuscate it

**NETReactorSlayer** is deobfuscator and unpacker for **Eziriz .NET Reactor**. 

**Eziriz .NET Reactor** prevents reverse engineering by adding different protection layers to .NET assemblies

Beside standard obfuscation techniques, it includes special features like NecroBit, Virtualization, x86 Code Generation, or Anti Tampering.

**NETReactorSlayer** job is to remove these protection layers from our CryptNET sample


![](/images/cryptnet/image3.jpg)

Let's open the deobfuscated sample in dnspy

![](/images/cryptnet/image45.jpg)
 
yeah it's a bit clearer now but we didn't finish

## decrypting the strings

In **smethod_13** class (Class0.smethod_13 -> Class2.smethod_14 -> Class2.smethod_13) 

we can see some string decryptions

![](/images/cryptnet/image33.jpg)
![](/images/cryptnet/image34.jpg)

I'll use **de4dotgui** for that

The tool takes obfuscated .NET assemblies as input. These assemblies are typically protected using various obfuscation techniques to hinder reverse engineering. Then it uses dnlib, a .NET assembly manipulation library, to analyze and understand the structure and content of the obfuscated assemblies. dnlib enables de4dot to read and write assemblies programmatically, allowing it to inspect and modify the assembly's metadata, IL code, and other components.

**De4dot** can use many deobfuscation techniques like:

Inline Methods: Some obfuscators relocate parts of a method to separate static methods and then call them. de4dot attempts to inline these methods to simplify the code.
String and Constant Decryption: It can decrypt strings and other constants statically or dynamically if they've been encrypted by the obfuscator.
Symbol Renaming: Although symbol renaming is usually impossible to fully restore, de4dot attempts to rename symbols to more human-readable names.
Method and Resource Decryption: It can decrypt methods, resources, and embedded files encrypted by the obfuscator.
Control Flow Deobfuscation: de4dot reverses modifications to IL code made by obfuscators, restoring logical control flow.
Class Field Restoration: If obfuscators move fields from one class to another, de4dot attempts to restore them.
PE to .NET Conversion: It can convert a PE executable wrapped around a .NET assembly back to a pure .NET assembly.
Error Correction: de4dot fixes some errors introduced by buggy obfuscators, making the code verifiable again.
Other Techniques: It removes junk classes, tamper detection code, anti-debugging code, and can devirtualize virtualized code.

We need to get tokens to pass them to **de4dot** for the decryption process

Let's see the xrefs of **smethod_13**

we are looking for that because, in normal situations, the encrypted data will be accessed by the decryption function, so we are looking for the decryption function this way.

![](/images/cryptnet/image38.jpg)

![](/images/cryptnet/image35.jpg)

Here is our 1st token: 0x0600003B

![](/images/cryptnet/image41.jpg)

let's deobfuscate

![](/images/cryptnet/image39.jpg)
![](/images/cryptnet/image40.jpg)

The strings decrypted successfully, but we didn't finish yet

We should pass these tokens also to de4dot (0x0600000E, 0x06000014)

![](/images/cryptnet/image5.jpg)

It's better now.

![](/images/cryptnet/image42.jpg)


## Cleaned sample Analysis

The malware is creating a mutex to prevent multiple instances. This is accomplished by creating a mutex with a specific name that uniquely identifies its presence or current state. By doing so, the malware ensures that only one instance of itself is running on the infected system at any given time.

![](/images/cryptnet/image6.jpg)

Then It adds the ID to the ransomware note, It's a good technique to prevent the presence of the entire ransomware note during string examination

![](/images/cryptnet/image7.jpg)
![](/images/cryptnet/image8.jpg)

ID = ```4LrnjYzKHm5wEbQzcIdFOV0pWPMuv3p4```

Let's go to **Class0.string_4**

Here is the text written on the wallpaper:

![](/images/cryptnet/image9.jpg)

If we go up, we can see the file extensions that will be encrypted by the ransomware.

![](/images/cryptnet/image11.jpg)

File Extensions:
<details>
  <summary>Click to expand</summary>
.myd
.ndf
.qry
.sdb
.sdf
.tmd
.tgz
.lzo
.txt
.jar
.dat
.contact
.settings
.doc
.docx
.xls
.xlsx
.ppt
.pptx
.odt
.jpg
.mka
.mhtml
.oqy
.png
.csv
.py
.sql
.indd
.cs
.mp3
.mp4
.dwg
.zip
.rar
.mov
.rtf
.bmp
.mkv
.avi
.apk
.lnk
.dib
.dic
.dif
.mdb
.php
.asp
.aspx
.html
.htm
.xml
.psd
.pdf
.xla
.cub
.dae
.divx
.iso
.7zip
.pdb
.ico
.pas
.db
.wmv
.swf
.cer
.bak
.backup
.accdb
.bay
.p7c
.exif
.vss
.raw
.m4a
.wma
.ace
.arj
.bz2
.cab
.gzip
.lzh
.tar
.jpeg
.xz
.mpeg
.torrent
.mpg
.core
.flv
.sie
.sum
.ibank
.wallet
.css
.js
.rb
.crt
.xlsm
.xlsb
.7z
.cpp
.java
.jpe
.ini
.blob
.wps
.docm
.wav
.3gp
.gif
.log
.gz
.config
.vb
.m1v
.sln
.pst
.obj
.xlam
.djvu
.inc
.cvs
.dbf
.tbi
.wpd
.dot
.dotx
.webm
.m4v
.amv
.m4p
.svg
.ods
.bk
.vdi
.vmdk
.onepkg
.accde
.jsp
.json
.xltx
.vsdx
.uxdc
.udl
.3ds
.3fr
.3g2
.accda
.accdc
.accdw
.adp
.ai
.ai3
.ai4
.ai5
.ai6
.ai7
.ai8
.arw
.ascx
.asm
.asmx
.avs
.bin
.cfm
.dbx
.dcm
.dcr
.pict
.rgbe
.dwt
.f4v
.exr
.kwm
.max
.mda
.mde
.mdf
.mdw
.mht
.mpv
.msg
.myi
.nef
.odc
.geo
.swift
.odm
.odp
.oft
.orf
.pfx
.p12
.pl
.pls
.safe
.tab
.vbs
.xlk
.xlm
.xlt
.xltm
.svgz
.slk
.tar.gz
.dmg
.ps
.psb
.tif
.rss
.key
.vob
.epsp
.dc3
.iff
.opt
.onetoc2
.nrw
.pptm
.potx
.potm
.pot
.xlw
.xps
.xsd
.xsf
.xsl
.kmz
.accdr
.stm
.accdt
.ppam
.pps
.ppsm
.1cd
.p7b
.wdb
.sqlite
.sqlite3
.db-shm
.db-wal
.dacpac
.zipx
.lzma
.z
.tar.xz
.pam
.r3d
.ova
.1c
.dt
.c
.vmx
.xhtml
.ckp
.db3
.dbc
.dbs
.dbt
.dbv
.frm
.mwb
.mrg
.txz
.mrg
.vbox
.wmf
.wim
.xtp2
.xsn
.xslt
</details>

There is also a RSA Key

![](/images/cryptnet/image43.jpg)

RSA Key:
```
<RSAKeyValue><Modulus>8TO8tQQRyFqQ0VShtSpLkDqtDVsrxS8SfdOsqRAj8mWF7sVoGzyZMcv501DF6iZUdKYsFDlaSMnuckG9+MJmD2ldZwU/0H6Xztkta1BkJWSO2qHg2JAGDp9ZsFGP1wDR9oRb1w7wtBe7Db3wf7q848+qKPWiTP/2R/jlR4evW73M65Jdo9uOzQnbmvw+blsloXeszuYlW2nCcwQ7WarzAK29UmM9ZHS0/lqzU0KHNU+DvyfGwmMJgtb2HN6GFGXq9Z0n3dNBCQVzdUl2G/7fLAMoFbJeExn5USZdFHr2ygheTilo/shmfq7tcPCZM8C4zqBtb0Nbct0f/M48+H920Q==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>
```

Let's go to **smethod_0**

The malware iterates over each drive and avoids interference with essential system files. These files not only lack critical data for encryption but also possess large sizes, which would significantly slow down the encryption process, creating unnecessary noise without yielding any benefits. By sidestepping directories associated with system files or containing large, non-essential data, the malware optimizes its operation, focusing on encrypting valuable user data swiftly and discreetly. This strategic approach not only conserves resources but also enhances the malware's effectiveness in achieving its intended goal of data encryption while minimizing the risk of detection by security software. 

![](/images/cryptnet/image12.jpg)

Paths to exclude
```
*windows.old
*windows.old.old
*amd
*nvidia
*program files
*program files (x86)
*windows
*$recycle.bin
*documents and settings
*intel
*perflogs
*programdata
*boot
*games
*msocache
```
## The main encryption method

![](/images/cryptnet/image13.jpg)

The malware checks for the size of the files that will be encrypted if it is less than 524288 bytes (which is equivalent to 512 KB) or not

If a file is less than 524288 bytes, the malware will encrypt it entirely. If it's larger, the malware will split it into three parts and encrypt a portion of each part.

The malware is doing that because encrypting large files might consume considerable system resources and time.

![](/images/cryptnet/image46.jpg)

The malware will exclude these files to avoid interfering with critical system files

![](/images/cryptnet/image14.jpg)

```
iconcache.db
autorun.inf
thumbs.db
boot.ini
bootfont.bin
ntuser.ini
bootmgr
bootmgr.efi
bootmgfw.efi
desktop.ini
ntuser.dat
```
The ransomware note file name:

![](/images/cryptnet/image15.jpg)

The next functions are used in encrypting files

**smethod_4** takes five parameters: **string_7** (file path), **int_0** (size), **int_1** (position), **long_0** (position), and **long_1** (position).

It initializes two strings (**text** and **text2**) and converts these strings to byte arrays using ASCII encoding.

This function uses a **smethod_5** to encrypt parts of the file specified by positions and sizes.
Then it overwrites the encrypted data to the file.

![](/images/cryptnet/image16.jpg)

**smethod_5** takes two strings (**string_7** and **string_8**) and a byte array (**byte_1**) as parameters.

It initializes an AES encryption provider with a specified key size, block size, key, IV, mode, and padding.

Then Encrypts the input byte array using AES encryption.

**smethod_6** takes a single parameter: **string_7** (file path).

It Reads the entire file into a byte array.
Initializes two strings (**text** and **text2**).

>The string **text** is used as a key for encryption, however, the deobfuscators we used incorrectly identified it as a constant string, rather than a randomly generated one.

Then Converts these strings to byte arrays using ASCII encoding.

Encrypts the file contents using AES encryption and keys generated previously and writes the encrypted data back to the file.

![](/images/cryptnet/image17.jpg)

**smethod_7** takes two parameters: **string_7** (RSA public key) and **byte_1** (data to encrypt).

It initializes an **RSACryptoServiceProvider** and loads the public key from the XML string.
Encrypts the AES keys using RSA encryption.

![](/images/cryptnet/image18.jpg)

The files are encrypted with **AES** **CBC** and the AES keys are encrypted with **RSA** key appended to the encrypted files.

This function checks if the malware running as an adminstrator or not

![](/images/cryptnet/image19.jpg)

The next function generates a random string

![](/images/cryptnet/image20.jpg)

Then it executes a command in a hidden command prompt 

![](/images/cryptnet/image21.jpg)

## Delete Shadow Copies
The malware deletes the shadow copies that can hinder the system's ability to restore files to previous versions and may make it more difficult to recover from certain types of data loss, such as ransomware encryption.

The malware author aims to hinder users' ability to restore their files without paying the ransom.

![](/images/cryptnet/image22.jpg)
```
vssadmin delete shadows /all /quiet & wmic shadowcopy delete

bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no

wbadmin delete catalog -quiet
```

The first one is used to delete Volume Shadow Copies (VSS) on a Windows system. VSS is a feature in Windows that allows for backup and snapshot capabilities. This command deletes all existing shadow copies silently without prompting for confirmation.

The second one is 2 commands, these commands are related to the Windows Boot Configuration Data (BCD) store. The first command sets the boot status policy to ignore all failures, which means that the system will not enter into recovery mode automatically upon encountering boot failures. The second command disables the automatic recovery feature, preventing the system from attempting automatic recovery upon boot failure. 

The last one is used to delete the backup catalog in Windows Backup. The backup catalog contains information about backups made using the Windows Backup utility. This command deletes the catalog silently without prompting for confirmation.

## Processes and services termination
![](/images/cryptnet/image24.jpg)

The function begins by defining an array of strings named array. Each string in this array represents the name of a process. Then iterates over each string in the array using a foreach loop. For each string (process name) in the array, it attempts to find and terminate the corresponding process running on the system. 

Within the nested foreach loop, it uses **Process.GetProcessesByName(processName)** to find all processes with the given name and attempts to close them using **process.CloseMainWindow()**.
![](/images/cryptnet/image44.jpg)


```
sqlwriter sqbcoreservice VirtualBoxVM sqlagent sqlbrowser sqlservr code steam zoolz agntsvc firefoxconfig infopath synctime VBoxSVC tbirdconfig thebat thebat64 isqlplussvc mydesktopservice mysqld ocssd onenote mspub mydesktopqos CNTAoSMgr Ntrtscan vmplayer oracle outlook powerpnt wps xfssvccon ProcessHacker dbeng50 dbsnmp encsvc excel tmlisten PccNTMon mysqld-nt mysqld-opt ocautoupds ocomm msaccess msftesql thunderbird visio winword wordpad mbamtray
```

Then it stops these services by iterating over each string (service name) in the array using a foreach loop.

Within the loop, it attempts to stop each service using the **ServiceController** class. It instantiates a **ServiceController** object with the name of the service and calls the **Stop()** method on it to attempt to stop the service.

![](/images/cryptnet/image25.jpg)

```
*BackupExecAgentBrowser
*veeam
*VeeamDeploymentSvc
*PDVFSService
*BackupExecVSSProvider
*BackupExecAgentAccelerator
*vss
*sql
*svc$
*AcrSch2Svc
*AcronisAgent
*Veeam.EndPoint.Service
*CASAD2DWebSvc
*CAARCUpdateSvc
*YooIT
*memtas
*sophos
*DefWatch
*ccEvtMgr
*SavRoam
*RTVscan
*QBFCService
*Intuit.QuickBooks.FCS
*YooBackup
*BackupExecRPCService
*MSSQLSERVER
*backup
*GxVss
*GxBlr
*GxFWD
*GxCVD
*GxCIMgr
*VeeamNFSSvc
*BackupExecDiveciMediaService
*SQLBrowser
*SQLAgent$VEEAMSQL2008R2
*SQLAgent$VEEAMSQL2012
*VeeamDeploymentService
*BackupExecJobEngine
*Veeam.EndPoint.Tray
*BackupExecManagementService
*SQLAgent$SQL_2008
*zhudongfangyu
*sophos
*stc_raw_agent
*VSNAPVSS
*QBCFMonitorService
*VeeamTransportSvc
```

It's stopping backup services and antivirus software to prevent the user from
- Restoring its files
- Detecting and deleting the malware by using antiviruses

Also if any of these services are currently accessing a file, the ransomware won't be able to encrypt it.

# Summary
CryptNet is a form of ransomware-as-a-service that was discovered in April 2023. It is known for its double extortion attacks, which involve combining data exfiltration with file encryption. The codebase used in CryptNet shares similarities with that of the Chaos ransomware, including encryption methods and the ability to disable backup services and delete shadow copies.

A basic analysis of CryptNet has revealed that 54 out of 70 security vendors detected the ransomware sample as malicious. The ransomware is a .NET executable that has not been packed. Deobfuscation using NETReactorSlayer has revealed clearer code.

Advanced analysis has uncovered the ransomware's functionalities, which include creating a mutex to prevent multiple instances, adding an ID to the ransom note to prevent the entire note from appearing during string examination, identifying file extensions for decryption, using RSA encryption for AES keys appended to encrypted files, deleting shadow copies to hinder file restoration, and terminating processes and services, including backup and antivirus services, to impede file restoration and malware detection.
# IOCs
```
Sample:
    2e37320ed43e99835caa1b851e963ebbf153f16cbe395f259bd2200d14c7b775
CryptNET leaks site:
    hxxp[://]cryptr3fmuv4di5uiczofjuypopr63x2gltlsvhur2ump4ebru2xd3yd[.]onion

```

# References
- https://research.openanalysis.net/dotnet/cryptnet/ransomware/2023/04/20/cryptnet.html
- https://www.zscaler.com/blogs/security-research/technical-analysis-cryptnet-ransomware


This report is authored by Mostafa Farghaly [@M4lcode](https://twitter.com/M4lcode).
