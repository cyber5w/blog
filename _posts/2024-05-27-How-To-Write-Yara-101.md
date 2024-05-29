---
layout: post
title:  "Writing YARA Rules"
image: "/images/howtowriteyararule/cover.png"
description: "How to write a good YARA Rule"
tags: [Malware-Analysis, Reverse-Engineering] 
---
 

# Objectives

In this blog, we will learn how to write a YARA Rule to detect different samples from the same families and hunt for them on a scale.

# Rule Header

This section defines the metadata for the rule such as (the description of the rule, the author's name, the date of writing the rule, etc.)

example
{% highlight text %}
rule rule_name {
 meta:
 description = "detect a ransomware"
 author = "@Cyber5W"
 date = "6/2/2024"
}
{% endhighlight %}

# Strings Section

This section contains the strings that the rule will search for

strings can be in (Ascii, Unicode, hexadecimal, and Regular expressions)

The strings should be unique in this malware family as much as you can to have fewer false positives.

If there are common bytes in a malware family we can add it in our rule. If there are differences in some hexadecimal digits we can replace the different hexadecimal digits with "?"

example
{% highlight text %}
 strings:
 $s1 = "himarkh.xyz" wide
 $s2 = "No system is safe" ascii
 $s3 = "vssadmin Delete Shadows /all /quiet" ascii
 $s4 = {6A 8B EC 6A FF 68 ?? ?? 42 00 64 A1 00 00 00 00 50 8? EC}
{% endhighlight %}

# Conditions Section

This section contains the conditions that must be met for the rule to trigger

We can use these operators (<, <=, >, >=, ,==, !=, and, or, etc.)

## Checking the imported functions

If the malware imports a suspicious function we can use "pe.imports("dll name", "function name")" after importing "pe" at the beginning of the rule

example
{% highlight text %}
import "pe"
rule rule_name {
 meta:
 description = "detect a ransomware"
 author = "@Cyber5W"
 date = "6/2/2024"
 strings:
 $s1 = "himarkh.xyz" wide
 $s2 = "No system is safe" ascii
 $s3 = "vssadmin Delete Shadows /all /quiet" ascii
 $s4 = {6A 8B EC 6A FF 68 ?? ?? 42 00 64 A1 00 00 00 00 50 8? EC}
 condition:
 pe.imports("Shell32.dll", "ShellExecuteW") and 3 of them
}
{% endhighlight %}
## Searching for sections

If we want the rule to search for a section we can use

(for any section in pe.sections : ( section.name == ".upx0" ))

we can also check for the number of section

(pe.number_of_sections >= 4)

## Checking Sample size

If we observe that the sample size is less than 500KB, for example, we can add this to our rule's conditions to make it more specific.

{% highlight text %}
rule rule_name {
 condition:
 filesize > 500KB
}
{% endhighlight %}
## Checking bytes

We can check the first bytes of the sample by using (uint16(offset number) == hex value)

example
{% highlight text %}
rule rule_name {
 condition:
 uint16(0) == 0x4d5a
}
{% endhighlight %}

# Writing a YARA Rule 1#

Now let's practice what we have learned and write a YARA Rule.

I downloaded two samples of **Stealc** Stealer

{% highlight text %}
07b3c4a47ec2b0e62681dd4de6866b809a82262c45360b24a19e47b2b17ed5c9
716cf3d14949e2892a8a215c7d97ab4534a35af1ea09321fe8c8bae07ceb3dcf
{% endhighlight %}
![](/images/howtowriteyararule/image1.jpg)

We can observe that the two samples are less than 250KB

Let's search for common strings

![](/images/howtowriteyararule/image2.jpg)


Let's search for common bytes. I'll use **PEbear**

![](/images/howtowriteyararule/image4.jpg)

This is our final YARA rule

{% highlight text %}
rule stealc_stealer {
 meta:
 description = "detect Stealc Stealer"
 author = "@Cyber5W"
 date = "6/2/2024"
 hash1 = "07b3c4a47ec2b0e62681dd4de6866b809a82262c45360b24a19e47b2b17ed5c9"
 hash2 = "716cf3d14949e2892a8a215c7d97ab4534a35af1ea09321fe8c8bae07ceb3dcf"
 strings:
 $s1 = "senewuparagoratiyipevojura" wide
 $s2 = "TASUNIYUVOMOVEVOJUCUXO" wide
 $s3 = {E8 ?? ?? 00 00 E9 79 FE FF FF}
 condition:
 uint16(0) == 0x4d5a and filesize < 250KB and all of them
}
{% endhighlight %}
Let's test it

![](/images/howtowriteyararule/image5.jpg)

# Writing a YARA Rule 2#

I downloaded **Ryuk Ransomware** sample, this sample has two stages, so we have to write a yara rule to detect both of them

![](/images/howtowriteyararule/image6.jpg)

Let's see some common strings

![](/images/howtowriteyararule/image7.jpg)
![](/images/howtowriteyararule/image8.jpg)
![](/images/howtowriteyararule/image9.jpg)

After analyzing the two samples by IDA we can observe that the dropper uses **ShellExecuteW** function to execute the second stage.

![](/images/howtowriteyararule/image10.jpg)

**ShellExecuteW** is a function imported from **Shell32.dll**

{% highlight text %}
import "pe"
rule ryuk {
 meta:
 description = "detect Ryuk ransomware"
 author = "@M4lcode"
 hash1 = "23f8aa94ffb3c08a62735fe7fee5799880a8f322ce1d55ec49a13a3f85312db2"
 hash2 = "8b0a5fb13309623c3518473551cb1f55d38d8450129d4a3c16b476f7b2867d7d"
 strings:
 $s1 = "RyukReadMe.txt" wide
 $s2 = "No system is safe" ascii
 $s3 = "vssadmin Delete Shadows /all /quiet" ascii
 condition:
 (1 of them and pe.imports("Shell32.dll", "ShellExecuteW")) or 2 of them
}
{% endhighlight %}

Let's test our rule in **hybrid analysis**

![](/images/howtowriteyararule/image11.jpg)

It worked!

This blog is authored by Mostafa Farghaly(M4lcode).