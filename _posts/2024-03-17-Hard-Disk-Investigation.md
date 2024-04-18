---
layout: post
title:  "Hard disk structure and analysis"
image: "/images/hard_disk/cover.png"
description: "Looking at how Hard disks works and how to extend their investigation"
tags: [Disk-Forensics] 
---
# Introduction

Hard disks are the containers that hold our evidence files "from the investigator's perspective", understanding them is mandatory for every forensic analyst as they can provide valuable information within the investigation.
As the investigator is required to handle the case with caution to preserve the data, he must understand how this data is stored and how it's handled by the hard disk itself, this will make him understand the consequences of any action he makes while handling the evidence.

here we are going to discuss how the Hard disk is structured from a hardware and a logical point of view.

# HDD "Hard Disk Drive"

HDD Disks record data magnetically on a metallic platter, this type of disk depends on a mechanical way to access the data "Read/Write", where we have a moving part with a magnetic head controlled by a device driver "software part" directs it to the position where it should read or write.

here we can see a diagram for HDD disk parts.

![image](/images/hard_disk/HDD_Diagram.png)

what is important to us is how the platter itself is structured to make access to any part of it easier and more efficient.

![image](/images/hard_disk/platter.png)

As we can see, the platter is divided into several parts, what we are interested in as they are the terms used in our field are the following:

- Sector: we use the term sector to mention "Track Sector", this is the smallest storage unit in the hard disk.

- Cluster: the cluster is a combination of 3 sectors.

the other parts are more often used for measuring hard disk performance and other factors that may be not relevant to our topic.

Additional information you need to know about the sector is that in the disks you will encounter you can find two sizes for the sectors.

- 512 Bytes: which are the most used these days.

- 4KB "4096 Bytes": which is a new standard that may become more popular in the future.

What is meant by "sector is the smallest storage unit" is that the hard disk can't deal  with sizes smaller than it, which means for example:

if we have a file with a size of "700 bytes" the hard disk will allocate "1024 bytes" 2 sectors to store it and the remaining bytes will be wasted.

It's worth noting that the hard disk consists of multiple platters and heads not only one.

# SSD

SSD drives use an entirely different method of storing data, which completely depends on software to handle storing and retrieving the data.

what is worth noting about SSD drives is that, they use NAND electronic gates to hold the data which means there are no moving parts that can cause delay, this is what makes it so special in terms of speed.


# Disk Logical Structure

In this part we are going to discuss how the disks are logically structured to enable other software like operating systems to deal with it efficiently, this will give us insights into what exactly happens on the hardware level when the user stores or removes data from a file and what traces could be left behind for us as investigators to extract.

At the start, we need to understand the flow of how the evidence files are stored and what analysis steps we can take to achieve our maximum ability in extracting artifacts from hard drives.

the following image shows the steps that we can follow to ensure that there are no missing parts in our disk analysis.

![image](/images/hard_disk/flow.png)


Here we can see that we can start by analyzing the "physical Media" which means the actual disk hardware in terms of sectors where we can find some important data like:

- Data stored in Unallocated space:

The Data stored in unallocated space means that this data was here in the system but it got deleted, the delete process that we are doing using the OS is not actually deleting the file from the disk, instead, it just removes the pointers to it from the file system tables, this means that the data is still there but the OS can't see it because there are no pointers to it.


- Data Stored in Slack spaces:

The slack spaces can be considered the same but with a small difference which is that it's an unallocated space that is allocated again for storing something else, but the new data is smaller than the previous data and didn't overwrite it totally, in this case, the remaining part from the old data is stored in what we call "Slack Space".

To extract data out of the unallocated space in the hard disk we can use a technique called "Carving".

Carving is a technique that works by going over every bit presented on the hard disk and looking for a pattern that we specify for it to search for, and when it finds that pattern it grabs the data we want from the address it found then reassembles it together in a new file for us.

A very good tool that is used to do that and has a large number of prebuilt patterns for different file types is ["PhotoRec"](https://www.cgsecurity.org/wiki/TestDisk_Download)

The second step in the flow is "Volume Analysis", in this step we are analyzing what is called a volume.

A volume is a part of the hard disk that is formatted using a file system, this means it's a reserved space that uses some tables and structures depending on the file system chosen to control this area, these tables and structures keep track of each file and folder is used by the operating system to deal with this controlled area of the hard disk that is controlled by the File system.

you can find another blog post at Cyber5w where we discussed in detail how to analyze the NTFS file system and extract what you want out of it [here](https://blog.cyber5w.com/ntfs-artifacts-analysis).

The last step of the analysis is the analysis of the actual files of the operating system that contain different artifacts related to the OS being investigated.

 
# Conclusion

Hard disks can contain valuable information that you may miss if you don't pay attention to the structure and the layout of the hard disks, as this will open another area for you as an investigator to understand how data recovery can happen and how each read and write operation is tracked on hard disks

`Author: Amr Ashraf`