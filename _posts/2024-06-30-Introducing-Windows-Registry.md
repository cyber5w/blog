---
layout: post
title:  "Windows Registry Analysis"
image: "/images/registry_pic/cover.png"
description: "understanding how Registry works in windows and how to analyze it"
tags: [Disk-Forensics]  
---

# What Is Registry 

The registry is a hierarchical database, The Windows Registry holds configuration information about all the applications on the system, user-specific settings, configuration of various hardware devices used by the system, settings for all the software on the system, etc.


DIVE INTO THE REGISTRY, ONE OF THE FIRST THING WE NEED TO KNOW IS… WHERE IS IT? AND WHERE IS THE KEY COMPONANT? HOW IS IT ORGANIZED? Why is this registry path useful?


Let’s assume you downloaded a video attachment from an email. When you opened that video, you noticed that it also opens up the Notepad application on its own and it has some content written in a foreign language. You closed that video, but every time you restart your system, you notice that the Notepad application opens automatically and the same foreign language content is displayed.

What is happening here is:

when you downloaded the video attachment, you accidentally downloaded some malware onto your computer. The video could have been from a malicious source. That malware has modified the autostart location in the registry to bring up the binary for Notepad whenever the system is rebooted.
and WE DIVE INTO THAT IN THE PRACTISE SECTION! 



# Registry Structure

The registry is structured very similarly to the Windows directory/subdirectory structure. You have the five root keys or hives and then subkeys. In some cases, you have sub-subkeys. These subkeys then have descriptions and values that are displayed in the contents pane. the values are simply `0` or `1`, meaning on or off, but also can contain more complex information usually displayed in hexadecimal.

![error](/images/registry_pic/reg_editor.png)

Inside the registry, there are root folders. These root folders are referred to as hives. There are five (5) registry hives. 

- **HKEY_USERS:** contains all the loaded user profiles 

- **HKEY_CURRENT_USER:** profile of the currently logged-on user 

- **HKEY_CLASSES_ROOT:** configuration information on the application used to open files 

- **HKEY_CURRENT_CONFIG:** hardware profile of the system at startup 

- **HKEY_LOCAL_MACHINE:** configuration information including hardware and software settings 


![error](/images/registry_pic/reg_structure.png)


**Keys:**

- Similar to folders(keys) and subfolders(subkeys),

- produces a folder directory hierarchy 

**Values:**

- Data stored within a key, contains data in the form of strings, binary data, integers, and lists.

- where the most valuable forensics data is found 

Collection of data files called hives.

When viewed in a registry viewer, hive names are used:

*Hkey_local_machine(HKLM)* contain hives:

- SAM 

- Security

- system

- software

*hkey_current_user(Hkcu)* contain hive:

- NTuser.dat


![error](/images/registry_pic/key_value.png)


# Registry file acquisition 

Investigating the Windows registry is quite a difficult task because to investigate it properly, the registry needs to be extracted from the computer. Extraction of the registry file is not just a normal copy-and-paste function.

Since registry files store all the configuration information of the computer, it automatically updates every second. To extract Windows registry files from the computer, investigators have to use third-party software such as FTK Imager. 

FTK Imager is one of the most widely used tools for this task. Apart from using third-party software, some research has been carried out to demonstrate how to extract registry information from Windows CE memory images and volatile memory (RAM).
The steps to extract registry files from Access Data FTK Imager are as follows: 

**Step 1:** Open access data ftk imager and click on the “add evidence item” button then select the “logical drive” radio button 


![error](/images/registry_pic/ftk_imager.png)


note: 

- Physical Drive: Extract from a hard drive

- Logical Drive: Extract from a partition

- Image File: Extract from an image file

- Contents of a Folder: Logical file-level analysis only: excludes deleted files and unallocated space 

**Step 2:** Then select the source drive and after that scan “MFT” by expanding “evidence tree”, go to windows/system32/config/ 

**Step 3:** Export the registry file by clicking the “export files” button then select the destination folder

![error](/images/registry_pic/export_registry.png)

We are going to open it in the registry explorer to view the content we have exported

![error](/images/registry_pic/registry_exeplorer.png)


# Deleted Registry keys/values 

Registry hives have unallocated space similar to filesystems

A deleted hive key is marked as unallocated 

recovery of unallocated keys possible 

- keys

- values 

- timestamps

lack of anti-forensics tools to completely wipe unallocated registry hive data
recovery of deleted keys possible 

- displays
  - hive unallocated space 
  - deleted keys 

![error](/images/registry_pic/unallocated_space.png)

# Interesting Windows Registry Keys 

**Windows Version and Owner Info**

- Located at <u>Software\Microsoft\Windows NT\CurrentVersion</u>, you'll find the Windows version, Service Pack, installation time, and the registered owner's name straightforwardly.

**Computer Name**

- The hostname is found <u>underSystem\ControlSet001\Control\ComputerName\ComputerName</u>.

**Time Zone Setting**

- The system's time zone is stored in <u>System\ControlSet001\Control\TimeZoneInformation</u>.
Access Time Tracking

- By default, the last access time tracking is turned off (NtfsDisableLastAccessUpdate=1). To enable it, use: fsutil behavior set disablelastaccess 0
Windows Versions and Service Packs

- The Windows version indicates the edition (e.g., Home, Pro) and its release (e.g., Windows 10, Windows 11), while Service Packs are updates that include fixes and, sometimes, new features.

**Enabling Last Access Time**

- Enabling last access time tracking allows you to see when files were last opened, which can be critical for forensic analysis or system monitoring.

**Network Information Details**

- The registry holds extensive data on network configurations, including types of networks (wireless, cable, 3G) and network categories (Public, Private/Home, Domain/Work), which are vital for understanding network security settings and permissions.

**CLIENT-SIDE Caching (CSC)**

- CSC enhances offline file access by caching copies of shared files. Different CSCFlags settings control how and what files are cached, affecting 
performance and user experience, especially in environments with intermittent connectivity.

**AutoStart Programs**

- Programs listed in various Run and RunOnce registry keys are automatically launched at startup, affecting system boot time and potentially being points of interest for identifying malware or unwanted software.

**Shellbags**

- Shellbags not only store preferences for folder views but also provide forensic evidence of folder access even if the folder no longer exists. They are invaluable for investigations, revealing user activity that isn't obvious through other means.

**USB Information and Forensics**

- The details stored in the registry about USB devices can help trace which devices were connected to a computer, potentially linking a device to sensitive file transfers or unauthorized access incidents.

**Volume Serial Number**

- The Volume Serial Number can be crucial for tracking the specific instance of a file system, useful in forensic scenarios where file origin needs to be established across different devices.

**Shutdown Details**

- Shutdown time and count (the latter only for XP) are kept in <u>System\ControlSet001\Control\Windows System\ControlSet001\Control\Watchdog\Display</u>.


**Network Configuration**

- For detailed network interface info, refer to <u>System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}</u>.

- First and last network connection times, including VPN connections, are logged under various paths in Software\Microsoft\Windows NT\CurrentVersion\NetworkList.

**Shared Folders**

- Shared folders and settings are under System\ControlSet001\Services\lanmanserver\Shares.
-The CLIENT-SIDE Caching (CSC) settings dictate offline file availability.
Programs that Start Automatically

- Paths like <u>NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Runand</u> similar entries under <u>Software\Microsoft\Windows\CurrentVersion</u> detail programs set to run at startup.
Searches and Typed Paths

- Explorer searches and typed paths are tracked in the registry under <u>NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer</u> for WordwheelQuery and TypedPaths, respectively.
Recent Documents and Office Files

- Recent documents and Office files accessed are noted in <u>NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs</u> and specific Office version paths.
Most Recently Used (MRU) Items

- MRU lists, indicating recent file paths and commands, are stored in various ComDlg32 and Explorer subkeys under NTUSER.DAT.


**User Activity Tracking**

- The User Assist feature logs detailed application usage stats, including run count and last run time, at <u>NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count</u>.

**Shellbags Analysis**

- Shellbags, revealing folder access details, are stored in USRCLASS.DAT and NTUSER.DAT under <u>Software\Microsoft\Windows\Shell</u>.

- Use Shellbag Explorer for analysis.

**USB Device History**

- <u>HKLM\SYSTEM\ControlSet001\Enum\USBSTORand HKLM\SYSTEM\ControlSet001\Enum\USB</u> contain rich details on connected USB devices, including manufacturer, product name, and connection timestamps.

- The user associated with a specific USB device can be pinpointed by searching NTUSER.DAT hives for the device's {GUID}.

- The last mounted device and its volume serial number can be traced through <u>System\MountedDevicesand Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt</u>, respectively.




# Practice Section 

In this show, I will show you two tasks using the Windows registry.

- first, I will configure an application to start whenever a user logs in to the computer 

- then I will show you how can find information about recently used documents, within the registry.

We will then discuss about the significance of these two tasks in digital forensics.


first, I will add an entry in the registry to start up the Notepad application whenever a user logs into the system.
within the: <u>Hkey_local_machine/Software/Microsoft/windows/current version/Run</u>
I will add a new string value to this key, just by performing a right click in this white space, the name is provided as notepad


![error](/images/registry_pic/new_value.png)


when I double-click this name, I can add the value, and the value is the absolute path of the Notepad executable.

![error](/images/registry_pic/notebad.png)


now I log out and back again to see what happened… and here we go :)
you can see that right after a user logs in to the system notepad application is started automatically.
now this is a legitimate application, cyber attackers may modify the registry run key, and configure malicious applications to run, when a user logs in.
knowing where the registry Run key is, may help you identify some malicious autostart programs on the computer 


![error](/images/registry_pic/auto_start.png)



Let’s take a look at another one:
I will edit this text file “sample”, add some text, and save this file.

![error](/images/registry_pic/modify_time_notepad.png)


with the registry, I will show you that we can find information about recently modified files.
I will open the registry editor application again, within the <u>HKEY_current_user/software/Microsoft/windowos/current version/explorer/recentdocs</u> key.
within the text subkey, we will find information about recently modified text files on the system. here in the center pane, we can find one entry the name zero 

the data appears to be hex bytes. and I will double-click the name 


![error](/images/registry_pic/edit_reg.png)


In this window, you can see the same hex data in the center. the hex data is displayed in ASCII in the right pane, here you can see the same of name the text file I modified recently, the sample 


![error](/images/registry_pic/edit_bin_val.png)

using tools to parse the registry, you can find the timestamp of when a file was recently modified. 
There are many more <u>FORENSICS ARTIFACTS WITHIN THE REGISTRY WHEN YOU ARE AWARE of THE ARTIFACTS YOU CAN FIND, AND WHERE YOU CAN FIND THEM, YOU CAN EASILY LOCATE THEM DURING AN INVESTIGATION.
WITHIN MEMORY DUMPS, YOU CAN RECOVER REGISTRY ENTRIES THAT UNDERWENT MODIFICATION RECENTLY</u> 




