---
layout: post
title:  Email Forensics
image: "/images/mail/cover.png"
description: "Looking at how you can perform an investigation and detect malicious Emails"
tags: [Disk-Forensics] 
---

# Email forensics overview 

Email forensics involves the examination, extraction, and analysis of email data to gather digital evidence crucial for resolving crimes and specific incidents, ensuring the integrity of the investigation process.
This investigative process encompasses various aspects of emails, focusing on:

- Email content, including messages and attachments.
- Sender and recipient email addresses.
- IP addresses associated with email transmissions.
- Timestamps indicating the date and time of email exchanges.
- User information linked to email accounts.
- Passwords associated with email accounts.
- Logs from cloud services, servers, and local computers.




# HOW EMAIL WORKS

Understanding how email works is essential for conducting effective email forensics, as it provides insight into the underlying technologies and processes involved in email communication.
Emails originate from various devices, such as phones or computers, and go through complex processing before reaching their intended recipients.
Key Components and Protocols:

- Simple Mail Transfer Protocol (SMTP): This standard protocol is used to transmit and send emails.
- Internet Message Access Protocol (IMAP): One of the standard protocols for receiving emails.
- Post Office Protocol 3 (POP3): Another standard protocol for receiving mail.
- Mail Transfer Agent (MTA): Responsible for sending and forwarding emails through SMTP, examples include Sendmail and Postfix.
- Mail User Agent (MUA): A mail client used to receive emails, communicating with the server via IMAP or POP3 protocol, such as Outlook, Apple Mail, or Gmail.
- Mail Delivery Agent (MDA): Saves received mails to local, cloud disk, or designated location, often scanning for spam mails and viruses, e.g., ProMail or Dropmail.

      “POP3: just have one copy on MDA”

- Mail Receive Agent (MRA): Implements IMAP and POP3 protocols and interacts with MUA, e.g., Dovecot.




# EMAIL PROCESS OVERVIEW 

**Creation:** A user creates an email using a Mail User Agent (MUA), like Gmail or Outlook.
  
**Transmission:** The email is sent to the user's Mail Transfer Agent (MTA) using the SMTP protocol.
 
**Routing:** The MTA checks the recipient, queries the DNS server for the recipient's domain name and sends the email to the recipient's MTA via SMTP.
  
**Delivery:** The recipient's MTA delivers the email to a Mail Delivery Agent (MDA), which saves it to the local disk.
  
**Retrieval:** The recipient uses the MUA, employing IMAP or POP3 protocol, to query the mail server for their email, authenticate themselves, and retrieve the message.

![error](/images/mail/email_forensics_overview.png)
 


# HOW TO CONDUCT EMAIL FORENSICS INVESTIGATION

- Email headers contain crucial evidence for investigations, hiding significant information that can help in clarifying the case.
- During analysis, it's recommended to begin from the bottom and work upwards. The sender's vital information typically resides at the bottom, while details about the recipient are found towards the top.
- Given our discussion on Mail Transfer Agents (MTAs), scrutinizing the email header thoroughly allows for tracing the route the email traversed, providing valuable insights into its journey.



# EMAIL HEADER ANALYSIS # 

Analyzing the email header is the first step in email forensics. It gives us a lot of details about the email, like who sent it and where it came from. By checking the header, we can spot if an email is fake or real. This helps us catch email-related crimes like phishing and spamming.

![error](/images/mail/email_header_analysis.png)


**Message-ID header:**

message ID which is supposed to be a unique identifier for a specific instance of the email

![error](/images/mail/message_id_header.png)

**Threade index:**

Because of the difference between the time from the thread index and the origination data of the email we might be able to surmise composition time or an approximate composition time so how long it took from the message being created to its being sent also applies to those delayed scenarios.

So, let’s say that somebody uses an email client and uses the feature to not send an email immediately but send it at a scheduled time then you would say the first artifact that will tie in back to the original creation time of the email will be thread index there and it has some other benefits too you, can look at the child messages so if there are multiple messages in the conversation thread you would see them and be able to construct a skeleton of the entire conversation and each email thread has its own unique identifier as a grid and you’ll be able to use that in the contextual analysis as we’ll discuss  

If you have other time stamps to rely on let’s, say you have the origination data of email in UTC perhaps with time zone, and if you have this then you might be able to get the difference between those two values and figure out how many hours of the user is from UTC which be their time zone, so you could figure out what time zone sending computer was in.


# ANALYSIS BODY PART OF EMAIL
   
***Delivered To:*** This shows the email address of the person who was supposed to receive the email.
***Received By:*** This field tells us about the SMTP server that handled the email before it reached us. It includes:

- IP address of the server
- SMTP ID of the server
- Date and time when the server received the email.
    
***X-Received:*** Some email systems use extra fields not defined in standard protocols. This field, starting with X often contains similar information to "Received By" including:

- IP address of the server that received the email
- SMTP ID of the server
- Date and time when the server received the email.
 
***ARC-Seal:*** This contains a signature that includes information from other ARC headers, helping to authenticate the email's path.
***ARC-Message-Signature:*** Similar to a DKIM signature, this captures details from the email header, like sender, recipient, subject, and body.

![error](/images/mail/ARC_Message_Signature.png)


Received-SPF: header field indicates the status of the Sender Policy Framework (SPF) check, a security mechanism for email authentication. Here are the possible codes and their meanings:
     
- *Pass:* The email source is verified as legitimate.
- *Soft* Fail: There's a possibility of a fake source, but it's not definitive.
- *Neutral:* Determining the validity of the source is challenging.
- *None:* No SPF record was found for the sender's domain.
- *Unknown:* The SPF check couldn't be performed due to unknown reasons.
- *Error:* An error occurred during the SPF check process.

![error](/images/mail/Received_SPF.png)

***ARC Authentication Results:*** This header contains email authentication results like SPF, DKIM, and DMARC.

![error](/images/mail/ARC_Authentication.png)


***DKIM-signature:*** header stands for domain key identified mail and it essentially relies on public key cryptography it digitally signs the contents of the email and its attachment and subset of its header and the signing of the signature is performed by the entity who assumes responsibility for the email 

Like the email service provider for example google or Microsoft, once it’s signed the receiver can retrieve the signer’s public key and then verify that signature and if everything checks out then you can have good confidence that the email hasn’t changed since it’s been signed.

So, it is a fantastic artifact for email authentication and as such when you see missing in an email that should have had it, but it doesn’t have it anymore that might throw out some red flags.

Here are the main tags found in a DKIM signature header:

- *v:* Application version.
- *a:* Encryption algorithms used.
- *c:* Canonicalization algorithms used.
- *s:* Selector record name associated with the domain.
- *h:* Header fields that are signed to create the hash.
- *bh:* Hash of the message body.
- *b:* Hash data of the signed headers (DKIM signature).
- *d:* Domain used with the selector record.

When DKIM, SPF, and DMARC checks pass, it indicates that the email source is legitimate and can be considered valid.
 

![error](/images/mail/DKIM_signature.png)


