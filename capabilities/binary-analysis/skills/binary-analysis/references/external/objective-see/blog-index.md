![](https://objective-see.org/images/blogIcon.png)

Objective-See's Blog

writings on malware, exploits, coding, & more...


📚   Never miss a post!


Subscribe to our [RSS feed](https://objective-see.org/rss.xml), or subscribe to our [newsletter](https://objective-see.org/subscribe.html).


Catching macOS Stealers in the Wild

04/01/2026

macOS stealers continue to be a pervasive threat!


In this guest blog post, one of our #OBTS student scholars, Pablo Redondo Castro, shares the technical details of a macOS stealer he analyzed.


[continue reading »](https://objective-see.org/blog/blog_0x88.html)

No Paste for You!

03/31/2026

In macOS 26.4, Apple added ClickFix protections.


In this post, we reverse macOS to uncover exactly how these protections are implemented, and whether we can replicate the same approach in our own tools.


[continue reading »](https://objective-see.org/blog/blog_0x87.html)

Building a Firewall ...via Endpoint Security!?

03/27/2026

You can now build macOS firewalls/network tools via Endpoint Security ...no Network Extension needed! 🤯


In this post, we reverse macOS 26.4's new ES\_EVENT\_TYPE\_RESERVED\_\* ES events shows some are network auth/notify hooks.


[continue reading »](https://objective-see.org/blog/blog_0x86.html)

ClickFix: Stopped at ⌘+V

02/15/2026

ClickFix represents a shift in attacker tradecraft, exploiting user trust rather than software vulnerabilities.


In this post, we introduce a lightweight execution-boundary defense that intervenes at paste time to generically disrupt most ClickFix-style attacks on macOS.


[continue reading »](https://objective-see.org/blog/blog_0x85.html)

The Mac Malware of 2025

01/01/2026

It's here! Our annual report on all the Mac malware of the year (2026 edition).


Besides providing samples for download, we cover infection vectors, persistence mechanisms, payloads, and more!


[continue reading »](https://objective-see.org/blog/blog_0x84.html)

A Remote Pre-Authentication Overflow in LLDB's debugserver

12/07/2025

In this guest blog post, Nathaniel Oh, details a recent bug he discovered and reported to Apple: a remote pre-authentication buffer overflow in LLDB’s debugserver, now patched as CVE-2025-43504.


[continue reading »](https://objective-see.org/blog/blog_0x83.html)

Restoring Reflective Code Loading on macOS (Part II)

11/24/2025

Let’s continue our research into fully restoring reflective code loading on macOS — now with support for macOS 26 and in-memory Objective-C payloads. And what about detection? We cover that too!


[continue reading »](https://objective-see.org/blog/blog_0x82.html)

\[0day\] From Spotlight to Apple Intelligence

03/27/2025

Malicious Spotlight plugins can leak bytes from TCC-protected files. And while the core bug was publicly disclosed almost a decade ago, it's still present in macOS 26!


[continue reading »](https://objective-see.org/blog/blog_0x81.html)

TCCing is Believing! Apple finally adds TCC events to Endpoint Security!

03/27/2025

Apple will bring TCC events to Endpoint Security in macOS 15.4. Here, we covers details, nuances, and provide PoC code for the new 'ES\_EVENT\_TYPE\_NOTIFY\_TCC\_MODIFY' event.


[continue reading »](https://objective-see.org/blog/blog_0x7F.html)

Leaking Passwords (and more!) on macOS

03/20/2025

In this guest blog post, researcher Noah Gregory shares the technical details of a bug he uncovered (that was subsequently patched by Apple as CVE-2024-5447).


[continue reading »](https://objective-see.org/blog/blog_0x7E.html)

The Mac Malware of 2024

01/01/2025

It's here! Our annual report on all the Mac malware of the year (2024 edition).


Besides providing samples for download, we cover infection vectors, persistence mechanisms, payloads, and more!


[continue reading »](https://objective-see.org/blog/blog_0x7D.html)

Restoring Reflective Code Loading on macOS

12/16/2024

A side effect of Apple's privacy mindset: in-memory payloads remain largely invisible/inaccessible to macOS security/3rd-party tools


Knowing this, Apple nuked their reflective code loading APIs ...but was that enough?


[continue reading »](https://objective-see.org/blog/blog_0x7C.html)

The Hidden Treasures of Crash Reports

08/13/2024

Analyzing crash reports reveals malware, bugs, & much more!


...but you first have to know how to dissect them. Which, after reading this post, you'll be a pro at!


[continue reading »](https://objective-see.org/blog/blog_0x7B.html)

This Meeting Should Have Been an Email

07/15/2024

A DPRK stealer, dubbed BeaverTail, targets users via a trojanized meeting app.


Let's analyze it comprehensively!


[continue reading »](https://objective-see.org/blog/blog_0x7A.html)

Apple Gets an 'F' for Slicing Apples

02/22/2024

Universal binaries contain multiple architecture-specific Mach-O, known as slices.


...however, the Apple API to identify the best slice, is broken. Let's investigate and find out why!


[continue reading »](https://objective-see.org/blog/blog_0x80.html)

Why Join The Navy If You Can Be A Pirate?

01/15/2024

From a security point of view, pirating software is not recommended!


Let's analyze a pirated application that contains a (malicious) surprise.


[continue reading »](https://objective-see.org/blog/blog_0x79.html)

Analyzing DPRK's SpectralBlur

01/04/2024

The first malware of 2024 is (already) here. Let's dive in!


[continue reading »](https://objective-see.org/blog/blog_0x78.html)

The Mac Malware of 2023

01/01/2024

It's here! Our annual report on all the Mac malware of the year (2023 edition).


Besides providing samples for download, we cover infection vectors, persistence mechanisms, payloads, and more!


[continue reading »](https://objective-see.org/blog/blog_0x77.html)

It's Turtles All The Way Down

11/30/2023

Yet more ransomware targeting macOS!


In this post we analyze the newly discovered "Turtle" ransomware and provide both a decryptor and a method to procactively thwart it.


[continue reading »](https://objective-see.org/blog/blog_0x76.html)

The LockBit ransomware (kinda) comes for macOS

04/16/2023

The infamous LockBit ransomware group has created a macOS variant.


In this post we comprehensively analyze this new threat, showing it's not ready for prime-time and iw easily detected with heuristic-based approaches.


[continue reading »](https://objective-see.org/blog/blog_0x75.html)

Ironing out (the macOS) details of a Smooth Operator (Part II)

04/01/2023

The initial macOS component of 3CX supply chain attack, downloaded & executed a 2nd stage payload named `UpdateAgent`.


In this post we comprehensively analyze this new payload, highlighting its capabilities and discussing methods of both detection and protection.


[continue reading »](https://objective-see.org/blog/blog_0x74.html)

Ironing out (the macOS) details of a Smooth Operator (Part I)

03/29/2023

The 3CX supply chain attack gives us an opportunity to analyze a trojanized macOS application!


Here, we uncover the malicious component and thoroughly analyze its capabilities.


[continue reading »](https://objective-see.org/blog/blog_0x73.html)

Where there is love, there is ...malware?

02/14/2023

Today, Valentine's day, is a day to celebrate love, and for better or worse one my main loves is malware!


Let's analyze a new macOS backdoor/updater component: 'iWebUpdate' ...which has been around, undetected for 5 years!


[continue reading »](https://objective-see.org/blog/blog_0x72.html)

The Mac Malware of 2022

01/01/2023

It's here! Our annual report on all the Mac malware of the year (2022 edition).


Besides providing samples for download, we cover infection vectors, persistence mechanisms, payloads, IoCs and more!


[continue reading »](https://objective-see.org/blog/blog_0x71.html)

How Shlayer Hides its Configuration

12/27/2022

The prolific adware known as Shlayer continues to evolve in creative ways!


In this guest blog post, security researcher Taha Karim, details an unusual Shlayer sample that encrypts its configuration within the DMG file header structure.


[continue reading »](https://objective-see.org/blog/blog_0x70.html)

SeaFlower 藏海花

06/13/2022

It's not everyday that we get to talk about backdoors targeting iOS users.


In this guest blog post, security researcher Taha Karim, details a sophisticated threat targeting iOS web3 users.


[continue reading »](https://objective-see.org/blog/blog_0x6F.html)

From The DPRK With Love

05/09/2022

A report from the Cybersecurity & Infrastructure Security Agency detailed " _\[A\] North Korean State-Sponsored APT Target\[ing\] Blockchain Companies_."


We build upon CISA’s report, diving deeper into one of the malicious macOS samples.


[continue reading »](https://objective-see.org/blog/blog_0x6E.html)

Analyzing OSX.DazzleSpy

01/25/2022

DazzleSpy is a fully-featured cyber-espionage macOS implant, installed via a remote Safari exploit!


Besides providing a sample for download, we show how it persists, describe it's capabilties and show how it stacks up against Objective-See's tools.


[continue reading »](https://objective-see.org/blog/blog_0x6D.html)

SysJoker, the first (macOS) malware of 2022!

01/11/2022

Here, we analyze the macOS versions of a cross-platform backdoor.


Besides providing a sample for download, we cover its persistence mechanism, capabilties and more!


[continue reading »](https://objective-see.org/blog/blog_0x6C.html)

The Mac Malware of 2021

01/01/2022

It's here! Our annual report on all the Mac malware of the year (2021 edition).


Besides providing samples for download, we cover infection vectors, persistence mechanisms, payloads and more!


[continue reading »](https://objective-see.org/blog/blog_0x6B.html)

Where's the Interpreter!?

12/22/2021

`CVE-2021-30853` was able to bypass file quarantine, gatekeeper, & notarization requirements. In this post, we show exactly why!


[continue reading »](https://objective-see.org/blog/blog_0x6A.html)

Analyzing OSX.CDDS (MacMa)

11/11/2021

A nationstate attack leverages n-/0-day exploits to persistently infect Apple systems with a new macOS implant.


[continue reading »](https://objective-see.org/blog/blog_0x69.html)

Made In America: Green Lambert for OS X

10/01/2021

In this guest blog post, the security researcher Runa Sandvik analyzes OSX.GreenLambert, a first-stage macOS implant utilized by the CIA.


[continue reading »](https://objective-see.org/blog/blog_0x68.html)

Made in China: OSX.ZuRu

09/14/2021

Attackers are leveraging trojanized applications to spread malware, via sponsored search results.


In this post we detail the malware's stealthy trojanization technique, subsequent payloads, and more!


[continue reading »](https://objective-see.org/blog/blog_0x66.html)

Analysis of CVE-2021-30860

09/16/2021

In this guest blog post, the security researcher Tom McGuire details the flaw and fix of CVE-2021-30860, azero-click vulnerability, exploited in the wild.


[continue reading »](https://objective-see.org/blog/blog_0x67.html)

Made in China: OSX.ZuRu

09/14/2021

Attackers are leveraging trojanized applications to spread malware, via sponsored search results.


In this post we detail the malware's stealthy trojanization technique, subsequent payloads, and more!


[continue reading »](https://objective-see.org/blog/blog_0x66.html)

OSX.Hydromac

06/04/2021

In this guest blog post, the security researcher [Taha Karim](https://twitter.com/@lordx64) of ConfiantIntel, dives into a new macOS adware specimen: Hydromac.


[continue reading »](https://objective-see.org/blog/blog_0x65.html)

All Your Macs Are Belong To Us

04/26/2021

This is our 100th blog post ...and it's a doozy!


In this post, we detail a bug that trivially bypasses many core Apple security mechanisms, leaving Mac users at grave risk!


[continue reading »](https://objective-see.org/blog/blog_0x64.html)

Creating Shield

03/10/2021

In this guest blog post, the Mac security researcher [Csaba Fitzl](https://twitter.com/theevilbit9), descrbibes his journey creating an app to protect against process injection on macOS.


[continue reading »](https://objective-see.org/blog/blog_0x63.html)

Arm'd & Dangerous

02/14/2021

Apple's new M1 systems offer a myriad of benefits, that malware authors are now leveraging.


Here, we detail the first malicious program, compiled to natively target Apple Silicon (M1/arm64)!


[continue reading »](https://objective-see.org/blog/blog_0x62.html)

Discharging ElectroRAT

01/05/2021

The first (macOS) malware of 2021 is an insidious remote access tool (RAT), containing a variety of embedded payloads to extend its functionality.


...in this post we analyze the macOS variant of `ElectroRAT`, uncovering its persistence mechanism and capabilities.


[continue reading »](https://objective-see.org/blog/blog_0x61.html)

The Mac Malware of 2020

01/01/2021

It's here! Our annual report on all the Mac malware of the year (2020 edition).


Besides providing samples for download, we cover infection vectors, persistence mechanisms, payloads and more!


[continue reading »](https://objective-see.org/blog/blog_0x5F.html)

Detecting SSH Activity via Process Monitoring

12/10/2020

In this guest blog post, the noted Mac security researcher/author [Jaron Bradley](https://twitter.com/jbradley89) explains how to detect (potentially malicious) SSH activity


...via process monitoring and the analysis of process hierarchies.



[continue reading »](https://objective-see.org/blog/blog_0x5D.html)

Adventures in Anti-Gravity (Part II)

11/27/2020

Here we continue to deconstruct the Mac variant of GravityRAT.


...reverse-engineering a malicious Electron application component.



[continue reading »](https://objective-see.org/blog/blog_0x5C.html)

Adventures in Anti-Gravity (Part I)

11/03/2020

Here we deconstruct a Mac variant of GravityRAT (the cross-platform spyware, known to target the Indian armed forces).


...reverse-engineering its Python, AppleScript, and Mach-O components.



[continue reading »](https://objective-see.org/blog/blog_0x5B.html)

Property List Parsing Bug(s)

10/21/2020

In this guest blog post, the security researcher behind [@OSCartography](https://twitter.com/OSCartography), describes a bug related to parsing property lists.


...via this bug, it was trivial to crash macOS!



[continue reading »](https://objective-see.org/blog/blog_0x5A.html)

FinFisher Filleted

09/26/2020

Interested in learning about a macOS cyber-espionage implant ...that leveraged priv-escalation exploits and a kernel-mode rootkit!?


In this post, we analyze the macOS version of FinSpy.



[continue reading »](https://objective-see.org/blog/blog_0x4F.html)

Apple Approved Malware

08/30/2020

Unfortunately we didn't have to wait long before hackers found a way to (ab)use Apple's new notarization service to get their malware approved!


In this post, we tear apart an adware campaign that utilized malicious payloads containing Apple's notarization "stamp of approval".



[continue reading »](https://objective-see.org/blog/blog_0x4E.html)

Office Drama on macOS

08/04/2020

Even wondered how a system can be persistently infected by simply opening a document?


In this post, I detail an exploit chain (created by yours truly), that was able fully infect a fully-patched macOS Catalina system, by simply opening a malicious (macro-laced) Office document ...no alerts, prompts, nor other direct user interactions required!



[continue reading »](https://objective-see.org/blog/blog_0x4B.html)

CVE-2020–9854: "Unauthd"

08/01/2020

Security researcher [Ilias Morad](https://twitter.com/A2nkF_) describes an impressive exploit chain, combining three macOS logic bugs he uncovered in macOS.


His exploit chain allowed a local user to elevate privileges all the way to ring-0 (kernel)!



[continue reading »](https://objective-see.org/blog/blog_0x4D.html)

CVE-2020–9934: Bypassing TCC for Unauthorized Access

07/29/2020

In this guest blog post, security researcher [Matt Shockley](https://twitter.com/mattshockl) describes a lovely security vulnerability he uncovered in macOS.


This bug allowed for a complete bypass of TCC's draconian entitlement checks, all without writing a single line of code!


[continue reading »](https://objective-see.org/blog/blog_0x4C.html)

Low-Level Process Hunting on macOS

07/19/2020

Parent-child relationships are one of the simplest & most effective ways to detect malicious activity at the host level.


...however on macOS things can get a little complex. Luckily security researcher [Jaron Bradley](https://twitter.com/jbradley89) is here to explain exactly what is going on!


[continue reading »](https://objective-see.org/blog/blog_0x4A.html)

OSX.EvilQuest Uncovered (part two)

07/03/2020

OSX.EvilQuest is a new piece of malware targeting Mac users.


In part two, we analyze the malware's viral infection capabilities, and detail its insidious capabilities.


[continue reading »](https://objective-see.org/blog/blog_0x60.html)

OSX.EvilQuest Uncovered (part one)

06/29/2020

OSX.EvilQuest is a new piece of malware targeting Mac users.


In part one, we analyze the malware's infection vector, persistence mechanism, and anti-analysis logic.


[continue reading »](https://objective-see.org/blog/blog_0x59.html)

Tiny SHell Under the Microscope

06/01/2020

Tiny SHell is a lightweight backdoor used in APT attacks against Mac users.


In this (guest) post, the noted macOS security researcher (and #OBTS speaker!) [Jaron Bradley](https://twitter.com/jbradley89) provides a comprehensive analysis!


[continue reading »](https://objective-see.org/blog/blog_0x58.html)

The Dacls RAT ...now on macOS!

05/05/2020

A sophisticated Lazarus Group implant has arrived on macOS.


In this post, we deconstruct the Mac variant of a OSX.Dacls, detailing its install logic, persistence, and capabilities.


[continue reading »](https://objective-see.org/blog/blog_0x57.html)

The 'S' in Zoom, Stands for Security

03/30/2020

Today we uncover two (local) security flaws in Zoom's latest macOS client.


First, a privilege escalation vulnerability, and second, a method to surreptitiously access a user's webcam and microphone (via Zoom).


[continue reading »](https://objective-see.org/blog/blog_0x56.html)

Sniffing Authentication References on macOS

03/17/2020

CVE-2017-7170 was a local priv-esc vulnerability that affected OSX/macOS for over a decade!


Here (for the first time!), we dive into the technical details of finding the bug, the core flaw, and exploitation.


[continue reading »](https://objective-see.org/blog/blog_0x55.html)

Weaponizing a Lazarus Group Implant

03/22/2020

The Lazarus group's latest implant/loader supports in-memory loading of 2nd-stage payloads.


In this post we describe exactly how to repurposing this 1st-stage loader to execute \*our\* custom 'fileless' payloads!


[continue reading »](https://objective-see.org/blog/blog_0x54.html)

The Mac Malware of 2019

01/01/2020

It's here! Our annual report on all the Mac malware of the year (2019 edition).


Besides providing samples for download, we cover infection vectors, persistence mechanisms, payloads and more!


[continue reading »](https://objective-see.org/blog/blog_0x53.html)

Mass Surveillance, is an (un)Complicated Business

12/20/2019

A massively popular iOS application turns out to be a government spy tool!


Here, we analyze the app; decrypting its binary and studying its network traffic.



[continue reading »](https://objective-see.org/blog/blog_0x52.html)

Lazarus Group Goes 'Fileless'

12/03/2019

The rather infamous APT group, "Lazarus" continues to evolve their macOS capabilities.


Today, we tear apart their latest 1st-stage implant that supports remote download & in-memory execution of secondary payloads!



[continue reading »](https://objective-see.org/blog/blog_0x51.html)

\[0day\] Abusing XLM Macros in SYLK Files

11/03/2019

Ever heard of SYLK files? Yah, me neither!


Turns out they can be abused to coerce Microsoft Excel to silently and automatically execute malicious macros on macOS. Yikes!



[continue reading »](https://objective-see.org/blog/blog_0x50.html)

Pass the AppleJeus

10/12/2019

A new macOS backdoor written by the infamous Lazarus APT group needs analyzing. Here, we examine it's infection vector, method of persistence, capabilities, and more!


[continue reading »](https://objective-see.org/blog/blog_0x49.html)

Writing a File Monitor with Apple's Endpoint Security Framework

09/17/2019

Turns out, we can also leverage Apple's new "Endpoint Security Framework" to create a comprehensive (user-mode) File Monitor for macOS 10.15!


[continue reading »](https://objective-see.org/blog/blog_0x48.html)

Writing a Process Monitor with Apple's Endpoint Security Framework

09/16/2019

Apple's new "Endpoint Security Framework" is 🔥


Learn how to leverage it to create a comprehensive (user-mode) Process Monitor for macOS 10.15!


[continue reading »](https://objective-see.org/blog/blog_0x47.html)

Getting Root with Benign AppStore Apps

07/02/2019

In this guest blog post, "Objective by the Sea" speaker, [Csaba Fitzl](https://twitter.com/theevilbit) writes about an interesting way to get root via Apps from the official Mac App Store!


[continue reading »](https://objective-see.org/blog/blog_0x46.html)

Burned by Fire(fox) (Part III)

06/23/2019

Recently, an attacker targeted (Mac) users via a Firefox 0day.


In this third post, we analyze a second backdoor used in the attack, detailing its persistence, capabilities, and ultimate identify it a new variant of the cross-platform Mokes malware!


[continue reading »](https://objective-see.org/blog/blog_0x45.html)

Burned by Fire(fox) (Part III)

06/22/2019

Recently, an attacker targeted (Mac) users via a Firefox 0day.


In this second post, we fully reverse OSX.NetWire.A, revealing (for the first time!), its inner workings and complex capabilities.


[continue reading »](https://objective-see.org/blog/blog_0x44.html)

Burned by Fire(fox) (Part I)

06/20/2019

Recently, an attacker targeted (Mac) users via a Firefox 0day.


Let's triage the malware utilized in this attack, identifying it's methods of persistence, and more!


[continue reading »](https://objective-see.org/blog/blog_0x43.html)

"Objective by the Sea" v2.0

06/11/2019

After the success of #OBTS v1.0, we decided to go international and plan #OBTS v2.0 in Europe! 💥


In this blog post, we re-live the highlights, from Monaco, of "Objective by the Sea" v2.0.


[continue reading »](https://objective-see.org/blog/blog_0x42.html)

Rootpipe Reborn (Part II)

04/24/2019

In part two of this guest blog post, [@CodeColorist](https://twitter.com/CodeColorist) continues writing about several more macOS vulnerabilities.


His bugs, CVE-2019-8521 and CVE-2019-8565 could be exploited to once again, elevate privileges to root!


[continue reading »](https://objective-see.org/blog/blog_0x41.html)

Rootpipe Reborn (Part I)

04/14/2019

In part one of a guest blog post, [@CodeColorist](https://twitter.com/CodeColorist) writes about several neat macOS vulnerabilities.


His bugs, CVE-2019-8513 and CVE-2019-8530, could be exploited in local privilege escalation (LPE) attacks!


[continue reading »](https://objective-see.org/blog/blog_0x40.html)

Mac Adware, à la Python

03/25/2019

Chances are, if an Apple user tells you their Mac is infected, it's likely adware.


Today, we tear apart a persistent piece of adware, decompiling, decoding, & decompressing it's code to uncover its methods & capabilities.


[continue reading »](https://objective-see.org/blog/blog_0x3F.html)

Death by vmmap

02/25/2019

A core macOS utility, vmmap is rather disastrously broken, and may cause a full-system lockup!


By reversing Apple's binary, we can uncover an interesting flaw introduced in macOS Mojave.


[continue reading »](https://objective-see.org/blog/blog_0x3E.html)

Middle East Cyber-Espionage (part two)

01/15/2019

The APT group WINDSHIFT, has been targeting Middle Eastern governments with Mac implants.


In part two, we continue to analyze a new sample of their 1st-stage macOS implant: OSX.WindTail.


[continue reading »](https://objective-see.org/blog/blog_0x3D.html)

The Mac Malware of 2018

01/01/2019

It's here! Our annual report on all the Mac malware of the year (2018 edition).


Besides providing samples for download, we cover infection vectors, persistence mechanisms, payloads and more!


[continue reading »](https://objective-see.org/blog/blog_0x3C.html)

Middle East Cyber-Espionage

12/20/2018

The APT group WINDSHIFT, has been targeting Middle Eastern governments with Mac implants.


We uncovered a new sample of their 1st-stage macOS implant: OSX.WindTail. Let's dive in!


[continue reading »](https://objective-see.org/blog/blog_0x3B.html)

Word to Your Mac

12/05/2018

A malicious Word document targeting macOS users, was recently uncovered.


Let's extract the embedded macros, decode an embedded downloader, and retrieve the 2nd-stage payload!


[continue reading »](https://objective-see.org/blog/blog_0x3A.html)

\[0day\] Mojave's Sandbox is Leaky

11/29/2018

The macOS sandbox is seeks to prevent malicious applications from surreptitiously spy on unsuspecting users.


Turns out, it's trivial to sidestep some of these protections, resulting in significant privacy implications!


[continue reading »](https://objective-see.org/blog/blog_0x39.html)

A Deceitful 'Doctor' in the Mac App Store

09/07/2018

A massively popular app from the official Mac App Store, surreptitiously steals your browsing history!


By fully reversing the application, we can fully expose its functionality and rather shady capabilities.


[continue reading »](https://objective-see.org/blog/blog_0x37.html)

Remote Mac Exploitation Via Custom URL Schemes

08/30/2018

The WINDSHIFT APT group is successfully infecting Macs with a novel infection mechanism.


By abusing custom URL scheme handlers and minimal user interaction, Macs can be remotely compromised!


[continue reading »](https://objective-see.org/blog/blog_0x38.html)

\[0day\] Synthetic Reality

08/20/2018

If you can programmatically generate synthetic mouse clicks, you can break macOS!


Approving kernel extensions, dismissing privacy alerts, and much more more...


[continue reading »](https://objective-see.org/blog/blog_0x36.html)

Escaping the Microsoft Office Sandbox

08/15/2018

Imagine you've gained remote code execution on a Mac via a malicious Word document.


Turns out, you're still stuck in a sandbox. However, via a faulty regex, you can escape and persist!


[continue reading »](https://objective-see.org/blog/blog_0x35.html)

Block Blocking Login Items

07/23/2018

Apple recently updated the way login items are stored by the OS.


Let's reverse the format of these (new) login item files, and discuss ways to programmatically parse them, in order to detect persistence.


[continue reading »](https://objective-see.org/blog/blog_0x31.html)

A Remote iOS Bug

07/10/2018

Apple wrote code to appease the Chinese government ...it was buggy.


In certain configurations, iOS devices were vulnerable a "emoji-related" flaw that could be triggered remotely!


[continue reading »](https://objective-see.org/blog/blog_0x34.html)

\[0day\] Bypassing SIP via Sandboxing

07/07/2018

In this guest blog post @CodeColorist writes about a neat macOS vulnerability.


Ironically, by abusing security mechanisms such as sandboxing, macOS can be coerced to load an untrusted library, into a SIP-entitled process!


[continue reading »](https://objective-see.org/blog/blog_0x33.html)

OSX.Dummy

06/29/2018

A new Mac malware targets the cryptocurrency community.


In this post, we dive into the malware and illustrate how Objective-See's tools can generically thwart this new threat at every step of the way.


[continue reading »](https://objective-see.org/blog/blog_0x32.html)

Cache Me Outside

06/15/2018

Turns out that Apple's 'QuickLook' cache may leak encrypted data.


Are full paths & preview thumbnails for files even on encrypted containers and removable usb devices really persistently stored? ...yes :(


[continue reading »](https://objective-see.org/blog/blog_0x30.html)

Breaking macOS Mojave Beta

06/06/2018

In macOS Mojave apps, to have to obtain user permission before using the Mac camera & microphone.


After detailing how this security mechanism is implemented, we illustrate how this is trivial to bypass (at least in the current beta).


[continue reading »](https://objective-see.org/blog/blog_0x2F.html)

When Disappearing Messages Don't Disappear

05/08/2018

Did you know on macOS, notifications are stored in a unencrypted database? Which means that even 'disappearing' messages from apps such as Signal - may not really disappear. Yikes!


Let's dig into why this occurs, how to dump (and parse) the binary content of this database, and discuss possible mitigations.


[continue reading »](https://objective-see.org/blog/blog_0x2E.html)

An Insecurity in Apple's Security Framework?

05/02/2018

Turns out that writing security tools is a great way to inadvertently uncover bugs in macOS. How about a crash in Apple's 'Security' framework ... that can't be good!?


Going from a crash report to uncovering and understanding a flaw in Apple's code, takes a bit of work - but we got this!


[continue reading »](https://objective-see.org/blog/blog_0x2D.html)

Who Moved My Pixels?!

04/05/2018

In this guest blog post, my good friend Mikhail Sosonkin (@hexlogic) reverses Apple's screencapture utility in order to peak behind the (figurative) curtain and uncover how it works.


He also looks at some Mac malware from 2013 that captured desktop images, and suggests methods for detecting screen capturing!


[continue reading »](https://objective-see.org/blog/blog_0x2C.html)

A Surreptitious Cryptocurrency Miner in the Mac App Store?

03/11/2018

A friend pinged me about an application on the official Mac App Store that reportedly was rather surreptitiously mining cryptocurrency. I was intrigued, and thus decided to investigate!


Turns out the innocuously named "Calendar 2" app has the ability to rather surreptitiously turn your Mac into a cryptocurrency miner.


[continue reading »](https://objective-see.org/blog/blog_0x2B.html)

Tearing Apart the Undetected (OSX)Coldroot RAT

02/17/2018

In preparation for an upcoming conference talk, I was poking around on VirusTotal looking for illustrative examples and stumbled across something brand new!


CrossRat is a new (and previously undetected) cross-platform backdoor, providing persistent, remote, command and control of infected systems.


[continue reading »](https://objective-see.org/blog/blog_0x2A.html)

Analyzing OSX/CreativeUpdater

02/05/2018

Links to applications on the popular MacUpate website, were recently compromised to point to a malicious macOS trojan; OSX/CreativeUpdater.


This malware persistently installs itself in order to mine cryptocurrency on victims Macs...and did the author inadvertently leave his name in the malware!?


[continue reading »](https://objective-see.org/blog/blog_0x29.html)

Analyzing CrossRAT

01/24/2018

The EFF/Lookout discovered a cross-platform implant, named CrossRat. With ties to nationstate operators it is designed to spy on governments, military, plus journalists & activists.


In this blog post, we'll dive into CrossRat, analyzing its persistence mechanisms, features, and C&& server communications.


[continue reading »](https://objective-see.org/blog/blog_0x28.html)

An Unpatched Kernel Bug

01/16/2018

On my flight to ShmooCon, I managed to panic my fully-patched MacBook.


Analyzing the kernel panic report, it turns out Apple's AMDRadeonX4150 kext is responsible for the crash...why?


[continue reading »](https://objective-see.org/blog/blog_0x27.html)

Ay MaMi - Analyzing a New macOS DNS Hijacker: OSX/MaMi

01/11/2018

2018 is barely two weeks old, and already it looks like we've got new piece of macOS malware! Hooray :)


OSX/MaMi hijacks infected users' DNS settings and installs a malicious certificate into the System keychain, in order to give remote attackers 'access' to all network traffic.


[continue reading »](https://objective-see.org/blog/blog_0x26.html)

All Your Docs Are Belong To Us

01/01/2018

In this blog post we'll detail how to reverse, then 'extend' a popular macOS anti-virus engine. With the creation of a new anti-virus signature, classified documents will be automatically detected.


Why would anybody want to do this? You'll have to read the blog! Plus see why any anti-virus product is only one signature away from being the absolute perfect cyber-espionage collection tool.


[continue reading »](https://objective-see.org/blog/blog_0x22.html)

Mac Malware of 2017

12/23/2017

For the second year in a row, I've decided to post a blog that comprehensively covers all the new Mac malware that appeared during the course of the year.


For each sample, we'll identify the malware's infection vector, persistence mechanism, features & goals, and describe how to clean an infected system.


[continue reading »](https://objective-see.org/blog/blog_0x25.html)

Why <blank> Gets You Root

11/29/2017

Yet another a massive security flaw affects the latest version of macOS (High Sierra). The bug allows anybody to log into the root account with a blank, or password, of their choosing. Yikes!


Here, we reverse various macOS components to track down its root cause.


[continue reading »](https://objective-see.org/blog/blog_0x24.html)

From the Top to the Bottom; Tracking down CVE-2017-7149

11/25/2017

High Sierra suffered from a nasty bug (CVE-2017-7149) that afforded local attackers access to the contents of encrypted APFS volumes!


In this blog post, we'll start at the user-interface (UI) level, then dig deeper into various components of macOS in order to illustrate the root cause of the bug.


[continue reading »](https://objective-see.org/blog/blog_0x23.html)

High Sierra's 'Secure Kernel Extension Loading' is Broken

09/05/2017

A new 'security' feature in macOS 10.13, is trivial to bypass.


In this blog post we'll take a brief look at High Sierra's somewhat controversial "Secure Kernel Extension Loading" (SKEL) feature. Unfortunately despite Apple's (I hope not best) efforts, it's trivial to completely bypass. Opps!


[continue reading »](https://objective-see.org/blog/blog_0x21.html)

WTF is Mughthesec!? Poking on a Piece of Undetected Adware

8/8/2017

An undetected piece of adware is infecting Mac computers.


Our journey starts with the signed installer, a fake Flash Player installer. From this, we'll uncover the persistence techniques and capabilities of adware binary named "Mughthesec".


[continue reading »](https://objective-see.org/blog/blog_0x20.html)

OSX/MacRansom: Analyzing new Ransomware Targeting Macs

6/12/2017

Looks like somebody on the 'dark web' is offering 'Ransomware as a Service'...that's designed to infect Macs!


We'll dig into the technical details of this malware, OSX/MacRansom, discussing it's anti-analysis traps, persistence mechanisms, and logic for encrypting users' files. Though once the encryption has occurred files may be lost for ever, Objective-See's tools can stop the ransomware in its tracks :)


[continue reading »](https://objective-see.org/blog/blog_0x1E.html)

OSX/Proton.B; a Brief Analysis, at 6 Miles Up

5/10/2017

HandBrake's mirror server was compromised to distribute OSX/Proton.B.


First, we'll look at how the trojaned HandBrake.app executes the malware, before diving into the technical details and capabilities of OSX/Proton.B. For example, we'll show how to coerce the malware to decrypt its configuration & command file, revealing it's capabilities.


[continue reading »](https://objective-see.org/blog/blog_0x1F.html)

HandBrake Hacked! OSX/Proton (re)Appears

5/07/2017

The website of the popular open-source video transcoder, HandBrake, was hacked.


The hackers trojaned the legitimate HackBrake application with a new variant of OSX/Proton. In this blog post, we'll describe how the app was trojaned and how the malware persistently installs itself.


[continue reading »](https://objective-see.org/blog/blog_0x1D.html)

Two Bugs, One Func(), part three

4/24/2017

While analyzing code in the kernel audit subsystem, I discovered an exploitable heap overflow in Apple's code!


This final part of this 3-part blog 'series' describes the underlying cause of the ring-0 overflow, how it may be triggered, and discussing possibilities for exploitation.


[continue reading »](https://objective-see.org/blog/blog_0x1C.html)

Two Bugs, One Func(), part two

4/06/2017

Apple fixed the off-by-one error dicusssed in the last blog, that could cause a kernel panic. Or did they?


No, they didn't :( In fact they made it worse by introducing a new kernel information leak. We'll dive into this new security vulnerability found within the macOS kernel, to show about carefully crafted UNIX sockets can leak kernel memory to user-mode when auditing is enabled.


[continue reading »](https://objective-see.org/blog/blog_0x1B.html)

Two Bugs, One Func(), part one

3/27/2017

While improving RansomWhere? I triggered a kernel panic...from user-mode!


Armed with a kernel panic report, I was able to track down the faulting instruction and figure out the cause of the bug. Part one of this 3-part blog 'series' describes how to analyze a kernel panic report, reverse the macOS kernel to track down the faulting instruction, and why I believe this bug was intentional, albeit non-maliciously so.


[continue reading »](https://objective-see.org/blog/blog_0x1A.html)

Happy Birthday to Objective-See

3/19/2017

Today is our 2nd birthday! So far it's been an incredible ride :) And cliche as it sounds, Objective-See couldn't have done it without you.


In this brief blog, we look at our humble beginnings, what we've accomplished in 2 years, and plans for the future!


[continue reading »](https://objective-see.org/blog/blog_0x19.html)

From Italy With Love?

2/17/2017

A new piece of malware (XagentOSX/Komplex.B), was recently discovered with ties to Russia. I decided to analyze the code injection logic, with the goal of uncovering how the injection was being performed.


The reversing session took an interesting twist when I recognized that the injection code had clear ties to an Italian offensive cybersecurity company. Did the malware authors reimplement the injection logic or directly copy & paste from leaked source code!? Thru detailed reversing and code analysis, we'll provide a concise answer :)


[continue reading »](https://objective-see.org/blog/blog_0x18.html)

New Attack, Old Tricks

2/6/2017

Today, Monday the 6th, was a busy day for macOS malware! First, Nex (@botherder) posted a great writeup, [iKittens: iranian actor resurfaces with malware for mac (macdownloader)"](https://iranthreats.github.io/resources/macdownloader-macos-malware/), which detailed some new macOS malware.


Shortly thereafter, my friend Scott (@0xdabbad00) brought to my attention a tweet, which pointed to a malicious Word document targeting Mac users. Intriguing! I grabbed the sample, noting that only 4 AV engines currently flagged it as malicious...


[continue reading »](https://objective-see.org/blog/blog_0x17.html)

Mac Malware of 2016

1/1/2017

Due to sheer volume, Windows malware generally dominates the malicious code and news scene. Of course, Macs are susceptible to malware as well and 2016 saw a handful of new malware targeting Apple computers.


In this blog, we'll discuss all Mac malware that appeared in 2016. While each sample has been reported on before (i.e. by the AV company that discovered it), this blog aims to cumulatively cover all in one place. Moreover, for each, we'll identify the infection vector, persistence mechanism, features/goals, and describe disinfection.


[continue reading »](https://objective-see.org/blog/blog_0x16.html)

'Untranslocating' an App

12/15/2016

Apple introduced 'App Translocation' in macOS Sierra to fix a myriad of issues (e.g. CVE 2015-3715, CVE 2015-7024) which I uncovered in Gatekeeper.


Unfortunately it broke many legitimate applications including my own :( Here, I discuss various suggested solutions and illustrate how none are ideal. Instead, we'll see that if the application is locally 'untranslocated' this fixes all!



[continue reading »](https://objective-see.org/blog/blog_0x15.html)

\[0day\] Bypassing Apple's System Integrity Protection

12/01/2016

Apple's System Integrity Protection (SIP) is one of the cornerstones of macOS's local security posture. But what good is it if it can be bypassed? Or worse, used against itself?


Here, we discuss an unpatched 0day security issue that can allow an attacker to coerce the system to boot of a malicious image, and thus trivially bypass SIP. Opps!



[continue reading »](https://objective-see.org/blog/blog_0x14.html)

Forget the NSA, it's Shazam that's always listening!

11/13/2016

An OverSight user recently emailed me, asking why OverSight did not generate a 'Mic Deactivation' alert when he turned off Shazam on his Mac. I reverse-engineered the Shazam application, to figure out what was going on.


Turns out, that when Shazam (macOS) is toggled 'OFF' it to simply stops _processing_ recorded data...however recording continues.



[continue reading »](https://objective-see.org/blog/blog_0x13.html)

Click File, App Opens

08/23/2016

Recently, noted OS X malware analyst Thomas Reed (@thomasareed) of MalwareBytes posted a [writeup](https://blog.malwarebytes.com/threat-analysis/2016/08/pcvark-plays-dirty) detailing a new piece of OS X malware: 'Mac File Opener.' Packaged in an 'Advanced Mac Cleaner' installer, Thomas noted that this malware is a fairly standard 'run-of-the-mill' adware, save for way it attempts to gain execution via 'document handler(s).' Let's look closely at the concept "document handlers," how an application can register to handle various file types, and what goes on behind the scenes to make this all work.



[continue reading »](https://objective-see.org/blog/blog_0x12.html)

Persisting via a Finder Sync

07/24/2016

One of the benefits of writing security tools is that one gets a deeper understanding of the OS. I've been working on small utility that adds a menu item to the control-/right-click menu for files (in Finder.app, the desktop, etc). Apple states that the way to extend Finder.app is via a 'Finder Sync' extension. This blog post looks at how to achieve such Finder 'integration' and then explores how malicious code could abuse this for persistence.



[continue reading »](https://objective-see.org/blog/blog_0x11.html)

Are you from the Mac App Store?

05/01/2016

Let's discuss how to use receipt verification to determine if an application is from Apple's Mac App Store. While this has been covered elsewhere, such resources are somewhat outdated, require external dependencies (openssl), are iOS specific, or are copyrighted. To follow along in code, grab the complete [source code](https://github.com/objective-see/fromAppStore) from GitHub.



[continue reading »](https://objective-see.org/blog/blog_0x10.html)

Towards Generic Ransomware Detection

04/20/2016

Unless you've been living under an 'infosec rock', you're likely aware that ransomware is somewhat of a problem - to put it mildly. There are already claims that "2016 is shaping up as the year of ransomware" and that "this is basically becoming a national cyber emergency". And everywhere one looks, ransomware-related articles, tweets, and even FBI bulletins abound.



Sadly, existing anti-virus solutions fail to detect new samples, leaving most users completely unprotected. So what to do? panic? join the dark-side and create ransomware to make millions? naw...let's do something a little more productive (and responsible).


[continue reading »](https://objective-see.org/blog/blog_0x0F.html)

Analysis of an Intrusive Cross-Platform Adware; OSX/Pirrit

04/05/2016

In Objective-See's first guest blog post, Amit Serper ( [@0xAmit](https://twitter.com/0xAmit)) presents his detailed analysis of OSX/Pirrit. Amit, mahalo for sharing your research!


Amit: I remember adware being a really big buzzword at the beginning of the previous decade. Windows machines were being constantly bombarded with popups, popunders, toolbars and other annoying ways to plant advertisements in your browser. Back then I was a teenager running Windows and refused to install anti-spyware and anti-adware software because there was a rumor that those applications were, in fact, adware themselves! I created my own workaround by running msconfig, going through all of the startup items and removing anything that looked weird. That method almost always worked!



Fast forward to today...


[continue reading »](https://objective-see.org/blog/blog_0x0E.html)

HackingTeam Reborn; A Brief Analysis of an RCS Implant Installer

02/26/2016

As I'm generally quite occupied with my day job as Director of R&D at [Synack](https://synack.com/), the weekend is when I finally have some free time to blog. This weekend I wasn't sure what I'd write about until @osxreverser tweeted late Friday afternoon: " _Apple Encrypted binaries? I guess Italians still unable to create packers? :X_"


Obviously the Italians, referenced here, are HackingTeam - but what about _"Apple's Encrypted binaries"_...that to me was the intriguing part! (well and the fact that I didn't know HackingTeam was still around, after getting totally owned).


[continue reading »](https://objective-see.org/blog/blog_0x0D.html)

Analyzing the Anti-Analysis Logic of an Adware Installer

02/07/2016

Recently, SANS posted a short blog post titled ["Fake Adobe Flash Update OS X Malware"](https://isc.sans.edu/forums/diary/Fake+Adobe+Flash+Update+OS+X+Malware/20693/). While the blog covers the initial infection vector, and subsequent [articles](https://www.intego.com/mac-security-blog/fake-flash-player-update-infects-mac-with-scareware) provide a decent overview of the attack, here, let's briefly discuss some of the anti-analysis techniques utilized by the malware installer.


[continue reading »](https://objective-see.org/blog/blog_0x0C.html)

Monitoring Process Creation via the Kernel (Part III)

12/13/2015

The previous two [blog](https://objective-see.org/blog.html#blogEntry9) [posts](https://objective-see.org/blog/blog_0x0A.html) discussed why BlockBlock required processes creation notifications, and showed several ways to achieve this via a kernel extension. Today, let's conclude this blog mini-series by describing one way to get this 'process creation information' from the kernel to a user-mode application.


The starting point for this blog is in the kernel, where the kext has just received a process creation notification, either via a MAC policy or a KAuth listener. This information must now be delivered to the user-mode component of BlockBlock so that when a persistent file I/O event occurs, the event may be correlated with the responsible process.


[continue reading »](https://objective-see.org/blog/blog_0x0B.html)

Monitoring Process Creation via the Kernel (Part II)

11/22/2015

Last week, in ( [part I](https://objective-see.org/blog.html#blogEntry9)) of this blog mini-series, I discussed why BlockBlock required processes creation notifications, and one way to achieve this via a kext. Specifically, the blog post showed a MAC policy could be registered that would receive notification whenever a process was started.


Once I posted the blog, the venerable @osxreverser and others (mahalo Simon!), were kind enough to reach out to me to mention that such process monitoring could equally be achieved via the Kernel Authorization (KAuth) subsystem. As the KAuth interface is a more stable API than the MAC framework (which is 'unsupported' by Apple), I decided to explore this option.


[continue reading »](https://objective-see.org/blog/blog_0x0A.html)

Monitoring Process Creation via the Kernel (Part I)

11/15/2015

Update: Several people have reached out to me (mahalo!) to mention that the KAuth API can also be used to monitor process creation from a kext. While I wait for a kext signing certificate from Apple I'll going to check this out, as KAuth interface appears more stable than the prototype of the MAC policy function. Findings will be included in part II of this blog posting :)

Having recently returned from presenting at VirusBulletin and EkoParty, I finally have some free time to catchup on my _todo_ list. First up? - updating BlockBlock for El Capitan compatibility. Although most of BlockBlock's code and logic works great on El Capitan, one component is completely broken...thanks to Apple's changes to their latest OS.


Background

BlockBlock monitors file I/O events in order to detect "persistence attempts." When it detects such an event, it alerts the user. In order to provide an informative alert, the alert popup contains the pid, path, and ancestry of the process responsible for at attempted persistence:


![](https://objective-see.org/images/BB/bb.png)

Although an application could use the [FSEvents API](https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/FSEvents_ProgGuide/Introduction/Introduction.html#//apple_ref/doc/uid/TP40005289-CH1-SW1) to be alerted of specific file and directory changes, this API does not provide information about the process that generated the event. That is to say, sure you get notifications from the API such as, "hey, a new launch daemon (plist) was created" - but there is no direct or trivial way to then get the pid and/or path of the process that created the new daemon.


As such BlockBlock utilizes the /dev/fsevents device directly, as [suggested](http://osxbook.com/software/fslogger/download/fslogger.c) by Amit Singh in his seminal "OS X Internals" book. While this mechanism captures all file I/O (as opposed to only events of interest), it does provide the process id (pid) of the process that generated the file I/O event. Now this is a good start, but as previously mentioned, BlockBlock seeks to provide the user more information about the responsible process such that the user may make an educated decision. For example, being able to display the process's path and process ancestry is definitely useful (if not essential), information that should be contained in a BlockBlock alert.


Generally, given a pid, one can simply call API functions such as proc\_pidpath (see [libproc.c)](http://www.opensource.apple.com/source/xnu/xnu-2782.40.9/libsyscall/wrappers/libproc/libproc.c) to get a process's path. However, if the process is short-lived and has already exited, this (and other) APIs will fail. As such, BlockBlock separately keeps a list of all process creations that includes somewhat detailed information about each process such as its pid and full path. Then, when a "persistence attempt" is detected via the file I/O monitoring component, even if the process has exited, BlockBlock can use the pid that's tied to the file I/O event to query its process list to get required information, such as the process's path.


Prior to El Capitan, BlockBlock used programmatic dtrace probes in order to record process creation events. Specifically it set probes from user-mode, on:


1\. syscall::exec\*:return

2\. proc::posix\_spawn:exec-success

3\. syscall::fork:return

These probes allowed not only pids, but also process paths, uids, and ppids to be recorded by BlockBlock. All was well :)


Then along came El Capitan - and basically said, "no more (meaningful) dtrace" Don't believe me? Try running Apple's very own exesnoop that ships with the OS. As it uses dtrace, it's totally broken, even when run as root :(


![](https://objective-see.org/images/blog/blog9/execSnoop.png)

When I reached out to Apple about this I was [told](https://twitter.com/hey_pom/status/663175315854766082): "\[you\] can't trace syscalls using dtrace when SIP is enabled. We \[Apple\] can't make the distinction between a path or something more private."


It should be noted that yes, one can still do basic dtracing of some processes. However, there appears to be no (legitimate) way of tracking process creation events via dtrace, in a way that also provided semi-detailed information about the process, such as its full path. As BlockBlock requires (or I should say, prefers) such detailed information I had to explore other approaches.


First, thanks to [suggestion](https://twitter.com/hey_pom/status/663186671983161344?lang=en) from @hey\_pom, I dove into the audit (open BSM) framework. While this isn't that well documented, I was able to coerce some user-mode code to cough up some semi-detailed information for each process creation. Unfortunately, this information varied based on how the process was created (execv'd, forked, or spawned). For example; when a process is forked, the audit subsystem only provides the pid (no path), while for a spawned process, only the process's path is provided:


![](https://objective-see.org/images/blog/blog9/openBSM.png)

This is less than ideal, as BlockBlock requires a comprehensive pid -> process path mapping (even for short-lived/terminated processes). With all user-mode options (to the best of my knowledge) exhausted, I decided to head into ring-0.


Ring-0/Kext

Again, my goal was simple; record all process creation events so that at a later time, both the process id and full path of the newly created process would (still be) accessible. After a bunch of googling, it seemed that the simplest way to monitor process creations in ring-0 was via a mandatory access control (MAC) policy. Although this is (still?) an unsupported KPI, we'll see it provides the perfect solution to our issue. That is to say; it provides a comprehensive way to monitor process creations in a detailed manner.


The mandatory access control implementation for OS X is TrustedBSD. For a quick primer and solid overview, checkout ["Working with TrustedBSD in Mac OS X."](http://sysdev.me/trusted-bsd-in-osx/) In terms of using a MAC policy to monitor process creations, I recalled one of @osxreverser's blog post titled ["Can I SUID: a TrustedBSD policy module to control suid binaries execution"](https://reverse.put.as/2014/10/03/can-i-suid-a-trustedbsd-policy-module-to-control-suid-binaries-execution/). In this posting he discussed how one might control the execution of suid binary execution via a MAC policy. The [code](https://github.com/gdbinit/can_I_suid) he shared is easy to follow and shows exactly how to register, via a MAC policy, a function that will be automatically called by the OS anytime process is created. Though he uses this policy function to determine if the process's binary has any SUID bit set, we can tweak the code so that the function can also access process id, path, parent id, and uid. Perfect - that's all we need :)


Let's now walk thru some ring-0 code that implements such a MAC policy/hook (note, we'll cover how to make this information available to BlockBlock's user-mode components in part II of this blog post). If you'd like to follow along in code, its downloadable as an [Xcode project](https://objective-see.org/downloads/BlockBlockKext_MAC.zip). Again, mahalo to @osxreverser - this code is fully inspired by his previous work!


Kernel extensions (or 'kexts') are the legitimately way introduce code into the kernel. There are two kinds of kexts; 'Generic Kernel Extensions' and 'IOKit Drivers':


![](https://objective-see.org/images/blog/blog9/xcodeKextTemplates.png)

Since I wanted BlockBlock to be installable without requiring a reboot, I went with the former. (Apple [answered](https://developer.apple.com/library/mac/qa/qa1319/_index.html) when asked if it is possible to install an I/O Kit kext without requiring a restart: _"There is no easy solution to this problem. Currently, even Apple's own installers require restarting after a kext installation."_)


Conceptually, in order to record detailed information of all process creations, our generic kext only has to do two things. First, register a MAC policy (indicating our desire to monitor process creations). Then, implement the MAC policy function that is automatically invoked by the OS whenever a process is started. Within this function, we can add code to record details about the process (pid, path, ppid, etc).


Step 1: Registering the MAC Policy

In the kext's start function, (specified in kext's build settings, under 'Module Start Routine'), invoke the mac\_policy\_register function. As shown below, this function takes three parameters; a pointer to the MAC policy configuration, an (out) pointer to the MAC policy handle, and the second argument that was passed to the kext's entry point function.


![](https://objective-see.org/images/blog/blog9/macPolicyRegister.png)

The following code snippet, illustratess the invocation of this function:


kern\_return\_t BlockBlockKext\_start(kmod\_info\_t \* ki, void \*d)

{

    ...

//register MAC policy

**mac\_policy\_register(&policyConf, &policyHandle, d);**

    ...

}


Let's take a closer look at the first two parameters of the mac\_policy\_register function. As just mentioned, the first parameter is a pointer to a MAC policy configuration. Specifically this is pointer to a structure of type mac\_policy\_conf. Defined in security/mac\_policy.h this structure is defined as follows:


//defined in security/mac\_policy.h

**struct mac\_policy\_conf**

{

    const char \*mpc\_name;

    const char \*mpc\_fullname;

    const char \*\*mpc\_labelnames;

    unsigned int mpc\_labelname\_count;

    struct mac\_policy\_ops \*mpc\_ops;

    int mpc\_loadtime\_flags;

    int \*mpc\_field\_off;

    int mpc\_runtime\_flags;

    mpc\_t mpc\_list;

    void \*mpc\_data;

};


Although somewhat complex, luckily most the members in this structure can be initialized to blank or NULL values. However, four should (must?) be set.


1) const char \*mpc\_name

This is the policy name. You can pick any string ("BB Process Monitor")


2) const char \*mpc\_fullname

This is the policies full name. Again, pick any string ("BlockBLock Kernel-Mode Process Monitor")


3) struct mac\_policy\_ops \*mpc\_ops;

This is the most important member of the mac\_policy\_con structure. Described by Apple, as an 'operations vector' it should contain a pointer to a mac\_policy\_ops structure. The mac\_policy\_ops structure specifies what operation (e.g. 'process creation') the kext is interested in, and the name of the callback function to invoke when said operation or event occurs. This details of the mac\_policy\_ops structure are discussed in more detail below.


4) int mpc\_loadtime\_flags

These flags indicate such things as whether the policy (and thus kext) can be unloaded ('MPC\_LOADTIME\_FLAG\_UNLOADOK') or when the policy should be loaded.


The following shows the fully populated mac\_policy\_con structure, used in BlockBlock's kext:


//MAC policy

// ->pretty much empty, save for name and pointer to ops vector

static struct mac\_policy\_conf policyConf =

{

    .mpc\_name = "BB Process Monitor",

    .mpc\_fullname = "BlockBLock Kernel-Mode Process Monitor",

    .mpc\_labelnames = NULL,

    .mpc\_labelname\_count = 0,

**.mpc\_ops = &bbPolicyOps,**

    .mpc\_loadtime\_flags = MPC\_LOADTIME\_FLAG\_UNLOADOK,

    .mpc\_field\_off = NULL,

    .mpc\_runtime\_flags = 0,

    .mpc\_list = NULL,

    .mpc\_data = NULL

};


As mentioned (step #3), the mac\_policy\_ops structure tells the OS what policy or event one is interested in. In order to register for process creation notifications, specify the mpo\_vnode\_check\_exec\_t MAC policy operation and provide a callback policy function:


//policy ops

// ->specific MAC hooks

static struct mac\_policy\_ops bbPolicyOps =

{

//only interested in exec

    // ->blockblock's policy function

    .mpo\_vnode\_check\_exec = processExec

};


Step 2: Implementing the MAC Policy Function

Once registered, the policy function (here, named 'processExec') will be automatically invoked by the OS anytime a process is being created.


The prototype of the policy function is rather long, and unfortunately, as @osxreverser notes, sometimes changes between OSs. However, since Yosemite it has remained the same. (As such this kext will only run on versions of OS X Yosemite and newer):


static int \[functionName\] (kauth\_cred\_t cred, struct vnode \*vp, struct vnode \*scriptvp, struct label \*vnodelabel,struct label \*scriptlabel, struct label \*execlabel, struct componentname \*cnp, u\_int \*csflags, void \*macpolicyattr, size\_t macpolicyattrlen);


Luckily, in order to access detailed information about the process being created, only the first vnode parameter (vp) is needed. All other parameters for the purpose of this project, can be ignored. Recall, BlockBlock requires the pid, ppid, uid, and process path, for all created process. Turns out, all this information is readily available within the mpo\_vnode\_check\_exec's policy function (here, named processExec):


1) pid

The process's id, can be accessed via a call to the proc\_selfpid() function


2) ppid

The process's parent id, can be accessed via a call to the proc\_selfppid() function


3) uid

The process's user identifier can be accessed via a call to the kauth\_getuid() function


4) path

The passed in vnode argument pointer ('vp') can be used to get the process's full path. Simply invoke the vn\_getpath() function, passing in the vnode parameter and an out buffer, and pointer to the out buffer's size:


//path

char path\[MAXPATHLEN\] = {0};


//length

int pathLength = MAXPATHLEN;


//get process path

vn\_getpath(vp, path, &pathLength);


Performing steps 1 thru 4 in the MAC policy function (which we named processExec), allows the BlockBlock kext to retrieve all required information about process creations:


//MAC policy function for mpo\_vnode\_check\_exec

// ->automatically invoked anytime a new process is started

static int processExec(kauth\_cred\_t cred, struct vnode \*vp, struct vnode \*scriptvp, struct label \*vnodelabel,struct label \*scriptlabel, struct label \*execlabel, struct componentname \*cnp, u\_int \*csflags, void \*macpolicyattr, size\_t macpolicyattrlen)

{

//path

    char path\[MAXPATHLEN\] = {0};

//length

    int pathLength = MAXPATHLEN;

//uid

    uid\_t uid = -1;

//pid

    pid\_t pid = -1;

//ppid

    pid\_t ppid = -1;

//dbg msg

    printf("BLOCKBLOCK KEXT: MAC policy hook invoked\\n");

//get path

    vn\_getpath(vp, path, &pathLength);

//null-terminate

    // ->just to be safe

    path\[MAXPATHLEN-1\] = 0x0;

//get UID

    uid = kauth\_getuid();

//get pid

    pid = proc\_selfpid();

//get ppid

    ppid = proc\_selfppid();

//dbg msg

    printf("BLOCKBLOCK KEXT: %s %d/%d/%d\\n", path, pid, ppid, uid);

//TODO: part II, send to user-mode!

    ...

}


Go Time

Time to test this out! Since this is a beta kext, I'd suggest testing it in a VM. Once the kext is compiled (simply open in Xcode and hit Project->Build) and copied to the VM, change its owner to root/wheel:


$ sudo chown -R root:wheel BlockBlockKext.kext


Since OS X no longer (legitimately) allows the loading of unsigned kernel extensions by default, the VM must be explicitly configured to disable this 'security' feature. For Yosemite, tell the OS to allow the loading of unsigned kernel extensions via:


$ sudo nvram boot-args=kext-dev-mode=1

$ sudo reboot


On El Capitan accomplish the same via:


a) boot into recovery mode via cmd+r


b) csrutil disable (from Terminal.app)

c) reboot


Now, load the kext:


$ sudo kextload BlockBlockKext.kext


If all goes well the kext should be loaded (I've tested it on Yosemite, and El Capitan). Open Console.app to monitor the kext's output. Try launch some apps, or execute some processes:


![](https://objective-see.org/images/blog/blog9/kextOutput.png)

Obviously for production code, one would want to sign the kernel extension so users can install BlockBlock without having to turn off kext-signing checks. According to online documentation a normal Apple Developer ID is not longer enough to sign a kernel extension. Instead, one must request a 'Developer ID for Signing Kexts' via this [form](https://developer.apple.com/contact/kext/). Seems easy enough assuming one is developing legitimate OS X software? Or so I though:


Me: _"Aloha, Objective-See LLC would like a Developer ID for Signing Kext, so that it may sign its kernel extensions for it customers. This is for a legitimate software product that does not attempt to bypass OS X security features in any way"_

(note: I also provided the technical reasoning why BlockBlock (now) required a kext, as well as a link to BlockBlock's [product page](https://objective-see.org/products/blockblock.html))


Apple: GTFO:


![](https://objective-see.org/images/blog/blog9/denied.png)

Me: ...


On that bitter(sweet) note, let's end. Check back soon for part II (and maybe Apple will have reconsidered their decision to deny me the ability to sign kexts). I'll detail about how the process information captured in the BlockBlock kext, is made available to the user-mode component of BlockBlock via broadcasting to a system socket :)


Kernel Debugging a Virtualized OS X El Capitan Image

11/05/2015

Invariably, any serious security researcher or hacker will at some point, need to debug a live kernel. Recently I found some interesting code within a kernel extension that I wanted to poke on...dynamically. My previous kernel debugging experience involved GDB, and older versions of OS X. Setting up kernel debugging against an OS X 10.11 image with LLDB, was thus a new experience. As such, I figured a short blog detailing the necessary steps, perhaps would be useful to others :)


Host: My host is running OS X 10.11.1, however any recent version of OS X should work similarly.


I've also got XCode and VMWare Fusion installed.


Target: My target is a virtual instance of the release build of OS X 10.11 (running within VMWare).


This is what we'll be remotely debugging.


So how can we kernel-debug an OS X 10.11 image running release kernel, in a VM. Turns out, it's really not too hard!


Step 1 (target): Disable System Integrity Protection (SIP)

Boot the target (VM) into recovery mode. This is accomplished by hitting cmd+r as the system boots. Note; if the target boots to a login prompt, you've missed recovery mode. Reboot and try again.


![](https://objective-see.org/images/blog/blog8/recoveryMode.png)

Once in recovery mode, open the terminal (Utilities ->Terminal) and enter the following: csrutil disable

![](https://objective-see.org/images/blog/blog8/sipDisable.png)

This will disable system integrity protection. Reboot the target, allowing it to boot normally.


Step 2 (target): Enable Debugging

Once SIP has been disabled, and the target has booted normally, you need to tell the system to boot in 'debug-mode'. This is achieved via the following command, executed from the terminal, within the target:

sudo nvram boot-args="debug=0x141 pmuflags=1 -v"

The 'debug=0x141' tells the system to wait for a remote debugger while booting. While the 'pmuflags=1' disables the kernel's watchdog timer. Finally -v just tells the kernel to boot in verbose mode. For more information on these parameters, see [Kernel debugging with LLDB and VMware Fusion](http://ddeville.me/2015/08/kernel-debugging-with-lldb-and-vmware-fusion/) or [Apple's Kernel Programming Guide](https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/KernelProgramming).


Reboot the target, it should begin booting, then pause waiting for a remote debugger to attach:


![](https://objective-see.org/images/blog/blog8/wait4Debugger.png)

Step 3 (host): Download the Kernel Debug Kit

Head over to [Apple's developer page](https://developer.apple.com/downloads/) and find the kernel debug kit that matches the target's kernel. Since the target, (the image we're debugging) is the final version of OS X 10.11 (i.e. non-beta), the correct kernel build is 15A284:


![](https://objective-see.org/images/blog/blog8/kernelDownload.png)

Download this dmg, and install it.


Step 4 (host): Start LLDB and Configure

From a terminal, fire up lldb. Then, specify the target you'll be connecting to. Do this via the 'target create \[path to target kernel\]' command:


![](https://objective-see.org/images/blog/blog8/specifyTarget.png)

Note that the path to the kernel, is the path to the release kernel in the kernel debug kit (downloaded in the previous step).


Once the target has been specified, a warning message is displayed, indicating the presence of a debug script. Run this script via the specified command ('command script import ...):


![](https://objective-see.org/images/blog/blog8/debugScript.png)

Step 5: (host) Connect to the Target

Now, you are ready to connect to the remote target, via kdp (the kernel debugging protocol). Connect via the following command: 'kdp-remote \[target IP addr\]. Note the target's IP address will be displayed by the target, in the line above the 'Waiting for remote debugger connection'. Now the host should be connected to the target!


![](https://objective-see.org/images/blog/blog8/hostConnected.png)

![](https://objective-see.org/images/blog/blog8/targetConnected.png)

Step 6: Debug!

Hooray, now connected to the remote target, you and can debug to your heart's content, for example dumping a backtrace or listing the loaded kexts:


![](https://objective-see.org/images/blog/blog8/backTrace.png)

![](https://objective-see.org/images/blog/blog8/imageList.png)

One important note, is that (with this setup), the debugger, cannot stop the running kernel - unless a breakpoint is hit! This means, if you don't set a breakpoint before continuing, you won't be able to stop (and thus debug) the running kernel:


![](https://objective-see.org/images/blog/blog8/cantStop.png)

There may be ways around this 'limitation.' For example, [Kernel debugging with LLDB and VMware Fusion](http://ddeville.me/2015/08/kernel-debugging-with-lldb-and-vmware-fusion/) talks about Non-Maskable Interrupts (NMI), that in theory allow one to manually generate an interrupt in the target (at anytime), that will be caught (and thus stop) the debugger on the host. However, I could not get this working...


Well that's a wrap. Hopefully I've adequately described the steps needed to debug the kernel of a virtualized OS X El Capitan image. If you have any issues, or if I've missed a step(s) please shoot me an [email](mailto:issues@objective-see.com) :) Happy bug hunting!


Reversing to Engineer: Learning to 'Secure' XPC from a Patch

8/29/2015

Update: blog post updated to describe the use of dynamic (versus static) code references/APIs. Though Apple SPI'd (System Private Interfaced), as pointed out by Damien Sorresso of Apple, these APIs provide a higher level of security, and thus should be used. Mahalo Damien :)

As backwards as it may seem, my (limited) software engineering knowledge has largely come from reverse-engineering other people's software. For example, reversing OS binaries while hunting for vulnerabilities has provided insight into how 'real' software developers think, code, and approach problems. In this brief writeup I want to share such an experience; where knowledge gleaned from a reversing session turned out to be directly applicable to one of my own projects.


At DefCon, I gave a talk entitled, ["Stick that in your (root)Pipe and Smoke it"](https://media.defcon.org/DEF%20CON%2023/DEF%20CON%2023%20presentations/Patrick%20Wardle%20-%20UPDATED/DEFCON-23-Patrick-Wardle-Stick-that-in-your-(Root)Pipe-and-Smoke-it-UPDATED.pdf) (photo credit, @Ryanwsmith13):


![](https://objective-see.org/images/blog/blog7/defcon.png)

The talk began with a brief overview an OS X IPC mechanism named XPC, before diving into an analysis of an XPC-related vulnerability name 'RootPipe' (discovered by Emil Kvarnhammar). Following this, the talk analyzed Apple attempt at a patch, and illustrated how both I and others were able to bypass the patch and re-exploit the initial vulnerability. While researching content for the talk and reversing Apple's patch, I learned a lot about XPC and how to secure privileged XPC services. This knowledge turned out to be directly applicable to my latest tool; [TaskExplorer](https://objective-see.org/products/taskexplorer.html).


![](https://objective-see.org/images/TE/te.png)

TaskExplorer allows one to explore all the tasks (processes) running on a Mac. IMHO, it provides a much needed improvement over Apple's Activity Monitor, as it allows one to view a task's loaded dylibs, open files, network connections, signature/signing status, and VirusTotal detection ratio. Moreover, a global search feature provides a way to quickly find all tasks that contain a loaded dylib or file. In order to enumerate information about running tasks, such as loaded dylibs and command-line arguments, root privileges are required. Sure TaskExplorer could ask for credentials each time it is launched, but there is a better way: XPC.


As detailed in my talk (and shown in the following figure), XPC is great for splitting up an application into various 'logically-separate' components.


![](https://objective-see.org/images/blog/blog7/xpcConcepts.png)

Besides achieving stability, this provides a great way to separate logic that requires different (e.g. elevated) privileges. (For more on XPC, see Apple's ["Creating XPC Services"](https://developer.apple.com/library/mac/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html) or Damien Sorresso's presentation ["Efficient Design with XPC"](http://devstreaming.apple.com/videos/wwdc/2013/702xfx2xmlrics5pyrjfwu2m/702/702.pdf)). TaskExplorer was architected to utilize XPC to achieve such separation; splitting out a privileged XPC component from the application's main UI interface. The privileged XPC component is authenticated the initial time TaskExplorer is launched. From then on, it is able to service requests from the UI component in order to provide required information about remote tasks, without the need for further authentication.


![](https://objective-see.org/images/blog/blog7/xpcOverview.png)

Ok, so back to the DefCon talk and 'RootPipe'. The bug discovered by Emil was both simple and elegant. In short, OS X contained a privileged XPC service (WriteConfig) that applications could communicate with in order to perform privileged actions without constantly bugging the user for credentials.
Unfortunately, this XPC service performed no authentication on any clients that connected to it. As such, any local adversary could abuse its services to elevate their privileges to root!


![](https://objective-see.org/images/blog/blog7/exploit.png)

Though TaskExplorer's privileged XPC component does not confer such powerful capabilities, none-the-less I wanted to secure it by only allowing authorized clients to connect. But how?


By reversing Apple's patch, we can see that 'RootPipe' was patched, (after two attempts!), by only allowing authorized clients to connect to the all powerful WriteConfig XPC service. Specifically only Apple-signed binaries with special entitlements, (e.g com.apple.private.admin.writeconfig), are able to connect to the XPC service.


![](https://objective-see.org/images/blog/blog7/patchOverview.png)

Where is this new logic, that either allows trusted or blocks untrusted clients, implemented? In WriteConfig's implementation of the -listener:shouldAcceptNewConnection: method. Apple's [documentation](https://developer.apple.com/library/mac/documentation/Foundation/Reference/NSXPCListenerDelegate_reference/) states that this delegate method can be used to "accepts or rejects a new connection to the listener." In other words, the XPC service can examine a candidate client and block or reject the client, if it so chooses. Apple's 'RootPipe' patch and now TaskExplorer, both utilize this delegate method in order to validate candidate clients.


![](https://objective-see.org/images/blog/blog7/shouldAcceptConnection.png)

Apple's [documentation](https://developer.apple.com/library/mac/documentation/Foundation/Reference/NSXPCListenerDelegate_reference/) states that this NSXPCListenerDelegate delegate method can be used to "accepts or rejects a new connection to the listener." In other words, the XPC service can examine a candidate client and block or reject the client, if it so chooses. Apple's 'RootPipe' patch and now TaskExplorer, both utilize this delegate method in order to validate candidate clients.


Instead of using entitlements to validate candidate clients connecting to TaskExplorer's XPC service, I choose a simpler route: only applications signed by Objective-See are allowed to connect, and thus utilize the XPC service. Unfortunately, there's not a lot of documentation or examples about how to verify if an candidate client is signed with a specific Apple Developer's ID. However, a few StackOverflow posts, code snippets on GitHub, and fully reversing Apple's patch, initially proved quite helpful. Of course a little coaching from Damien Sorresso (@launchz) was amazingly helpful as well ;)


![](https://objective-see.org/images/blog/blog7/patchDetails.png)

As with Apple's 'RootPipe' patch, code within TaskExplorer's -listener:shouldAcceptNewConnection: method, first invokes the SecTaskCreateWithAuditToken() function. Though undocumented, the definition and a brief overview can be found in the
[SecTask.h](https://opensource.apple.com/source/libsecurity_codesigning/libsecurity_codesigning-55037.15/lib/SecTask.h) header file.
As explained in the header file, this function "create\[s\] a SecTask object for the task that sent the mach message represented by the audit token." In other words,
given an audit token of the client task that is attempting to connect to the XPC service, it will return a SecTask object representing said client. As described shortly, such an object will allow us to fully validate the client. So how to get the audit token of the connecting client to pass to the SecTaskCreateWithAuditToken() function?


Well, as can be seen in the disassembly of Apple's patch, it appears that the shouldAcceptNewConnection: parameter, a pointer to an NSXPCConnection object, has method
named 'auditToken', which presumable return's the connection's (client's) audit token:


![](https://objective-see.org/images/blog/blog7/patchIDA.png)

Unfortunately, the is no mention of such a method in any Apple documentation or header files. However using a tool such as [RuntimeBrowser](https://github.com/nst/RuntimeBrowser/) we can view NSXPCConnection's full class. This confirms the presence of such a method:


![](https://objective-see.org/images/blog/blog7/methods.png)

Since this method is not 'public', one has to gently coerce the Objective-C runtime to give us access to it. One easy method is simply to create an custom class that contains an instance variable and '@synthesize' of the same name ('auditToken'). Then the following code will return, executed upon the NSXPCConnection object, will return the client's audit token: ((ExtendedNSXPCConnection\*)newConnection).auditToken. With the ability to access the client's audit token, we can invoke the SecTaskCreateWithAuditToken() function and get back the needed SecTask object, and then validate the client.


Within the [SecTaskPriv.h](https://opensource.apple.com/source/Security/Security-57031.20.26/Security/include/security_codesigning/SecTaskPriv.h) header file, exists a function named SecTaskValidateForRequirement(). A comment above the function states that it will "validate a SecTask instance for a specified requirement" - sounds perfect! Besides taking a reference to a SecTask object (which we now have), this function takes a 'requirement' string. Such a string articulates the desired requirement that can be validated against the connecting client, for example: "client; you must be signed with Objective-See's Apple Developer ID". The following format string illustrates the format of such a requirement, that can be passed into the SecTaskValidateForRequirement() function to validate a connecting client.


@"anchor trusted and certificate leaf \[subject.CN\] = \\"Developer ID Application: your Apple Developer ID\\"";

By the way, to find the correct string for your Apple Developer ID, run the codesign tool with the '-dvv' flags. Use the text following the first 'Authority=' as the requirement string (e.g. "Developer ID Application: Objective-See, LLC (VBG97UB4TA)").


![](https://objective-see.org/images/blog/blog7/codesign.png)

To summarize, the following steps can validate that a client, connecting to an XPC instance, is signed by a particular Apple Developer ID. This code should be placed within the XPC service's -listener:shouldAcceptNewConnection: method.


**0)** Declare a custom class that 'extends' the NSXPCConnection object, allowing access to it's 'private' auditToken. While there are likely other ways to accomplish the following seems to work :)


@interface ExtendedNSXPCConnection : NSXPCConnection


{


audit\_token\_t auditToken;


}


@property audit\_token\_t auditToken;


@end


@implementation ExtendedNSXPCConnection


@synthesize auditToken;


@end


**1)** Invoke the SecTaskCreateWithAuditToken() function with the client's audit token to create a SecTask object for the connecting client.


**2)** Invoke the SecTaskValidateForRequirement() function, passing in the SecTask object and a requirement string for validation. To validate that the client is signed with a particular Apple Developer ID, use the following string (of course inserting your Apple Developer ID) :@"anchor trusted and certificate leaf \[subject.CN\] = \\"Developer ID Application: your Apple Developer ID\\"";

Putting these steps together, here's a snippet of code from TaskExplorer that attempts to ensure that only authorized clients can connect to its privileged XPC service. And yes, it uses 'goto' - deal with it ;)


![](https://objective-see.org/images/blog/blog7/fullCode.png)

Often, the primary goal of reverse-engineering is to find vulnerabilities, understand malware, or validate vendor patches. However, if you're an amateur software developer, reversing can provide the means to improve ones very own tools. So, mahalo Apple!


Building HackingTeam's OS X Implant For Fun & Profit

7/12/2015

By now, it's old news that HackingTeam got hacked. The collective info-sec community has being pouring thru the [400GB haul](https://ht.transparencytoolkit.org/) of 0days, juicy emails, and source code. Here, we add to this chorus by discussing how to build HackingTeam's persistent OS X implant from source - as what's cooler than being able to step thru malware's source code in Xcode?


The HackingTeam's OS X implant, 'Crisis' has been previously seen in the wild and [analyzed](https://reverse.put.as/2012/08/20/tales-from-crisis-chapter-2-backdoors-first-steps/). However, thanks to the leak, full source code is now [available](https://github.com/hackedteam/core-macos/tree/master/)! Having access to malware's source code alone, can provide unparalleled insight and reveal its innermost secrets. However, being able to fully build and thus dynamically debug said source code, can greatly simplify and expedite this analysis. Therefore this was goal: get HackingTeam's OS X implant to compile, in order to be debuggable under Xcode, on a modern version of OS X.


Ok, let's dive in! Within the /core-macos-master/core/ directory is the Xcode project of the malware's core; RCSMac.xcodeproj. This is the project that compiles various components of the malware, such as its installer and local 'server' components.


![](https://objective-see.org/images/blog/blog6/xcodeProj.png)

Opening this file in Xcode results in various popups asking to modernize the project. Agreeing to these allows Xcode to attempt various project 'modernizations' such as updating the SDK configuration and converting the project to make use of ARC (garbage collection).


![](https://objective-see.org/images/blog/blog6/modernizeProj.png)

Unfortunately, despite Xcode's best efforts various issues remain, preventing compilation. First, as the project's compiler is unsupported, this has to be updated to the current default compiler (Apple LLVM 6.1):


![](https://objective-see.org/images/blog/blog6/compilerError.png)

Then, since recent versions of Xcode prefer to compile only for 64-bit (x86\_64) platforms, all references to 32-bit architectures (i386) have to be removed.


![](https://objective-see.org/images/blog/blog6/archError.png)

After this, various ARC-related issues that Xcode could not automatically fix, have to be manually addressed:


![](https://objective-see.org/images/blog/blog6/gcConversionErrors.png)

For example, code related to auto-release pools, retain, and release must be removed.


![](https://objective-see.org/images/blog/blog6/gcPoolError.png)

Finally after these various manual fixes, the code compiles...but alas, does not link :( This is due to fact the included copy of a required library, speex, was not built for 64-bit:


![](https://objective-see.org/images/blog/blog6/linkError.png)

To build a 64-bit compatible version of the library, simply [download](http://www.speex.org/downloads/) the speex library source code and build it (./configure; make; etc). Once built, the library, libspeex.a, should be copied into the malware's project (/core-macos-master/core/Support/Speex/libspeex.a), overwriting the existing 32-bit version.


Horray, everything now (finally) compiles and links!


![](https://objective-see.org/images/blog/blog6/builtProducts.png)

Once the HackingTeam's malware has been build, it should be trivial to analyze by debugging it in Xcode. However, the compiled malware still has various features that may complicate this process. For example it contains amongst other things, anti-debugging code. Luckily, this and various other features can be controlled by several #defines found within RCSMDebug.h header file. Though commented out, simply uncommenting them and re-compiling disables all anti-debugging, as well as enables other useful features such as logging and placing the malware into 'demo' mode:


![](https://objective-see.org/images/blog/blog6/defines.png)

With a cleanly built, debug version of the implant, debugging and analysis can commence:


![](https://objective-see.org/images/blog/blog6/debugging.png)

While a full analysis of the code is beyond the scope of this blog entry (but should be fairly easy for anybody with Xcode to perform), let's end with discussing the malware's persistence mechanism. Looking at the runMeh method (within RCSMCore.m), reveals the malware persistently installing itself via a call to the makeBackdoorResident method.


![](https://objective-see.org/images/blog/blog6/makeResident.png)

This method eventually calls into the saveSLIPlist method, which is responsible for persisting the implant as a LaunchAgent, via ~/Library/LaunchAgents/com.apple.loginStoreagent.plist:


![](https://objective-see.org/images/blog/blog6/persist.png)

Since LaunchAgent persistence is detected by BlockBlock, if the HackingTeam had targeted your Mac and you had BlockBlock installed, it's unlikely they'd have succeeded in infecting you. Booya!


![](https://objective-see.org/images/blog/blog6/BlockBlock.png)

Update: an anonymous individual has uploaded a ready-to-go 'Xcode-buildable' version of the implant. [Download](https://infotomb.com/oon3g.zip) it, build it, and play :)


CVE-2015-3673: Goodbye Rootpipe...(for now?)

7/01/2015

In a previous [blog post](https://objective-see.org/blog.html#blogEntry3), I posted a video showing a modified version of 'rootpipe' (the priv-esc [disclosed](https://truesecdev.wordpress.com/2015/04/09/hidden-backdoor-api-to-root-privileges-in-apple-os-x/) by Emil Kvarnhammar), bypassing Apple's patch to successfully (re)gain root on OS X 10.10.3. The bug, which I reported to Apple, was assigned CVE-2015-3673 and patched in OS X 10.10.4:


![](https://objective-see.org/images/blog/CVE-2015-3673_appleCredits.png)

Interesting, though not that surprisingly, Emil found the same way to bypass Apple's original patch. As such, we share the CVE :)


With the release of OS X 10.10.4 and Apple's new patch, Emil wrote a great blog revealing the details our independent OS X 10.10.3 [bypass](https://truesecdev.wordpress.com/2015/07/01/exploiting-rootpipe-again/). In short, Apple's original patch allowed only trusted processes (specifically those with the com.apple.private.admin.writeconfig entitlement), to talk to the WriteConfig XPC service; the service that the original 'rootpipe' exploit abused. However, we both found that the trusted Directory Utility application could easily be coerced to load unsigned, malicious plugins:


![](https://objective-see.org/images/blog/CVE-2015-3673_dylibLoaded.png)

Since the Directory Utility application possesses the com.apple.private.admin.writeconfig entitlement, even on a patched OS X 10.10.3 system, the malicious plugins were allowed to talk to the writeConfig XPC service - game over! Apple's most recent patch prevents this attack in variety of ways (such as ensuring the trusted process originates from /System or /usr, both which are of course, only writable by root). As such, (for now?), 'rootpipe' is no more.


If this adventure has interested you, I'm happy to announce that I will be presenting an in-depth talk at DefCon 23. The talk, titled ["Stick That In Your (root)Pipe & Smoke It"](https://www.defcon.org/html/defcon-23/dc-23-speakers.html#Wardle2) will cover in great detail: XPC fundamentals, the rootpipe vulnerability, malware (from China?) that exploited the flaw as an 0day, Apple's attempted patch, the bypass (mentioned here), and Apple's OS X 10.10.4 patch. Can't make the talk? No problem; I'll be sure to post the slides online. Here's a sneak preview:


![](https://objective-see.org/images/blog/CVE-2015-3673_slidePreview.png)

While on the topic of upcoming events, I've also been accepted to BlackHat Las Vegas where I'll be presenting a talk on ["Writing Bad @$$ Malware for OS X"](https://www.blackhat.com/us-15/briefings.html#Patrick-Wardle) :) Also, I'll be giving yet another talk at DefCon 23 titled ["'DLL Hijacking' on OS X? #@%& Yeah!"](https://www.defcon.org/html/defcon-23/dc-23-speakers.html#Wardle). Finally, I was invited to demonstrate Objective-See's tools at [BlackHat Arsenal](https://www.blackhat.com/us-15/arsenal.html#Patrick-Wardle), where I'll be releasing a new tool - so come check it out.


Hopefully see you in Vegas at BlackHat, Arsenal, DefCon - or all three!


More on, "Adware for OS X Distributes Trojans"

6/22/2015

Today, Dr. Web released a brief writeup titled ["Adware for OS X Distributes Trojans"](http://news.drweb.com/show/?i=9502&lng=en). Though the writeup provided a decent overview of the malware, it glossed over many technical details. Here, we provide a little more technical depth as well as the malicious sample - in case you want to play along at home! (See the MacInstaller/ folder in Objective-See's [malware archive](https://objective-see.org/downloads/malware.zip) (password: infect3d), for the malware mentioned here).


The Dr. Web writeup mentions an installer that is distributed as adware, specifically "disguised as a useful application or an MP3 file." While the websites that host the malicious installer are not directly mentioned, one of the screen shots contains the URL, listentoyoutube.com. Visiting and interacting with this site (e.g. providing a youtube video or song to download), results in the following 'Download MP3' button:


![](https://objective-see.org/images/blog/macInstaller_downloadButton.png)

Observant readers will notice the checked (by default), "Download with accelerator and get recommendation offers" option. With this option checked, clicking the download button will download a .dmg image, named to matched the MP3. When executed, an application within the .dmg is launched which may infect the user, installing several pieces of persistent adware.


The Dr. Web write up mentioned that this image contains a "rather remarkable structure; that is, it contains two hidden folders that cannot be viewed on the computer running with standard operating system settings if the user decides to browse the contents of the DMG file using Finder." This "remarkable structure" IMHO is rather unremarkable, the folders are simple prefixed with a '.' so that Finder will not, by default, display them. However, they are visible if Finder has been instructed to show hidden files, or of course, from the Terminal:


![](https://objective-see.org/images/blog/macInstaller_dirStructure.png)


When the .dmg is mounted (e.g. double clicked) the following is shown:


![](https://objective-see.org/images/blog/macInstaller_dmg.png)

Double-clicking launches the <song>\_mp3.app which executes its binary image: 'macLauncher' (MD5: 5f1e998e0213364ae44472495a71f123). This binary simply executes an application named 'Downloader' found within the hidden .app/ folder. Interestingly, this execution is achieved by the programmatic invocation of an AppleScript script:


![](https://objective-see.org/images/blog/macInstaller_appleScript.png)

As its name implies, 'Downloader' is a application that downloads (and installs) other software. Strings within the binary reveal it name, 'macInstaller', and version, 1.7.12-d. The MD5 hash of this binary is a6a23e7815d08a596da37e38b466e7a2.


When executed, this software infects the system with persistent adware. Analysis of this adware is beyond the scope of this writeup. However, brief triage indicated that this includes a (signed) variant of Genieo, as well as the abhorred 'SaveOnMac' or (Crossrider?) adware.


This adware will result in variety of unwanted or malicious behavior. For example, via malicious browser extensions it will hijack the browser in various ways. These malicious extensions can be viewed with [KnockKnock](https://objective-see.org/products/knockknock.html):


![](https://objective-see.org/images/blog/macInstaller_KK.png)

Genieo, goes a step further and attempts to persist as a LaunchAgent. Luckily, [BlockBlock](https://objective-see.org/products/blockblock.html) can block this:


![](https://objective-see.org/images/blog/macInstaller_BB.png)

Since this version of Genieo was unknown to VirusTotal and (when [submitted](https://www.virustotal.com/en/file/b59af72f24103a82c914fd83fab4da1715614db729cb5c3b4efcb480640e2f17/analysis/1435039769/)), undetected by Dr. Web and other AV products, a malware-agnostic tools such as BlockBlock is clearly quite valuable ;)


![](https://objective-see.org/images/blog/macInstaller_VT.png)

Phoenix: RootPipe lives! ...even on OS X 10.10.3

4/18/2015

Recently, a new OS X priv-esc vulnerability named 'rootpipe' was [disclosed](https://truesecdev.wordpress.com/2015/04/09/hidden-backdoor-api-to-root-privileges-in-apple-os-x/). Apple attempted to patch the vulnerability in OS X 10.10.3, by adding access checks via a new private entitlement: com.apple.private.admin.writeconfig. (see @osxreverser's excellent [writeup](https://reverse.put.as/2015/04/13/how-to-fix-rootpipe-in-mavericks-and-call-apples-bullshit-bluff-about-rootpipe-fixes/) for details). In theory this seemed a reasonable fix.


However, on my flight back from presenting at Infiltrate (amazing conference btw), I found a novel, yet trivial way for any local user to re-abuse rootpipe - even on a fully patched OS X 10.10.3 system. I the spirit of responsible disclosure, (at this time), I won't be providing the technical details of the attack (besides of course to Apple). However, I felt that in the meantime, OS X users should be aware of the risk.


Phoenix; RootPipe Reborn from patrick wardle on Vimeo

![video thumbnail](https://i.vimeocdn.com/video/515417467-bd636f5f43f5d9ef66a3eaa5a9320543ef159bfe1ae6fac0e920453ad16c71a3-d?mw=80&q=85)

Playing in picture-in-picture

Like

Add to Watch Later

Share

Play

00:00

00:29

Settings

QualityAuto

SpeedNormal

Picture-in-PictureFullscreen

[Watch on Vimeo](https://vimeo.com/125345793?fl=pl&fe=vl)

Phoenix (rootpipe reborn) demo on OS X 10.10.3


Dylib Hijack Scanner Released

3/19/2015

Objective-See's first tool, ['Dylib Hijack Scanner' (DHS)](https://objective-see.org/products/dhs.html) has been released! This product attempts to counter a new class of OS X attacks, dubbed 'dylib hijacking.' For details on this novel attack, check out my [slides](http://syn.ac/cansecw) or [paper](https://www.virusbtn.com/pdf/magazine/2015/vb201503-dylib-hijacking.pdf).


By abusing weak or run-path dependent imports, found within countless Apple and 3rd party applications, this attack class opens up a myriad attack scenarios to both local and remote attackers. From stealthy local persistence to a Gatekeeper bypass that provides avenues for remote infections, dylib hijacking is likely to become a powerful weapon in the arsenal of OS X attackers. Apple appears apathetic toward to this novel attack, so download DHS to ensure you haven't been hijacked.


I've tried my best to ensure this tool is both accurate and stable, but please [email](mailto:issues@objective-see.com) me with any issues you may have.


Website Launch

3/19/2015

And we're (finally) live! Welcome to Objective-See, my personal OS X security website :)


OS X malware and security has been a personal passion for many years. However the more I learned about this topic, the more insecure I felt. Malware for OS X is trivial to write and unfortunately has become ever more pervasive. And, using attacks such as [dylib hijacking](https://www.virusbtn.com/pdf/magazine/2015/vb201503-dylib-hijacking.pdf) attackers can easily bypass all current OS X security products.


As an avid Mac user this worried me, so I decided to do something about it. Initially this was for somewhat 'selfish' reasons; I simply wanted to write OS X security tools to secure my Mac. But then I though, "hey, sharing is caring, I should make my tools publicly available, free of charge." This is the idea that drives the website.


So welcome to the website launch. There isn't a lot up here yet, but I promise some cool stuff is coming shortly!
