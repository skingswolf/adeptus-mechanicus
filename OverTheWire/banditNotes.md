# OverTheWire Bandit Notes

- Test TCP/UDP connections
  - netcat [options] host port
- Test SSL connections
  - openssl s_client -connect localhost:30001
- We will redirect standard error to standard output using the `2>&1` bash syntax
- Passwords kept here /etc/bandit_pass/bandit15 
- alias c=clear
- nmap -p31000-32000 localhost
- ssh -i /tmp/skarzon/sshkey.pem bandit17@localhost
- `cat /etc/shells/`
  - Display valid login shells. 
- `ssh -p 2220 bandit18@bandit.labs.overthewire.org "mkdir /tmp/skarzon; touch /tmp/skarzon/.bashrc; cat ~/.bashrc | head -n -1 > /tmp/skarzon/.bashrc; bash --rcfile /tmp/skarzon/.bashrc"`
- `ssh bandit18@bandit.labs.overthewire.org -p 2220 -t "/bin/sh"`
  - The -t flag of the SSH command is used to specify the shell to be used to login into the system

- The system-wide cron jobs are located in the /etc/crontab file and /etc/cron.d directory, and they are run through /etc/cron.hourly, /etc/cron.daily, /etc/cron.weekly and /etc/cron.monthly. Only a system administrator can access these files.

- an "s" in listed permissions denotes with the setuid/setguid is set. If set the executing user will run with the permissions of the executable's owner/group
  - -rwsr-xr-x 1 root root
  - `chmod u+s pepperNeggMaker.sh`
    - sets the setuid bit
- The sticky bit restricts who can delete files in a directory on Linux systems. Specifically, when the sticky bit is set, only the user that owns, the user that owns the directory, or the root user can delete files within the directory.
  - `chmod +t /recipes/`
  - drwxrwxrwt 2 cooluser cooluser
    - 

- The “/etc/passwd” file consist of information regarding the users on the device along with the shell that is being used by each user.


-https://stackoverflow.com/questions/24793069/what-does-do-in-bash
  - &>name is like 1>name 2>name -- redirect stdout and stderr to the file name (however name is only opened once; if you actually wrote 1>name 2>name it'd try to open name twice and perhaps malfunction).
xxd -p -r
strings test.txt | tr -d "\n" | base64 -d


- `while true; do { echo -e 'HTTP/1.1 200 OK\r\n'; cat /etc/bandit_pass/bandit20; } | nc -l 8080; done`
  - example one line web server
- cat /etc/bandit_pass/bandit20 | nc -lp 12808
- backdoor.sh: `cat /etc/bandit_pass/bandit24  > /tmp/vader/password.txt`  

- `for i in {0000..9999}; do echo "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i"; done | nc localhost 30002`

- git tag
- git log --no-walk --tags --pretty="%h %d %s" --decorate=full
- Apparently you can have git tags that aren't associated with commits ...(level 30-31)

- https://unix.stackexchange.com/questions/412707/why-0-is-not-a-positional-parameter
- $0 is the filename
- There's a clear parallel from the numbered parameters ($0, $1, ...) to argv[], the array that contains the command line parameters when a process starts. The first element of the array, argv[0], usually holds the name of the process, and the actual arguments start from argv[1].
  - (Usually. It doesn't have to. The description of execve(2) states: "The value in argv[0] should point to a filename string that is associated with the process being started")
  - At least post-facto, it's easy to imagine the convention was just copied directly to the shell.
  - The values aren't directly copied, though. At least on my systems the shell process that starts when running ./script.sh with the hashbang #!/bin/bash -x gets the parameters /bin/bash, -x, ./script.sh. That is, the value that goes to $0 as seen by the script, is in argv[2] of the shell process.

- final level (32-33)
  - What we need to understand here is that this shell that we see is nothing but an binary file that takes whatever we enter convert it into uppercase and then have bash/sh shell execute the command.
  - sh -c "<capitalised-user-input>"
  - cat /home/bandit32/uppershell
    - uppershell looks like a binary compiled from some C program. So it's C code that takes in the user input and capitalises it, and then runs the capitalises command using a standard shell like sh or bash

Bandit Level 32 → Level 33

ssh -p 2220 bandit32@bandit.labs.overthewire.org

c9c3199ddf4121b10cf581a98d51caee

----

bandit33@bandit:~$ cat README.txt
Congratulations on solving the last level of this game!

At this moment, there are no more levels to play in this game. However, we are constantly working
on new levels and will most likely expand this game with more levels soon.
Keep an eye out for an announcement on our usual communication channels!
In the meantime, you could play some of our other wargames.

If you have an idea for an awesome new level, please let us know!