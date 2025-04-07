# Linux Fundamentals

- [Linux Fundamentals](#linux-fundamentals)
  - [Key Concepts](#key-concepts)
- [Linux Distributions](#linux-distributions)
  - [Philosophy](#philosophy)
  - [Components](#components)
  - [Linux Architecture](#linux-architecture)
  - [File System Hierarchy](#file-system-hierarchy)
  - [Getting Help](#getting-help)
  - [Shell](#shell)
  - [System Information](#system-information)
  - [Navigation](#navigation)
  - [Working with Files and Directories](#working-with-files-and-directories)
  - [Editing Files](#editing-files)
  - [Find Files and Directories](#find-files-and-directories)
  - [File Descriptors and Redirections](#file-descriptors-and-redirections)
  - [Filter Contents](#filter-contents)
  - [Regular Expressions](#regular-expressions)
    - [Regex in Detail](#regex-in-detail)
  - [Permission Management](#permission-management)
  - [User Management](#user-management)
  - [Package Management](#package-management)
  - [Service and Process Management](#service-and-process-management)
  - [Task Scheduling](#task-scheduling)
  - [Network Services](#network-services)
  - [Working with Web Services](#working-with-web-services)
  - [Backup and Restore](#backup-and-restore)
  - [File System Management](#file-system-management)
  - [Containerization](#containerization)
  - [Network Configuration](#network-configuration)
  - [Remote Desktop Protocols in Linux](#remote-desktop-protocols-in-linux)
  - [Linux Security](#linux-security)
  - [Firewall Setup](#firewall-setup)
  - [System Logs](#system-logs)
  - [Solaris](#solaris)
  - [Exercises](#exercises)
  - [Other](#other)

These are very basic notes. They've have been copied & pasted from HackTheBox's module for completeness

## Key Concepts

- Kernel (v basic)
  - The kernel is a computer program at the core of a computer's operating system and generally has complete control over everything in the system. It is the portion of the operating system code that is always resident in memory and facilitates interactions between hardware and software components.
  - https://www.techtarget.com/searchdatacenter/definition/kernel
  - During normal system startup, a computer's basic input/output system, or BIOS, completes a hardware bootstrap or initialization. It then runs a bootloader which loads the kernel from a storage device -- such as a hard drive -- into a protected memory space. Once the kernel is loaded into computer memory, the BIOS transfers control to the kernel. It then loads other OS components to complete the system startup and make control available to users through a desktop or other user interface.
  - Primary jobs:
    - It provides the interfaces (for services) needed for users and applications to interact with the computer.
    - It launches and manages applications.
    - It manages the underlying system hardware devices.

# Linux Distributions

- Linux distributions - or distros - are operating systems based on the Linux kernel. They are used for various purposes, from servers and embedded devices to desktop computers and mobile phones. Each Linux distribution is different, with its own set of features, packages, and tools.
- Linux is open source, meaning its source code is available for scrutiny and customization.
- We look for security, stability, reliability and frequent updates in a Linux distribution.
- Popular because it's free, open source, and highly customizable.
- Popular distributions:
  - Ubuntu, Fedora, CentOS, Debian, Red Hat Enterprise Linux
- Popular distributions for cybersecurity:
  - ParrotOS, Ubuntu, Debian, Raspberry Pi OS, CentOS, BackBox, BlackArch, Pentoo
- The main differences between the various Linux distributions are the included packages, the user interface, and the tools available.
  - Kali Linux is the most popular distribution for cyber security specialists, including a wide range of security-focused tools and packages.
  - Ubuntu is widespread for desktop users.
  - Debian is popular for servers and embedded systems.
  - Red Hat Enterprise Linux and CentOS are popular for enterprise-level computing.
- Debian
  - Known for its stability and reliability.
  - Used for desktop computing, servers, and embedded system.
  - Uses an Advanced Package Tool (apt) package management system to handle software updates and security patches. The package management system helps keep the system up-to-date and secure by automatically downloading and installing security updates as soon as they are available. This can be executed manually or set up automatically.
  - Debian can have a steeper learning curve than other distributions, but it is widely regarded as one of the most flexible and customizable Linux distros. The configuration and setup can be complex, but it also provides excellent control over the system, which can be good for advanced users.
  - Stability and reliability are key strengths of Debian. The distribution is known for its long-term support releases, which can provide updates and security patches for up to five years. This can be especially important for servers and other systems that must be up and running 24/7. It has had some vulnerabilities, but the development community has quickly released patches and security updates. In addition, Debian has a strong commitment to security and privacy, and the distribution has a well-established security track record. Debian is a versatile and reliable Linux distribution that is widely used for a range of purposes. Its stability, reliability, and commitment to security make it an attractive choice for various use cases, including cyber security.

## Philosophy

- Everything is a file
  - All configuration files for the various services running on the Linux operating system are stored in one or more text files.
- Small, single-purpose programs
  - Linux offers many different tools that we will work with, which can be combined to work together.
- Ability to chain programs together to perform complex tasks
  - The integration and combination of different tools enable us to carry out many large and complex tasks, such as processing or filtering specific data results.
- Avoid captive user interfaces
  - Linux is designed to work mainly with the shell (or terminal), which gives the user greater control over the operating system.
- Configuration data stored in a text file
  - An example of such a file is the /etc/passwd file, which stores all users registered on the system.

## Components

- Bootloader
  - A piece of code that runs to guide the booting process to start the operating system. Parrot Linux uses the GRUB Bootloader.
- OS Kernel
  - The kernel is the main component of an operating system. It manages the resources for system's I/O devices at the hardware level.
- Daemons
  - Background services are called "daemons" in Linux. Their purpose is to ensure that key functions such as scheduling, printing, and multimedia are working correctly. These small programs load after we booted or log into the computer.
- OS Shell
  - The operating system shell or the command language interpreter (also known as the command line) is the interface between the OS and the user. This interface allows the user to tell the OS what to do. The most commonly used shells are Bash, Tcsh/Csh, Ksh, Zsh, and Fish.
- Graphics server
  - This provides a graphical sub-system (server) called "X" or "X-server" that allows graphical programs to run locally or remotely on the X-windowing system.
- Window Manager
  - Also known as a graphical user interface (GUI). There are many options, including GNOME, KDE, MATE, Unity, and Cinnamon. A desktop environment usually has several applications, including file and web browsers. These allow the user to access and manage the essential and frequently accessed features and services of an operating system.
- Utilities
  - Applications or utilities are programs that perform particular functions for the user or another program.

## Linux Architecture

- Hardware
  - Peripheral devices such as the system's RAM, hard drive, CPU, and others.
- Kernel
  - The core of the Linux operating system whose function is to virtualize and control common computer hardware resources like CPU, allocated memory, accessed data, and others. The kernel gives each process its own virtual resources and prevents/mitigates conflicts between different processes.
- Shell
  - A command-line interface (CLI), also known as a shell that a user can enter commands into to execute the kernel's functions.
- System Utility
  - Makes available to the user all of the operating system's functionality.

## File System Hierarchy

- The Linux operating system is structured in a tree-like hierarchy and is documented in the [Filesystem Hierarchy Standard](https://www.pathname.com/fhs/) (FHS). Linux is structured with the following standard top-level directories:

- The standard top-level directories are:
  - /
    - The top-level directory is the root filesystem and contains all of the files required to boot the operating system before other filesystems are mounted as well as the files required to boot the other filesystems. After boot, all of the other filesystems are mounted at standard mount points as subdirectories of the root.
  - /bin
    - Contains essential command binaries.
  - /boot
    - Consists of the static bootloader, kernel executable, and files required to boot the Linux OS.
  - /dev
    - Contains device files to facilitate access to every hardware device attached to the system.
  - /etc
    - Local system configuration files. Configuration files for installed applications may be saved here as well.
    - /etc/shadow is the shadow password file and is a system file in Linux that stores encrypted user passwords and is accessible only to the root user, preventing unauthorized users or malicious actors from breaking into the system.
  - /home
    - Each user on the system has a subdirectory here for storage.
  - /lib
    - Shared library files that are required for system boot.
  - /media
    - External removable media devices such as USB drives are mounted here.
  - /mnt
    - Temporary mount point for regular filesystems.
  - /opt
    - Optional files such as third-party tools can be saved here.
  - /root
    - The home directory for the root user.
  - /sbin
    - This directory contains executables used for system administration (binary system files).
  - /tmp
    - The operating system and many programs use this directory to store temporary files. This directory is generally cleared upon system boot and may be deleted at other times without any warning.
  - /usr
    - Contains executables, libraries, man files, etc.
  - /var
    - This directory contains variable data files such as log files, email in-boxes, web application related files, cron files, and more.

## Getting Help

- `apropos`
  - Each manual page has a short description available within it. This tool searches the descriptions for instances of a given keyword.
    - e.g. `apropos sudo`
- Useful resource to get help if we have issues to understand a long command is:
  - [explainshell](https://explainshell.com/)

## Shell

- A Linux terminal/shell/command line, provides a text-based input/output (I/O) interface between users and the kernel for a computer system.

  - The term console is also typical but does not refer to a window but a screen in text mode. In the terminal window, commands can be executed to control the system.

- Terminal emulation is software that emulates the function of a terminal.

  - It allows the use of text-based programs within a graphical user interface (GUI).
  - Example terminals include GNOME Terminal, XFCE4 Terminal, XTerm, and many others.
  - There are also so-called command-line interfaces that run as additional terminals in one terminal and thus are multiplexers. These multiplexers include Tmux, GNU Screen, and others. In short, a terminal serves as an interface to the shell interpreter.

- Terminal emulators and multiplexers are beneficial extensions for the terminal. They provide us with different methods and functions to work with the terminal, such as splitting the terminal in one window, working in multiple directories, creating different workspaces, and much more.
- Bash prompt `<username>@<hostname>[~]$`
  - The dollar sign, in this case, stands for a user. As soon as we log in as root, the character changes to a hash <#> and looks like this: `root@htb[/htb]#`
- Customing the shell prompt
  - [bashrcgenerator](https://bashrcgenerator.com/)
  - [powerline](https://github.com/powerline/powerline)

## System Information

- `whoami`
  - Displays current username.
- `id`
  - Returns users identity.
  - Expands on the whoami command and prints out our effective group membership and IDs.
  - This can be of interest to penetration testers looking to see what access a user may have and sysadmins looking to audit account permissions and group membership.
  - The `adm` group means that the user can read log files in /var/log and could potentially gain access to sensitive information
  - Membership in the `sudo` group is of particular interest as this means our user can run some or all commands as the all-powerful root user.
    - Sudo rights could help us escalate privileges or could be a sign to a sysadmin that they may need to audit permissions and group memberships to remove any access that is not required for a given user to carry out their day-to-day tasks.
  - `id` -> e.g. `uid=1000(cry0l1t3) gid=1000(cry0l1t3) groups=1000(cry0l1t3),1337(hackthebox),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lpadmin),126(sambashare)`
- `hostname`
  - Sets or prints the name of current host system.
- `uname`
  - Prints basic information about the operating system name and system hardware.
  - Running `uname -a` will print all information about the machine in a specific order: kernel name, hostname, the kernel release, kernel version, machine hardware name, and operating system. The `-a` flag will omit `-p` (processor type) and `-i` (hardware platform) if they are unknown.
    - `uname -a` output
      - `Linux box 4.15.0-99-generic #100-Ubuntu SMP Wed Apr 22 20:32:56 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux`
      - The Kernel name is `Linux`, the hostname is `box`, the kernel release is `4.15.0-99-generic`, the kernel version is `#100-Ubuntu SMP Wed Apr 22 20:32:56 UTC 2020`, and so on.
    - `uname -r`
      - Prints the kernel release
- `pwd`
  - Returns working directory name.
- `ifconfig`
  - The ifconfig utility is used to assign or to view an address to a network interface and/or configure network interface parameters.
- `ip`
  - Ip is a utility to show or manipulate routing, network devices, interfaces and tunnels.
- `netstat`
  - Shows network status.
- `ss`
  - Another utility to investigate sockets.
- `ps`
  - Shows process status.
- `who`
  - Displays who is logged in.
- `env`
  - Prints environment or sets and executes command.
- `lsblk`
  - Lists block devices.
- `lsusb`
  - Lists USB devices
- `lsof`
  - Lists opened files.
- `lspci`
  - Lists PCI devices.
  - Peripheral Component Interconnect (PCI) is a local computer bus for attaching hardware devices in a computer
  - PCI is often used to attach hardwares like sound cards, video cards and modem with the motherboard. By this logic, a PCI device means any device that can connect into the motherboard by utilizing the PCI slot

## Navigation

- `pwd`, `ls`, `ls -l`, `ls -l /var/`, `cd /dev/shm`
- `cd -`
  - Jump back to the directory we were last in.
- The shell also offers us the auto-complete function.
  - If we now type `cd /dev/s` and then press [TAB] twice, we will get all entries starting with the letter "s" in the directory of /dev/.
- `ls -al` output:
  - The first entry with a single dot (.) indicates the current directory we are currently in. The second entry with two dots (..) represents the parent directory. This means that we can jump to the parent directory with the following command: `cd ..`
- Since our shell is filled with some records, we can clean the shell with the command `clear`.

## Working with Files and Directories

- We can use `touch` to create an empty file and `mkdir` to create a directory.
  - The command `mkdir` has an option marked `-p` to add parent directories.
- `tree .`
  - We can look at the whole structure after creating the parent directories with the tool tree.
- `touch ./Storage/local/user/userinfo.txt`
- `mv <file/directory> <renamed file/directory>`
  - With the command `mv`, we can move and also rename files and directories.
- `cp Storage/readme.txt Storage/local/`

## Editing Files

- Text editors - `vi`, `vim`, `nano`, etc. Nano is supposedly a bit easier to understand.
- nano

  - `nano notes.txt`
  - GNU nano 2.9.3 notes.txt  
    Here we can type everything we want and make our notes.▓

    ^G Get Help ^O Write Out ^W Where Is ^K Cut Text ^J Justify ^C Cur Pos M-U Undo
    ^X Exit ^R Read File ^\ Replace ^U Uncut Text ^T To Spell ^\_ Go To Line M-E Redo

  - The caret (^) stands for our "[CTRL]" key.
  - Now we can save the file by pressing [CTRL + O] and confirm the file name with [ENTER].
  - After we have saved the file, we can leave the editor with [CTRL + X].

- `cat notes.txt`
- `vim`
  - Vim offers a total of six fundamental modes that make our work easier and make this editor so powerful:
  - Normal
  - In normal mode, all inputs are considered as editor commands. So there is no insertion of the entered characters into the editor buffer, as is the case with most other editors. After starting the editor, we are usually in the normal mode.
  - Insert
    - With a few exceptions, all entered characters are inserted into the buffer.
  - Visual
    - The visual mode is used to mark a contiguous part of the text, which will be visually highlighted. By positioning the cursor, we change the selected area. The highlighted area can then be edited in various ways, such as deleting, copying, or replacing it.
  - Command
    - It allows us to enter single-line commands at the bottom of the editor. This can be used for sorting, replacing text sections, or deleting them, for example.
  - Replace
    - In replace mode, the newly entered text will overwrite existing text characters unless there are no more old characters at the current cursor position. Then the newly entered text will be added.
  - When we have the Vim editor open, we can go into command mode by typing ":" and then typing "q" to close Vim.
  - Vim offers an excellent opportunity called `vimtutor` to practice and get familiar with the editor.
    - Play with the vimtutor. Get familiar with the editor and experiment with their features.

## Find Files and Directories

- `which`
  - This tool returns the path to the file or link that should be executed. This allows us to determine if specific programs, like cURL, netcat, wget, python, gcc, are available on the operating system.
- `find <location> <options>`
  - Besides the function to find files and folders, this tool also contains the function to filter the results. We can use filter parameters like the size of the file or the date. We can also specify if we only search for files or folders.
  - e.g. `find / -type f -name *.conf -user root -size +20k -newermt 2020-03-03 -exec ls -al {} \; 2>/dev/null`
    - `-type f`
      -     Hereby, we define the type of the searched object. In this case, 'f' stands for 'file'.
    - `-name *.conf`
      - With '-name', we indicate the name of the file we are looking for. The asterisk (\*) stands for 'all' files with the '.conf' extension.
    - `-user root`
      - This option filters all files whose owner is the root user.
    - `-size +20k`
      - We can then filter all the located files and specify that we only want to see the files that are larger than 20 KiB.
    - `-newermt 2020-03-03`
      -     With this option, we set the date. Only files newer than the specified date will be presented.
    - `-exec ls -al {} \;`
      - This option executes the specified command, using the curly brackets as placeholders for each result. The backslash escapes the next character from being interpreted by the shell because otherwise, the semicolon would terminate the command and not reach the redirection.
    - `2>/dev/null`
      - This is a STDERR redirection to the 'null device', which we will come back to in the next section. This redirection ensures that no errors are displayed in the terminal. This redirection must not be an option of the 'find' command.
- `locate *.conf`
  - This searches for all files with the ".conf" extension, you will find that this search produces results much faster than using find.
  - The command `locate` offers us a quicker way to search through the system. In contrast to the find command, locate works with a local database that contains all information about existing files and folders. We can update this database with the following command.
    - `sudo updatedb`
    -
- `wc -l`
  - Counts the number of lines in input.
  - wc = word count

## File Descriptors and Redirections

- A **file descriptor** (FD) in Unix/Linux operating systems is an indicator of connection maintained by the kernel to perform Input/Output (I/O) operations.
  - In Windows-based operating systems, it is called filehandle.
  - It is the connection (generally to a file) from the Operating system to perform I/O operations (Input/Output of Bytes). By default, the first three file descriptors in Linux are:
    - Data Stream for Input:
      - STDIN – 0
    - Data Stream for Output:
      - STDOUT – 1
    - Data Stream for Output that relates to an error occurring.
      - STDERR – 2
- `2>/dev/null`
  - Here, we redirect the file descriptor for the errors (FD 2 - STDERR) to "/dev/null." This way, we redirect the resulting errors to the "null device," which discards all data.
- `find /etc/ -name shadow 2>/dev/null > results.txt`
  - Here, the standard output (STDOUT), has been redirected to a file with the name results.txt that will only contain standard output without the standard errors.
  - We didn't use a number before the greater-than sign (>) in this example. That is because we redirected all the standard errors to the "null device" before, and so the only output we have left is the standard output (FD 1 - STDOUT).
- `find /etc/ -name shadow 2> stderr.txt 1> stdout.txt`
  - To make this more precise, we will redirect standard error (FD 2 - STDERR) and standard output (FD 1 - STDOUT) to different files.
- `cat < stdout.txt`
  - Redirecting STDIN
  - The lower-than "<" sign serves as standard input (FD 0 - STDIN). These characters can be seen as "direction" in the form of an arrow that tells us "from where" and "where to" the data should be redirected. We use the cat command to use the contents of the file "stdout.txt" as STDIN.
- `find /etc/ -name passwd >> stdout.txt 2>/dev/null`
  - Redirecting STDOUT and Append to a File
  - When we use the greater-than sign (>) to redirect our STDOUT, a new file is automatically created if it does not already exist. If this file exists, it will be overwritten without asking for confirmation. If we want to append STDOUT to our existing file, we can use the double greater-than sign (>>).
- `cat << EOF > stream.txt`
  - Redirecting STDIN Stream to a File
  - We can also use the double lower-than characters (<<) to add our standard input through a stream. We can use the so-called End-Of-File (EOF) function of a Linux system file, which defines the input's end. In the next example, we will use the cat command to read our streaming input through the stream and direct it to a file called "stream.txt."
- ` find /etc/ -name *.conf 2>/dev/null | grep systemd | wc -l`
  - Another way to redirect STDOUT is to use pipes (|). These are useful when we want to use the STDOUT from one program to be processed by another. One of the most commonly used tools is grep, which we will use in the next example. Grep is used to filter STDOUT according to the pattern we define. In the next example, we use the find command to search for all files in the "/etc/" directory with a ".conf" extension. Any errors are redirected to the "null device" (/dev/null). Using grep, we filter out the results and specify that only the lines containing the pattern "systemd" should be displayed.

## Filter Contents

- A pager allow us to scroll through the file in an interactive view.
- `more /etc/passwd`
  - After we read the content using cat and redirected it to more, the already mentioned pager opens, and we will automatically start at the beginning of the file.
  - With the [Q] key, we can leave this pager. We will notice that the output remains in the terminal.
- `less /etc/passwd`
  - Notice on the man page that `less` contains many more features than more.
  - When closing less with the [Q] key, we will notice that the output we have seen, unlike more, does not remain in the terminal.
- `head /etc/passwd`
  - By default, head prints the first ten lines of the given file or input, if not specified otherwise.
- `tail /etc/passwd`
  - Returns the last ten lines.
- `cat /etc/passwd | sort`
  - By default sorts it alphabetically
- `cat /etc/passwd | grep "/bin/bash"`
- `cat /etc/passwd | grep -v "false\|nologin"`
  - Option "-v" is used with grep to exclude specific results.
- `cat /etc/passwd | grep -v "false\|nologin" | cut -d":" -f1`
  - Specific results with different characters may be separated as delimiters. Here it is handy to know how to remove specific delimiters and show the words on a line in a specified position. One of the tools that can be used for this is cut. Therefore we use the option "-d" and set the delimiter to the colon character (:) and define with the option "-f" the position in the line we want to output.
- `cat /etc/passwd | grep -v "false\|nologin" | tr ":" " "`
  - Another possibility to replace certain characters from a line with characters defined by us is the tool tr. As the first option, we define which character we want to replace, and as a second option, we define the character we want to replace it with. In the next example, we replace the colon character with space.
- `cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | column -t`
  - Since such results can often have an unclear representation, the tool column is well suited to display such results in tabular form using the "-t."
- `cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | awk '{print $1, $NF}'`
  - As we may have noticed, the user "postgres" has one row too many. To keep it as simple as possible to sort out such results, the (g)awk programming is beneficial, which allows us to display the first ($1) and last ($NF) result of the line.
- `cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | awk '{print $1, $NF}' | sed 's/bin/HTB/g'`

  - There will come moments when we want to change specific names in the whole file or standard input. One of the tools we can use for this is the stream editor called sed. One of the most common uses of this is substituting text. Here, sed looks for patterns we have defined in the form of regular expressions (regex) and replaces them with another pattern that we have also defined. Let us stick to the last results and say we want to replace the word "bin" with "HTB."

  The "s" flag at the beginning stands for the substitute command. Then we specify the pattern we want to replace. After the slash (/), we enter the pattern we want to use as a replacement in the third position. Finally, we use the "g" flag, which stands for replacing all matches.

- `cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | awk '{print $1, $NF}' | wc -l`
  - Last but not least, it will often be useful to know how many successful matches we have. To avoid counting the lines or characters manually, we can use the tool wc. With the "-l" option, we specify that only the lines are counted.

## Regular Expressions

- A regular expression is a sequence of letters and symbols that form a search pattern.
  - They can be used to find and replace text, analyze data, validate input, perform searches, and more. In simple terms, they are a filter criterion that can be used to analyze and manipulate strings.
- In addition, regular expressions can be created with patterns called metacharacters. Meta characters are symbols that define the search pattern but have no literal meaning.

- Grouping
  | Operators | Description |
  | ----------- | ----------- |
  | `(a)` | The round brackets are used to group parts of a regex. Within the brackets, you can define further patterns which should be processed together. |
  | `[a-z]` | The square brackets are used to define character classes. Inside the brackets, you can specify a list of characters to search for. |
  | `{1,10}` | The curly brackets are used to define quantifiers. Inside the brackets, you can specify a number or a range that indicates how often a previous pattern should be repeated. |
  | `|` | Also called the OR operator and shows results when one of the two expressions matches|
  | `.*` | Also called the AND operator and displayed results only if both expressions match |

- To use , `|` and `.*`, you need to apply the extended regex using the -E option in grep.

- `grep -E "(my|false)" /etc/passwd`
  - Search for lines containing the word _my_ or _false_.
- `grep -E "(my.*false)" /etc/passwd`
  - Search for a line where both _my_ and _false_ are present.
  - This is equivalent to `grep -E "my" /etc/passwd | grep -E "false"`

### Regex in Detail

- [20 Small Steps to Become a Regex Master](https://dev.to/awwsmm/20-small-steps-to-become-a-regex-master-mpc)
- [Regular Expressions Cheat Sheet](https://cheatography.com/davechild/cheat-sheets/regular-expressions/)

- Any word which contains an 'o'
  - `\w*o\w*`
- Once we find a pattern in some text, what do we do with it? Well, modern regex engines allow you to extract those substrings from the contained text, or remove them, or replace them with other text. Regular expressions are used for text parsing and manipulation.

- Open-and-close square brackets tell the regex engine to match any one of the characters specified, but only one.
  - pattern: ca[rt]
    string: The cat was cut when it ran under the cart.
    matches: ^^^ ^^^
- Backslash character `\` escapes special characters

  - Only special characters should be preceded by \ to force a literal match. All other characters are interpreted literally by default. For instance, the regular expression t matches only literal lowercase letter t characters
  - pattern: \[\]
    string: You can't match [] using regex! You will regret this!
    matches: ^^
  - pattern: \\\[\\\]
    string: ...match this regex `\[\]` with a regex?
    matches: ^^^^
  - Other common escape sequences include \n (UNIX-style line breaks) and \r (used in Windows-style line breaks, \r\n). \r is the "carriage return" character and \n is the "line feed" character, both of which were defined along with the ASCII standard when teletypes were still in common usage.
    - A CR immediately followed by a LF (CRLF, \r\n, or 0x0D0A) moves the cursor down to the next line and then to the beginning of the line.

- There's another special character which is used to match (nearly) any character, and that's the period / full stop character ..
  - pattern: .
    string: I'm sorry, Dave. I'm afraid I can't do that.
    matches: ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  - If you want to match only patterns that look like escape sequences, you could do something like:
    - pattern: \\.
      string: Hi Walmart is my grandson there his name is "\n \r \t".
      matches: ^^ ^^ ^^
- Characters are "whitespace" if they don't create any visible mark within text. A space character ' ' is whitespace, as is a line break, or a tab.

- Character classes and ranges allow us to match certain types of characters - e.g. letters, digits, or just vowels.
  - pattern: \\[a-z]
    string: `\n`, `\r`, `\t`, and `\f` are whitespace characters, `\.`, `\\` and `\[` are not.
    matches: ^^ ^^ ^^ ^^
  - pattern: \\[a-gq-z]
    string: `\n`, `\r`, `\t`, and `\f` are whitespace characters, `\.`, `\\` and `\[` are not.
    matches: ^^ ^^ ^^
  - Other common character ranges include: `A-Z` and `0-9`.
- The "not" carat `^` allows us to specify characters and character ranges which the regex engine should not match on.

  - The carat `^` as the leftmost character inside the square brackets [] tells the regex engine to match one single character which is not within the square brackets.
  - pattern: [^aeiou]
    string: The walls in the mall are totally, totally tall.
    matches: ^^ ^^ ^^^^ ^^^^ ^^ ^^^ ^ ^^ ^ ^^^^^^ ^ ^^^^^ ^^^
  - pattern: [a-z][a-z][^y ]
    string: day dog hog hay bog bay ray rub
    matches: ^^^ ^^^ ^^^ ^^^
  - Be careful with the "not" carat `^`. It's easy to think, "well, I said `[^b-f]`", so I should get a lowercase letter a, or something after f. That's not the case. That regex will match any character not within that range, including digits, symbols, and whitespace.

  - Character classes work very similarly to ranges, but you can't specify the "start" and "end" values:
    | Class | Characters |
    | ----------- | ----------- |
    | `\d` | "digits" `[0-9]` |
    | `\w` | "word characters" `[A-Za-z0-9_]` |
    | `\s` | "whitespace" `[ \t\r\n\f]` |

### Grouping Operators

| Operators | Description |
| --------- | ----------- |
| `(a)`     | The round brackets are used to group parts of a regex. Within the brackets, you can define further patterns which should be processed together. |
| `[a-z]`   | The square brackets are used to define character classes. Inside the brackets, you can specify a list of characters to search for. |
| `{1,10}`  | The curly brackets are used to define quantifiers. Inside the brackets, you can specify a number or a range that indicates how often a previous pattern should be repeated. |
| `\|`       | Also called the OR operator and shows results when one of the two expressions matches. |
| `.*`      | Operates similarly to an AND operator by displaying results only when both expressions are present and match in the specified order. |

- To use these operators, apply the extended regex using the `-E` option in `grep`.

- To use these operators, apply the extended regex using the `-E` option in `grep`.

---
### OR operator

- The regex searches for one of the given search parameters.
- In the example below, it matches lines containing **my** or **false**.

```
grep -E "(my|false)" /etc/passwd
```

---

### AND operator

- Displays results where **both** expressions are present and match in the specified order.

```
grep -E "(my.*false)" /etc/passwd
```

- This is equivalent to chaining two `grep` commands:

```
grep -E "my" /etc/passwd | grep -E "false"
```

## Permission Management

- Linux uses a permission system to control access to files and directories.
  - These permissions act like keys assigned to **users** and **groups**.
  - A user can belong to multiple groups.
- Every file/directory has:
  - An **owner** (the user who created it)
  - An associated **group**
- Permissions are defined separately for:
  - The **owner**
  - The **group**
  - **Others** (everyone else)
- Each can be granted:
  - `r` - Read
  - `w` - Write
  - `x` - Execute

---

### Directory Traversal

- Execute (`x`) permission is required to **enter** a directory, similar to unlocking a door.
- Without execute permission:
  - The contents of the directory may still be **listed**, but not **accessed** or **entered**.
  - The user will receive a `Permission Denied` error.
- Example:
  ```
  ls -l
  drw-rw-r-- 3 cry0l1t3 cry0l1t3 4096 Jan 12 12:30 scripts

  ls -al mydirectory/
  ls: cannot access 'mydirectory/script.sh': Permission denied
  ls: cannot access 'mydirectory/..': Permission denied
  ...
  ```

---

### File vs Directory Permissions

- **On files:**
  - `r` allows reading file contents.
  - `w` allows editing the file.
  - `x` allows executing the file (e.g., scripts or binaries).
- **On directories:**
  - `r` allows listing the directory contents.
  - `w` allows creating or deleting files inside the directory.
  - `x` allows **entering** the directory or accessing items inside.

---

### Viewing Permissions

- Use `ls -l` to view file permissions.
- Example:
  ```
  ls -l /etc/passwd
  -rwxrw-r-- 1 root root 1641 May  4 23:42 /etc/passwd
  ```
  - The first character (`-`) = file (can also be `d` for directory, `l` for symlink)
  - Next 3 characters = owner permissions (`rwx`)
  - Next 3 = group permissions (`rw-`)
  - Last 3 = others (`r--`)

---

### Changing Permissions

- Use `chmod` to modify file or directory permissions.

Examples:
```
ls -l shell
-rwx--x--x 1 cry0l1t3 htbteam 0 May  4 22:12 shell
```

- Grant read permission to **all users**:
  ```
  chmod a+r shell && ls -l shell
  -rwxr-xr-x 1 cry0l1t3 htbteam 0 May  4 22:12 shell
  ```

- Set permissions using octal format:
  ```
  chmod 754 shell && ls -l shell
  -rwxr-xr-- 1 cry0l1t3 htbteam 0 May  4 22:12 shell
  ```

---

### Permission Encoding (Octal System)

- Permissions can be represented numerically (octal) using:
  - `r = 4`
  - `w = 2`
  - `x = 1`
- Add values to form each digit (e.g., `rwx = 4+2+1 = 7`)
- Example:
  ```
  Binary Notation:       4 2 1 | 4 2 1 | 4 2 1
  Binary Representation: 1 1 1 | 1 0 1 | 1 0 0
  Octal Value:           7     | 5     | 4
  Permission:            rwx   | r-x   | r--
  ```

---

### Changing Ownership

- Use `chown` to change file owner and/or group.

Syntax:
```
chown <user>:<group> <file>
```

Example:
```
chown root:root shell && ls -l shell
-rwxr-xr-- 1 root root 0 May  4 22:12 shell
```

---

### SUID / SGID

- Special permission bits that grant **temporary privilege escalation**.
- SUID (`s` instead of `x` in user section):
  - Run the file as its **owner**, not the invoking user.
- SGID (`s` in group section):
  - Run with the file’s **group** privileges.
- Useful for:
  - Administrative tools
  - Running programs with elevated rights
- **Security risk** if misused:
  - E.g., assigning SUID to `journalctl` could allow privilege escalation.
- Reference: [GTFOBins](https://gtfobins.github.io/)

---

### Sticky Bit

- Used mainly on shared directories (e.g., `/tmp`)
- Prevents users from **deleting or renaming files** they don't own, even if they have write access to the directory.

- Representation:
  - `t` = sticky bit set with execute
  - `T` = sticky bit set **without** execute

Example:
```
ls -l
drw-rw-r-t 3 cry0l1t3 cry0l1t3 4096 Jan 12 12:30 scripts
drw-rw-r-T 3 cry0l1t3 cry0l1t3 4096 Jan 12 12:32 reports
```

- `scripts` directory has execute permission and sticky bit.
- `reports` has sticky bit but lacks execute permission (uppercase `T`).

## User Management

- `sudo`
  - Execute command as a different user.
- `su`
  - The su utility requests appropriate user credentials via PAM and switches to that user ID (the default user is the superuser). A shell is then executed.
    - Linux Pluggable Authentication Modules (PAM) is a suite of libraries that allows a Linux system administrator to configure methods to authenticate users.
- `useradd`
  - Creates a new user or update default new user information.
- `userdel`
  - Deletes a user account and related files.
- `usermod`
  - Modifies a user account.
- `addgroup`
  - Adds a group to the system.
- `delgroup`
  - Removes a group from the system.
- `passwd`
  - Changes user password.

## Package Management

- Packages are archives that contain binaries of software, configuration files, information about dependencies and keep track of updates and upgrades.
- The features that most package management systems provide are:
  - Package downloading
  - Dependency resolution
  - A standard binary package format
  - Common installation and configuration locations
  - Additional system-related configuration and functionality
  - Quality control
- The package management software changes to the system to install the package are taken from the package and implemented by the package management software. If the package management software recognizes that additional packages are required for the proper functioning of the package that has not yet been installed, a dependency is included and either warn the administrator or tries to reload the missing software from a repository, for example, and install it in advance.
- If an installed software has been deleted, the package management system then retakes the package's information, modifies it based on its configuration, and deletes files.
- Package manager + related tools:

  - `dpkg`
    - The dpkg is a tool to install, build, remove, and manage Debian packages. The primary and more user-friendly front-end for dpkg is aptitude.
  - `apt`
    - Apt provides a high-level command-line interface for the package management system.
  - `aptitude`
    - Aptitude is an alternative to apt and is a high-level interface to the package manager.
  - `snap`
    - Install, configure, refresh, and remove snap packages. Snaps enable the secure distribution of the latest apps and utilities for the cloud, servers, desktops, and the internet of things.
  - `gem`
    - Gem is the front-end to RubyGems, the standard package manager for Ruby.
  - `pip`
    - Pip is a Python package installer recommended for installing Python packages that are not available in the Debian archive. It can work with version control repositories (currently only Git, Mercurial, and Bazaar repositories), logs output extensively, and prevents partial installs by downloading all requirements before starting installation.
  - `git`
    - Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals.

- APT
  - Debian-based Linux distributions use the APT package manager.
  - A package is an archive file containing multiple ".deb" files.
  - The dpkg utility is used to install programs from the associated ".deb" file.
  - APT makes updating and installing programs easier because many programs have dependencies. When installing a program from a standalone ".deb" file, we may run into dependency issues and need to download and install one or multiple additional packages. APT makes this easier and more efficient by packaging together all of the dependencies needed to install a program.
  - Each Linux distribution uses software repositories that are updated often. When we update a program or install a new one, the system queries these repositories for the desired package. Repositories can be labeled as stable, testing, or unstable. Most Linux distributions utilize the most stable or "main" repository. This can be checked by viewing the contents of the /etc/apt/sources.list file. The repository list for Parrot OS is at /etc/apt/sources.list.d/parrot.list.
  - APT uses a database called the APT cache. This is used to provide information about packages installed on our system offline. We can search the APT cache, for example, to find all Impacket related packages.
    - `apt-cache search impacket`
  - We can then view additional information about a package.
    - `apt-cache show impacket-scripts`
  - We can also list all installed packages.
    - `apt list --installed`
  - If we are missing some packages, we can search for it and install it using the following command.
    - `sudo apt install impacket-scripts -y`
- git
  - e.g. `mkdir ~/nishang/ && git clone https://github.com/samratashok/nishang.git ~/nishang`
- dpkg
  - Example
    - First separately download the progam/tools needed
      - `wget http://archive.ubuntu.com/ubuntu/pool/main/s/strace/strace_4.21-1ubuntu1_amd64.deb`
    - Then use dpkg to install package (could use apt instead)
      - `sudo dpkg -i strace_4.21-1ubuntu1_amd64.deb `

## Service and Process Management

- There are two types of services:
  - internal, the relevant services that are required at system startup, which for example, perform hardware-related tasks, and services that are installed by the user, which usually include all server services.
  - Such services run in the background without any user interaction. These are also called daemons and are identified by the letter 'd' at the end of the program name, for example, `sshd` or `systemd`.
- Most Linux distributions have now switched to `systemd`.
  - This daemon is an Init process started first and thus has the process ID (PID) 1.
    - This daemon monitors and takes care of the orderly starting and stopping of other services.
  - All processes have an assigned PID that can be viewed under /proc/ with the corresponding number. Such a process can have a parent process ID (PPID), known as the child process.
  - Besides `systemctl` we can also use update-rc.d to manage SysV init script links.
  - `systemctl - Control the systemd system and service manager`
- What is SysV?

  - System V is a form of Unix operating system which was developed by AT&T lab, first released in 1983.
  - (Old and replaced by systemd)
  - Init is the program on Unix and Linux systems which spawns all other processes. It runs as a daemon and typically has PID 1. It is the parent of all processes. Its primary role is to create processes from a script stored in the file /etc/inittab file.
  - All System V init scripts are stored in /etc/rc.d/init.d/ or /etc/init.d directory. These scripts are used to control system startup and shutdown. Usually you will find scripts to start a web server or networking.
    - e.g. `/etc/init.d/httpd start` or `/etc/init.d/network restart`

| Term | What it is | What it does |
| ------------ | ------------ | ------------ | 
| SysV (System V init) | An older init system | Handles the startup/shutdown of Linux using shell scripts |
| systemd | A modern init system | Replaces SysV; manages services, boot, logging, dependencies
| systemctl | A command-line tool for systemd | Lets you control and inspect systemd services

| Feature | SysV Init | systemd |
| ------------ | ------------ | ------------ | 
| Startup style | Sequential | Parallel |
| Service control | /etc/init.d/ scripts | systemctl and units |
| Logging | Relies on syslog | Built-in journal (journalctl) |
| Dependencies | Manual | Automatic and declarative |
| Boot speed | Slower | Faster |

- Start the `ssh` service
  - `systemctl start ssh`
- Check if it runs without errors.
  - `systemctl status ssh`
- To add OpenSSH to the SysV script (these scripts are used to control system startup and shutdown) to tell the system to run this service after startup, we can link it with the following command:
  - `systemctl enable ssh`
- Once we reboot the system, the OpenSSH server will automatically run. We can check this with a tool called ps.
  - `ps -aux | grep ssh`
- List all services.
  - `systemctl list-units --type=service`
- Sometimes services do not start due to an error. To see the problem, we can use the tool journalctl to view the logs.
  - `journalctl -u ssh.service --no-pager`
- A process can be in the following states:
  - Running
  - Waiting (waiting for an event or system resource)
  - Stopped
  - Zombie (stopped but still has an entry in the process table).
- Processes can be controlled using `kill`, `pkill`, `pgrep`, and `killall`. To interact with a process, we must send a signal to it.
- We can view all signals with the following command:
  - `kill -l`
- Common signals:
  - 1 SIGHUP
    - This is sent to a process when the terminal that controls it is closed.
  - 2 SIGINT
    - Sent when a user presses [Ctrl] + C in the controlling terminal to interrupt a process.
  - 3 SIGQUIT -
    - Sent when a user presses [Ctrl] + D to quit.
  - 9 SIGKILL
    - Immediately kill a process with no clean-up operations.
  - 15 SIGTERM
    - Program termination.
  - 19 SIGSTOP
    - Stop the program. It cannot be handled anymore.
  - 20 SIGTSTP
    - Sent when a user presses [Ctrl] + Z to request for a service to suspend. The user can handle it afterward.
- If a program were to freeze, we could force to kill it with the following command:
  - `kill 9 <PID> `
- Backgrounding a Process
  - Sometimes it will be necessary to put the scan or process we just started in the background to continue using the current session to interact with the system or start other processes.
    - Can do this with [Ctrl] + Z. This sends a SIGTSTP signal to the kernel, which suspends the process.
  - The [Ctrl] + Z shortcut suspends the processes, and they will not be executed further. To keep it running in the background, we have to enter the command `bg` to put the process in the background.
  - Another option is to automatically set the process with an AND sign (&) at the end of the command.
    - e.g. `ping -c 10 www.hackthebox.eu &`
    - Once the process finishes, we will see the results.
- Foregrounding a Process
  - Use the `jobs` command to list all background processes. Backgrounded processes do not require user interaction, and we can use the same shell session without waiting until the process finishes first. Once the scan or process finishes its work, we will get notified by the terminal that the process is finished.
  - If we want to get the background process into the foreground and interact with it again, we can use the `fg <ID>` command.
- Execute Multiple Commands
  - The semicolon (`;`) is a command separator and executes the commands by ignoring previous commands' results and errors.
    - For example, if we execute the same command but replace it in second place, the command ls with a file that does not exist, we get an error, and the third command will be executed nevertheless.
      - `echo '1'; ls MISSING_FILE; echo '3'`
        - 1
          ls: cannot access 'MISSING_FILE': No such file or directory
          3
  - However, it looks different if we use the double AND characters (`&&`) to run the commands one after the other. If there is an error in one of the commands, the following ones will not be executed anymore, and the whole process will be stopped.
  - Pipes (`|`) depend not only on the correct and error-free operation of the previous processes but also on the previous processes' results. We will deal with the pipes later in the File Descriptors and Redirections section.

## Task Scheduling

- Task scheduling allows automating tasks at specific times or regular intervals.
- Removes the need for manual intervention — useful for:
  - Software updates
  - Backup automation
  - Script execution
- Alerts can be configured to notify admins/users when tasks complete.
- Useful both for **legitimate system management** and **malicious persistence** (e.g., unauthorized cron jobs or backdoors).

---

### Systemd

- `systemd` can run processes or scripts at a specific time or on a recurring basis.
- It uses **timers** and **services**.

Steps to schedule a task with systemd:
1. Create a timer file (defines when the service should run)
2. Create a service file (defines what to run)
3. Activate the timer

#### Create Timer File

```
sudo mkdir /etc/systemd/system/mytimer.timer.d
sudo vim /etc/systemd/system/mytimer.timer
```

Example `mytimer.timer`:
```
[Unit]
Description=My Timer

[Timer]
OnBootSec=3min
OnUnitActiveSec=1hour

[Install]
WantedBy=timers.target
```

- `OnBootSec` runs the task once after boot.
- `OnUnitActiveSec` repeats the task every 1 hour.

#### Create Service File

```
sudo vim /etc/systemd/system/mytimer.service
```

Example `mytimer.service`:
```
[Unit]
Description=My Service

[Service]
ExecStart=/full/path/to/my/script.sh

[Install]
WantedBy=multi-user.target
```

- Describes the script and when to run it (multi-user mode = normal OS state)

#### Reload and Start

Reload systemd to register changes:
```
sudo systemctl daemon-reload
```

Start and enable the timer:
```
sudo systemctl start mytimer.timer
sudo systemctl enable mytimer.timer
```

- `mytimer.service` will now execute on the schedule defined in `mytimer.timer`.

---

### Cron

- `cron` is another tool for scheduling tasks.
- Tasks are defined in a `crontab` file.
- You specify a command and when it should run.

#### Cron Time Format

| Time Field         | Description                                      |
|--------------------|--------------------------------------------------|
| Minutes (0–59)     | Minute the task should run                       |
| Hours (0–23)       | Hour the task should run                         |
| Day of Month (1–31)| Day of the month the task should run             |
| Month (1–12)       | Month the task should run                        |
| Day of Week (0–7)  | Day of week the task should run (0/7 = Sunday)   |

#### Example Crontab Entries

```
# System Update (every 6 hours)
0 */6 * * * /path/to/update_software.sh

# Execute script on first of each month at midnight
0 0 1 * * /path/to/scripts/run_scripts.sh

# Cleanup DB every Sunday at midnight
0 0 * * 0 /path/to/scripts/clean_database.sh

# Weekly backup every Sunday at midnight
0 0 * * 7 /path/to/scripts/backup.sh
```

- Cron jobs can also be logged or set to send notifications.
- A `crontab` can simulate attack scenarios during pentests.

---

### Systemd vs. Cron

| Feature     | systemd                             | cron                                  |
|-------------|--------------------------------------|----------------------------------------|
| Config File | `.timer` and `.service` units        | `crontab` file                         |
| Flexibility | Precise system integration and logging| Lightweight and widely supported       |
| Use Cases   | Boot timers, system-wide services    | Simple repeating tasks (e.g. cleanup)  |

- **systemd**: better for complex service management and boot-time tasks.
- **cron**: simpler for regular timed tasks.

## Network Services

- Network services allow Linux systems to perform remote operations like file transfer, system access, and service hosting.
- These services are useful for both system administration and penetration testing.
- Misconfigured services can lead to vulnerabilities (e.g. unencrypted FTP transfers exposing credentials).
- Common services to know as a pentester:
  - SSH
  - NFS
  - Web servers
  - VPNs

---

### SSH

- SSH (Secure Shell) provides **secure remote access** over a network.
- OpenSSH is the most common SSH server on Linux.
- Allows users to run commands remotely, transfer files, and tunnel connections securely.

Install OpenSSH:
```
sudo apt install openssh-server -y
```

Check if the SSH server is running:
```
systemctl status ssh
```

Connect to a remote host:
```
ssh username@<IP>
```

Example:
```
ssh cry0l1t3@10.129.17.122
```

- SSH config can be changed in `/etc/ssh/sshd_config`
  - Options include: allowed login methods, key authentication, max sessions, etc.

---

### NFS (Network File System)

- NFS allows file sharing across the network **as if mounted locally**.
- Often used for:
  - Centralized storage
  - Cross-host collaboration
  - Replacing insecure FTP setups

Install NFS server:
```
sudo apt install nfs-kernel-server -y
```

Check if it's running:
```
systemctl status nfs-kernel-server
```

NFS is configured via `/etc/exports`, where you define share paths and permissions.

#### Example permissions:

| Option           | Description                                                        |
|------------------|--------------------------------------------------------------------|
| `rw`             | Read-write access                                                  |
| `ro`             | Read-only access                                                   |
| `no_root_squash` | Allows root access from clients                                    |
| `root_squash`    | Limits root on clients to regular user permissions                 |
| `sync`           | Write only after data is fully written                             |
| `async`          | Write may complete before data is fully written (faster, riskier)  |

---

### NFS Example

Create NFS share:
```
mkdir nfs_sharing
echo '/home/user/nfs_sharing hostname(rw,sync,no_root_squash)' >> /etc/exports
```

Mount NFS share on target:
```
mkdir ~/target_nfs
mount 10.129.12.17:/home/john/dev_scripts ~/target_nfs
tree ~/target_nfs
```

- After mounting, contents of `dev_scripts` are available at `~/target_nfs`

---

### Web Servers

- Web servers are common attack targets and can also be used by testers for:
  - Hosting malicious payloads
  - Logging credentials
  - Transferring files via HTTP

#### Apache Web Server

Install:
```
sudo apt install apache2 -y
```

Edit configuration:
```
/etc/apache2/apache2.conf
```

Example directory config:
```apache
<Directory /var/www/html>
  Options Indexes FollowSymLinks
  AllowOverride All
  Require all granted
</Directory>
```

- Can serve files from `/var/www/html`
- Supports `.htaccess` overrides and modules like `mod_rewrite`, `mod_security`, `mod_ssl`

---

### Python Web Server

- Simple alternative for transferring files over HTTP.

Start server in current directory (default port 8000):
```
python3 -m http.server
```

Serve a specific directory:
```
python3 -m http.server --directory /home/user/target_files
```

Specify port:
```
python3 -m http.server 443
```

---

### VPN

- VPN (Virtual Private Network) creates **encrypted tunnels** for secure access to remote/internal networks.
- Useful for:
  - Accessing internal resources
  - Masking IP addresses
  - Performing remote pentests

Install OpenVPN:
```
sudo apt install openvpn -y
```

Connect using a config file:
```
sudo openvpn --config internal.ovpn
```

- OpenVPN server settings can be configured in `/etc/openvpn/server.conf`
- The `.ovpn` config file is needed to connect as a client.

## Working with Web Services

- Popular web servers include IIS, Nginx and Apache.
- For an Apache web server, we can use appropriate modules, which can encrypt the communication between browser and web server (mod_ssl), use as a proxy server (mod_proxy), or perform complex manipulations of HTTP header data (mod_headers) and URLs (mod_rewrite).

- Apache offers the possibility to create web pages dynamically using server-side scripting languages.
  - Scripting languages are PHP, Perl, Ruby, Python, JavaScript, Lua, and .NET.
- We can install the Apache webserver with the following command.
  - `apt install apache2 -y`
- After starting the web server, can access it via http://localhost - you should see a Apache2 Ubuntu Default Page.
- `curl http://localhost`
  - Used to transfer files over multiple protocols hTTP, HTTPS, FTP, SFTP, FTPS, and SCP.
  - This tool gives us the possibility to control and test websites remotely. Besides the remote servers' content, we can also view individual requests to look at the client's and server's communication.
- `wget http://localhost`
  - ith this tool, we can download files from FTP or HTTP servers directly from the terminal and serves as a good download manager.
  - The difference to curl is that the website content is downloaded and stored locally.
    - Saving to: 'index.html'
      index.html 100%[=======================================>] 10,66K --.-KB/s in 0s  
      2020-05-15 17:43:52 (33,0 MB/s) - ‘index.html’ saved [10918/10918]
- `python3 -m http.server`
  - Another option that is often used when it comes to data transfer is the use of Python 3. In this case, the web server's root directory is where the command is executed to start the server.
  - Say that we are in a directory where WordPress is installed and contains a "readme.html".
  - Starting the Python 3 web server in this directory makes the readme file accessably via the web server.
- [Big list of http static server one-liners](https://gist.github.com/willurd/5720255)

## Backup and Restore

- Backups are essential for protecting data against loss, corruption, or accidental deletion.
- Linux offers various tools for secure, incremental, and even encrypted backups.
- Common tools:
  - `rsync` (CLI tool for syncing files and folders)
  - `duplicity` (adds encryption to `rsync`)
  - `deja-dup` (GUI wrapper for `duplicity`)

---

### Rsync Overview

- `rsync` is a fast and efficient tool for syncing files locally or over the network.
- Only transfers changes in files (delta transfer), which makes it ideal for incremental backups.
- Supports compression, SSH for encryption, and a wide variety of flags for fine control.

---

### Install Rsync

Install on Ubuntu:
```
sudo apt install rsync -y
```

---

### Basic Backup with Rsync

Backup a local directory to a remote server:
```
rsync -av /path/to/mydirectory user@backup_server:/path/to/backup/directory
```

- `-a` (archive) preserves file attributes and permissions.
- `-v` (verbose) gives output during transfer.

---

### Enhanced Backup with Options

Add compression, incremental backup dir, and deletion of removed files:
```
rsync -avz --backup --backup-dir=/path/to/backup/folder --delete /path/to/mydirectory user@backup_server:/path/to/backup/directory
```

- `-z`: enable compression during transfer
- `--backup`: keeps changed/deleted files separately
- `--delete`: removes deleted files from destination

---

### Restore from Backup

Restore from remote server to local machine:
```
rsync -av user@remote_host:/path/to/backup/directory /path/to/mydirectory
```

---

### Encrypted Rsync Transfer (via SSH)

Encrypt `rsync` traffic using SSH:
```
rsync -avz -e ssh /path/to/mydirectory user@backup_server:/path/to/backup/directory
```

- Secure channel ensures confidentiality and integrity of transferred data
- Recommended for remote backups across untrusted networks

---

### Auto-Synchronization with Rsync + Cron

- Combine `cron` and `rsync` for automated sync at regular intervals.
- Useful when syncing data across systems or keeping remote storage up to date.

---

### Generate SSH Key Pair for Rsync Authentication

Create SSH keys:
```
ssh-keygen -t rsa -b 2048
```

Copy public key to remote host:
```
ssh-copy-id user@backup_server
```

---

### Backup Script: `RSYNC_Backup.sh`

Example script:
```bash
#!/bin/bash
rsync -avz -e ssh /path/to/mydirectory user@backup_server:/path/to/backup/directory
```

Make script executable:
```
chmod +x RSYNC_Backup.sh
```

---

### Schedule with Crontab

Edit crontab:
```
crontab -e
```

Add cron job to run the script every hour:
```
0 * * * * /path/to/RSYNC_Backup.sh
```

- `cron` will now run `rsync` automatically every hour
- Ensures local changes are pushed to backup without manual intervention

---

### Pwnbox Local Testing (Optional)

To test sync without a remote host:
1. Create two local dirs: `to_backup/` and `synced_backup/`
2. Run `rsync` between them
3. Use `127.0.0.1` as loopback IP if you want to simulate remote behavior

This makes testing automated backups safer and more convenient.

## File System Management

- Managing file systems on Linux is a crucial task that involves organizing, storing, and maintaining data on a disk or other storage device.
- Linux supports many different file systems, including ext2, ext3, ext4, XFS, Btrfs, and NTFS.
- Each file system has unique features suited to specific use cases.

### Common Linux File Systems

- `ext2`
  - An older file system with no journaling.
  - Suited for low-overhead scenarios like USB drives.
- `ext3` and `ext4`
  - Include journaling, which helps recover from crashes.
  - `ext4` is the default on most modern distros due to its balance of performance, reliability, and support for large files.
- `Btrfs`
  - Supports snapshotting and built-in integrity checks.
  - Ideal for complex storage setups.
- `XFS`
  - High-performance and optimized for handling large files.
  - Good in high I/O environments.
- `NTFS`
  - Originally developed for Windows.
  - Useful for dual-boot systems or external drives used across OSs.

---

### Inodes

- Linux file systems follow a Unix-like hierarchical structure.
- Each file and directory is represented by an `inode`.

#### Inode Basics

- An `inode` stores metadata about files/directories:
  - Permissions
  - Ownership
  - Size
  - Timestamps
- It **does not** store the actual data or file name — just pointers to the data blocks.

#### Inode Table

- A database of all inodes used by the kernel to track files and directories.
- Allows efficient access and management of files.
- If the system runs out of inodes, you cannot create new files even if free space is available.

View inode information:
```
ls -il
```

---

### Disk Management

- Use `fdisk` to list and manage disk partitions.

List all partitions:
```
sudo fdisk -l
```

- Shows device names, sizes, types (Linux, swap, etc).

---

### Mounting File Systems

- To access the contents of a device, it must be mounted.

Mount a USB or partition:
```
sudo mount /dev/sdb1 /mnt/usb
cd /mnt/usb && ls -l
```

Check all currently mounted devices:
```
mount
```

Unmount the device:
```
sudo umount /mnt/usb
```

If a mount is in use, check with:
```
lsof | grep /mnt/usb
```

---

### Automount on Boot

- Edit `/etc/fstab` to configure persistent mounts.

Example entry:
```
/dev/sdb1 /mnt/usb ext4 rw,noauto,user 0 0
```

Options:
- `rw`: read-write access
- `noauto`: do not mount automatically at boot
- `user`: allow regular users to mount

---

### Swap Space

- Swap extends RAM by moving inactive memory pages to disk.
- Used to prevent crashes when memory runs low.

Create and activate swap:
```
sudo mkswap /dev/sdX
sudo swapon /dev/sdX
```

View active swap:
```
swapon --show
```

Persist swap in `/etc/fstab`:
```
UUID=<uuid> none swap sw 0 0
```

- Swap can also be used for hibernation.
- It is recommended to encrypt swap on systems handling sensitive data.

## Containerization


Containerization is the process of packaging and running applications in isolated environments called containers. These containers provide consistent, lightweight environments for running applications, ensuring they behave the same way regardless of where they’re deployed.

Technologies like Docker, Docker Compose, and Linux Containers (LXC) make containerization possible—primarily in Linux-based systems. Unlike virtual machines, containers share the host system’s kernel, which makes them more efficient in terms of resource usage. This lightweight nature also makes them highly portable and scalable.

Containers are especially beneficial for microservice architectures, where different application components are packaged and managed independently. Since containers encapsulate all dependencies (e.g., libraries, binaries), they allow applications to run reliably across different environments—development, testing, and production.

### Key Benefits

- **Lightweight**: Shares the host OS kernel; no need to emulate hardware like VMs.
- **Portable**: Can run on any system with a container runtime.
- **Isolated**: Runs in its own environment, separate from the host and other containers.
- **Scalable**: Supports running many instances simultaneously on the same host.

> Analogy: Containers are like portable stage pods for a concert. Each band gets a pod with its lights, speakers, and gear. They all play on the same main stage (host), but don’t interfere with each other.

---

### Dockers

Docker is a platform for building, shipping, and running containerized applications. It uses a layered filesystem and tools for automating deployments.

Docker containers are built using **Dockerfiles** and shared via **Docker Hub**, which offers both **public** and **private** registries.

#### Installing Docker (Ubuntu)

```bash
# Preparation
sudo apt update -y
sudo apt install ca-certificates curl gnupg lsb-release -y
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt update -y
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

# Add user to Docker group
sudo usermod -aG docker htb-student
echo '[!] You need to log out and log back in for the group changes to take effect.'

# Test Docker
docker run hello-world
```

---

### Dockerfile Example

```Dockerfile
# Base image
FROM ubuntu:22.04

# Install packages
RUN apt-get update && \
    apt-get install -y apache2 openssh-server && \
    rm -rf /var/lib/apt/lists/*

# Create user
RUN useradd -m docker-user && \
    echo "docker-user:password" | chpasswd

# Permissions
RUN chown -R docker-user:docker-user /var/www/html && \
    chown -R docker-user:docker-user /var/run/apache2 && \
    chown -R docker-user:docker-user /var/log/apache2 && \
    chown -R docker-user:docker-user /var/lock/apache2 && \
    usermod -aG sudo docker-user && \
    echo "docker-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Expose ports
EXPOSE 22 80

# Start services
CMD service ssh start && /usr/sbin/apache2ctl -D FOREGROUND
```

---

### Docker Build and Run

```bash
# Build
docker build -t FS_docker .

# Run container
docker run -p 8022:22 -p 8080:80 -d FS_docker
```

---

### Docker Management Commands

| Command         | Description                        |
|----------------|------------------------------------|
| `docker ps`     | List running containers            |
| `docker stop`   | Stop container                     |
| `docker start`  | Start stopped container            |
| `docker restart`| Restart container                  |
| `docker rm`     | Remove container                   |
| `docker rmi`    | Remove image                       |
| `docker logs`   | View container logs                |

Note: Docker containers are stateless. Data inside the container is lost when stopped unless volumes are used.

---

### Linux Containers (LXC)

**LXC** is a lightweight virtualization system that runs multiple isolated Linux containers on a single host. Unlike Docker, which is application-centric, LXC behaves more like a traditional virtual machine environment.

| Category       | Docker                              | LXC                                 |
|----------------|--------------------------------------|-------------------------------------|
| **Approach**   | App-focused                          | System-level                        |
| **Image**      | Prebuilt Docker images               | Manual rootfs setup                 |
| **Portability**| Very portable via Docker Hub         | Less portable, host-specific        |
| **Ease of use**| Easier CLI and ecosystem             | Requires more sysadmin knowledge    |
| **Security**   | Good defaults, isolation via namespaces | More control, requires hardening |

---

### Installing LXC (Ubuntu)

```bash
sudo apt-get install lxc lxc-utils -y
```

---

### Creating a Container

```bash
sudo lxc-create -n linuxcontainer -t ubuntu
```

---

### Managing LXC Containers

| Command                                      | Description                           |
|---------------------------------------------|---------------------------------------|
| `lxc-ls`                                     | List containers                       |
| `lxc-start -n <container>`                  | Start container                       |
| `lxc-stop -n <container>`                   | Stop container                        |
| `lxc-restart -n <container>`                | Restart container                     |
| `lxc-attach -n <container>`                 | Enter container shell                 |
| `lxc-config -n <container> -s <key>`        | Configure container (storage, net)    |

---

### Limiting Resources (CPU & Memory)

Create or edit config file:

```bash
sudo vim /usr/share/lxc/config/Linuxcontainer.conf
```

Add:

```text
lxc.cgroup.cpu.shares = 512
lxc.cgroup.memory.limit_in_bytes = 512M
```

Apply:

```bash
sudo systemctl restart lxc.service
```

---

### Namespaces & Isolation

LXC uses **namespaces** for:

- **pid**: isolated process IDs
- **net**: isolated network stack
- **mnt**: separate filesystem
- **cgroups**: control CPU, memory, disk usage

These features allow containers to run securely and independently of the host system. However, additional hardening is recommended.

## Network Configuration

Configuring and managing network settings on Linux is a core skill for penetration testers. It enables efficient test environment setup, traffic manipulation, and vulnerability exploitation. Understanding Linux network configuration allows us to tailor our testing approach, improving both procedures and outcomes.

Key tasks in network configuration include managing network interfaces, assigning IPs, configuring routers/switches, and setting up protocols like:

- **TCP/IP** (communication backbone)
- **DNS** (domain name resolution)
- **DHCP** (dynamic IP allocation)
- **FTP** (file transfer)

We must also be able to troubleshoot wired and wireless interfaces.

---

### Network Access Control (NAC)

Network Access Control helps regulate who can access what in a network. As testers, understanding NAC improves our grasp of system hardening and user restrictions.

| Type      | Description |
|-----------|-------------|
| **DAC** (Discretionary Access Control) | The owner of the resource sets permissions. Most flexible, but least secure. |
| **MAC** (Mandatory Access Control) | Permissions are enforced by the OS. More secure but less flexible. |
| **RBAC** (Role-Based Access Control) | Permissions are based on user roles, making access management easier. |

Linux NAC tools include:

- **SELinux** (Security-Enhanced Linux)
- **AppArmor** (Application-level control)
- **TCP Wrappers** (IP-based access control)

Use tools like `syslog`, `rsyslog`, `lsof`, and the **ELK Stack** to monitor and analyze traffic.

---

### Configuring Network Interfaces

We use `ifconfig` or `ip` to configure interfaces.

- `ifconfig` is older but still widely used.
- `ip` is newer and preferred for modern systems.

These commands let us:

- View network interfaces
- Assign IP addresses
- Set netmasks
- Bring interfaces up/down

---

### Activate Network Interface

```bash
sudo ifconfig eth0 up         # OR
sudo ip link set eth0 up
```

---

### Assign IP Address to Interface

```bash
sudo ifconfig eth0 192.168.1.2
```

---

### Assign a Netmask to an Interface

```bash
sudo ifconfig eth0 netmask 255.255.255.0
```

---

### Assign Route to an Interface

```bash
sudo route add default gw 192.168.1.1 eth0
```

This sets the default gateway to `192.168.1.1` for `eth0`.

---

### Editing DNS Settings

Edit `/etc/resolv.conf`:

```bash
sudo vim /etc/resolv.conf
```

```text
nameserver 8.8.8.8
nameserver 8.8.4.4
```

Note: These changes are not persistent across reboots unless saved in `/etc/network/interfaces` or managed by tools like `NetworkManager` or `systemd-resolved`.

---

### Editing Interfaces File

```bash
sudo vim /etc/network/interfaces
```

```text
auto eth0
iface eth0 inet static
    address 192.168.1.2
    netmask 255.255.255.0
    gateway 192.168.1.1
    dns-nameservers 8.8.8.8 8.8.4.4
```

This configuration ensures the IP, gateway, and DNS persist across reboots.

---

### Restart Networking Service

```bash
sudo systemctl restart networking
```

---

### Monitoring

Network monitoring tools help us identify traffic anomalies and suspicious activity.

Common tools include:

- `Wireshark`
- `tshark`
- `tcpdump`
- `Intro to Network Traffic Analysis` module (HTB)

These tools can help us spot:

- Unencrypted credentials
- Privilege escalation attempts
- Malicious behavior

---

### Troubleshooting

Common network issues include:

- Connectivity problems
- DNS resolution failures
- Packet loss
- Slow speeds

Useful tools:

1. `ping`
2. `traceroute`
3. `netstat`
4. `tcpdump`
5. `Wireshark`
6. `nmap`

---

#### Ping

```bash
ping <remote_host>
ping 8.8.8.8
```

Sends ICMP packets to test connectivity.

---

#### Traceroute

```bash
traceroute www.inlanefreight.com
```

Traces the path packets take to a host.

---

#### Netstat

```bash
netstat -a
```

Displays all active internet connections and listening ports.

---

#### Example Netstat Output

```text
Proto Recv-Q Send-Q Local Address    Foreign Address  State
tcp   0      0      0.0.0.0:smtp     0.0.0.0:*         LISTEN
tcp   0      0      0.0.0.0:http     0.0.0.0:*         LISTEN
tcp   0      0      0.0.0.0:ssh      0.0.0.0:*         LISTEN
```

Issues it helps uncover:

- Firewall misconfigurations
- Incorrect DNS entries
- Cable failures
- Network congestion

---

### Hardening

Security hardening tools in Linux:

#### SELinux

- Mandatory Access Control (MAC)
- Fine-grained process/file-level controls
- Powerful but complex to manage

#### AppArmor

- MAC system using application profiles
- Simpler and user-friendly
- Less granular than SELinux

#### TCP Wrappers

- Controls access by IP address
- Lightweight and easy to configure
- Good for basic network-layer access control

---

These tools:

- Reduce unauthorized access
- Limit exposure of services
- Enhance overall system security

By implementing NAC and using monitoring and troubleshooting tools, we can secure and manage Linux networks effectively in both offensive and defensive scenarios.

## Remote Desktop Protocols in Linux

Remote desktop protocols allow graphical access to remote systems and are widely used in system administration, troubleshooting, and even penetration testing.

Common protocols include:

- **RDP (Remote Desktop Protocol)**
  - Mainly used in Windows environments.
  - Provides full graphical access to the desktop.

- **VNC (Virtual Network Computing)**
  - Common in Linux environments.
  - Allows cross-platform graphical access.
  - Can be used for headless servers or user support.

---

### XServer

The XServer is the user-side component of the **X11** (X Window System), responsible for rendering the GUI locally.

- Enables GUI apps to run remotely but display locally.
- Uses TCP ports `6000–6009` for displays `:0–:9`.

To enable X11 forwarding:

```bash
cat /etc/ssh/sshd_config | grep X11Forwarding
```

Expected output:

```
X11Forwarding yes
```

SSH into a remote system and run a GUI app:

```bash
ssh -X htb-student@10.129.23.11 /usr/bin/firefox
```

---

### X11 Security

X11 is insecure by default:

- Data is sent in plaintext.
- Keystrokes, mouse movements, and window content can be intercepted.
- Tools like `xwd` and `xgrabsc` can capture screen contents.
- X11 vulnerabilities (e.g. CVE-2017-2624/2625/2626) have led to code execution exploits.

Mitigation:
- Use X11 over SSH for encryption.
- Avoid exposing X11 ports directly.

---

### XDMCP

**X Display Manager Control Protocol** provides GUI login screens over the network.

- Uses UDP port `177`.
- Allows users to connect to remote login managers like GDM, LightDM.
- Insecure and susceptible to MITM attacks.
- Not recommended for sensitive environments.

---

### VNC (Virtual Network Computing)

VNC is a graphical desktop sharing system using the RFB protocol.

- Allows full desktop access remotely.
- Used for support, system monitoring, and GUI-based tasks.
- Default port: `5900` for `:0`, `5901` for `:1`, etc.

Popular implementations:
- TigerVNC
- TightVNC
- RealVNC

---

### Installing TigerVNC and XFCE

```bash
sudo apt install xfce4 xfce4-goodies tigervnc-standalone-server -y
vncpasswd
```

---

### Configuring VNC

Create startup files:

```bash
touch ~/.vnc/xstartup ~/.vnc/config
```

Add to `~/.vnc/xstartup`:

```bash
#!/bin/bash
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
/usr/bin/startxfce4
[ -x /etc/vnc/xstartup ] && exec /etc/vnc/xstartup
[ -r $HOME/.Xresources ] && xrdb $HOME/.Xresources
x-window-manager &
```

Add to `~/.vnc/config`:

```
geometry=1920x1080
dpi=96
```

Make the startup script executable:

```bash
chmod +x ~/.vnc/xstartup
```

---

### Starting the VNC Server

```bash
vncserver
```

Example output:

```
New 'linux:1 (htb-student)' desktop at :1 on machine linux
```

---

### Listing Active VNC Sessions

```bash
vncserver -list
```

Example:

```
X DISPLAY #    RFB PORT #    PROCESS ID
:1             5901          79746
```

---

### SSH Tunneling for Secure Access

```bash
ssh -L 5901:127.0.0.1:5901 -N -f -l htb-student 10.129.14.130
```

---

### Connecting via VNC Viewer

```bash
xtightvncviewer localhost:5901
```

Example output:

```
Connected to RFB server, using protocol version 3.8
Performing standard VNC authentication
Password: ******
Authentication successful
```

## Linux Security

Linux systems, while generally more secure than many others, are still vulnerable to a range of attacks. Security is a continual process, not a one-time setup. This section explores foundational steps and configuration best practices to help secure a Linux system.

---

### System Updates

One of the most important fundamentals is keeping the OS and installed packages up to date:

```bash
sudo apt update && apt dist-upgrade
```

---

### Network-Level Protection

If firewall rules aren't properly configured, we can use tools like `iptables` to restrict traffic in/out of the host.

---

### SSH Hardening

SSH should be secured by:
- Disabling password authentication.
- Disallowing root login.
- Using keys instead of passwords.
- Applying the principle of least privilege.

**Avoid full sudo rights**—instead, use the `sudoers` configuration for fine-grained privilege access.

A common tool for brute-force protection is `fail2ban`, which blocks hosts after repeated failed login attempts.

---

### Auditing and Least Privilege

It's important to audit regularly for:
- Outdated kernels
- World-writable files
- Misconfigured cron jobs/services

Outdated kernel versions can be an overlooked vulnerability.

---

### SELinux and AppArmor

For stronger access control, consider enabling:

- **SELinux**: Provides granular access labels and policies.
- **AppArmor**: A simpler MAC system using profiles for access control.

Both restrict what users and applications can access based on enforced policies.

---

### Additional Security Services

Useful security applications include:
- [Snort](https://www.snort.org/)
- [chkrootkit](http://www.chkrootkit.org/)
- [rkhunter](https://rkhunter.sourceforge.net/)
- [Lynis](https://cisofy.com/lynis/)

---

### Recommended Security Settings

- Removing or disabling all unnecessary services and software
- Removing all services that rely on unencrypted authentication mechanisms
- Ensuring NTP is enabled and syslog is running
- Ensuring that each user has their own account
- Enforcing the use of strong passwords
- Setting password aging and reuse limits
- Locking accounts after login failures
- Disabling all unwanted SUID/SGID binaries

---

### TCP Wrappers

TCP Wrappers allow you to control access to services based on IP or hostname. Configuration files:

- `/etc/hosts.allow`: Permits access
- `/etc/hosts.deny`: Denies access

The system checks `hosts.allow` first. If no match is found, it then checks `hosts.deny`.

#### `/etc/hosts.allow` Example

```bash
cat /etc/hosts.allow

# Allow access to SSH from the local network
sshd : 10.129.14.0/24

# Allow access to FTP from a specific host
ftpd : 10.129.14.10

# Allow access to Telnet from any host in the inlanefreight.local domain
telnetd : .inlanefreight.local
```

#### `/etc/hosts.deny` Example

```bash
cat /etc/hosts.deny

# Deny access to all services from any host in the inlanefreight.com domain
ALL : .inlanefreight.com

# Deny access to SSH from a specific host
sshd : 10.129.22.22

# Deny access to FTP from hosts in a subnet
ftpd : 10.129.22.0/24
```

**Note**: Order matters. The first match wins. Also, TCP wrappers are **not** a replacement for a firewall. They control access to services, not ports.

---

## Firewall Setup

Linux systems provide robust firewall capabilities that help protect against unauthorized access, malicious traffic, and network-based attacks. Firewalls act as a vital security layer for filtering inbound and outbound traffic based on defined rules.

The most common firewall system in Linux is **iptables**, which replaced older systems like `ipchains` and `ipfwadm`. The `iptables` tool allows system administrators to define packet filtering rules based on various criteria like IP address, protocol, and port number. It interfaces with the Linux kernel’s Netfilter framework to control traffic flow.

Other solutions like **nftables**, **ufw** (Uncomplicated Firewall), and **firewalld** also exist, offering various levels of abstraction and user-friendliness.

---

### Iptables Overview

`iptables` organizes firewall rules into several components:

| Component | Description |
|----------|-------------|
| **Tables** | Categorize and organize firewall rules |
| **Chains** | Group rules for specific types of network traffic |
| **Rules** | Define criteria for filtering traffic |
| **Matches** | Match traffic characteristics like IP address, port, or protocol |
| **Targets** | Define what action to take on matched packets (e.g., ACCEPT, DROP) |

---

### Tables

Each `iptables` table is designed for specific tasks:

| Table | Description | Built-in Chains |
|-------|-------------|------------------|
| `filter` | Filters network traffic based on IPs, ports, protocols | INPUT, OUTPUT, FORWARD |
| `nat` | Modifies source or destination IPs for NAT | PREROUTING, POSTROUTING |
| `mangle` | Alters packet headers | PREROUTING, OUTPUT, INPUT, FORWARD, POSTROUTING |
| `raw` | Special processing options | PREROUTING, OUTPUT |

---

### Chains

Chains are sets of rules applied in sequence. There are two types:

- **Built-in chains**: Automatically created for each table.
- **User-defined chains**: Custom chains created by the user for better rule organization.

Built-in chains for each table:

- `filter`: INPUT, OUTPUT, FORWARD
- `nat`: PREROUTING, POSTROUTING
- `mangle`: PREROUTING, OUTPUT, INPUT, FORWARD, POSTROUTING

**Example use of user-defined chain:**

> An organization with multiple web servers could create a chain `HTTP_CHAIN` to apply HTTP rules across all of them.

---

### Rules and Targets

Rules define the criteria to match packets, while targets specify what action to take.

| Target | Description |
|--------|-------------|
| `ACCEPT` | Allow the packet through |
| `DROP` | Silently discard the packet |
| `REJECT` | Discard the packet and notify the sender |
| `LOG` | Log the packet in system logs |
| `SNAT` | Source NAT for IP translation |
| `DNAT` | Destination NAT for IP forwarding |
| `MASQUERADE` | Dynamic SNAT for variable IPs |
| `REDIRECT` | Redirect traffic to another port or address |
| `MARK` | Tag packets for further processing |

**Example command:**

```bash
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

This adds a rule to the INPUT chain allowing SSH traffic on port 22.

---

### Matches

Matches determine which packets rules apply to. Common match options:

| Match | Description |
|-------|-------------|
| `-p`, `--protocol` | Match based on protocol (e.g., tcp, udp) |
| `--dport` | Match destination port |
| `--sport` | Match source port |
| `-s`, `--source` | Match source IP address |
| `-d`, `--destination` | Match destination IP address |
| `-m state` | Match connection state (NEW, ESTABLISHED) |
| `-m multiport` | Match multiple ports |
| `-m tcp` / `-m udp` | Match TCP/UDP-specific options |
| `-m string` | Match based on string content |
| `-m limit` | Match at a specified rate |
| `-m conntrack` | Match based on connection tracking info |
| `-m mac` | Match based on MAC address |
| `-m iprange` | Match IPs in a specified range |

**Example command:**

```bash
sudo iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
```

This rule allows incoming HTTP traffic (TCP on port 80).

---

By mastering the use of tables, chains, rules, matches, and targets, Linux users can implement a highly customizable and secure firewall setup tailored to their network and application needs.

## System Logs

System logs on Linux are a crucial resource for monitoring and troubleshooting system activity. They provide insight into the behavior of the system, user activities, application errors, and potential security incidents. These logs help penetration testers detect unauthorized actions, failed access attempts, or anomalies that could indicate an intrusion or misconfiguration.

Types of logs stored on a Linux system include:

- **Kernel Logs**
- **System Logs**
- **Authentication Logs**
- **Application Logs**
- **Security Logs**

---

### Kernel Logs

- Stored in: `/var/log/kern.log`
- Contain information related to the kernel, such as:
  - Hardware drivers
  - System calls
  - Kernel events
- Useful for:
  - Detecting outdated or vulnerable drivers
  - Observing hardware failures or resource limitations
  - Identifying malicious software or kernel exploits

---

### System Logs

- Stored in: `/var/log/syslog`
- Include:
  - Service start/stop info
  - Reboots
  - Login attempts
- Helpful for detecting:
  - Failed services
  - Reboot reasons
  - Unexpected activities or patterns

#### Example:

```bash
Feb 28 2023 15:06:01 server CRON[2715]: (root) CMD (/usr/local/bin/backup.sh)
Feb 28 2023 15:04:22 server sshd[3010]: Failed password for htb-student from 10.14.15.2 port 50223 ssh2
Feb 28 2023 15:08:05 server apache2[2094]: 127.0.0.1 - - [28/Feb/2023:15:06:43 +0000] "GET /index.html HTTP/1.1" 200 13484 "-" "Mozilla/5.0"
```

---

### Authentication Logs

- Stored in: `/var/log/auth.log`
- Record:
  - Successful & failed authentication attempts
  - `sudo` usage
  - SSH login activity
- Useful for:
  - Detecting brute force attempts
  - Monitoring privilege escalation
  - Investigating unauthorized access

#### Example:

```bash
Feb 28 2023 18:15:01 sshd[5678]: Accepted publickey for admin from 10.14.15.2 port 43210
Feb 28 2023 18:15:03 sudo: admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
Feb 28 2023 18:15:10 sshd[5678]: Disconnected from 10.14.15.2 port 43210 [preauth]
Feb 28 2023 18:15:12 kernel: [ 778.049217] firewall: unexpected traffic allowed on port 22
Feb 28 2023 18:15:13 systemd-logind[1234]: New session 4321 of user admin.
```

---

### Application Logs

- Common log paths:
  - Apache: `/var/log/apache2/error.log`
  - MySQL: `/var/log/mysql/error.log`
- Include:
  - Web request handling
  - DB transaction info
  - Errors, warnings, crashes
- Useful for:
  - Detecting vulnerabilities in services
  - Monitoring suspicious requests or behaviors
  - Debugging service-level issues

---

### Access Logs

- Track user actions like:
  - File accesses
  - Command executions
  - Modifications to system configs

#### Example Log Entry:

```bash
2023-03-07T10:15:23+00:00 servername privileged.sh: htb-student accessed /root/hidden/api-keys.txt
```

In this case:
- User `htb-student` accessed a sensitive file via the `privileged.sh` script
- May indicate lateral movement or sensitive data collection

---

### Common Log Locations by Service

| **Service**   | **Log Location**                                       |
|---------------|--------------------------------------------------------|
| Apache        | `/var/log/apache2/access.log`                          |
| Nginx         | `/var/log/nginx/access.log`                            |
| OpenSSH       | `/var/log/auth.log`, `/var/log/secure`                |
| MySQL         | `/var/log/mysql/mysql.log`                             |
| PostgreSQL    | `/var/log/postgresql/postgresql-version-main.log`     |
| Systemd       | `/var/log/journal/`                                    |

---

### Security Logs

- Key files:
  - `/var/log/fail2ban.log`
  - `/var/log/ufw.log`
  - `/var/log/syslog`
  - `/var/log/auth.log`
- Useful for:
  - Detecting brute force login attempts
  - Observing firewall blocks
  - Tracking policy violations and anomalies

---

### Log Analysis Tools

To inspect and search logs effectively, use:

- `less`, `more`, `cat` — basic viewing
- `grep`, `awk`, `sed` — pattern matching & filtering
- `tail -f` — live monitoring
- `/var/log/journal/` — persistent log store for `systemd`

---

By configuring, storing, and reviewing system logs properly, we can identify issues early, detect attacks, and ensure overall system health and compliance.

## Solaris

Solaris is a Unix-based operating system developed by Sun Microsystems (later acquired by Oracle Corporation) in the 1990s. It is renowned for its robustness, scalability, and high-end hardware/software support. Solaris is widely used in enterprise environments, especially for mission-critical applications such as database management, cloud computing, and virtualization.

One of Solaris’ standout features is its built-in hypervisor called **Oracle VM Server for SPARC**, which allows multiple virtual machines to run on a single physical server. Solaris is known for high availability, fault tolerance, and system management features that make it ideal for industries where reliability and performance are paramount, including finance, government, and large-scale data centers.

---

### Linux Distributions vs Solaris

While both Solaris and Linux are Unix-based, they differ significantly in philosophy and implementation:

- **Solaris** is proprietary and maintained by Oracle, with closed-source code.
- **Linux distributions** are open-source and community-driven.

Key differences:
- Solaris uses **ZFS** (Zettabyte File System) for advanced filesystem management.
- Solaris uses **SMF** (Service Management Facility) for service reliability and observability.
- Linux favors more open and modular alternatives.

---

### Common Directories in Linux

| Directory      | Description                                                                 |
|----------------|-----------------------------------------------------------------------------|
| `/`            | Root directory.                                                              |
| `/bin`         | Essential user binaries.                                                     |
| `/boot`        | Boot loader and kernel-related files.                                        |
| `/dev`         | Device files.                                                                |
| `/etc`         | System configuration files.                                                  |
| `/home`        | User home directories.                                                       |
| `/kernel`      | Kernel-related files.                                                        |
| `/lib`         | Shared libraries.                                                            |
| `/lost+found`  | Recovered file fragments.                                                    |
| `/mnt`         | Temporary mounts.                                                            |
| `/opt`         | Optional software.                                                           |
| `/proc`        | Kernel and process information.                                              |
| `/sbin`        | System administration binaries.                                              |
| `/tmp`         | Temporary files.                                                             |
| `/usr`         | Read-only user data.                                                         |
| `/var`         | Variable files (logs, mail, print queues).                                   |

---

### Key Differences

Categories of differences:

- Filesystem
- Process management
- Package management
- Kernel/Hardware support
- Monitoring
- Security

---

### System Information

**Linux (Ubuntu):**
```bash
uname -a
```
Example:
```
Linux ubuntu 5.4.0-1045 #48-Ubuntu SMP Fri Jan 15 10:47:29 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```

**Solaris:**
```bash
showrev -a
```
Example:
```
Hostname: solaris
Kernel architecture: sun4u
OS version: Solaris 10 8/07 s10s_u4wos_12b SPARC
Application architecture: sparc
Hardware provider: Sun_Microsystems
Domain: sun.com
Kernel version: SunOS 5.10 Generic_139555-08
```

---

### Installing Packages

**Linux:**
```bash
sudo apt-get install apache2
```

**Solaris:**
```bash
pkgadd -d SUNWapchr
```

Solaris uses the **Image Packaging System (IPS)** and does not always require `sudo` because of the **RBAC** system.

---

### Permission Management

**Linux:**
```bash
chmod 700 filename
find / -perm 4000
```

**Solaris:**
```bash
chmod 700 filename
find / -perm -4000
```

Note the `-` in Solaris' permission checking.

---

### NFS in Solaris

**Share directory:**
```bash
share -F nfs -o rw /export/home
```

**Mount in Solaris:**
```bash
mount -F nfs 10.129.15.122:/nfs_share /mnt/local
```

**NFS config file:**
```bash
cat /etc/dfs/dfstab
```

---

### Process Mapping

**Linux:**
```bash
sudo lsof -c apache2
```

**Solaris:**
```bash
pfiles `pgrep httpd`
```

---

### Executable Access

**Linux with strace:**
```bash
sudo strace -p `pgrep apache2`
```

**Solaris with truss:**
```bash
truss ls
```

- `strace` traces syscalls made by the process.
- `truss` does the same but also supports child processes and signals.

---
```

## Exercises

- How many services are listening on the target system on all interfaces? (Not on localhost and IPv4 only)
  - `netstat -l4 |  grep LISTEN | grep -v "127\.0\.0\|localhost" | wc -l`
  - `ss -l4 |  grep LISTEN | grep -v "127\.0\.0\|localhost" | wc -l`
- Determine what user the ProFTPd server is running under.
  - `ps -aux | grep -i ProFTPd`
- Use cURL from your Pwnbox (not the target machine) to obtain the source code of the "https://www.inlanefreight.com" website and filter all unique paths of that domain. Submit the number of these paths as the answer.
- `curl https://www.inlanefreight.com | tr " " "\n" | cut -d"'" -f2 | cut -d"\"" -f2 | grep https://www.inlanefreight.com | sort -u | wc -l`

## Other

- Maximum transmission unit (MTU) is a measurement representing the largest data packet that a network-connected device will accept.
  - The Maximum Transmission Unit (MTU) is the size of the largest packet or frame that can be transmitted on a network. The MTU size is determined by the physical layer of the network. For example, Ethernet has an MTU size of 1500 bytes.
  - It is important to check MTU size because the wrong setting can lead to poor network performance. A too-large MTU can cause fragmentation, which can lead to lower throughput and higher latency. A too-small MTU can also cause problems, such as dropped packets and retransmissions.
  - The best practice for MTU size in Linux is to set the MTU size to the same size as the largest packet size that your network can handle. This will help to ensure that packets are not dropped due to being too large.
  - The MTU size on server side should be same as the MTU size in switch side. otherwise it will cause issues.
