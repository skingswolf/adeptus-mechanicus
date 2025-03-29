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
  - [User Management](#user-management)
  - [Package Management](#package-management)
  - [Service and Process Management](#service-and-process-management)
  - [Working with Web Services](#working-with-web-services)
  - [Exercises](#exercises)
  - [Other](#other)

These are very basic notes. They've have been copied & pasted from HackTheBox's module for completeness
3

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
  - Init is the program on Unix and Linux systems which spawns all other processes. It runs as a daemon and typically has PID 1. It is the parent of all processes. Its primary role is to create processes from a script stored in the file /etc/inittab file.
  - All System V init scripts are stored in /etc/rc.d/init.d/ or /etc/init.d directory. These scripts are used to control system startup and shutdown. Usually you will find scripts to start a web server or networking.
    - e.g. `/etc/init.d/httpd start` or `/etc/init.d/network restart`

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
