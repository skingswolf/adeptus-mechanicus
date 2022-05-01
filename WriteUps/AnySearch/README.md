# Any Search Malware

Recently was troubleshooting a browser issue on my Sister's laptop. Despite never having explicitly reset her Chrome browser's default search engine, it had been set to search.anysearch.net.

Looking into this took me down the rabbit hole. Here's what I found ...

Observations:

- Slow webpage loading, inspite of a stable WiFi connectopm.
- Some websites completely blocked from loading. "No Internet" message rendered.
- In *System Preferences/Network/Advanced Settings*, I could see the the SOCKS proxy setting was turned on. Switched it back on. Going back to this page I can see that it's been turned on.
- Suspicious profiles set in *System Preferences/Profiles*

