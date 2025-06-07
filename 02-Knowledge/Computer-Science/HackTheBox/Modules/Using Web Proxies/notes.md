# Using Web Proxies

- [Intro to Web Proxies](#intro-to-web-proxies)
- [Setting Up](#setting-up)
- [Proxy Setup](#proxy-setup)
- [Intercepting Web Requests](#intercepting-web-requests)
- [Intercepting Responses](#intercepting-requests)
- [Automatic Modification](#automatic-modification)
- [Repeating Requests](#repeating-requests)
- [Encoding/Decoding](#encoding-decoding)
- [Proxying Tools](#proxying-tools)
- [Burp Intruder](#burp-intruder)
- [ZAP Fuzzer](#zap-fuzzer)
- [Burp Scanner](#burp-scanner)
- [ZAP Scanner](#zap-scanner)
- [Extensions](#extensions)
- [Skills Assessment](#skills-assessment)

## Intro to Web Proxies

Today, most modern web and mobile applications work by continuously connecting to back-end servers to send and receive data and then processing this data on the user's device, like their web browsers or mobile phones. With most applications heavily relying on back-end servers to process data, testing and securing the back-end servers is quickly becoming more important.

Testing web requests to back-end servers make up the bulk of Web Application Penetration Testing, which includes concepts that apply to both web and mobile applications. To capture the requests and traffic passing between applications and back-end servers and manipulate these types of requests for testing purposes, we need to use **Web Proxies**.

---

### What Are Web Proxies?

Web proxies are specialized tools that can be set up between a browser/mobile application and a back-end server to capture and view all the web requests being sent between both ends, essentially acting as man-in-the-middle (MITM) tools. While other **Network Sniffing** applications, like Wireshark, operate by analyzing all local traffic to see what is passing through a network, Web Proxies mainly work with web ports such as, but not limited to, **HTTP/80** and **HTTPS/443**.

Web proxies are considered among the most essential tools for any web pentester. They significantly simplify the process of capturing and replaying web requests compared to earlier CLI-based tools. Once a web proxy is set up, we can see all HTTP requests made by an application and all of the responses sent by the back-end server. Furthermore, we can intercept a specific request to modify its data and see how the back-end server handles them, which is an essential part of any web penetration test.

---

### Uses of Web Proxies

While the primary use of web proxies is to capture and replay HTTP requests, they have many other features that enable different uses for web proxies. The following list shows some of the other tasks we may use web proxies for:

- Web application vulnerability scanning  
- Web fuzzing  
- Web crawling  
- Web application mapping  
- Web request analysis  
- Web configuration testing  
- Code reviews  

In this module, we will not discuss any specific web attacks, as other HTB Academy web modules cover various web attacks. However, we will thoroughly cover how to use web proxies and their various features and mention which type of web attacks require which feature. We will be covering the two most common web proxy tools: **Burp Suite** and **ZAP**.

---

### Burp Suite

[Burp Suite (Burp)](https://portswigger.net/burp) - pronounced Burp Sweet - is the most common web proxy for web penetration testing. It has an excellent user interface for its various features and even provides a built-in Chromium browser to test web applications. Certain Burp features are only available in the commercial version **Burp Pro/Enterprise**, but even the free version is an extremely powerful testing tool to keep in our arsenal.

Some of the **paid-only** features are:
- Active web app scanner  
- Fast Burp Intruder  
- The ability to load certain Burp Extensions  

The community **free** version of Burp Suite should be enough for most penetration testers. Once we start more advanced web application penetration testing, the **pro** features may become handy. Most of the features we will cover in this module are available in the community **free** version of Burp Suite, but we will also touch upon some of the **pro** features, like the Active Web App Scanner.

> **Tip:** If you have an educational or business email address, then you can apply for a free trial of Burp Pro at this [link](https://portswigger.net/burp) to be able to follow along with some of the Burp Pro-only features showcased later in this module.

---

### OWASP Zed Attack Proxy (ZAP)

[OWASP Zed Attack Proxy (ZAP)](https://www.zaproxy.org/) is another common web proxy tool for web penetration testing. ZAP is a free and open-source project initiated by the [Open Web Application Security Project (OWASP)](https://owasp.org) and maintained by the community, so it has no paid-only features as Burp does. It has grown significantly over the past few years and is quickly gaining market recognition as the leading open-source web proxy tool.

Just like Burp, ZAP provides various basic and advanced features that can be utilized for web pentesting. ZAP also has certain strengths over Burp, which we will cover throughout this module. The main advantage of ZAP over Burp is being a free, open-source project, which means that we will not face any throttling or limitations in our scans that are only lifted with a paid subscription. Furthermore, with a growing community of contributors, ZAP is gaining many of the paid-only Burp features for free.

In the end, learning both tools can be quite similar and will provide us with options for every situation through a web pentest, and we can choose to use whichever one we find more suitable for our needs. In some instances, we may not see enough value to justify a paid Burp subscription, and we may switch to ZAP to have a completely open and free experience. In other situations where we want a more mature solution for advanced pentests or corporate pentesting, we may find the value provided by Burp Pro to be justified and may switch to Burp for these features.

---

## Setting Up

Both **Burp** and **ZAP** are available for Windows, macOS, and any Linux distribution. Both are already installed on your PwnBox instance and can be accessed from the bottom dock or top bar menu. Both tools are pre-installed on common Penetration Testing Linux distributions like Parrot or Kali. We will cover the installation and setup process for Burp and ZAP in this section which will be helpful if we want to install the tools on our own VM.

---

### Burp Suite

If Burp is not pre-installed in our VM, we can start by downloading it from [Burp’s Download Page](https://portswigger.net/burp). Once downloaded, we can run the installer and follow the instructions, which vary from one operating system to another, but should be pretty straightforward. There are installers for Windows, Linux, and macOS.

Once installed, Burp can either be launched from the terminal by typing `burpsuite`, or from the application menu as previously mentioned.  
Another option is to download the **JAR** file (which can be used on all operating systems with a Java Runtime Environment (JRE) installed) from the above downloads page. We can run it with the following command line or by double-clicking it:

```bash
java -jar </path/to/burpsuite.jar>
```

> **Note:** Both Burp and ZAP rely on Java Runtime Environment to run, but this package should be included in the installer by default. If not, we can follow the instructions found on this [page](https://www.java.com/en/download/).

Once we start up Burp, we are prompted to create a new project. If we are running the community version, we would only be able to use temporary projects without the ability to save our progress and carry on later.

We may need to save our progress if we were pentesting huge web applications or running an **Active Web Scan**. However, we may not need to save our progress and, in many cases, can start a **temporary** project every time.

So, let’s select **temporary project**, and click continue. Once we do, we will be prompted to either use **Burp Default Configurations**, or to **Load a Configuration File**, and we'll choose the first option.

Once we start heavily utilizing Burp’s features, we may want to customize our configurations and load them when starting Burp. For now, we can keep **Use Burp Defaults**, and **Start Burp**. Once all of this is done, we should be ready to start using Burp.

---

### ZAP

We can download ZAP from its [download page](https://www.zaproxy.org/download/), choose the installer that fits our operating system, and follow the basic installation instructions to get it installed. ZAP can also be downloaded as a cross-platform JAR file and launched with the `java -jar` command or by double-clicking on it, similarly to Burp.

To get started with ZAP, we can launch it from the terminal with the `zaproxy` command or access it from the application menu like Burp. Once ZAP starts up, unlike the free version of Burp, we will be prompted to either create a new project or a temporary project. Let’s use a temporary project by choosing **no**, as we will not be working on a big project that we will need to persist for several days.

After that, we will have ZAP running, and we can continue the proxy setup process, as we will discuss in the next section.

> **Tip:** If you prefer to use a dark theme, you may do so in Burp by going to `(User Options > Display)` and selecting "dark" under `(theme)`,  
> and in ZAP by going to `(Tools > Options > Display)` and selecting "Flat Dark" in `(Look and Feel)`.

---

## Proxy Setup

Now that we have installed and started both tools, we'll learn how to use the most commonly used feature: **Web Proxy**.

We can set up these tools as a proxy for any application, such that all web requests would be routed through them so that we can manually examine what web requests an application is sending and receiving. This will enable us to better understand what the application is doing in the background and allows us to intercept and change these requests or reuse them with various changes to see how the application responds.

---

### Pre-Configured Browser

To use the tools as web proxies, we must configure our browser proxy settings to use them as the proxy or use the pre-configured browser. Both tools have a pre-configured browser that comes with pre-configured proxy settings and the CA certificates pre-installed, making starting a web penetration test very quick and easy.

In Burp's `(Proxy > Intercept)`, we can click on **Open Browser**, which will open Burp's pre-configured browser, and automatically route all web traffic through Burp.

In ZAP, we can click on the Firefox browser icon at the end of the top bar, and it will open the pre-configured browser:

> ![ZAP Firefox Icon](screenshot-placeholder)

For our uses in this module, using the pre-configured browser should be enough.

---

### Proxy Setup (Manual Browser)

In many cases, we may want to use a real browser for pentesting, like Firefox. To use Firefox with our web proxy tools, we must first configure it to use them as the proxy. We can manually go to Firefox preferences and set up the proxy to use the web proxy listening port. Both Burp and ZAP use port `8080` by default, but we can use any available port. If we choose a port that is in use, the proxy will fail to start, and we will receive an error message.

> **Note:** In case we wanted to serve the web proxy on a different port, we can do that in Burp under `(Proxy > Options)`, or in ZAP under `(Tools > Options > Local Proxies)`. In both cases, we must ensure that the proxy configured in Firefox uses the same port.

Instead of manually switching the proxy, we can utilize the Firefox extension **Foxy Proxy** to easily and quickly change the Firefox proxy. This extension is pre-installed in your PwnBox instance and can be installed to your own Firefox browser by visiting the **Firefox Extensions Page** and clicking **Add to Firefox** to install it.

Once we have the extension added, we can configure the web proxy on it by clicking on its icon on Firefox’s top bar and then choosing **options**:

Once we’re on the **options** page, we can click on **add** on the left pane, and then use `127.0.0.1` as the IP, and `8080` as the port, and name it **Burp** or **ZAP**:

> **Note:** This configuration is already added to Foxy Proxy in PwnBox, so you don’t have to do this step if you are using PwnBox.

Finally, we can click on the **Foxy Proxy** icon and select **Burp/ZAP**.

---

### Installing CA Certificate

Another important step when using Burp Proxy/ZAP with our browser is to install the web proxy’s CA Certificates. If we don’t do this step, some HTTPS traffic may not get properly routed, or we may need to click **accept** every time Firefox needs to send an HTTPS request.

We can install Burp’s certificate once we select Burp as our proxy in **Foxy Proxy**, by browsing to `http://burp`, and download the certificate from there by clicking on **CA Certificate**.

To get ZAP’s certificate, we can go to `(Tools > Options > Dynamic SSL Certificate)`, then click on **Save**.

We can also change our certificate by generating a new one with the **Generate** button.

Once we have our certificates, we can install them within Firefox by browsing to `about:preferences#privacy`, scrolling to the bottom, and clicking **View Certificates**.

After that, we can select the **Authorities** tab, and then click on **import**, and select the downloaded CA certificate:

Finally, we must select:

- **Trust this CA to identify websites**
- **Trust this CA to identify email users**

...and then click **OK**.

---

## Intercepting Web Requests

Now that we have set up our proxy, we can use it to intercept and manipulate various HTTP requests sent by the web application we are testing. We'll start by learning how to intercept web requests, change them, and then send them through to their intended destination.

---

### Intercepting Requests

#### Burp

In Burp, we can navigate to the **Proxy** tab, and request interception should be on by default. If we want to turn request interception on or off, we may go to the **Intercept** sub-tab and click on `Intercept is on/off` button to do so:

```ascii
+------------+--------+--------+--------+--------+--------+---------+----------------+
| Dashboard  | Target | Proxy  | ...    | Decoder| Logger | Options | User Options   |
+------------+--------+--------+--------+--------+--------+---------+----------------+
| Intercept  | HTTP history | WebSockets history | Options                      |
+------------+----------------------------------------------------------+
| [Forward] [Drop] [Intercept is on] [Action] [Open Browser]            |
```

Once interception is on, we can start up the pre-configured browser and visit our target website. Then back in Burp, we'll see the intercepted request awaiting our action.

```http
GET / HTTP/1.1
Host: 46.101.23.188:30820
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,...
Connection: close
```

If needed, click **Forward** to send the request through.

---

#### ZAP

In ZAP, interception is off by default. You can click the green power icon in the top right to toggle it, or press `CTRL+B`.

To intercept:

1. Click the circle button to toggle request interception.
2. Revisit the target in the pre-configured browser.
3. When the request appears, click the step (>) button next to it.

```http
GET http://46.101.23.188:30768/ HTTP/1.1
Host: 46.101.23.188:30768
User-Agent: Mozilla/5.0
Accept: text/html,...
```

ZAP also has a HUD (Heads-Up Display), which lets you interact with intercepted requests from the browser itself.

To intercept with HUD:

1. Turn HUD on using the top bar.
2. Visit the target URL.
3. When a request is triggered, a HUD overlay will show an HTTP message pop-up.

---

### Manipulating Intercepted Requests

Once a request is intercepted, it remains paused until you forward it. You can:

- Inspect the request.
- Modify headers or data.
- Change parameters.
- Replay it.

This is useful in many attack scenarios:

1. SQL injections  
2. Command injections  
3. Upload bypass  
4. Authentication bypass  
5. XSS  
6. XXE  
7. Error handling  
8. Deserialization

Let’s see a practical manipulation example.

---

#### Exploiting Input via Intercepted Request

Suppose we send a POST request:

```http
POST /ping HTTP/1.1
Host: 46.101.23.188:30820
Content-Length: 4
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 ...
Accept: text/html,...
Connection: close

ip=1
```

Modify it to:

```http
ip=1;ls;
```

Upon forwarding this, the server’s response will be:

```
flag.txt  
index.html  
node_modules  
package-lock.json  
public  
server.js  
```

This means we successfully injected and executed a command by modifying the intercepted HTTP request.

> ⚠️ **Note:** This module does not dive into specific attack types — only how proxies can be used to intercept and alter requests. You’ll learn more in future web exploitation modules.

--- 

## Intercepting Web Requests

Now that we have set up our proxy, we can use it to intercept and manipulate various HTTP requests sent by the web application we are testing. We'll start by learning how to intercept web requests, change them, and then send them through to their intended destination.

---

### Intercepting Requests

#### Burp

In Burp, navigate to the **Proxy** tab. Interception should be on by default. If not, go to the **Intercept** sub-tab and click the button to toggle interception.

```
┌─────────────────────────────────────────────────────────────┐
│ Dashboard | Target | Proxy | Intruder | Repeater | ...      │
├─────────────────────────────────────────────────────────────┤
│ Intercept | HTTP history | WebSockets history | Options     │
├─────────────────────────────────────────────────────────────┤
│ [Forward] [Drop] [Intercept is on] [Action] [Open Browser]  │
└─────────────────────────────────────────────────────────────┘
```

Start the pre-configured browser and visit the target. Return to Burp and you'll see the intercepted request, which you can **Forward**.

Example intercepted request:

```
GET / HTTP/1.1
Host: 46.101.23.188:30820
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
Accept: text/html,...
Connection: close
```

> Tip: Firefox may intercept multiple requests. Keep forwarding until you hit the correct one.

---

#### ZAP

In ZAP, interception is off by default. Toggle it using the green button or `CTRL+B`.

```
┌────────────────────────────────────────────┐
│ [Standard Mode] ▪ Sites ◯ ◯ ◯ ◯ ◯ ◯ ◯ ●     │
└────────────────────────────────────────────┘
```

After starting the browser and making a request, intercepted requests appear in the top-right pane. You can use the **Step** or **Continue** buttons.

Intercepted request:

```
GET http://46.101.23.188:30768/ HTTP/1.1
Host: 46.101.23.188:30768
User-Agent: Mozilla/5.0
Accept: text/html,...
```

---

ZAP also has a HUD (Heads-Up Display):

- Enable it via the HUD button in the top bar.
- It overlays the browser and shows intercepted requests inline.

Intercepted message in HUD:

```
GET http://46.101.23.188:30768/ HTTP/1.1
Host: 46.101.23.188:30768
...
```

---

### Manipulating Intercepted Requests

Requests remain paused until forwarded. We can edit them, which is useful for:

```
1. SQL injection
2. Command injection
3. Upload bypass
4. Authentication bypass
5. XSS
6. XXE
7. Error handling
8. Deserialization
```

Example intercepted POST request:

```
POST /ping HTTP/1.1
Host: 46.101.23.188:30820
Content-Length: 4
...
ip=1
```

Modify:

```
ip=1;ls;
```

Resulting page output:

```
flag.txt
index.html
node_modules
package-lock.json
public
server.js
```

---

### Intercepting Responses

Sometimes, we want to change server **responses** before the browser renders them.

#### Burp

Go to:
```
Proxy > Options > Intercept Server Responses
```

Enable interception rules like:

```
Edit: Content type header Matches text
Remove: Request Was modified
Remove: Status code Does not match ^304$
```

Intercepted response:

```html
<body>
  <form name='ping' method='post'>
    <label for="ip">Ping Your IP:</label>
    <input type="number" id="ip" maxlength="3" />
  </form>
</body>
```

Change:
- `type="number"` ➝ `type="text"`
- `maxlength="3"` ➝ `maxlength="100"`

Modified version:

```html
<input type="text" id="ip" maxlength="100" />
```

Now we can submit payloads like:

```
;ls;
```

---

### Intercepting Responses in ZAP

When using ZAP:

1. Click **Step** to intercept the response.
2. Modify the HTML in the response window.

Example intercepted HTML:

```html
<input type="text" id="ip" name="ip" min="1" max="255" maxlength="100">
```

Submitting `;ls;` now works directly in the browser.

---

### ZAP HUD Features

HUD lets us:

- Enable disabled fields (click light bulb icon).
- Show hidden inputs.
- Reveal HTML comments using the **Comments** button.

Example:

```
<!-- Developer comment: admin=true -->
```

This lets us bypass restrictions and inspect otherwise hidden functionality.

---

By intercepting and modifying requests and responses, we gain powerful control for penetration testing and vulnerability exploration.

---

## Automatic Modification

We may want to apply certain modifications to all outgoing HTTP requests or all incoming HTTP responses in certain situations. In these cases, we can utilize automatic modifications based on rules we set, so the web proxy tools will automatically apply them.

---

### Automatic Request Modification

Let us start with an example of automatic request modification. We can choose to match any text within our requests, either in the request header or request body, and then replace them with different text. For the sake of demonstration, let's replace our `User-Agent` with `HackTheBox Agent 1.0`, which may be handy in cases where we may be dealing with filters that block certain User-Agents.

---

#### Burp Match and Replace

We can go to `Proxy > Options > Match and Replace` and click on **Add** in Burp. As the below screenshot shows, we will set the following options:

```
Type: Request header
Match: ^User-Agent.*$
Replace: User-Agent: HackTheBox Agent 1.0
Comment: [leave empty]
Regex match: ✅
```

📌 This means:

- **Type:** The change is made in the request header.
- **Match:** The regex pattern will match any `User-Agent` string.
- **Replace:** We replace it with our custom string `User-Agent: HackTheBox Agent 1.0`.
- **Regex match:** True, so the `^User-Agent.*$` pattern works.

Once we click `OK`, this new Match and Replace rule is added and enabled. From this point forward, any request made via Burp will have its `User-Agent` header automatically replaced.

💡 We can verify it by visiting any site in Burp’s pre-configured browser. After intercepting a request, we should see:

```
User-Agent: HackTheBox Agent 1.0
```

---

### ZAP Replacer

ZAP has a similar feature called **Replacer**, accessible via `CTRL + R` or the `Replacer` option in the menu.

You can click **Add** and fill in the following:

```
Description: HTB User-Agent
Match Type: Request Header (will add if not present)
Match String: User-Agent
Match Regex: ✅
Replacement String: HackTheBox Agent 1.0
Initiators: Applies to all initiators
Enable: ✅
```

✅ This will ensure ZAP replaces any outgoing `User-Agent` headers with your desired custom value.

You can enable request interception (`CTRL + B`) and inspect an outgoing request to verify. You should see:

```
User-Agent: HackTheBox Agent 1.0
```

---

### Automatic Response Modification

We can also apply modifications to **incoming responses** — especially helpful when the same element (e.g. form input) gets reset on every page reload.

For example, previously we manually intercepted and modified:

```html
<input type="number" id="ip" ... maxlength="3">
```

To avoid doing that repeatedly, we can automate it in **Burp** via `Proxy > Options > Match and Replace`.

Here’s a rule to modify the field type:

```
Type: Response body
Match: type="number"
Replace: type="text"
Regex match: ❌
```

And optionally, another rule:

```
Match: maxlength="3"
Replace: maxlength="100"
```

Now the HTML field will persistently accept text input and longer values like `;ls;`, even across page reloads.

---

🧪 Once we refresh the page (`CTRL + SHIFT + R`), we should see:

```
Ping Your IP:
127.0.0.1
[ ;ls; ]
```

And we can click **Ping**, triggering the injection without further interception.

---

## Repeating Requests

In the previous sections, we successfully bypassed the input validation to use a non-numeric input to reach command injection on the remote server. If we want to repeat the same process with a different command, we would have to intercept the request again, provide a different payload, forward it again, and finally check our browser to get the final result.

As you can imagine, if we did this for each command, it would take us forever to enumerate a system, as each command would require 5–6 steps to get executed. However, for such repetitive tasks, we can utilize request repeating to make this process significantly easier.

Request repeating allows us to resend any web request that has previously gone through the web proxy. This allows us to make quick changes to any request before we send it, then get the response within our tools without intercepting and modifying each request.

---

### Proxy History

To start, we can view the HTTP requests history in **Burp** at (`Proxy>HTTP History`):

```
+----+--------------------------+--------+-------------+--------+--------+--------+----------+----------+--------------+
| #  | Host                     | Method | URL         | Status | MIME   | Comment| TLS      | Length   | IP           |
+----+--------------------------+--------+-------------+--------+--------+--------+----------+----------+--------------+
| 4  | http://46.101.23.188:32505 | POST | /ping       | 200    | script |        |          | 370      | 46.101.23.188|
| 3  | http://46.101.23.188:32505 | GET  | /favicon.ico| 404    | HTML   | Error  |          | 394      | 46.101.23.188|
| 1  | http://46.101.23.188:32505 | GET  | /           | 200    | HTML   | Ping IP|          | 1443     | 46.101.23.188|
+----+--------------------------+--------+-------------+--------+--------+--------+----------+----------+--------------+
```

In **ZAP HUD**, we can find it in the bottom History pane or ZAP’s main UI at the bottom **History** tab as well:

```
+----------+--------+--------+-----------------------------------+
| Time     | Status | Method | URL                               |
+----------+--------+--------+-----------------------------------+
| 17:56:37 | 200    | POST   | http://46.101.23.188:32505/ping   |
| 17:56:38 | 200    | GET    | http://46.101.23.188:32505        |
+----------+--------+--------+-----------------------------------+
```

Both tools also provide filtering and sorting options for requests history, which may be helpful if we deal with a huge number of requests and want to locate a specific request. _Try to see how filters work on both tools._

> Note: Both tools also maintain **WebSockets history**, which shows all connections initiated by the web application even after being loaded, like async updates and data fetching. WebSockets can be useful when performing advanced web penetration testing.

---

### Burp:

Clicking on a request in the history pane shows:

**Request**:
```
POST /ping HTTP/1.1
Host: 46.101.23.188:32505
...
User-Agent: Mozilla/5.0 ...
ip=1
```

**Response**:
```
HTTP/1.1 200 OK
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.020 ms
...
```

---

### ZAP:

**Request**:
```
POST http://46.101.23.188:32505/ping HTTP/1.1
User-Agent: Mozilla/5.0
...
ip=1
```

**Response**:
```
HTTP/1.1 200 OK
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
...
```

> 💡 Tip: While ZAP only shows the final/modified request that was sent, **Burp** provides the ability to examine both the original and modified request. If a request was edited, the pane header would say **Original Request**, and we can select **Edited Request** to examine the final request that was sent.

---

## Repeating Requests

### Burp

Once we locate the request we want to repeat, we can click `[CTRL+R]` in Burp to send it to the **Repeater** tab or use `[CTRL+SHIFT+R]` to go directly. Once there, click **Send**:

```
POST /ping HTTP/1.1
Host: 46.101.23.188:30968
...
ip=1
```

Response output includes:
```
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
...
```

> 💡 Tip: We can also right-click on the request and select **Change Request Method** to switch between POST and GET without rewriting the entire request.

---

### ZAP

In ZAP, we can right-click the request and select:
**Open/Resend with Request Editor**, then press **Send**.

This opens an editable view:
```
POST http://46.101.23.188:30968/ping HTTP/1.1
...
ip=1
```

> We can also change the method using the **Method** drop-down menu.

> 💡 Tip: By default, ZAP’s editor separates **Request/Response** in tabs. Use the view buttons to switch to side-by-side.

We can also use **ZAP HUD**:

1. Find the request in the bottom History panel
2. Click it
3. Select **Replay in Console** or **Replay in Browser**

Example HUD pop-up:
```
POST http://46.101.23.188:30968/ping HTTP/1.1
ip=1
```

---

Finally, let's try modifying the payload and sending it again.

All three tools (**Burp Repeater**, **ZAP Request Editor**, and **ZAP HUD**) allow editing:

Example:

```
ip=1;ls;
```

Response shows:
```
flag.txt
index.html
node_modules
...
```

This confirms that our new command was executed successfully.

> ✅ We can easily modify the command and instantly get its output by using Burp Repeater or ZAP equivalents.

Lastly, our POST request is **URL-encoded** — an essential part of sending custom HTTP requests, which we’ll explore in the next section.

---

## Encoding/Decoding

As we modify and send custom HTTP requests, we may have to perform various types of encoding and decoding to interact with the webserver properly. Both tools have built-in encoders that can help us in quickly encoding and decoding various types of text.

---

### URL Encoding

It is essential to ensure that our request data is URL-encoded and our request headers are correctly set. Otherwise, we may get a server error in the response. This is why encoding and decoding data becomes essential as we modify and repeat web requests. Some of the key characters we need to encode are:

- **Spaces**: May indicate the end of request data if not encoded
- **&**: Otherwise interpreted as a parameter delimiter
- **#**: Otherwise interpreted as a fragment identifier

To URL-encode text in Burp Repeater:
- Select the text → right-click → **Convert Selection > URL > URL encode key characters**
- Or press `CTRL+U` after selecting the text.

Burp also supports auto URL-encoding as you type (enable via right-click).

ZAP generally performs automatic URL-encoding in the background before sending the request.

> There are other types of URL-encoding, like **Full URL-Encoding** or **Unicode URL encoding**, useful for requests with special characters.

---

### Decoding

While URL-encoding is key to HTTP requests, it's not the only type of encoding we'll encounter. It’s very common for web applications to encode their data. We should be able to decode that data to examine the original text, or encode data for specific back-end expectations.

#### Examples of decoding formats:
- HTML
- Unicode
- Base64
- ASCII hex

To access full decoder in **Burp**:
- Use the **Decoder** tab

In **ZAP**:
- Use the **Encoder/Decoder/Hash** tool (`CTRL+E`)

Example of a Base64-encoded cookie:
```
eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZmlzX2FkbWluIjpmYWxzZX0=
```

Decoded output:
```json
{"username":"guest", "is_admin":false}
```

---

### Burp Decoder

**Burp Decoder** lets us input any encoded string and convert it using different decoders:
- Select the string
- Choose `Decode as > Base64`

You can also **encode** or **hash** the input using drop-downs in the Decoder interface.

---

### Burp Inspector

In newer versions of Burp, the **Inspector** tool appears alongside tools like Burp Proxy or Burp Repeater.

Inspector allows:
- Highlighting & selecting request payloads
- Decoding layered encodings
- Smart detection of encoding types

Example flow:
1. Select base64 string from request
2. Decoder panel:
   - URL Decoding → Base64 Decoding
3. Output:
```
127.0.0.1;ls -la
```

---

### ZAP Encoder/Decoder/Hash Tool

ZAP’s **Encoder/Decoder/Hash** tool has multiple tabs:
- Encode
- Decode
- Hash
- Unicode
- Illegal UTF-8

Example of decoding:
```
eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZmlzX2FkbWluIjpmYWxzZX0=
↓ Base64 Decode ↓
{"username":"guest", "is_admin":false}
```

You can also create **custom tabs** and add specific encoders/decoders to it.

---

### Encoding

After decoding, we may want to re-encode values for privilege escalation tests.

For example:
```json
{"username":"admin", "is_admin":true}
```

Re-encode this value using Base64:
```
eyJ1c2VybmFtIjoiYWRtaW4iLCAiaXNfYWRtaW4iOnRydWV9
```

Paste it back into the request payload to test.

---

### Final Tip

> Decoder output can be re-encoded using a different method directly.

Use the same value in:
- **Burp Repeater**
- **ZAP Request Editor**

This allows you to create and test custom encoded payloads without needing external tools.

---

## Proxying Tools

An important aspect of using web proxies is enabling the interception of web requests made by command-line tools and thick client applications. This gives us transparency into the web requests made by these applications and allows us to utilize all of the different proxy features we have used with web applications.

To route all web requests made by a specific tool through our web proxy tools, we have to set them up as the tool’s proxy (i.e. `http://127.0.0.1:8080`), similarly to what we did with our browsers. Each tool may have a different method for setting its proxy, so we may have to investigate how to do so for each one.

> **Note:** Proxying tools usually slows them down, therefore, only proxy tools when you need to investigate their requests, and not for normal usage.

This section will cover a few examples of how to use web proxies to intercept web requests made by such tools. You may use either Burp or ZAP, as the setup process is the same.

---

### Proxychains

One very useful tool in Linux is [proxychains](https://github.com/haad/proxychains), which routes all traffic coming from any command-line tool to any proxy we specify. `proxychains` adds a proxy to any command-line tool and is hence the simplest and easiest method to route web traffic of command-line tools through our web proxies.

To use `proxychains`, we first have to edit `/etc/proxychains.conf`, comment out the final line and add the following line at the end of it:

```
#socks4  127.0.0.1 9050
http    127.0.0.1 8080
```

On mac, brew install proxychains. conf file can be found here:

```
~ ❯❯❯ ll /opt/homebrew/etc/proxychains.conf
-rw-r--r--@ 1 stevenkingswolf  admin   5.7K  6 Jun 22:28 /opt/homebrew/etc/proxychains.conf
~ ❯❯❯ brew list proxychains-ng | grep conf
/opt/homebrew/Cellar/proxychains-ng/4.17/.bottle/etc/proxychains.conf
```

We should also enable **Quiet Mode** to reduce noise by un-commenting `quiet_mode`. Once that’s done, we can prepend `proxychains` to any command, and the traffic of that command should be routed through `proxychains` (i.e., our web proxy). For example, let’s try using `curl` on one of our previous exercises:

```bash
proxychains curl http://SERVER_IP:PORT
```

Sample output:

```html
ProxyChains-3.1 (http://proxychains.sf.net)
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Ping IP</title>
    <link rel="stylesheet" href="./style.css">
</head>
...SNIP...
</html>
```

We see that it worked just as it normally would, with the additional `ProxyChains-3.1` line at the beginning, to note that it is being routed through `ProxyChains`. If we go back to our web proxy (Burp in this case), we will see that the request has indeed gone through it:

```
GET / HTTP/1.1
Host: 139.59.166.56:32157
User-Agent: curl/7.74.0
Accept: */*
Connection: close
```

I'll be honest, I could get it to hit mt burpsuite proxy. ChatGPT said something about proxychain doesn't support http proxies very well (??) and instead use SOCKS, but then also pointed out that burpsuite's doesn't supoprt SOCKS proxies particularly well either.

In this curl command did work with hitting my burpsuite proxy.

```shell
curl --proxy http://127.0.0.1:8080 http://example.com -v
```

---

### Nmap

Next, let’s try to proxy `nmap` through our web proxy. To find out how to use the proxy configurations for any tool, we can view its manual with `man nmap`, or its help page with `nmap -h`:

```bash
nmap -h | grep -i prox
--proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
```

As we can see, we can use the `--proxies` flag. We should also add the `-Pn` flag to skip host discovery (as recommended on the man page). Finally, we’ll also use the `-sC` flag to examine what an nmap script scan does:

```bash
nmap --proxies http://127.0.0.1:8080 SERVER_IP -pPORT -Pn -sC
```

Sample output:

```
PORT     STATE SERVICE
PORT/tcp open  unknown
```

If we go to our web proxy tool, we will see all of the requests made by nmap in the proxy history (example below shows Burp):

| #   | Host              | Method | URL               | MIME type | Status |
|-----|-------------------|--------|-------------------|-----------|--------|
| 111 | http://139.59...  | POST   | /IPHTTPS          | -         | 200    |
| 110 | http://139.59...  | PROPFIND| /                | -         | 200    |
| 109 | http://139.59...  | PROPFIND| /                | -         | 200    |
| 108 | http://139.59...  | OPTIONS| /                | -         | 200    |
| 107 | http://139.59...  | GET    | /robots.txt       | text      | 404    |

> **Note:** Nmap’s built-in proxy is still in its experimental phase, as mentioned by its manual (`man nmap`), so not all functions or traffic may be routed through the proxy. In these cases, we can simply resort to `proxychains`, as we did earlier.

---

### Metasploit

Finally, let’s try to proxy web traffic made by Metasploit modules to better investigate and debug them. We should begin by starting Metasploit with `msfconsole`. Then, to set a proxy for any exploit within Metasploit, we can use the `set PROXIES` flag. Let’s try the `robots_txt` scanner as an example and run it against one of our previous exercises:

```bash
msfconsole

use auxiliary/scanner/http/robots_txt
set PROXIES HTTP:127.0.0.1:8080
set RHOST SERVER_IP
set RPORT PORT
run
```

Sample output:

```
[+] Scanned 1 of 1 hosts (100% complete)
[+] Auxiliary module execution completed
```

Once again, we can go back to our web proxy tool of choice and examine the proxy history to view all sent requests:

```
GET /robots.txt HTTP/1.0
Host: 139.59.166.56:32157
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Connection: close
```

And the intercepted response from the server:

```
HTTP/1.1 404 Not Found
X-Powered-By: Express
Content-Security-Policy: default-src 'none'
X-Content-Type-Options: nosniff
Content-Type: text/html; charset=utf-8
Content-Length: 149
```

---

We can similarly use our web proxies with other tools and applications, including scripts and thick clients. All we have to do is set the proxy of each tool to use our web proxy. This allows us to examine exactly what these tools are sending and receiving and potentially repeat and modify their requests while performing web application penetration testing.

---

## Burp Intruder

Both Burp and ZAP provide additional features beyond just web proxies. One of the most important for web application penetration testing is web fuzzing. Built-in fuzzers can automate directory discovery, brute-force parameter values, and even exploit common injection vectors.

Burp's web fuzzer is called **Burp Intruder**, and it's used for:

- Fuzzing pages
- Fuzzing subdomains
- Parameter and value brute-forcing

The **Burp Community Edition** includes Intruder but throttles its speed to 1 request/second. This makes it suitable for small tests only. The **Pro** version removes this throttle and supports advanced attack types, making it one of the best web fuzzing tools available.

---

### Target

After selecting a request from the Proxy History in Burp, right-click and choose:

```
Send to Intruder
```

You can also use the shortcut:

```
[CTRL + I]
```

This sends the request to the **Intruder** tab, which you can then open or go to via:

```
[CTRL + SHIFT + I]
```

On the first tab, **Target**, you define the host and port for the attack. This data is automatically populated from the request you sent to Intruder.

---

### Positions

On the second tab, **Positions**, you select payload markers. These are inserted around the part of the request you'd like to fuzz.

For example, if you want to fuzz a directory:

```
GET /§DIRECTORY§/ HTTP/1.1
```

In Burp, click on the word (like `DIRECTORY`) and hit **Add §** to mark it as a position.

Attack Type = `Sniper` (default)

💡 **Tip:** The marker name (like `DIRECTORY`) is for your reference only. It can be anything.

---

### Payloads

In the **Payloads** tab, you configure how your payload list will behave.

There are 4 key configurations:

- Payload Sets
- Payload Options
- Payload Processing
- Payload Encoding

#### Payload Sets

Payload set = `1`  
Payload type = `Simple list`

Other types include:

- `Runtime file`: loads line-by-line
- `Character substitution`: substitutes characters with permutations

#### Payload Options

Here you load or type your wordlist, such as:

```
/opt/useful/seclists/Discovery/Web-Content/common.txt
```

[Can find the above here](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common.txt)
Or you can manually enter words like:

```
.bashrc
.config
.forward
```

#### Payload Processing

You can add rules to filter or transform payloads.

Example: Skip items starting with a `.` (dotfiles)

Regex:

```
^\..*$
```

#### Payload Encoding

Burp can URL-encode payloads automatically.

Checkbox (enabled by default):

```
URL-encode these characters: ./=\<>?+&*:;"'[]^`
```

---

### Options

From the **Options** tab, configure attack behaviors.

Set:

```
Retries on failure = 0
Pause before retry = 0
```

Use **Grep - Match** to flag results:

- Enable: `200 OK`
- Match type: `Simple string`
- Uncheck `Exclude HTTP headers`

This filters results to only show successful requests.

---

### Attack

Once setup is complete, click:

```
Start Attack
```

The **Community Version** will run slowly. The **Pro Version** runs at full speed.

Results are displayed in a table. You can sort by:

- `Status`
- `Length`
- `200 OK`

Example Output:

```
Request   Payload   Status   Length   200 OK
0         admin     200      244      ✔
1         00        404      458
2         01        404      458
```

💡 The hit on `/admin` means that endpoint exists.

---

### Summary

You can use **Burp Intruder** for:

- Directory fuzzing
- Login brute-force
- PHP parameter fuzzing
- Password spraying (e.g. AD/OWA/RDS/SSL VPNs)

The free version is sufficient for learning and testing small wordlists. For larger tasks, the **Pro** version is strongly recommended due to the speed throttling limitation in the Community Edition.

---

## ZAP Fuzzer

ZAP's Fuzzer is called `ZAP Fuzzer`. It can be very powerful for fuzzing various web end-points, though it is missing some of the features provided by Burp Intruder. ZAP Fuzzer, however, does **not throttle** the fuzzing speed, which makes it much more useful than Burp’s free Intruder.

In this section, we will try to replicate what we did in the previous section using ZAP Fuzzer to have an "apples to apples" comparison and decide which one we like best.

---

### Fuzz

To start our fuzzing, we will visit the URL from the exercise at the end of this section to capture a sample request. As we will be fuzzing for directories, let's visit:

```
http://<SERVER_IP:PORT>/test/
```

Once we locate our request in the proxy history, we right-click on it and select:

```
Attack > Fuzz
```

Which opens the **Fuzzer** window.

Main options to configure:

- Fuzz Location
- Payloads
- Processors
- Options

---

### Locations

The **Fuzz Location** is similar to **Intruder Payload Position**, where the payloads will be placed. To mark the fuzz location, we highlight the word (e.g., `test`) and click:

```
Add
```

This adds a green marker and opens the **Payloads** window.

---

### Payloads

Payloads in ZAP Fuzzer are similar to Burp’s Intruder Payloads but not as powerful. We can choose from 8 different types. Some of them include:

- **File**: Use a local wordlist
- **File Fuzzers**: Use ZAP's built-in wordlists
- **Numberzz**: Generate sequences

To use built-in lists, choose:

```
Type: File Fuzzers
```

Select a list, e.g.,:

```
dirbuster > directory-list-1.0.txt
```

Then click:

```
Add
```

---

### Processors

Processors perform transformations on each payload. Available types include:

- Base64 Decode/Encode
- MD5, SHA-1/256/512 Hash
- Prefix / Postfix String
- URL Decode/Encode
- Script

For our fuzzing, we choose:

```
Type: URL Encode
Character Encoding: UTF-8
```

Click:

```
Generate Preview
```

Then:

```
Add > OK
```

---

### Options

Options allow configuring scan behavior. Notable settings:

- **Concurrent threads per scan**: Set to 20
- **Retries on IO error**: 3
- **Max errors allowed**: 1000
- **Delay**: 0ms
- **Payload replacement strategy**:
  - `Depth First`: Try all payloads for one position before moving to next
  - `Breadth First`: Try one payload across all positions before moving on

---

### Start

Once ready, click:

```
Start Fuzzer
```

Then sort results by:

```
Response Code = 200
```

If a match is found, we can view the successful payload and its response by clicking the request.

Example successful response might include:

```
GET /skills/ HTTP/1.1
...
HTTP/1.1 200 OK
...
Set-Cookie: cookie=abc123...
...
<html>
  <head>
    <title>Welcome</title>
  </head>
  <body>
    ...
  </body>
</html>
```

### Interpretation

Indicators of successful fuzzing include:

- HTTP 200 responses
- Set-Cookie headers
- Size differences (`Size Resp. Body`)
- Time delay (`RTT`) for time-based SQL injection discovery

---

## Burp Scanner

An essential feature of web proxy tools is their web scanners. Burp Suite comes with **Burp Scanner**, a powerful scanner for various types of web vulnerabilities, using a **Crawler** for building the website structure, and **Scanner** for passive and active scanning.

Burp Scanner is a Pro-Only feature, and it is not available in the free Community version of Burp Suite. However, given the wide scope that Burp Scanner covers and the advanced features it includes, it makes it an enterprise-level tool, and as such, it is expected to be a paid feature.

---

### Target Scope

To start a scan in Burp Suite, we have the following options:

1. Start scan on a specific request from Proxy History  
2. Start a new scan on a set of targets  
3. Start a scan on items in-scope  

To start a scan on a specific request from Proxy History, we can right-click on it once we locate it in the history, and then select **Scan** to be able to configure the scan before we run it, or select **Passive/Active Scan** to quickly start a scan with the default configurations:

```
> Dashboard > Proxy > HTTP history > Right-click > Scan or Passive Scan
```

We may also click on the **New Scan** button on the **Dashboard** tab, which would open the **New Scan** configuration window to configure a scan on a set of custom targets. Instead of creating a custom scan from scratch, let’s see how we can utilize the scope to properly define what’s included/excluded from our scans using the **Target Scope**.

The **Target Scope** can be utilized with all Burp features to define a custom set of targets that will be processed. Burp also allows us to limit Burp to in-scope items to save resources by ignoring any out-of-scope URLs.

---

If we go to \`Target > Site map\`, it will show a listing of all directories and files Burp has detected in various requests that went through its proxy:

To add an item to our scope, we can right-click on it and select **Add to scope**:

```
http://46.101.23.188:30760/
├── index.php
├── wp-content/
├── wp-includes/
└── xmlrpc.php
```

> **Note:** When you add the first item to your scope, Burp will give you the option to restrict its features to in-scope items only.

We may also exclude a few items from scope if scanning them may be dangerous (e.g., logout functionality). We can right-click and select **Remove from scope**. To view or edit scope:

```
Target > Scope
```

You can include/exclude using advanced regex scope control.

---

### Crawler

Once we have our scope ready, we can go to the **Dashboard** tab and click on **New Scan** to configure our scan.

Choose between:
- **Crawl** (just maps the target)
- **Crawl and audit** (includes active/passive scanning)

We’ll select **Crawl** and go to the **Scan configuration** tab. Choose from built-in options such as:

- Crawl strategy - fastest  
- Crawl limit - 10/30/60 minutes  
- Crawl strategy - most complete  
- Never stop crawl due to application errors

If needed, continue to the **Application login** tab to record a login sequence (for authenticated scans).

Once ready, click **OK** to begin the scan. Progress appears under:

```
Dashboard > Tasks
```

> Click **View details** to get insights about the scan in progress or finished.

---

### Passive Scanner

Once the site map is fully built, we may select the target and choose:

```
Do passive scan / Passively scan this target
```

The Passive Scan will analyze all previously visited pages and suggest vulnerabilities (e.g., missing headers, clickjacking). It does not send new requests.

Check results under:

```
Dashboard > Issue activity
```

Look for:
- High severity
- Confident/Firm confidence

---

### Active Scanner

This is the most powerful part of Burp Scanner. It:

1. Crawls the target  
2. Runs a Passive Scan  
3. Verifies each vulnerability  
4. Executes JS-based analysis  
5. Fuzzes common vulnerabilities (XSS, SQLi, OS command injection)

Run it by choosing:

```
Do active scan / Crawl and audit
```

You can configure:
- Crawl settings  
- Audit settings: choose from presets (e.g., **Audit checks - critical issues only**)

Progress and details appear in the **Tasks** pane.

You can inspect traffic and vulnerabilities via:

- **View details**
- **Logger** tab
- **Issue activity** tab

---

### Sample Output

Example finding:

- **OS Command Injection**  
- **Severity**: High  
- **Confidence**: Firm  
- Payload:
```
| echo 7Hy4yq3fl h8zqfsqedv|a |#
```

The advisory describes the injection vector and provides guidance on remediation.

---

### Reporting

After finishing scans, go to:

```
Target > Site map > Right-click target > Issues > Report issues for this host
```

Customize what to include by severity and confidence.

Sample summary table:

```
+-----------+---------+----------+----------+
| Severity  | Certain |  Firm    | Tentative|
+-----------+---------+----------+----------+
| High      |    0    |    1     |     0    |
| Medium    |    0    |    0     |     0    |
| Low       |    1    |    0     |     0    |
| Info      |    2    |    3     |     0    |
+-----------+---------+----------+----------+
```

> Use reports as supporting data for your own testing summary or technical report. Avoid using tool reports as final deliverables.

---

## ZAP Scanner

ZAP also comes bundled with a Web Scanner similar to Burp Scanner. ZAP Scanner is capable of building site maps using ZAP Spider and performing both passive and active scans to look for various types of vulnerabilities.

---

### Spider

Let's start with \`ZAP Spider\`, which is similar to the Crawler feature in Burp. To start a Spider scan on any website, we can locate a request from our History tab and select \`(Attack>Spider)\` from the right-click menu. Another option is to use the HUD in the pre-configured browser. Once we visit the page or website we want to start our Spider scan on, we can click on the second button on the right pane \`(Spider Start)\`, which would prompt us to start the scan.

```ascii
+-------------------------------------------------------------+
|                        HTB ACADEMY                          |
|           Just another WordPress site                       |
|                                                             |
|                    Customer Support                         |
| For any customer support tickets, please contact us at:     |
| http://academy.htb/customer-support.php                     |
| or email: support@academy.htb                               |
+-------------------------------------------------------------+
```

> Note: When we click on the Spider button, ZAP may tell us that the current website is not in our scope, and will ask us to automatically add it to the scope before starting the scan, to which we can say 'Yes'.  
> Note: In some versions of browsers, ZAP's HUD might not work as intended.

---

### Sites Tree

Once we click on \`Start\` on the pop-up window, our Spider scan should start spidering the website by looking for links and validating them. We can check the \`Sites\` tab in the main ZAP UI, or the first button on the right pane \`(Sites Tree)\` to see an expandable view of all discovered directories.

```ascii
Sites Tree
├── http://46.101.23.188:30873
│   ├── GET /
│   ├── GET ?p=9
│   ├── GET ?s
│   ├── [+] devtools
│   ├── [+] index.php
│   ├── GET robots.txt
│   ├── GET sitemap.xml
│   └── POST wp-comments-post.php
```

> Tip: ZAP also has a different type of Spider called \`Ajax Spider\`, started from the third button on the right pane. It identifies JavaScript-based dynamic links.

---

### Passive Scanner

As ZAP Spider runs and makes requests, it automatically runs its passive scanner on each response to identify issues like missing security headers or DOM-based XSS vulnerabilities.

```ascii
HTB ACADEMY
Customer Support

Page Alerts: Medium
Site Alerts: Medium
```

We can also check the \`Alerts\` tab on the main ZAP UI. Clicking on any alert reveals the affected pages:

```ascii
Site Alerts [Medium]
- X-Frame-Options Header Not Set
  - http://46.101.23.188:30873/
  - http://46.101.23.188:30873/?s
  - http://46.101.23.188:30873/devtools/
  ...
```

---

### Active Scanner

Once the site tree is populated, we can click on the \`Active Scan\` button on the right pane. ZAP will run tests against all known endpoints.

```ascii
HTB ACADEMY
Customer Support

Active Scan: 4%
```

We can monitor the scan progress in the ZAP UI. When the scan completes, alerts increase:

```ascii
Site Alerts [High]
- Remote OS Command Injection
```

Clicking into the alert reveals details:

```ascii
Remote OS Command Injection
---------------------------
Risk: High
Confidence: Medium
Parameter: -
Attack: 127.0.0.1&cat /etc/passwd&
Evidence: root:x:0:0
```

We can click the associated URL to view the full request/response and even repeat it via HUD/Request Editor:

```http
HTTP Message
------------
Content-Type: text/html; charset=UTF-8

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

---

### Reporting

We can generate a final report of all identified alerts via \`Report > Generate HTML Report\`. ZAP also allows export as XML or Markdown.

```ascii
Summary of Alerts
-----------------
Risk Level       Number of Alerts
-----------      ----------------
High             1
Medium           3
Low              8
Informational    6

Detailed Alerts
---------------
- Remote OS Command Injection (High, 1 instance)
- Cross-Domain Misconfiguration (Medium, 1)
- Directory Browsing (Medium, 9)
- X-Frame-Options Header Not Set (Medium, 8)
- Absence of Anti-CSRF Tokens (Low, 11)
- Incomplete/No Cache-control Header (Low, 37)
- X-Content-Type-Options Header Missing (Low, 44)
- Charset Mismatch (Informational, 1)
- Information Disclosure - Comments (Informational, 7)
- Timestamp Disclosure - Unix (Informational, 144)
```

As we can see, the report organizes all findings by severity and count, and helps track vulnerability instances across scans.

---

## Extensions

Both Burp and ZAP have extension capabilities, such that the community of Burp users can develop extensions for Burp for everyone to use. Such extensions can perform specific actions on any captured requests, for example, or add new features, like decoding and beautifying code. Burp allows extensibility through its **Extender** feature and its **BApp Store**, while ZAP has its **ZAP Marketplace** to install new plugins.

---

### BApp Store

To find all available extensions, we can click on the **Extender** tab within Burp and select the **BApp Store** sub-tab. Once we do this, we will see a host of extensions. We can sort them by **Popularity** so that we know which ones users are finding most useful:

```
+-------------------------+--------------+-------------+-------------------+
| Name                    | Installed    | Popularity  | Last Updated      |
+-------------------------+--------------+-------------+-------------------+
| Active Scan++           | ✓            | ★★★★★        | 25 Mar 2021       |
| HTTP Request Smuggler   | ✓            | ★★★★★        | 06 Aug 2021       |
| Logger++                | ✓            | ★★★★★        | 06 Aug 2021       |
| Param Miner             | ✓            | ★★★★★        | 06 Aug 2021       |
| JSON Web Tokens         | ✓            | ★★★★☆        | 19 Feb 2021       |
| Retire.js               |              | ★★★☆☆        | 24 Jun 2021 (Pro) |
| Turbo Intruder          |              | ★★★☆☆        | 11 Aug 2021       |
+-------------------------+--------------+-------------+-------------------+
```

> 🛈 **Note:** Some extensions are for Pro users only, while most others are available to everyone.

Take some time to go through the list and install ones you find useful. Let’s try installing the **Decoder Improved** extension:

---

### Installing and Using Extensions

Once we install **Decoder Improved**, we will see its new tab added to Burp. Each extension has a different usage, so we may click on any extension’s documentation in **BApp Store** to read more about it or visit its GitHub page for more information.

We can use this extension just like Burp's Decoder, with the benefit of having many additional encoders included.

Example workflow:

1. Input text we want to hash.
2. Select `Hash With: MD5`.

```
+-------------------+---------------------------+
| Input             | Hash With:                |
+-------------------+---------------------------+
| HTB Academy       | MD5                       |
+-------------------+---------------------------+
| Hex Output:       | 83 55 2D ...              |
+-------------------+---------------------------+
```

You can also encode or decode using different methods. There are many more Burp extensions that extend its capabilities.

---

### Other Notable Extensions

Some useful extensions include:

- `.NET beautifier`
- `J2EEScan`
- `Software Vulnerability Scanner`
- `AWS Security Checks`
- `Active Scan++`
- `Backslash Powered Scanner`
- `C02`
- `Cloud Storage Tester`
- `CMS Scanner`
- `Error Message Checks`
- `Detect Dynamic JS`
- `Headers Analyzer`
- `HTML5 Auditor`
- `PHP Object Injection Check`
- `JavaScript Security`
- `Retire.JS`
- `CSP Auditor`
- `Random IP Address Header`
- `Autorize`
- `CSRF Scanner`
- `JS Link Finder`

---

## ZAP Marketplace

ZAP also has its own extensibility feature with the **Marketplace** that allows us to install various types of community-developed add-ons. To access ZAP's marketplace:

- Click the **Manage Add-ons** button.
- Select the **Marketplace** tab.

```
+------------------------------------------+
| Installed | Marketplace | [Filter Bar]   |
+------------------------------------------+
| Release   | FuzzDB Files      | ✓        |
| Release   | FuzzDB Offensive  | ✓        |
+------------------------------------------+
```

> These add-ons enhance ZAP's fuzzers and scanners with new payloads and behaviors.

---

### Example: Using FuzzDB in ZAP

Once we install **FuzzDB Files** and **FuzzDB Offensive**, we can use them for fuzzing, e.g., OS command injection:

1. Go to: `File Fuzzers > fuzzdb > attack > os-cmd-execution`
2. Select: `command-execution-unix.txt`

```
Payloads Preview:
1: <!--#exec cmd="/usr/bin/id"-->
2: <!--#exec cmd="id"-->
3: /index.html|id|
4: ;id;
5: |id
6: ;netstat -a;
...
```

We can run these against the application. If the fuzzer gets 200 OK responses, we know our payloads were successful.

```
+---------+--------------+--------+---------+-------------------+-------------------+
| ID      | Message Type | Code   | Payload | Size Resp. Body   | Resp. Time (ms)   |
+---------+--------------+--------+---------+-------------------+-------------------+
| 5       | Fuzzed       | 200 OK | ;id     | 54 bytes          | 12.6              |
| 6       | Fuzzed       | 200 OK | |id     | 54 bytes          | 12.5              |
| 7       | Fuzzed       | 200 OK | id      | 54 bytes          | 12.1              |
+---------+--------------+--------+---------+-------------------+-------------------+
```

---

## Closing Thoughts

This module showcased the power of both Burp and ZAP proxies and their extension ecosystems. These tools are essential for penetration testers focused on web application assessments.

After working through this module:

- Explore HTB's main platform for web-attack boxes.
- Continue sharpening your skills in both tools.
- Keep exploring extensions to expand your capabilities.

> 🛠️ Tools to keep in your belt: Nmap, Hashcat, Wireshark, tcpdump, sqlmap, ffuf, gobuster, and more.