# Using Web Proxies

- [Intro to Web Proxies](#intro-to-web-proxies)
- [Setting Up](#setting-up)
- [Proxy Setup ](#proxy-setup)

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