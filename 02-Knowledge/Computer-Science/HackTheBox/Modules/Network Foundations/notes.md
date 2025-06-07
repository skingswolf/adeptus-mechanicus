# Netowrk Foundations

- [Introduction to Networks](#intro)
- [Network Concepts](#network-concepts)
- [Components of a Network](#network-components)
- [Network Communication](#network-communication)
- [Dynamic Host Configuration Protocol DHCP](#dhcp)
- [Network Address Translation](#nat)
- [Domain Name System](#dns)
- [Internet Architecture](#internet-architecture)
- [Wireless Networks](#wireless-networks)
- [Network Security](#network-security)
- [Data Flow Example](#data-flow)
- [Skills Assessment](#skills-assessment)

## Introduction to Networks

Welcome to Network Foundations! In this introductory module, we will explore the technology behind computer networking — also known as “networking” or “networks” — and why it is essential to our lives. We will mostly focus on two primary types of networks: `Local Area Networks (LANs)` and `Wide Area Networks (WANs)`.

Understanding how devices communicate — from within our homes to across the globe — is fundamental knowledge for anyone entering the field of cybersecurity. The interconnectedness of nearly every device in the modern world sets the stage for the increasing demand for security professionals.

---

### What is a Network?

A **network** is a collection of interconnected devices that can communicate (send and receive data) and share resources with each other. These endpoint devices, often called **nodes**, include:

- Computers
- Smartphones
- Printers
- Servers

However, **nodes** alone do not comprise the entire network. Below are some key networking concepts:

| **Concepts**   | **Description**                                           |
|----------------|-----------------------------------------------------------|
| **Nodes**      | Individual devices connected to a network.                |
| **Links**      | Communication pathways connecting nodes (wired/wireless). |
| **Data Sharing** | The primary goal of a network — to enable data exchange. |

### Analogy

Think of a group of friends chatting in a room:
- Each person is a **node**
- Their ability to talk/listen = **communication links**
- The actual conversation = **data**

---

### Why Are Networks Important?

Networks, particularly since the Internet’s advent, have radically transformed society. Some of the key benefits include:

| **Function**       | **Description**                                                        |
|--------------------|------------------------------------------------------------------------|
| **Resource Sharing** | Share hardware (e.g., printers) and software across multiple devices. |
| **Communication**  | Messaging, email, and video calls rely on networks.                    |
| **Data Access**     | Access files and databases remotely from any connected device.         |
| **Collaboration**   | Real-time teamwork, even across vast distances.                        |

---

### Types of Networks

We focus on two main types:

- **Local Area Network (LAN)**
- **Wide Area Network (WAN)**

#### Local Area Network (LAN)

A **LAN** connects devices over a **short distance** (e.g., home, school, or office). Key characteristics:

| **Characteristic**     | **Description**                                                       |
|------------------------|------------------------------------------------------------------------|
| **Geographical Scope** | Covers a small area.                                                   |
| **Ownership**          | Typically managed by one person or organization.                      |
| **Speed**              | High data transfer rates.                                              |
| **Media**              | Uses wired (Ethernet) or wireless (Wi-Fi) connections.                |

##### Diagram: LAN Example

```
        +-----------+
        | Internet  |
        +-----------+
             |
         +--------+
         | Modem  |
         +--------+
             |
         +--------+
         | Router |
         +--------+
        /    |     \
       /     |      \
+-----+  +--------+  +-----------+
| PC  |  | Laptop |  | Smartphone|
+-----+  +--------+  +-----------+
             |
         +--------+
         |Printer|
         +--------+
```

---

#### Wide Area Network (WAN)

A **WAN** connects **multiple LANs** across large distances. Key characteristics:

| **Characteristic**     | **Description**                                                             |
|------------------------|-----------------------------------------------------------------------------|
| **Geographical Scope** | Covers cities, countries, continents.                                       |
| **Ownership**          | Often owned collectively (e.g., by ISPs).                                   |
| **Speed**              | Slower than LANs due to long-distance transmission.                         |
| **Media**              | Uses fiber optics, satellite, or leased telecommunication lines.            |

##### Diagram: WAN Example

```
                            +-----------+
                            | Internet  |
                            +-----------+
                                 |
        +--------+     +--------+     +--------+
        | Modem  |     | Modem  |     | Modem  |
        +--------+     +--------+     +--------+
            |              |              |
        +--------+     +--------+     +--------+
        | Router |     | Router |     | Router |
        +--------+     +--------+     +--------+
        /   |   \       /   |   \       /   |   \
      PC Laptop Phone  PC Laptop Phone  PC Laptop Phone
```

---

### Comparing LAN vs WAN

| **Aspect**     | **LAN**                         | **WAN**                                |
|----------------|----------------------------------|-----------------------------------------|
| **Size**       | Small/local area                | Large/global area                      |
| **Ownership**  | Single org/person               | Multiple orgs/ISPs                     |
| **Speed**      | High                            | Slower than LAN                        |
| **Maintenance**| Simple/inexpensive              | Complex/expensive                      |
| **Example**    | Home or office                  | The Internet                           |

---

### How Do LANs and WANs Work Together?

**LANs** can connect to **WANs** for global access. For example:

- A home LAN connects to an ISP's WAN via a **modem**.
- The **modem** acts as a bridge between the LAN and ISP infrastructure.
- This allows access to remote resources like websites and cloud apps.

**In business settings**:
- Multiple office LANs can connect through a WAN.
- Enables centralized access to data, collaboration tools, and shared systems.

**Conclusion**:
The seamless integration of LAN and WAN lets us:
- Access global resources
- Work remotely
- Collaborate in real-time

---

## Network Concepts

Understanding networking is vital in cybersecurity. This module explores the basics of computer networking, particularly focusing on:

- **Local Area Networks (LANs)**
- **Wide Area Networks (WANs)**

---

### What is a Network?

A **network** is a collection of interconnected devices that share data and resources. These devices, or **nodes**, can be computers, smartphones, printers, etc.

| Concepts      | Description                                                |
|---------------|------------------------------------------------------------|
| Nodes         | Individual devices connected to a network.                 |
| Links         | Communication pathways (wired/wireless) connecting nodes. |
| Data Sharing  | Primary purpose: enabling data exchange.                  |

**Analogy:** Friends in a room chatting:
- Friends = nodes
- Talking/listening = links
- Conversation = data

---

### Why Are Networks Important?

| Function           | Description                                                         |
|-------------------|---------------------------------------------------------------------|
| Resource Sharing   | Share hardware and software resources.                             |
| Communication      | Instant messaging, emails, video calls.                            |
| Data Access        | Access files and databases remotely.                               |
| Collaboration      | Real-time teamwork across distances.                               |

---

### Types of Networks

#### Local Area Network (LAN)

Connects devices in small areas (homes, schools, offices).

| Characteristic      | Description                                              |
|---------------------|----------------------------------------------------------|
| Geographical Scope  | Small/local area                                         |
| Ownership           | One person or organization                               |
| Speed               | High                                                     |
| Media               | Ethernet cables or Wi-Fi                                 |

```
              Internet
                 |
              Modem
                 |
              Router
              /  |  \
          Wired WiFi WiFi
         /       |     \
       PC     Laptop  Smartphone
        \        |        /
       Wired    WiFi    WiFi
          \      |      /
             Printer
```

---

#### Wide Area Network (WAN)

Connects multiple LANs across large regions.

| Characteristic      | Description                                              |
|---------------------|----------------------------------------------------------|
| Geographical Scope  | Cities, countries, continents                            |
| Ownership           | ISPs or multiple organizations                           |
| Speed               | Lower (due to distance)                                  |
| Media               | Fiber optics, satellite, telecom lines                   |

**Example of a WAN: The Internet**

```
                    Internet
                   /   |   \
               Modem Modem Modem
                 |      |     |
              Router Router Router
             /|\     /|\    /|\
            LAN1   LAN2   LAN3
```

---

### Comparing LAN and WAN

| Aspect       | LAN                         | WAN                                |
|--------------|------------------------------|-------------------------------------|
| Size         | Small/local                  | Large/geographically broad          |
| Ownership    | Single org                   | Multiple service providers          |
| Speed        | High                         | Lower                               |
| Maintenance  | Easier, cheaper              | Complex, costly                     |
| Example      | Home/Office Network          | The Internet                        |

---

### How Do LANs and WANs Work Together?

A LAN connects to a WAN via a modem and ISP. This lets LAN devices access broader networks like the internet.

**Example:** At home:
- LAN = home devices + router
- Router connects to ISP's WAN
- Enables internet access to all devices

---

## Network Concepts

---

### OSI Model

Seven layers of standardized networking:

1. **Physical Layer**: Wires, hubs, raw bits.
2. **Data Link Layer**: MAC addresses, switches.
3. **Network Layer**: IP addresses, routers.
4. **Transport Layer**: TCP, UDP.
5. **Session Layer**: Session management, APIs.
6. **Presentation Layer**: Data formatting, encryption.
7. **Application Layer**: HTTP, FTP, DNS, SMTP.

```
  HTTP, FTP, SMTP, DNS
       ─ Application (7)
  Encryption, compression
       ─ Presentation (6)
  Session protocols, APIs
       ─ Session (5)
        TCP, UDP
       ─ Transport (4)
 Routers, IP addresses
       ─ Network (3)
Switches, MAC addresses
       ─ Data Link (2)
 Ethernet cables, hubs
       ─ Physical (1)
```

---

### Example: Sending a File

1. **Application**: User triggers transfer.
2. **Presentation**: File encrypted.
3. **Session**: Communication setup.
4. **Transport**: File segmented (TCP).
5. **Network**: Routing path determined.
6. **Data Link**: Frames created.
7. **Physical**: Bits transmitted.

---

### TCP/IP Model

Practical 4-layer alternative to OSI:

| Layer            | Function                                                                 |
|------------------|--------------------------------------------------------------------------|
| Application      | HTTP, FTP, SMTP, DNS                                                     |
| Transport        | TCP, UDP                                                                 |
| Internet         | IP, ICMP                                                                 |
| Link             | Ethernet, Wi-Fi                                                          |

```
HTTP, FTP, SMTP, DNS
    ─ Application (4)
      TCP, UDP
    ─ Transport (3)
 IP, routers, firewalls
    ─ Internet (2)
 NICs, Ethernet, switches
    ─ Link (1)
```

---

### Comparison with OSI

TCP/IP merges OSI’s upper layers:

```
OSI Layer 7 ─┐
OSI Layer 6 ─┼── TCP/IP Application
OSI Layer 5 ─┘
OSI Layer 4 ──── TCP/IP Transport
OSI Layer 3 ──── TCP/IP Internet
OSI Layer 2 ─┐
OSI Layer 1 ─┘ ── TCP/IP Link
```

---

### Protocols

Rules for how devices talk.

| Protocol | OSI Layer | Description |
|----------|-----------|-------------|
| HTTP     | Application | Web browsing |
| FTP      | Application | File transfers |
| SMTP     | Application | Email sending |
| TCP      | Transport   | Reliable delivery |
| UDP      | Transport   | Fast, connectionless |
| IP       | Network     | Routing packets |

---

### Transmission

#### Types:
- **Analog**: Continuous (radio waves)
- **Digital**: Discrete (binary)

#### Modes:
- **Simplex**: One-way only
- **Half-duplex**: Two-way, one-at-a-time
- **Full-duplex**: Two-way simultaneous

#### Media:
- **Wired**:
  - Twisted pair
  - Coaxial
  - Fiber optic
- **Wireless**:
  - Radio waves
  - Microwaves
  - Infrared

---

## Components of a Network

As we continue our journey into infosec, understanding the various components that formulate a network is essential. We know that currently, devices are able to communicate with each other, share resources, and access the internet with almost uniform consistency. What exactly facilitates this? The primary components of such a network include:

| Component                         | Description                                               |
|----------------------------------|-----------------------------------------------------------|
| `End Devices`                    | Computers, Smartphones, Tablets, IoT / Smart Devices      |
| `Intermediary Devices`           | Switches, Routers, Modems, Access Points                  |
| `Network Media and Software Components` | Cables, Protocols, Management and Firewalls Software |
| `Servers`                        | Web Servers, File Servers, Mail Servers, Database Servers |

---

### End Devices

An `end device`, also known as a `host`, is any device that ultimately ends up sending or receiving data within a network. Common examples include:

- Personal computers
- Smartphones
- Smart TVs
- Tablets

These devices allow users to interact directly with the network: browsing the web, sending messages, streaming videos, and more. They connect via wired (Ethernet) or wireless (Wi-Fi) methods and often act as the human interface to the broader internet or internal networks.

---

### Intermediary Devices

An `intermediary device` facilitates the flow of data between `end devices` and other networks. This includes:

- Routers
- Switches
- Modems
- Access Points

They are responsible for:

- `packet forwarding`
- Path selection using routing protocols
- Traffic management
- Security via `firewalls`

**OSI Model Mapping**:
- Routers: `Network Layer (Layer 3)`
- Switches: `Data Link Layer (Layer 2)`

---

#### Network Interface Cards (NICs)

A `Network Interface Card (NIC)` is a hardware component that enables a device to connect to a network. It manages the sending/receiving of data and assigns a unique `MAC address` to each device. NICs can be:

- Wired: Ethernet cables
- Wireless: Wi-Fi adapters (radio signals)

---

#### Routers

A `router` operates at `Layer 3 (Network Layer)` of the OSI model and:

- Reads IP addresses
- Directs data using routing tables/protocols like:
  - `OSPF (Open Shortest Path First)`
  - `BGP (Border Gateway Protocol)`
- Enhances `security` and manages `traffic`

**Functionality**:
- Connects multiple networks
- Analyzes incoming data
- Prevents congestion
- Secures traffic

---

#### Switches

A `switch` connects devices in a `Local Area Network (LAN)` and operates at `Layer 2 (Data Link Layer)`. Functions include:

- Uses MAC addresses to forward data
- Minimizes congestion
- Enables internal network communication
- Common in offices for printers, workstations, etc.

---

#### Hubs

A `hub` is a basic, outdated device that:

- Broadcasts incoming data to all connected ports
- Operates at `Layer 1 (Physical Layer)`
- Does not manage traffic or prevent collisions
- Replaced by switches in modern networks

---

### Network Media and Software Components

#### Network Media

These are the physical and wireless pathways for transmitting data:

- `Ethernet cables`
- `Fiber-optic cables`
- `Wi-Fi` and `Bluetooth`

---

#### Software Components

These define the rules for communication:

- `Network Protocols`: TCP/IP, HTTP, FTP, etc.
- `Management Software`: Performance monitoring, configuration, fault analysis, and `firewalls`

---

#### Cabling and Connectors

Physical links between devices:

- Examples: RJ-45 connectors, twisted pair cables
- Affect speed, reliability, and performance
- Common in structured office environments

---

## Network Protocols

`Network protocols` are the rules that govern communication. They ensure standardized interaction between devices and cover:

- `Data Segmentation`
- `Addressing`
- `Routing`
- `Error Checking`
- `Synchronization`

**Common Examples**:

- `TCP/IP`: Reliable packet delivery
- `HTTP/HTTPS`: Web content transmission
- `FTP`: File transfers
- `SMTP`: Email delivery

---

### Network Management Software

Provides visibility, control, and maintenance for network administrators. Functions include:

- `performance monitoring`
- `configuration management`
- `fault analysis`
- `security management`

---

### Software Firewalls

A `software firewall`:

- Is installed on individual devices
- Monitors incoming/outgoing traffic
- Blocks unauthorized connections
- Can be configured with tools like `iptables`

#### Example:

\```
$ sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
$ sudo iptables -L -v -n
\```

```
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
    0     0 DROP       icmp --  *      *       0.0.0.0/0            0.0.0.0/0           icmptype 8
```

---

### Servers

A `server` provides services to `clients` over a network. Functions:

- `Service Provision`: Hosts websites, files, etc.
- `Resource Sharing`: Allows multiple users access
- `Data Management`: Centralized storage
- `Authentication`: Controls access

Servers run under the `Client-Server Model`, waiting for and responding to client requests.

---

### Conclusion

Network components work together to:

- Interface with users (`End Devices`)
- Manage data flow (`Intermediary Devices`)
- Transmit information (`Network Media`)
- Provide services (`Servers`)

This seamless collaboration powers the modern digital world.

---

## Network Communication

For a network to function and facilitate communication properly, there are three crucial components: `MAC addresses`, `IP addresses`, and `ports`. Together, these elements ensure that data is correctly sent and received between devices across both local and global networks, forming the backbone of seamless network communication.

---

### MAC Addresses

#### What is a MAC Address?

A `Media Access Control (MAC) address` is a unique identifier assigned to the network interface card (NIC) of a device, allowing it to be recognized on a local network. Operating at the `Data Link Layer (Layer 2)` of the OSI model, the MAC address is crucial for communication within a local network segment, ensuring that data reaches the correct physical device.

A MAC address is 48 bits long and typically represented in hexadecimal format, e.g., `00:1A:2B:3C:4D:5E`. The first 24 bits represent the `Organizationally Unique Identifier (OUI)` assigned to the manufacturer; the remaining 24 bits are specific to the individual device.

_The Windows `GETMAC` command will return the MAC address of every network interface card on the host._

\```
C:\Windows\system32>getmac

Physical Address    Transport Name
==================  ==============================================
00-50-56-94-26-0E   \Device\Tcpip_{301DF930-093C-4434-B547-EC91E3AC667F}
\```

---

#### How MAC Addresses are Used in Network Communication

MAC addresses are fundamental for local communication within a LAN, used to deliver frames to the correct physical device. Switches use them to forward frames, and the `Address Resolution Protocol (ARP)` maps IP addresses to MAC addresses.

**Example:**

Computer A (192.168.1.2, MAC: `00:1A:2B:3C:4D:5E`) sends data to Computer B (192.168.1.5, MAC: `00:1A:2B:3C:4D:5F`). ARP resolves B's MAC, and data is sent to the appropriate MAC.

**Diagram:**
```
     +------------+             +------------+
     | 192.168.1.2|             |192.168.1.5 |
     | Computer A |             | Computer B |
     +-----+------+             +------+-----+
           |                          |
           |  ARP Request             |
           v                          |
         +----------+  ARP Reply   +----------+
         |  Router  |------------->|  Switch  |
         +----------+              +----------+
```

---

## IP Addresses

### What is an IP Address?

An `Internet Protocol (IP) address` is a numerical label assigned to each device on an IP-based network. It operates at the `Network Layer (Layer 3)` of the OSI model. Two versions:

- **IPv4**: 32-bit, e.g. `192.168.1.1`
- **IPv6**: 128-bit, e.g. `2001:0db8:85a3:0000:0000:8a2e:0370:7334`

---

### How IP Addresses are Used in Network Communication

Routers use IP addresses to determine where data packets go. Unlike MACs, IPs can change and are more flexible, dynamically assigned or based on network design.

---

### Ports

A `port` is a number assigned to services on a device to differentiate types of network traffic. It operates at the `Transport Layer (Layer 4)` and works with protocols like TCP and UDP.

Ports range from `0 to 65535`, categorized as:

- **Well-known Ports (0–1023)**: HTTP (80), HTTPS (443), FTP (20, 21)
- **Registered Ports (1024–49151)**: SQL Server (1433)
- **Dynamic/Private Ports (49152–65535)**: Used temporarily by client apps

---

#### Viewing Ports in Use

Using the `netstat` tool:
\```
C:\Windows\system32>netstat -ano -p tcp

Proto  Local Address   Foreign Address  State      PID
TCP    0.0.0.0:80      0.0.0.0:0        LISTENING  888
TCP    0.0.0.0:443     0.0.0.0:0        LISTENING  4
\```

---

### Browsing the Internet Example

Steps taken during a basic HTTP request:

#### 1. DNS Lookup
The browser resolves a domain to an IP, e.g. `93.184.216.34`.

### 2. Data Encapsulation
The browser forms a TCP packet with:
- Destination port: `80` or `443`
- Destination IP: `93.184.216.34`

#### 3. Data Transmission
- ARP finds MAC address of the router
- Frame sent to router
- Routers forward based on IP

#### 4. Server Processing
- Server listens on port 80
- Sends back HTTP response

#### 5. Response Transmission
- Response sent back to client
- Uses dynamic/private port to complete the session

---

### Summary Diagram (ASCII)

```
+-----------+       +-----------+       +-----------+
|  Browser  |       |   Router  |       |   Server  |
|192.168.1.2| <---> |192.168.1.1| <---> |93.184.216.34|
+-----------+       +-----------+       +-----------+
      |                   |                   |
      |  TCP/80 or 443    |  IP Forwarding    | Port Listening
      |------------------>|------------------>| (e.g. 80/443)
```

---

## Dynamic Host Configuration Protocol (DHCP)

### Introduction to DHCP

In a computer network, every device needs a unique IP (Internet Protocol) address to communicate with other devices. Manually assigning IP addresses to each device can be time-consuming and cause errors, especially in large networks. To resolve this issue, networks can rely on the Dynamic Host Configuration Protocol (**DHCP**).  
**DHCP** is a network management protocol used to automate the process of configuring devices on IP networks. It allows devices to automatically receive an IP address and other network configuration parameters, such as subnet mask, default gateway, and DNS servers, without manual intervention.

DHCP simplifies network management by automatically assigning IP addresses, significantly reducing the administrative workload. This automation ensures that each device connected to the network receives a unique IP address, preventing conflicts and duplication of addresses. Furthermore, DHCP recycles IP addresses that are no longer in use when devices disconnect from the network, optimizing the available address pool.

---

### How DHCP Works

The DHCP process involves a series of interactions between the client (the device requesting an IP address) and the DHCP server (the service running on a network device that assigns IP addresses). This process is often referred to as **DORA**, an acronym for **Discover**, **Offer**, **Request**, and **Acknowledge**.

#### DHCP Roles

| Role           | Description                                                                                   |
|----------------|-----------------------------------------------------------------------------------------------|
| `DHCP Server`  | A network device (like a router or dedicated server) that manages IP address allocation. It maintains a pool of available IP addresses and configuration parameters. |
| `DHCP Client`  | Any device that connects to the network and requests network configuration parameters from the DHCP server. |

#### The DORA Process

| Step         | Description                                                                                                     |
|--------------|-----------------------------------------------------------------------------------------------------------------|
| `1. Discover`| When a device connects to the network, it broadcasts a **DHCP Discover** message to find available DHCP servers. |
| `2. Offer`   | DHCP servers on the network receive the discover message and respond with a **DHCP Offer** message.             |
| `3. Request` | The client receives the offer and replies with a **DHCP Request** message, indicating that it accepts the offer. |
| `4. Acknowledge` | The DHCP server sends a **DHCP Acknowledge** message, confirming the client has been assigned the IP address.   |

---

### Example Command

To trigger the DHCP DORA process manually on a Linux machine:

\```
sudo dhclient wlan0
\```

---

### Lease Time

The IP address assignment via DHCP is not permanent but is instead issued with a specific **lease time**. For instance, a DHCP server might assign an IP address to a smartphone with a lease time of 24 hours. After this period, the client must request a **renewal** of the lease to continue using the IP address.

If the lease is close to expiration, the device must **proactively** send a renewal request to the DHCP server. If the server can renew the lease, it sends back a DHCP Acknowledge message.

---

### Example Scenario

Alice brings her new laptop to the office and connects to the network. Since the laptop doesn't yet have an IP address, it sends out a **DHCP Discover** message to find a DHCP server. The office's DHCP server receives this message and responds with a **DHCP Offer**, proposing the IP address `192.168.1.10`.

Alice's laptop responds with a **DHCP Request**, and the server finalizes the configuration by sending a **DHCP Acknowledge**.

Later, as the lease nears expiration, Alice's laptop sends a **renewal DHCP Request**, and if the server agrees, it responds with another **DHCP Acknowledge** to extend the lease.

---

### ASCII Diagram: DHCP Workflow

```
+-----+                                     +--------------+
| PC  |                                     | DHCP Server  |
+--+--+                                     +------+-------+
   | A New Device Connects                         |
   |--------------------------------------------->|
   |                                               |
   |               DHCP Discover                   |
   |--------------------------------------------->|
   |                                               |
   |               DHCP Offer                      |
   |<---------------------------------------------|
   |                                               |
   |               DHCP Request                    |
   |--------------------------------------------->|
   |                                               |
   |             DHCP Acknowledge                  |
   |<---------------------------------------------|
   |                                               |
   |            Device Configured                  |
   |<---------------------------------------------|
   |                                               |
   | Lease Expires Soon                            |
   |--------------------------------------------->|
   |                                               |
   |             DHCP Request                      |
   |--------------------------------------------->|
   |                                               |
   |           DHCP Acknowledge                    |
   |<---------------------------------------------|
   |           Lease Extended                      |
   +-----------------------------------------------+
```

---

## Network Address Translation (NAT)

### Introduction

The Internet relies on IP addresses to route data from one device to another. Due to IPv4’s limited address space (~4.3 billion addresses), **Network Address Translation (NAT)** was introduced to allow multiple internal devices to share a single public IP address. NAT not only helps conserve address space but also adds a layer of security to internal networks.

---

### Private vs. Public IP Addresses

- **Public IP Addresses**: Globally unique, assigned by ISPs, routable over the internet.
  - Example: `8.8.8.8`, `142.251.46.174`

- **Private IP Addresses**: Used within local networks, not routable over the public internet.
  - Common ranges:
    - `10.0.0.0` – `10.255.255.255`
    - `172.16.0.0` – `172.31.255.255`
    - `192.168.0.0` – `192.168.255.255`

Private IPs help conserve IPv4 space and enhance internal security by hiding internal structure from external networks.

---

### What is NAT?

**Network Address Translation (NAT)** is performed by routers to translate **private IP addresses** to a **single public IP address**. It modifies the source or destination IP address in the packet header.

---

### How NAT Works

Example setup:

- Devices: 
  - Laptop: `192.168.1.10`
  - Smartphone: `192.168.1.11`
  - Gaming Console: `192.168.1.12`
- Router:
  - LAN side: `192.168.1.1`
  - WAN side: `203.0.113.50`

Flow:

1. The laptop sends a request to `www.google.com`.
2. The NAT function changes:
   - Source IP: `192.168.1.10` → `203.0.113.50`
3. Server replies to `203.0.113.50`.
4. NAT matches response in its table and forwards it to `192.168.1.10`.

---

### ASCII Diagram of NAT in Action

```
           +-------------------+
           |    Remote Server  |
           |  Public IP: 503.0.135.60
           +--------+----------+
                    |
           +--------+----------+
           |     INTERNET      |
           +--------+----------+
                    |
           +--------+----------+
           |     Router/NAT     |
           |  Public IP: 203.0.113.50
           +--------+----------+
             |    |     |    |
  +----------+  +--+  +--+  +--+
  |  PC      |  |Printer|Smartphone|
  |192.168.1.10|192.168.1.111|192.168.1.112|
  +----------+  +--+  +--+  +--+
             |
        +----------+
        |  Laptop  |
        |192.168.1.113|
        +----------+
```

---

### Types of NAT

| Type                    | Description |
|-------------------------|-------------|
| **Static NAT**          | One-to-one mapping between private and public IPs. |
| **Dynamic NAT**         | Public IP assigned from a pool based on demand. |
| **Port Address Translation (PAT)** | Also called **NAT Overload**. Multiple private IPs share a single public IP using different port numbers. Most common in home networks. |

---

### Benefits and Trade-Offs

**Benefits:**
- Conserves limited IPv4 space.
- Adds basic security by hiding internal IPs.
- Supports flexible internal addressing.

**Trade-Offs:**
- Hosting internal services (like servers) requires port forwarding.
- Breaks protocols that need end-to-end connectivity.
- Makes troubleshooting harder.

---

## Domain Name System (DNS)

The Domain Name System (DNS) is like the phonebook of the internet. It helps us find the right number (an IP address) for a given name (a domain such as `www.google.com`). Without DNS, we would need to memorize long, often complex IP addresses for every website we visit. DNS makes our lives easier by allowing us to use human-friendly names to access online resources.

---

### Domain Names vs. IP Addresses

| Address      | Description                                                                 |
|--------------|-----------------------------------------------------------------------------|
| **Domain Name** | A readable address like `www.example.com` that people can easily remember. |
| **IP Address**  | A numerical label (e.g., `93.184.216.34`)                                  |

DNS bridges the gap between these two, so we can just type `www.google.com` without needing to remember the underlying IP address.

---

### DNS Hierarchy

DNS is organized like a tree, starting from the root and branching out into different layers.

| Layer                    | Description                                                                |
|--------------------------|----------------------------------------------------------------------------|
| **Root Servers**         | The top of the DNS hierarchy.                                              |
| **Top-Level Domains (TLDs)** | Such as `.com`, `.org`, `.net`, or country codes like `.uk`, `.de`.     |
| **Second-Level Domains** | For example, `example` in `example.com`.                                   |
| **Subdomains or Hostname** | For instance, `www` in `www.example.com`, or `accounts` in `accounts.google.com`. |

---

### URL Breakdown Diagram

```
https://www.example.com/home.html

┌────────┬───────────────┬─────────────┬──────────────┬────────┐
│ Scheme │ Subdomains    │ 2nd-Level   │ Top-Level     │ Page   │
│        │               │ Domain      │ Domain        │ Name   │
└────────┴───────────────┴─────────────┴──────────────┴────────┘
                                              └───────┘ Root
```

---

### DNS Resolution Process (Domain Translation)

When we enter a domain name in our browser, the computer needs to find the corresponding IP address. This process is known as **DNS resolution** or **domain translation**.

| Step | Description                                                                                 |
|------|---------------------------------------------------------------------------------------------|
| 1    | We type `www.example.com` into our browser.                                                 |
| 2    | Our computer checks its local DNS cache to see if it already knows the IP address.          |
| 3    | If not found locally, it queries a **recursive DNS server**.                                |
| 4    | The recursive DNS server contacts a **root server**, which points to the appropriate **TLD name server**. |
| 5    | The TLD server directs the query to the **authoritative name server** for `example.com`.    |
| 6    | The authoritative server responds with the IP address for `www.example.com`.                |
| 7    | The recursive server returns this IP address to the computer.                               |

This happens in fractions of a second and enables seamless access to online resources.

---

### DNS Query Flow Diagram (ASCII)

```
+--------------------------+
| Personal Computer        |
| (Web Browser)            |
+-----------+--------------+
            |
            | Asking for www.example.com’s IP address
            v
+-----------+--------------+
| Recursive DNS Server     |
| (ISP)                    |
+-----------+--------------+
            |
            | Query Root Server
            v
+-------------------+
| Root Server       |
+-------------------+
            |
            | Ask TLD server for example.com
            v
+-------------------+
| TLD Server (.com) |
+-------------------+
            |
            | Ask Authoritative DNS for www.example.com
            v
+---------------------------+
| Authoritative DNS Server |
| for example.com           |
+---------------------------+
            |
            | Respond with 93.184.216.34
            v
+--------------------------+
| Recursive DNS Server     |
+--------------------------+
            |
            | Respond with 93.184.216.34
            v
+--------------------------+
| Personal Computer         |
+--------------------------+
```

DNS simplifies the process of accessing websites by translating human-friendly domain names into machine-readable IP addresses.

---

## Internet Architecture

**Internet Architecture** describes how data is organized, transmitted, and managed across networks. Different architectural models serve different needs—some offer a straightforward client-server setup (like a website), while others rely on a more distributed approach (like file-sharing platforms). Understanding these models helps us see why networks are designed and operated the way they are. Different architectures solve different problems. Often, we see a combination of architectures creating hybrid models. Each model comes with its own set of trade-offs in terms of scalability, performance, security, and manageability.

---

### Peer-to-Peer (P2P) Architecture

In a **Peer-to-Peer (P2P)** network, each node, whether it's a computer or any other device, acts as both a client and a server. This setup allows nodes to communicate directly with each other, sharing resources such as files, processing power, or bandwidth, without the need for a central server.

P2P networks can be:
- **Fully decentralized** (no central authority),
- **Partially centralized** (a server may coordinate but not store data).

Example: A group of friends installs a P2P photo-sharing app and shares folders from their own machines directly.

A common application is **torrenting** (e.g., BitTorrent), where a *seeder* shares files that other peers download.

### ASCII Diagram

```
[PC]────┬────[Laptop]────┬────[Smartphone]
 |      |        |       |         |
 |    [PC]────[Printer]────[Server]
 |        └──────┬────────────┘
 └───────────────┘
```

#### Advantages

| Advantage         | Description                                                          |
|------------------|----------------------------------------------------------------------|
| **Scalability**     | Adding more peers increases shared resources                    |
| **Resilience**      | Network functions even if some peers go offline                |
| **Cost Distribution** | Load (storage, bandwidth) is distributed among users         |

#### Disadvantages

| Disadvantage              | Description                                                      |
|---------------------------|------------------------------------------------------------------|
| **Management complexity**     | Difficult to manage updates and policies across peers          |
| **Reliability issues**       | Network may degrade if many peers disconnect                   |
| **Security challenges**      | Each peer is a potential vulnerability                         |

---

### Client-Server Architecture

In the **Client-Server** model, clients (user devices) request services, and servers respond. A centralized server stores data and applications, with multiple clients accessing the same resources.

Example: A user visits `weatherexample.com`. The client sends a request to the web server hosting the site. The server processes it and sends back the requested data to the client.

#### ASCII Diagram

```
[Smartphone]   [PC]   [Laptop]
      \         |        /
       \        |       /
        \     [Internet]
         \       |
        [Server]
```

#### Advantages

| Advantage            | Description                                      |
|----------------------|--------------------------------------------------|
| **Centralized control** | Easier management of data, updates, policies    |
| **Security**            | Unified security policy enforcement             |
| **Performance**         | Dedicated servers can be optimized for tasks    |

#### Disadvantages

| Disadvantage            | Description                                             |
|-------------------------|---------------------------------------------------------|
| **Single point of failure** | If server fails, all clients lose access              |
| **Cost and Maintenance**    | Requires expert setup and ongoing upkeep             |
| **Network Congestion**      | High usage can cause performance issues              |

---

### Hybrid Architecture

A **Hybrid** architecture combines aspects of both Client-Server and P2P models. Authentication and control are handled by a server, but data is transferred directly between peers.

Example: In a video call app, the server authenticates users, but actual video/audio traffic goes peer-to-peer.

#### ASCII Diagram

```
        [Smartphone]  [PC]  [Laptop]
            \       |       /
             \   [Internet]
              \     |      /
              [Servers]  <──┐
                 |         │
        [Laptop]───[PC]───[Smartphone]
```

#### Advantages

| Advantage      | Description                                                |
|----------------|------------------------------------------------------------|
| **Efficiency**   | Reduces server load by offloading data to peer links       |
| **Control**      | Server still manages auth and session info                 |

#### Disadvantages

| Disadvantage                | Description                                               |
|-----------------------------|-----------------------------------------------------------|
| **Complex Implementation**    | More difficult to build and debug                         |
| **Potential Single Point of Failure** | If server fails, peer coordination might stop   |

---

### Cloud Architecture

**Cloud Architecture** is based on virtualized infrastructure managed by providers like AWS, Azure, etc. Users access services without managing the underlying hardware.

#### ASCII Diagram

```
           [Cloud]
         /   |   |   \
    [Servers][Apps][DB][Storage]
          |     |
       [Internet]
     /     |      \
[Laptop] [PC] [Smartphone]
```

#### Characteristics

| Characteristic             | Description                                          |
|----------------------------|------------------------------------------------------|
| **On-demand self-service** | Users can allocate computing resources automatically |
| **Broad network access**   | Services accessible from any location                |
| **Resource pooling**       | Shared among multiple users                          |
| **Rapid elasticity**       | Quickly scale resources up/down                      |
| **Measured service**       | Pay only for what is used                            |

#### Advantages

| Advantage              | Description                                   |
|------------------------|-----------------------------------------------|
| **Scalability**          | Add/remove resources as needed                |
| **Reduced cost**         | Hardware managed by provider                  |
| **Flexibility**          | Accessible from anywhere                      |

#### Disadvantages

| Disadvantage          | Description                                            |
|-----------------------|--------------------------------------------------------|
| **Vendor lock-in**       | Difficult to migrate between providers                |
| **Security/Compliance** | Privacy concerns due to external hosting              |
| **Connectivity**         | Requires reliable internet connection                |

---

### Software-Defined Architecture (SDN)

**Software-Defined Networking (SDN)** separates control and data planes. The control plane is centralized in a software-based controller that configures routing rules and traffic policies dynamically.

#### ASCII Diagram

```
     [Remote Servers]
            |
        [Internet]
            |
     [SDN Switches]
            |
     [SDN Controller]
            |
      ┌────┬─────┐
   [Laptop][PC][Smartphone]
```

#### Advantages

| Advantage                     | Description                                                       |
|------------------------------|-------------------------------------------------------------------|
| **Centralized control**        | Simplifies network management                                      |
| **Programmability**            | Rapid configuration through software                              |
| **Scalability & Efficiency**   | Dynamic optimization of traffic flow                              |

#### Disadvantages

| Disadvantage             | Description                                           |
|--------------------------|-------------------------------------------------------|
| **Controller Vulnerability** | Failure affects entire network                        |
| **Complex Implementation**   | Requires skilled personnel and tools                 |

---

### Key Comparisons

| Architecture   | Centralized          | Scalability        | Ease of Management      | Typical Use Cases                       |
|----------------|----------------------|--------------------|--------------------------|------------------------------------------|
| P2P            | Decentralized        | High               | Complex                  | File-sharing, blockchain                 |
| Client-Server  | Centralized          | Moderate           | Easy                     | Websites, email services                 |
| Hybrid         | Partially centralized| Higher than C-S    | Complex                  | Messaging apps, video conferencing       |
| Cloud          | Centralized provider | High               | Easy (outsourced)        | SaaS, PaaS, cloud storage                |
| SDN            | Centralized control  | High (policy-driven)| Moderate (specialized)  | Datacenters, large enterprises           |

---

### Conclusion

Each architecture presents unique strengths and trade-offs. Often, real-world systems combine elements from multiple models to balance scalability, security, cost, and flexibility. Understanding these architectures helps in designing efficient and resilient networks.

---

## Wireless Networks

A *wireless network* is a sophisticated communication system that employs radio waves or other wireless signals to connect various devices such as computers, smartphones, and IoT gadgets, enabling them to communicate and exchange data without the need for physical cables. This technology allows devices to connect to the internet, share files, and access services seamlessly over the air, offering flexibility and convenience in personal and professional environments.

### Advantages

| Advantage             | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| **Mobility**          | Users can move around freely within the coverage area.                      |
| **Ease of installation** | No need for extensive cabling.                                           |
| **Scalability**       | Adding new devices is simpler than a wired network.                         |

### Disadvantages

| Disadvantage          | Description                                                                 |
|------------------------|----------------------------------------------------------------------------|
| **Interference**       | Wireless signals can be disrupted by walls, other electronics, or atmospheric conditions. |
| **Security risks**     | Without proper security measures, wireless transmissions can be easier to intercept. |
| **Speed limitations**  | Generally, wireless connections are slower compared to wired connections of the same generation. |

## Wireless Router

A *router* is a device that forwards data packets between computer networks. In a home or small office setting, a *wireless router* combines the functions of:

### Functions

| Function              | Description                                                                 |
|------------------------|----------------------------------------------------------------------------|
| **Routing**            | Directing data to the correct destination (within your network or on the internet). |
| **Wireless Access Point** | Providing Wi-Fi coverage.                                             |

At home, smartphones, laptops, and smart TVs all connect wirelessly to the router. The router is plugged into a modem that brings internet service from the ISP (Internet Service Provider). The main components of a wireless router are:

### Components

| Component                  | Description                                                          |
|-----------------------------|----------------------------------------------------------------------|
| **WAN (Wide Area Network) Port** | Connects to your internet source (e.g., a cable modem).          |
| **LAN (Local Area Network) Ports** | For wired connections to local devices (e.g., desktop computer, printer). |
| **Antennae**                | Transmit and receive wireless signals. (Some routers have internal antennae.) |
| **Processor & Memory**      | Handle routing and network management tasks.                          |

### Mobile Hotspot

A *mobile hotspot* allows a smartphone (or other hotspot device) to share its cellular data connection via Wi-Fi. Other devices (laptops, tablets, etc.) then connect to this hotspot just like they would to a regular Wi-Fi network.

A mobile hotspot uses cellular data, connecting devices to the internet via a cellular network, such as 4G or 5G. The range is typically limited to just a few meters. Running a hotspot can significantly drain the battery of the device creating it. Security is typically password-protected like a home Wi-Fi network.

### Cell Tower

A *cell tower* (or *cell site*) is a structure where antennas and electronic communications equipment are placed to create a cellular network cell. This *cell* refers to the area of coverage provided by one tower, which connects seamlessly to adjacent cells.

Cell towers work via radio transmitters and receivers, communicating over specific radio frequencies. Base Station Controllers (BSCs) manage these towers, handling data transfer and mobility between them. Towers link to the core network via *backhaul links*, usually fiber optic or microwave.

**Types of cell towers:**

- **Macro cells:** Large towers with wide rural coverage.
- **Micro/small cells:** Short-range urban installations.

Imagine streaming music on a road trip — your phone switches between towers to maintain a connection.

### Frequencies in Wireless Communications

Wireless communication uses *radio waves*, emitted at specific *frequencies* (measured in hertz), for device interaction.

#### Frequency Bands

1. **2.4 GHz (Gigahertz)** – Used by older Wi-Fi standards (802.11b/g/n). Good range and wall penetration, but more interference.
2. **5 GHz** – Used by newer standards (802.11a/n/ac/ax). Faster, shorter range.
3. **Cellular Bands** – For 4G and 5G (700 MHz to 28 GHz). Higher speeds with higher frequencies.

#### Trade-offs

- **Lower frequencies**: Travel farther, carry less data.
- **Higher frequencies**: Carry more data, but over shorter distances.
- **Congestion**: Multiple devices on the same band cause interference.

Agencies like the FCC regulate frequencies to prevent this.

### Summarizing

On a typical day, we might use multiple wireless technologies:

- At home: **Wi-Fi** via 2.4 GHz and 5 GHz using a **wireless router**.
- On the go: Phone connects via **cell tower** over 4G/5G.
- While traveling: Enable **mobile hotspot** on phone to connect laptop.

These technologies together provide **Wi-Fi**, **cellular networks**, and **mobile hotspot** services for flexible connectivity.

---

## Network Security

In networking, the term security refers to the measures taken to protect data, applications, devices, and systems within the network from unauthorized access or damage. The goal is to uphold and maintain the **CIA triad**:

| Principle        | Description                                           |
|------------------|-------------------------------------------------------|
| `Confidentiality`| Only authorized users can view the data.             |
| `Integrity`      | The data remains accurate and unaltered.             |
| `Availability`   | Network resources are accessible when needed.        |

In the next paragraphs, we will discuss two critical components of network security: **Firewalls** and **Intrusion Detection/Prevention Systems (IDS/IPS)**.

---

### Firewalls

A **Firewall** is a network security device, either hardware, software, or a combination of both, that monitors incoming and outgoing network traffic. Firewalls enforce a set of rules (known as **firewall policies** or **access control lists**) to determine whether to `allow` or `block` specific traffic.

We can imagine a firewall as a security guard at the entrance of a building, checking who is allowed in or out based on a list of rules. If a visitor doesn’t meet the criteria (e.g., not on the guest list), they are denied entry.

*The open source router/firewall `pfSense`. It's large number of plugins (known as “Packages”) give it a range of capabilities.*

---

### Firewall Types

1. **Packet Filtering Firewall**

- **Description**:  
  Operates at Layer 3 (Network) and Layer 4 (Transport) of the OSI model.  
  Examines source/destination IP, source/destination port, and protocol type.  
  **Example**: A simple router ACL that only allows HTTP (port 80) and HTTPS (port 443) while blocking other ports.

2. **Stateful Inspection Firewall**

- **Description**:  
  Tracks the state of network connections. More intelligent than packet filters.  
  **Example**: Only allows inbound data that matches an already established outbound request.

3. **Application Layer Firewall (Proxy Firewall)**

- **Description**:  
  Operates up to Layer 7 (Application) of the OSI model.  
  Can inspect actual content of traffic (e.g., HTTP requests).  
  **Example**: A web proxy that filters out malicious HTTP requests.

4. **Next-Generation Firewall (NGFW)**

- **Description**:  
  Combines stateful inspection with advanced features like deep packet inspection, intrusion detection/prevention, and app control.  
  **Example**: A modern firewall that blocks known malicious IPs and inspects encrypted traffic.

---

### ASCII Diagram

```
         [Internet]
             |
         [Firewall]
             |
       [Router / Modem]
          /     \
     [Laptop]   [Smartphone]
         |
       [PC]
```

---

### Intrusion Detection and Prevention Systems (IDS/IPS)

**IDS/IPS** are security solutions designed to monitor and respond to suspicious network or system activity.

- **IDS (Intrusion Detection System)**: Observes traffic and generates alerts for suspicious behavior.
- **IPS (Intrusion Prevention System)**: Detects and also prevents malicious traffic in real time.

> *The widely used `Suricata` software can function as both an IDS and an IPS.*

---

### IDS/IPS Detection Techniques

| Technique                 | Description                                           |
|---------------------------|-------------------------------------------------------|
| `Signature-based detection` | Matches traffic against known exploits.              |
| `Anomaly-based detection`   | Detects anything unusual compared to normal activity.|

When malicious behavior is found, **IDS** alerts the administrator, while **IPS** may also block it in real time.

---

### IDS/IPS Types

1. **Network-Based IDS/IPS (NIDS/NIPS)**

- **Description**: Hardware/software placed in the network to inspect all passing traffic.  
  **Example**: A sensor monitoring data at a core switch.

2. **Host-Based IDS/IPS (HIDS/HIPS)**

- **Description**: Runs on individual devices and monitors system logs and inbound/outbound traffic.  
  **Example**: Antivirus software installed on a server.

---

### ASCII Diagram

```
         [Internet]
             |
         [Firewall]
             |
          [IPS/IDS]
             |
       [Router / Modem]
          /     \
     [Laptop]   [Smartphone]
         |
       [PC]
```

---

### Best Practices

| Practice                    | Description                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|
| `Define Clear Policies`     | Use principle of `least privilege` — only allow what is necessary.         |
| `Regular Updates`           | Keep firewall, IDS/IPS, and OS updated to defend against latest threats.   |
| `Monitor and Log Events`    | Regularly review logs to catch suspicious patterns early.                  |
| `Layered Security`          | Use `defense in depth` with multiple layers: firewalls, IDS/IPS, antivirus.|
| `Periodic Penetration Testing` | Simulate real attacks to test security effectiveness.                   |

---

## Data Flow Example

Based on the knowledge we have gained from the previous sections, the following paragraphs will show precisely what happens when a user tries to access a website from their laptop. Below is a breakdown of these events in a client-server model.

---

### 1. Accessing the Internet

Let’s imagine a user using their laptop to connect to the internet through their home Wireless LAN (WLAN) network. As the laptop is connecting to this network, the following happens:

| Steps |
|-------|
| The laptop first identifies the correct wireless network/SSID |
| If the network uses WPA2/WPA3, the user must provide the correct password or credentials to authenticate. |
| Finally, the connection is established, and the DHCP protocol takes over the IP configuration. |

---

### 2. Checking Local Network Configuration (DHCP)

When a user opens a web browser (such as Chrome, Firefox, or Safari) and types in `www.example.com` to access a website, the browser prepares to send out a request for the webpage. Before a packet leaves the laptop, the operating system checks for a valid IP address for the local area network.

| Steps                 | Description |
|----------------------|-------------|
| **IP Address Assignment** | If the laptop does not already have an IP, it requests one from the home router’s **DHCP** server. This IP address is only valid within the local network. |
| **DHCP Acknowledgement** | The DHCP server assigns a private IP address (for example, `192.168.1.10`) to the laptop, along with other configuration details such as subnet mask, default gateway, and DNS server. |

---

### 3. DNS Resolution

Next, the laptop needs to find the IP address of `www.example.com`. For this to happen, the following steps must be taken.

| Steps        | Description |
|--------------|-------------|
| **DNS Query**     | The laptop sends a DNS query to the DNS server, which is typically an external DNS server provided by the ISP or a third-party service like Google DNS. |
| **DNS Response**  | The DNS server looks up the domain `www.example.com` and returns its IP address (e.g., `93.184.216.34`). |

---

### 4. Data Encapsulation and Local Network Transmission

Now that the laptop has the destination IP address, it begins preparing the data for transmission. The following steps occur within the **OSI/TCP-IP** model:

| Steps              | Description |
|--------------------|-------------|
| **Application Layer** | The browser creates an HTTP (or HTTPS) request for the webpage. |
| **Transport Layer**   | The request is wrapped in a TCP segment (or UDP, but for web traffic it’s typically TCP). This segment includes source and destination ports (HTTP default port 80, HTTPS default port 443). |
| **Internet Layer**    | The TCP segment is placed into an IP packet. The source IP is the laptop’s private IP (e.g., `192.168.1.10`), and the destination IP is the remote server’s IP (`93.184.216.34`). |
| **Link Layer**        | The IP packet is finally placed into an Ethernet frame (if we’re on Ethernet) or Wi-Fi frame. Here, the MAC (Media Access Control) addresses are included (source MAC is the laptop’s network interface, and destination MAC is the router’s interface). |

When the encapsulated frame is ready, the laptop checks its ARP table or sends an ARP request to find the MAC address of the default gateway (the router). Then, the frame is sent to the router using the router’s MAC address as the destination at the **Link Layer**.

---

### 5. Network Address Translation (NAT)

Once the router receives the frame, it processes the IP packet. At this point, the router replaces the private IP (`192.168.1.10`) with its public IP address (e.g., `203.0.113.45`) in the packet header. This process is known as **Network Address Translation (NAT)**.

The router then forwards the packet to the ISP’s network, and from there, it travels across the internet to the destination IP (`93.184.216.34`). During this process, the packet goes through many intermediate routers that look at the destination IP and determine the best path to reach that network.

---

### 6. Server Receives the Request and Responds

Upon reaching the destination network, the server's firewall (if any) checks if the incoming traffic on port 80 (HTTP) or 443 (HTTPS) is allowed. If it passes firewall rules, it goes to the server hosting `www.example.com`.

The server receives and processes the request, prepares the webpage (HTML, CSS, images, etc.), and sends it back as a response.

The response process follows a similar path in reverse. Its IP (`93.184.216.34`) is now the source, and our home router’s public IP (`203.0.113.45`) is the destination. NAT ensures it is mapped back to the laptop’s private IP (`192.168.1.10`).

---

### 7. Decapsulation and Display

Finally, our laptop receives the response and strips away the Ethernet/Wi-Fi frame, the IP header, and the TCP header, until the application layer data is extracted. The laptop's browser reads the HTML/CSS/JavaScript and ultimately displays the webpage.

---

### Data Flow Diagram

Below is a flow chart showing the complete journey of a user accessing a website on the internet:

```
[PC]
 |
 |---(1) Connect to WLAN
 |---(2) DHCP IP Request
 |<--(3) DHCP IP Response
 |---(4) DNS Query
 |          |
 |          -->[Router]
 |             |---(5) DNS Query Forward
 |             |<--(6) DNS Response
 |---(7) HTTP Request
 |          |
 |          -->[Router]
 |             |---(8) NAT & Forward
 |             |          |
 |             |          -->[Web Server]
 |             |              |<--(10) HTTP Response
 |             |<--(11) NAT & HTTP Response
 |<--(12) Render Webpage
```

---

## Skills Assessment

Now that we are familiar with the foundational concepts of computer networking, it's time to see them in a real-world scenario. For this final section, we will explore the networking behind HTB Academy's lab environments. This guided assessment will be broken down into three chapters. Follow each chapter to answer the challenge questions and complete the assessment.

---

### Chapter 1 - Keep me in the Loop

We will start by investigating the network interfaces available on the Pwnbox.

#### Command
``shell
ifconfig -a
``

You will see interfaces such as `ens3`, `lo`, and `tun0`. Here's a snippet of what the output might look like:

```
ens3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500
      inet 209.50.61.235  netmask 255.255.252.0  broadcast 209.50.61.255
      ether a6:ba:3b:08:1e:4e txqueuelen 1000 (Ethernet)
      RX packets 30046  bytes 37369216 (35.6 MiB)
      TX packets 20239  bytes 33367968 (31.8 MiB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
    inet 127.0.0.1  netmask 255.0.0.0
    inet6 ::1  prefixlen 128  scopeid 0x10<host>
    loop txqueuelen 1000  (Local Loopback)

tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
     inet 10.10.14.21  netmask 255.255.255.0  destination 10.10.14.21
     inet6 fe80::abcd  prefixlen 64  scopeid 0x20<link>
     unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00
```

The loopback interface (`lo`) uses the address `127.0.0.1`. It’s commonly used for internal communication on the same device.

---

#### Command
```shell
netstat -tulnp4
```

This lists all TCP and UDP listening ports for IPv4.

Sample output:
```
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:5901          0.0.0.0:*               LISTEN      2814/xtigervnc
tcp        0      0 209.50.61.235:80        0.0.0.0:*               LISTEN      -
```

We can identify services running on both the loopback and public interfaces.

---

#### Command
```shell
netstat -tulp4
```

Without `-n`, hostnames and service names are resolved.

---

We also confirm that port forwarding can allow access from an external machine to an internal-only IP address using the loopback interface.

---

#### Command
```shell
ssh user@127.0.0.1 -p 8888
```

This connects to a local port forwarded SSH service.

---

### Chapter 2 - Having Tuns of Fun

We examine the `tun0` interface, used for VPN tunnels, allowing secure access to isolated lab environments.

---

#### Command
```shell
ip route get <target ip>
```

This confirms the route to the target IP is through `tun0`.

---

#### Command
```shell
ping -c 4 <target ip>
```

This sends 4 ICMP packets to test reachability.

---

#### Command
```shell
nmap <target ip>
```

This discovers open TCP ports on the target. Example result:
- 21/tcp open ftp
- 80/tcp open http

---

### Chapter 3 - Target Acquired

We now focus on port 21 (FTP) and port 80 (HTTP).

---

#### Command
```shell
nmap -p21,80 -sC -sV <target ip>
```

This runs default scripts and version detection.

---

#### Command
```shell
nc <target ip> 21
```

Use `netcat` to connect to the FTP service. You can log in anonymously:
```shell
USER anonymous[Ctrl+V][Enter][Enter]
PASS anything[Ctrl+V][Enter][Enter]
PASV[Ctrl+V][Enter][Enter]
```

PASV command returns the data port. If it’s `194,40`, calculate port as:

```
194 * 256 + 40 = 49704
```

---

#### Command

```shell
nc -v <target ip> 49704
```

Connect to the data port.

---

#### Command
```shell
LIST[Ctrl+V][Enter][Enter]
```

List available files. **Typically I found that you had to first run LIST|RETR in the main nc session, and *then* connect to the data port in the another nc session. Didn't work otherwise**

Sample response:

Note-From-IT.txt

To retrieve:
```shell
RETR Note-From-IT.txt[Ctrl+V][Enter][Enter]
```

Sample output:

The website is still under construction…
User-Agent: Server Administrator
…

---

Now switch to HTTP inspection.

---

#### Command
```shell
nc -v <target ip> 80
```

Then:
```shell
GET / HTTP/1.1[enter]
Host: <target ip>[enter]
User-Agent: Server Administrator[enter][enter]
```

The server responds with HTML and possibly flags hidden in comments.

---

### Conclusion

We now understand:
- Interface roles (`ens3`, `lo`, `tun0`)
- How to analyze port exposure with `netstat`, `ping`, `nmap`
- Manual FTP and HTTP communication with `netcat`
- Port forwarding concepts
- Protocol behavior and header mechanics

With this, you're ready to complete the Skills Assessment.

---