# FullDoh-a-prox-dns-server-usning-DoH
Author: Mitesh Kumar Mandal

## A Local DNS-over-HTTPS Proxy (Educational Project)

🔐 **Privacy** • 🌐 **Networking** • 📡 **Protocol Design**

An educational Java project to understand how **DNS over HTTPS (DoH)** works by translating standard DNS queries into HTTPS requests and back again.

---

## 📌 Overview

DNS is one of the most critical—and most overlooked—layers of the internet.  
It translates human-readable domain names into machine-readable IP addresses.

Traditionally, DNS traffic is **unencrypted**, making it observable and controllable at the network level.  
**DNS over HTTPS (DoH)** changes this by carrying DNS queries inside HTTPS, improving privacy and integrity.

**FullDoH** is a local DNS proxy built to *learn* how this translation works internally.

This project focuses on:

- Understanding DNS packet formats  
- Understanding DoH request/response models  
- Observing DNS behavior locally  
- Exploring privacy vs governance trade-offs  

---

## 🎯 Goals

- Learn how DNS resolution works at the protocol level  
- Explore how DNS queries can be transported over HTTPS  
- Build a minimal, readable implementation  
- Keep the scope focused on education and experimentation  

---

## 🚫 Non-Goals

This project is **not intended** to:

- Circumvent organizational security policies  
- Bypass access controls  
- Access restricted or illegal content  
- Replace enterprise DNS solutions  

> Understanding protocols ≠ violating rules.

---

## 🧠 How It Works (Conceptual)

At a high level, **FullDoH** acts as a translation layer:

1. Receives a standard DNS query  
2. Encodes the query for DNS over HTTPS  
3. Sends it to a DoH-capable resolver via HTTPS  
4. Receives the HTTPS response  
5. Decodes it back into a DNS response  
6. Returns the result to the requester  

This allows developers to observe and understand how DNS and DoH interact.

**No tunneling. No traffic obfuscation. Just protocol translation.**

---

## 🏗️ Architecture (High-Level)

Application
↓
Local DNS Proxy (FullDoH)
↓
HTTPS (DoH Resolver)
↓
DNS Response




- DNS parsing happens locally  
- Transport is HTTPS  
- Responses are reconstructed before returning  

---

## 💻 Technology Stack

- **Language:** Java  
- **Networking:** Java networking APIs  
- **Protocol Handling:** Binary DNS parsing  
- **Transport:** HTTPS  
- **Dependencies:** Minimal (standard Java libraries)  

---

## ▶️ Running the Project

This repository includes a runnable Java class: FullDoHBinaryServer.java


### Step-by-step (High-Level)

1. Clone the repository  
2. Open a command prompt / terminal  
3. Navigate to the directory containing `FullDoHBinaryServer.java`  
4. Run the server using:

```bash
java FullDoHBinaryServer.java
```

## ⚙️ System DNS Configuration (Required)

Before using this server, you must configure your system to use the machine where **FullDoH** is running as its DNS server.

- If the proxy is running on your **local system**, use:
  



### Windows DNS Configuration Steps

1. Open **Settings**
2. Go to **Network & Internet**
3. Select **Wi-Fi** or **Ethernet**
4. Click on the **connected network**
5. Click **Edit** under **DNS server assignment**
6. Select **Manual**
7. Enter the IP address of the system running this proxy server
8. Save the changes

⚠️ Always follow your organization’s network policies.

---

## 🔍 What You Can Observe

When running locally, the server logs:

- Incoming DNS queries  
- Domain names  
- Query types (A, AAAA, etc.)  
- Resolved IP addresses  

This visibility is useful for:

- Debugging  
- Learning  
- Understanding DNS resolution patterns  

---

## 🔐 Security & Ethics Notice

This project is for **educational and research purposes only**.

If a website is blocked in a managed network:

- ✅ The correct action is to request access  
- ❌ Not to bypass controls  

The author does not encourage or support misuse.

---

## 📚 What I Learned

- DNS is a policy enforcement layer, not just a lookup service  
- Encryption changes who you trust—not whether you trust  
- Privacy and governance often conflict  
- Protocol-level knowledge is essential for responsible engineering  

---

## 🧪 Possible Extensions

- Add caching with TTL awareness  
- Visualize DNS latency comparisons  
- Support multiple DoH resolvers  
- Add metrics for request timing  
- Implement rate limiting for safety  

---

## 🤝 Contributing

Contributions are welcome for:

- Code readability improvements  
- Documentation enhancements  
- Test coverage  
- Educational examples  

Please keep contributions:

- Ethical  
- Legal  
- Educational  

---

## 📝 Disclaimer

This project is provided **as-is**, without warranty of any kind.  
The author is not responsible for misuse.



