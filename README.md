# FullDoh-a-prox-dns-server-usning-DoH

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

