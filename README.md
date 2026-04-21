# Denial of Service (DoS) — SYN Flood Attack — Detection & Limitations Lab

A hands-on cybersecurity lab simulating a TCP SYN flood DoS attack on a local virtual network, with active Limitations using `iptables` rate limiting and intrusion detection using Suricata.

> **Theory & Background** → See [`THEORY.md`](./THEORY.md) for how SYN floods work, how `iptables` defends against them, and how Suricata detects them.

---

## Table of Contents

- [Overview](#overview)
- [Lab Environment](#lab-environment)
- [VM Setup](#vm-setup)
- [Module 1 — Attack Generation](#module-1--attack-generation-kali-vm)
- [Module 2 — Traffic Capture](#module-2--traffic-capture--visualisation-ubuntu-vm)
- [Module 3 — Firewall Rate Limiting](#module-3--firewall-rate-limiting-ubuntu-vm)
- [Module 4 — Intrusion Detection](#module-4--intrusion-detection-ubuntu-vm)
- [Results](#results)

---

## Overview

This lab demonstrates a full attack-and-defend cycle on a local virtual network:

- **Attacker (Kali Linux)** — launches a TCP SYN flood using `hping3` targeting port 80
- **Defender (Ubuntu Desktop 24.04)** — the attack target on port 80, with `iptables` for rate limiting, Suricata for IDS alerting, and Wireshark for traffic capture. No web service is running — port 80 is used purely as the flood target.

---

## Lab Environment

| | Attacker | Defender |
|---|---|---|
| **OS** | Kali Linux 2024.x | Ubuntu Desktop 24.04 LTS |
| **RAM** | 4 GB | 4 GB |
| **CPUs** | 2 vCores | 2 vCores |
| **Adapter 1** | Host-only | Host-only (lab communication) |
| **Adapter 2** | — | NAT (package downloads only) |
| **Role** | SYN flood source | Target + Limitations host |

**Tools used:**

| Tool | Version | Role |
|---|---|---|
| VirtualBox | 7.0+ | Virtualisation platform |
| hping3 | 3.0.0-alpha-2 | SYN packet generation |
| Wireshark | 4.x | Traffic capture & visualisation |
| iptables | 1.8.x | Firewall rate limiting |
| Suricata | 7.x | Intrusion detection & alerting |

---

## VM Setup

### Step 1 — Create the VMs in VirtualBox

**Kali Linux VM (Attacker)**
1. Download the [Kali Linux ISO](https://www.kali.org/get-kali/)
2. In VirtualBox, create a new VM → set RAM to 4 GB, 2 CPU cores
3. Set the network adapter to **Host-only** mode
4. Boot from the ISO and complete the standard Kali installation

**Ubuntu VM (Defender)**
1. Download the [Ubuntu Desktop 24.04 LTS ISO](https://ubuntu.com/download/desktop)
2. In VirtualBox, create a new VM → set RAM to 4 GB, 2 CPU cores
3. Add **two** network adapters:
   - **Adapter 1** → Host-only (used for lab traffic between the two VMs)
   - **Adapter 2** → NAT (used only during setup to download packages — can be disabled after)
4. Boot from the ISO and complete the standard Ubuntu installation

> The Host-only adapters on both VMs must be on the **same Host-only network** in VirtualBox so they can reach each other while staying isolated from the host network. IP addresses are assigned dynamically.

Kali VM Network Settings
![Kali Network Setting](<Screenshot/Screenshot 2026-04-21 214407.png>)
![Kali Lockscreen](<Screenshot/Screenshot 2026-04-12 223310.png>)


Ubuntu VM Network Settings
<p align="center">
  <img src="Screenshot/Screenshot 2026-04-21 214213.png" alt="First Image" width="49%">
  <img src="Screenshot/Screenshot 2026-04-21 214226.png" alt="Second Image" width="49%">
</p>

![Ubuntu Lockscreen](<Screenshot/Screenshot 2026-04-12 221414.png>)

---

### Step 2 — Install Services on Ubuntu

```bash
# Install Wireshark and add user to wireshark group
sudo apt install wireshark
sudo usermod -aG wireshark $USER

# Install Suricata with default config
sudo apt install suricata
```

---

## Module 1 — Attack Generation (Kali VM)

`hping3` is used to craft and flood TCP SYN packets at the Ubuntu VM. The `--flood` flag ignores round-trip time and pushes the NIC to maximum output. The `-S` flag sets the SYN bit, exploiting the first step of the TCP three-way handshake to keep the victim in a half-open state.

### Command

```bash
sudo hping3 -S --flood -p 80 <UBUNTU_VM_IP>
```

> Run for approximately 30 seconds, then stop with `Ctrl+C`.

![alt text](<Screenshot/Screenshot 2026-04-12 225552.png>)


---

## Module 2 — Traffic Capture & Visualisation (Ubuntu VM)

Wireshark captures all traffic on the Ubuntu VM during the attack. The filter below isolates only SYN packets (no ACK), making the flood immediately visible.

![Wireshark Installation](<Screenshot/Screenshot 2026-04-12 225042.png>)
### Wireshark Filter

```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```
![Wireshark Packet Capturing](<Screenshot/Screenshot 2026-04-12 225610.png>)


---

## Module 3 — Firewall Rate Limiting (Ubuntu VM)

Two `iptables` rules implement **token bucket rate limiting** on inbound SYN packets. The first rule accepts SYN packets up to a rate of 5/s with a burst of 10. The second rule drops everything that exceeds this rate.

### Rules

```bash
sudo iptables -A INPUT -p tcp --syn -m limit --limit 5/s --limit-burst 10 -j ACCEPT
sudo iptables -A INPUT -p tcp --syn -j DROP
```

### Verify dropped packets in real time

```bash
sudo iptables -L -v -n
```
![iptables rate-limiting](<Screenshot/Screenshot 2026-04-12 230053.png>)

---

## Module 4 — Intrusion Detection (Ubuntu VM)

Suricata runs in IDS mode alongside `iptables`. While `iptables` drops the excess traffic, Suricata identifies and logs the attack pattern — important for incident response and attribution. The rule triggers when a source IP sends 20 or more SYN packets to port 80 within a single second (threshold-based detection), which avoids false positives from slow or legitimate connections.

### Suricata Custom Rule

Add the following to `/etc/suricata/rules/local.rules`:

```
alert tcp any any -> $HOME_NET 80 (msg:"SYN Flood Attack Detected"; flags:S; threshold:type both, track by_src, count 20, seconds 1; sid:1000001; rev:1;)
```

Add `local.rules` to the rules list in `/etc/suricata/suricata.yaml`, then restart:

```bash
sudo systemctl restart suricata
```

### Check alerts

```bash
sudo tail -f /var/log/suricata/fast.log
```
![Suricata Alerts](<Screenshot/Screenshot 2026-04-13 005921.png>)

---

## Results

### Before Limitations
Wireshark shows an overwhelming volume of SYN packets with no ACK responses — the kernel's TCP backlog is flooded and the target port is saturated.
![Wireshark graphs](<Screenshot/Screenshot 2026-04-13 011026.png>)

### After Limitations
Once `iptables` rules are applied, the flood of SYN packets visible in Wireshark drops sharply. The `iptables -L -v -n` counter shows a large number of dropped packets, and `fast.log` confirms Suricata has logged the attack.

![Wireshark after graph](<Screenshot/Screenshot 2026-04-13 010622.png>)
