# Theory & Background

This document covers the theoretical foundations behind the SYN flood lab — how the attack works at a protocol level, and how `iptables` and Suricata work to defend against it.

---

## Table of Contents

- [DoS and DDoS Attacks](#dos-and-ddos-attacks)
- [TCP Three-Way Handshake](#tcp-three-way-handshake)
- [SYN Flood Attack Mechanics](#syn-flood-attack-mechanics)
- [Defence — iptables Rate Limiting](#defence--iptables-rate-limiting)
- [Defence — Suricata IDS](#defence--suricata-ids)

---

## DoS and DDoS Attacks

A Denial of Service attack has one goal: make a service unavailable to the people who need it. The attacker doesn't steal data or take over the machine. They just exhaust something, bandwidth, memory, CPU, open connections, until the server can't respond to real requests.

The distinction between DoS and DDoS is source count. A DoS attack comes from a single machine. A DDoS (Distributed Denial of Service) attack coordinates traffic from many machines simultaneously, often a botnet of thousands of compromised hosts. The distributed version is harder to block because you can't just firewall one IP.

Attacks generally fall into three categories. Volumetric attacks flood the network pipe with raw traffic, UDP floods and ICMP floods being the classic examples. Protocol-based attacks exploit how network protocols allocate state, targeting connection tables, routing infrastructure, or load balancers rather than raw bandwidth. Application layer attacks go higher up the stack, sending requests that are cheap to send but expensive to process, like malformed HTTP requests that force the server to do real work before rejecting them.

This project is a protocol-based attack. Specifically, it exploits how TCP manages connection state during the handshake.


---

## TCP Three-Way Handshake

Before two hosts exchange data over TCP, they negotiate a connection through a three-step sequence.

The client sends a SYN packet — short for synchronize — signaling it wants to open a connection and advertising its initial sequence number. The server receives the SYN, acknowledges it with a SYN-ACK, and sends back its own sequence number. The client then sends an ACK to confirm receipt, and the connection is established.

That last step matters more than it seems. When the server sends the SYN-ACK, it doesn't just send a packet and forget. It allocates a Transmission Control Block (TCB): a data structure in kernel memory that tracks everything about this pending connection — sequence numbers, window size, source and destination addresses. The TCB has to exist before the handshake completes, because the server needs somewhere to store that state while it waits for the client's ACK.

The server stores these half-open connections in a backlog queue. This queue has a fixed size, typically a few hundred to a few thousand entries depending on the OS and configuration. If the queue fills up, the server starts rejecting new SYN packets entirely — even from legitimate clients. Each TCB entry sits in that queue for 60 to 120 seconds by default before the connection times out and gets cleared.

That timeout is the attack surface.

---

## SYN Flood Attack Mechanics

A SYN flood exploits exactly this: the attacker sends SYN packets as fast as possible, never completing the handshake. For each SYN the server receives, it allocates a TCB and sends a SYN-ACK. The ACK never arrives. The TCB sits in the backlog queue consuming memory until it times out.

Send SYNs faster than entries expire, and the queue stays full. A full backlog queue means the server drops all new incoming SYN packets. The service is unreachable.

Spoofed source IPs make this significantly worse. If the attacker randomizes the source address in each SYN packet, the server sends SYN-ACKs to addresses that don't exist or didn't ask for them. The real machine at that IP (if it exists) sends a RST back, but the attacker's machine never receives anything, so there's nothing to stop the flood. The server keeps waiting for ACKs that can't arrive, because the source that was supposed to send them was fabricated.

The resource cost is modest per packet but adds up fast. Each TCB is roughly 280 bytes on Linux. Fill a backlog queue of 1,024 entries and you've consumed about 280 KB — trivial by itself, but the real damage is the queue saturation, not the memory. Once the queue is full, the server refuses new connections regardless of how much free RAM it has.

hping3 is the standard tool for generating SYN floods in lab environments. The -S flag sets the TCP SYN bit, constructing valid-looking SYN packets. The --flood flag removes any delay between packets, transmitting as fast as the network interface allows. Combined with --rand-source, hping3 randomizes the source IP on each packet, simulating a spoofed-source flood.

---

## Defence — iptables Rate Limiting

The token bucket algorithm is the mechanism behind most rate limiting, including iptables. Picture a bucket that holds tokens. Every time a packet arrives, it costs one token. Tokens refill at a fixed rate over time. If the bucket is empty when a packet arrives, that packet gets dropped. If tokens are available, the packet goes through and one token is consumed.

Two parameters define the bucket's behavior: the refill rate (how many tokens per second) and the burst capacity (the maximum the bucket can hold). A burst capacity higher than the refill rate lets the system absorb short spikes without dropping packets, as long as the average rate stays within limits.

The iptables rules for this lab map directly onto those two parameters:
```
-m limit --limit 5/s --limit-burst 10
```
--limit 5/s sets the refill rate: five tokens per second. --limit-burst 10 sets the bucket capacity: up to ten tokens can accumulate. A client that sends a burst of ten SYNs in quick succession gets through, because the bucket had enough tokens. An attacker sending hundreds of SYNs per second drains the bucket immediately and stays drained. Subsequent packets hit the DROP rule.

The tradeoff is real but acceptable. A slow legitimate connection that sends SYNs gradually will always have tokens available, since the refill rate keeps up with it. The flood gets blocked because no refill rate can keep up with thousands of packets per second. You're not rate-limiting by IP here, you're rate-limiting the total incoming SYN rate, so a single attacker saturating the limit does affect other users trying to connect simultaneously. More targeted per-source-IP limiting requires connection tracking (conntrack), which adds overhead.

---

## Defence — Suricata IDS

A firewall enforces policy: it allows or drops packets based on rules. An Intrusion Detection System (IDS) monitors traffic and generates alerts when it sees patterns that match known attack signatures. The two are complementary. A firewall can silently drop a flood; an IDS tells you the flood happened, when, and from where.

Suricata does threshold-based detection. Rather than alerting on every SYN packet (which would drown the log in noise on any production server), it tracks per-source counts over a time window and fires an alert only when a source crosses a defined threshold.

The rule written for this lab:
```
alert tcp any any -> $HOME_NET 80 (msg:"SYN flood detected"; flags:S; threshold: type threshold, track by_src, count 20, seconds 1; sid:1000001;)
```
Breaking this down: flags:S matches only packets with the SYN bit set, ignoring ACKs, data packets, and everything else. track by_src means the counter is per source IP, not global. count 20, seconds 1 means a source has to send 20 SYN packets within a single second before Suricata generates an alert.

The threshold of 20 per second exists to avoid false positives. A browser establishing multiple parallel connections to load a webpage might send three to five SYNs in a second. A CI pipeline hitting a server might send more. Twenty is high enough to let real usage through while still catching a flood, which typically runs in the hundreds or thousands of packets per second.

Suricata writes alerts to fast.log in a human-readable one-line format: timestamp, alert message, source and destination IP, and the rule that fired. In incident response, fast.log is the first place you look to confirm an attack is happening, identify the source IP (or range), and correlate timing with firewall drops. It doesn't block anything on its own, but it gives you the evidence you need to act.
