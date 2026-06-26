# 🛰️ Network Scanning & Recon Concepts — Field Guide

> A structured reference on network reconnaissance, port scanning, and vulnerability discovery concepts — covering ASN/CIDR enumeration, host discovery, port scanning, Nmap, and authorized-testing methodology.

---

## ⚠️ Read This First

This guide explains **how network reconnaissance tools and techniques work** so you can understand the methodology used in authorized penetration testing, bug bounty programs, and your own infrastructure audits.

> 🛑 **Scanning a system you do not own or do not have explicit written authorization to test is illegal in most jurisdictions** (in the US, this falls under the Computer Fraud and Abuse Act; most countries have equivalent computer-misuse laws). Bug bounty programs define a specific **scope** — IP ranges, domains, and ASNs you are permitted to test — and anything outside that scope is off-limits even if it's technically reachable.
>
> Every command in this guide should only be run against:
> - Infrastructure you personally own,
> - A lab environment you control (e.g., HackTheBox, TryHackMe, a local VM range), or
> - A target explicitly covered by a signed authorization or a bug bounty program's published scope.

---

## 📑 Table of Contents

1. [Introduction](#-introduction)
2. [Prerequisites](#-prerequisites)
3. [Installation](#-installation)
4. [Learning Roadmap](#-learning-roadmap)
5. [Chapter 1 — ASN Enumeration](#-chapter-1--asn-enumeration)
6. [Chapter 2 — IP Enumeration](#-chapter-2--ip-enumeration)
7. [Chapter 3 — Host Discovery via DNS](#-chapter-3--host-discovery-via-dns)
8. [Chapter 4 — Port Scanning Tools](#-chapter-4--port-scanning-tools)
9. [Chapter 5 — Nmap Complete Guide](#-chapter-5--nmap-complete-guide)
10. [Chapter 6 — Understanding Firewall/IDS Interaction](#-chapter-6--understanding-firewallids-interaction)
11. [Chapter 7 — Authorized Testing Workflows](#-chapter-7--authorized-testing-workflows)
12. [Chapter 8 — High-Value Ports Reference](#-chapter-8--high-value-ports-reference)
13. [Chapter 9 — Host Discovery Techniques (Layer 2/3/4)](#-chapter-9--host-discovery-techniques-layer-234)
14. [Chapter 10 — Shodan Recon](#-chapter-10--shodan-recon)
15. [Chapter 11 — Sandmap](#-chapter-11--sandmap)
16. [Chapter 12 — ScanCannon](#-chapter-12--scancannon)
17. [Cheat Sheet](#-cheat-sheet)
18. [Complete Workflow Diagram](#-complete-workflow-diagram)
19. [Best Practices](#-best-practices)
20. [Notes](#-notes)
21. [References](#-references)
22. [Disclaimer](#-disclaimer)

---

## 🧭 Introduction

Network reconnaissance is the **first phase** of any security assessment. Before you can test a system for vulnerabilities, you need to know:

- What organization owns which IP space (**ASN/CIDR enumeration**)
- Which IPs in that space are actually reachable (**host discovery**)
- Which ports are open on those hosts (**port scanning**)
- What software/version is listening on each port (**service detection**)
- Whether that software has known weaknesses (**vulnerability scanning**)

This guide walks through that pipeline end-to-end, tool by tool, explaining what each one does, why it's used, how to read its output, and where it fits into a lawful, scoped security assessment.

```
Target Org → ASN → CIDR → IPs → Hostnames → Live Hosts → Open Ports → Services → Findings → Report
```

---

## ✅ Prerequisites

| Requirement | Why |
|---|---|
| Linux environment (Kali, Ubuntu, Parrot, or WSL) | Most tools here are Linux-native or work best there |
| `Go` installed (1.21+) | Several tools (ASNMAP, MapCIDR, DNSX, Naabu) are Go binaries |
| `sudo`/root access | Raw-socket scans (SYN, UDP, ARP) require elevated privileges |
| Basic networking knowledge | Understanding IP, CIDR, TCP/UDP, and DNS will make this much easier to follow |
| **Written authorization or a defined bug bounty scope** | Non-negotiable — see the warning above |

---

## 📦 Installation

Quick reference for installing the core tools covered in this guide:

```bash
# Go-based ProjectDiscovery tools
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Nmap (most distros)
sudo apt install nmap

# Masscan
sudo apt install masscan

# Rustscan
cargo install rustscan
# or via Docker:
docker pull rustscan/rustscan:2.1.1
```

> 💡 **Tip:** Make sure `$GOPATH/bin` (usually `~/go/bin`) is in your `$PATH` so Go-installed tools are runnable from anywhere:
> ```bash
> export PATH=$PATH:$(go env GOPATH)/bin
> ```

---

## 🗺️ Learning Roadmap

This is the order the rest of the guide follows — each phase produces the input for the next.

| Phase | Goal | Primary Tool(s) |
|---|---|---|
| 1. ASN Enumeration | Find the org's Autonomous System Numbers | ARIN, BGP.he.net |
| 2. CIDR Collection | Get all IP ranges tied to those ASNs | ASNMAP |
| 3. IP Extraction | Expand CIDR ranges into individual IPs | MapCIDR |
| 4. Hostname Discovery | Reverse-resolve IPs to hostnames | DNSX |
| 5. Live Host Detection | Filter to hosts that actually respond | Nmap, Masscan |
| 6. Port Scanning | Find open ports on live hosts | Naabu, Masscan, Rustscan |
| 7. Service Enumeration | Identify software + version on open ports | Nmap `-sV` |
| 8. Deep Scanning | Run scripts, OS detection on interesting services | Nmap NSE |
| 9. Vulnerability Discovery | Check for known CVEs / misconfigurations | Nmap `--script vuln` |
| 10. Reporting | Document and responsibly disclose findings | — |

---

## 📡 Chapter 1 — ASN Enumeration

### 🧠 Theory

An **Autonomous System Number (ASN)** is a globally unique number assigned to a network or group of networks under one administrative control — for example, a large company, university, or ISP. ASNs are the backbone of how the internet routes traffic between organizations (via BGP — Border Gateway Protocol).

**CIDR (Classless Inter-Domain Routing)** notation compactly describes an IP range. For example:

```
82.24.0.0/22  →  covers 1,024 addresses: 82.24.0.0 – 82.24.3.255
```

The `/22` is the **prefix length** — it tells you how many of the 32 bits in an IPv4 address are fixed (the network portion); the rest are free to vary (the host portion). A smaller number after the slash means a *larger* range:

| Prefix | Addresses |
|---|---|
| /24 | 256 |
| /22 | 1,024 |
| /16 | 65,536 |
| /8 | 16,777,216 |

A single organization typically owns **multiple ASNs and multiple CIDR blocks** — especially large companies with regional offices, cloud presence, or acquired subsidiaries.

### 🔧 Discovery Tools & Websites

| Resource | URL | Purpose |
|---|---|---|
| ARIN WHOIS | `whois.arin.net/ui/` | Find ASN registrations for North American orgs |
| Hurricane Electric BGP Toolkit | `bgp.he.net/` | Global ASN & BGP routing lookup |
| MX Toolbox | `mxtoolbox.com/SuperTool.aspx` | Verify CIDR ranges and related network info |
| ASN Lookup | `asnlookup.com/` | Quick ASN-to-CIDR mapping |

> 💡 **Pro Tip:** Search the company name across multiple registries. Large organizations often hold several ASNs across regions and subsidiaries — relying on a single source will miss assets.

### 🛠️ Tool: ASNMAP

**What it is:** A Go-based CLI tool from ProjectDiscovery that maps an organization name or ASN number to its complete list of CIDR ranges, querying ARIN, RIPE, and APNIC in one shot.

**Why use it:** Manually querying multiple WHOIS databases is slow. ASNMAP consolidates that lookup into a single command.

#### Installation
```bash
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
```

#### Command Syntax
```bash
asnmap -a AS996 > tmobilecidr.txt
```

| Flag/Arg | Meaning |
|---|---|
| `-a AS996` | Target ASN number to query |
| `> tmobilecidr.txt` | Redirects (saves) output to a file instead of printing to screen |

#### Example Output
```
66.94.0.0/17
208.54.0.0/16
72.14.0.0/17
...
```

### ✅ Use Cases (in an authorized engagement)

- Mapping the full scope of a client's or your own organization's internet-facing footprint
- Discovering forgotten/unmonitored infrastructure that's still in-scope but not on the asset inventory
- Building an accurate target list before any active scanning begins

> 🚨 **Critical reminder:** Before scanning *any* IP range you discover, cross-check it against the bug bounty program's or client's **published scope**. An ASN belonging to a parent company is not automatically in scope just because you found it. Scanning out-of-scope assets can get you banned from the program — or prosecuted.

---

## 🌐 Chapter 2 — IP Enumeration

### 🧠 Theory

Once you have CIDR ranges, you need to expand them into a flat list of individual IPs to feed into scanners. This is purely mechanical — CIDR-to-IP expansion — but doing it by hand for large ranges is impractical.

### 🛠️ Tool: MapCIDR

**What it is:** A ProjectDiscovery tool that expands CIDR notation into a list of individual IPs. It accepts a single CIDR, a file of many CIDRs, or piped input.

**Why use it:** Automates an otherwise tedious and error-prone calculation, instantly, at any scale.

#### Installation
```bash
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
```

#### Commands & Explanation

```bash
mapcidr -cidr tmobilecidr.txt > allipaddress.txt
```
- `-cidr tmobilecidr.txt` — input file with one or more CIDR ranges
- `> allipaddress.txt` — saves every expanded IP, one per line

```bash
mapcidr -cidr 82.24.0.0/22 > singlecidr.txt
```
- Expands a single CIDR block directly from the command line

```bash
echo 82.24.0.0/22 | mapcidr -silent | dnsx -ptr -resp-only
```
- `echo 82.24.0.0/22` — pipes one CIDR into the next command
- `mapcidr -silent` — expands to individual IPs without printing the tool banner
- `dnsx -ptr -resp-only` — immediately does a reverse DNS lookup on each IP

#### Example Output
```
82.24.0.0
82.24.0.1
82.24.0.2
...
82.24.3.255
```

### 🔗 Combined Pipeline Example

```bash
# Full ASN-to-IP pipeline
asnmap -a AS714 > apple_cidr.txt
mapcidr -cidr apple_cidr.txt > apple_ips.txt
wc -l apple_ips.txt                       # count total IPs

# Or pipe directly without intermediate files
asnmap -a AS714 | mapcidr -silent > all_ips.txt
```

### ✅ Use Cases

- Building a complete inventory of an organization's IP space
- Feeding a clean target list into port scanners
- Combining with DNSX (next chapter) for hostname discovery

> 💡 **Tip:** Large ASNs can expand to millions of IPs. Always rate-limit subsequent scans, and where possible, filter to *live* hosts first (Chapter 9) before running expensive deep scans on every address.

---

## 🏷️ Chapter 3 — Host Discovery via DNS

### 🧠 Theory

A **PTR record** (reverse DNS) maps an IP address back to a hostname — the inverse of a normal "A record" lookup. Resolving IPs to hostnames reveals what services actually live at each address and can surface subdomains that weren't found through normal subdomain enumeration.

### 🛠️ Tool: DNSX

**What it is:** A fast, multi-purpose DNS toolkit from ProjectDiscovery. For this use case, it performs PTR (reverse) lookups at scale.

**Why use it:** Converting raw IPs into hostnames tells you *what* is actually running there — `cdn.example.com` vs. `internal-dev.example.com` are very different targets in terms of risk and relevance.

#### Installation
```bash
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

#### Commands & Explanation

```bash
cat allipaddress.txt | dnsx -ptr -resp-only
```
- `cat allipaddress.txt` — reads the IP list
- `-ptr` — perform reverse PTR DNS lookup
- `-resp-only` — print only the resolved hostname (omit the IP from output)

```bash
mapcidr -cidr tmobilecidr.txt | dnsx -ptr -resp-only > hostnames.txt
```
- Expands CIDRs and resolves hostnames in one pipeline, saving the result

#### Example Output
```
cdn.example.com
api.example.com
internal-dev.example.com
staging.example.com
```

### ✅ Use Cases

- Surfacing forgotten or unmonitored subdomains via reverse DNS that subdomain brute-forcing might miss
- Spotting internal naming conventions (`dev`, `staging`, `admin`, `internal`, `test`)
- Distinguishing CDN-fronted hosts from directly-owned infrastructure
- Cross-referencing discovered hostnames against the program's published scope

> 💡 **Why "dev/staging/admin/test" hostnames matter:** Non-production environments are frequently spun up quickly, may run outdated software, and often have weaker access controls than production. That's exactly why they need to be *in scope* and verified, not exploited — if you find one, the responsible move is to confirm it's covered by your authorization before going further, and to report what you find rather than dig into systems you weren't asked to test.

---

## 🔍 Chapter 4 — Port Scanning Tools

### 🧠 Theory

A port scanner determines which TCP/UDP ports on a host are **open** (accepting connections), **closed** (actively refusing), or **filtered** (no response, likely blocked by a firewall). This is the step that turns "a list of IPs" into "a list of services worth investigating."

### 🛠️ Tool: Naabu

**What it is:** A fast Go-based port scanner from ProjectDiscovery supporting SYN, CONNECT, and UDP scan modes, with built-in rate limiting and concurrency controls.

**Why use it:** It's fast, integrates cleanly with other ProjectDiscovery tools (httpx, nuclei), handles large target lists well, and has rate-limiting built in to avoid overwhelming a target.

#### Installation
```bash
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

#### Commands & Explanation

```bash
naabu -l allipaddress.txt
```
- `-l allipaddress.txt` — load targets from file
- (default behavior scans the top 100 most common ports)

```bash
naabu -l allipaddress.txt -rate 3000 -retries 1 -warm-up-time 0 -c 50
```

| Flag | Meaning |
|---|---|
| `-l allipaddress.txt` | Target list file |
| `-rate 3000` | Send up to 3,000 packets/second |
| `-retries 1` | Retry a failed probe once |
| `-warm-up-time 0` | Skip the gradual ramp-up; start at full configured rate |
| `-c 50` | Use 50 concurrent connections |

#### Example Output
```
172.16.1.1:80
172.16.1.1:443
172.16.2.5:8080
172.16.2.9:22
```

> 💡 **Tip:** Naabu pipes neatly into `httpx` for fast web-service triage:
> ```bash
> naabu -l ips.txt | httpx -title -status-code
> ```
> This gives you live web services with page titles and HTTP status codes in a single pass.

### ✅ Use Cases
- Scanning an entire authorized ASN range for open ports quickly
- Surfacing non-standard web ports
- Identifying exposed services for follow-up enumeration

---

### 🛠️ Tool: Masscan

**What it is:** An extremely fast asynchronous port scanner that implements its own TCP/IP stack, capable of scanning huge address spaces in a fraction of the time a standard scanner would take.

**Why use it:** When the priority is raw speed across very large CIDR ranges, Masscan is the standard choice — at the cost of the depth of detail you'd get from Nmap.

#### Installation
```bash
# Ubuntu/Debian
sudo apt install masscan

# Or build from source
git clone https://github.com/robertdavidgraham/masscan
cd masscan && make
```

#### Commands & Explanation

```bash
masscan -p0-65535 66.207.176.0/22 --rate=50000
```
- `-p0-65535` — scan every possible TCP port
- `66.207.176.0/22` — the target CIDR range
- `--rate=50000` — transmit 50,000 packets per second

```bash
masscan -iL allipaddress.txt --rate=50000 --ports 0-65535 -v
```
- `-iL allipaddress.txt` — load targets from a file
- `--ports 0-65535` — scan the full port range
- `-v` — verbose output

#### Example Output
```
Discovered open port 443/tcp on 66.207.176.5
Discovered open port 80/tcp on 66.207.176.10
```

> ⚠️ **Warning:** High-rate scanning is aggressive and easy to mistake for a denial-of-service attempt. Many bug bounty programs explicitly cap allowed scan rates — exceeding them can get you banned from the program regardless of intent. **Start conservative (`--rate=1000` or lower)** and always check the program's published rules first.

---

### 🛠️ Tool: Rustscan

**What it is:** A modern, Rust-based port scanner optimized for speed, which can automatically hand off discovered open ports to Nmap for detailed follow-up.

**Why use it:** It collapses the "fast discovery, then deep scan" workflow into a single command instead of two separate steps.

#### Installation
```bash
cargo install rustscan
# or via Docker
docker pull rustscan/rustscan:2.1.1
```

#### Commands & Explanation

```bash
rustscan -a allipaddress.txt -u 10000
```
- `-a allipaddress.txt` — target file (or a single IP/hostname)
- `-u 10000` — sets the ulimit (max open file descriptors), tuning scan speed

```bash
rustscan -a 192.168.1.1 --range 1-65535 -- -sV -sC
```
- `--range 1-65535` — port range to scan
- `-- -sV -sC` — everything after `--` is passed straight to Nmap for service detection and default-script scanning on the ports Rustscan finds open

#### Example Output
```
Open ports discovered → Nmap launches automatically:
PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache 2.4.49
443/tcp open  ssl/http    nginx 1.18
```

### 🖥️ Angry IP Scanner (GUI Option)

A free, cross-platform GUI tool (`angryip.org`) for visually scanning IP ranges. You can import an IP list, configure which ports to check, and get a sortable table of live hosts and open ports — useful for a quick visual sanity check without touching the command line.

---

## 🗡️ Chapter 5 — Nmap Complete Guide

Nmap ("Network Mapper"), first released in 1997, remains the most widely used open-source network scanner. It can discover hosts, enumerate services and versions, fingerprint operating systems, and run an extensible scripting engine (NSE) for deeper checks.

### 🔹 Basic Scanning

```bash
nmap target.com                          # default: top 1000 ports
nmap -p 80,443 target.com                # specific ports only
nmap -p- target.com                      # all 65,535 ports
nmap -p- --min-rate 5000 target.com      # all ports, faster
nmap -sV -sC -Pn target.com -oN output.txt   # common full-featured scan
```

### 🔹 Important Flags Reference

| Flag | Purpose | When to Use |
|---|---|---|
| `-sV` | Version detection | Almost always — identifies the exact software/version on each port |
| `-O` | OS detection | When you need to fingerprint the target operating system |
| `-A` | Aggressive (combines OS + version + scripts + traceroute) | Full-detail single-command scan |
| `-Pn` | Skip host-up ping check | When ICMP is blocked but you know the host is up |
| `-T4` | Faster timing template | Default choice for most non-stealth scans |
| `-T1` | Slower, "sneaky" timing | When minimizing detection footprint matters |
| `--open` | Show only open ports | Cuts noise from closed/filtered results |
| `-sC` | Run default (safe) NSE scripts | Good general-purpose enumeration pass |
| `--min-rate` | Minimum packets/sec | Speeds up large scans |
| `-oN file` | Normal text output | Human-readable saved results |
| `-oX file` | XML output | Machine-parseable, good for feeding other tools |
| `-oA all` | All formats at once | Saves `.nmap`, `.xml`, and `.gnmap` together |

### 🔹 Scan Types

```bash
sudo nmap -sS target.com     # SYN "half-open" scan (root required) — does not complete the handshake
nmap -sT target.com          # TCP Connect scan — completes the full handshake, no root needed
sudo nmap -sU target.com     # UDP scan — finds DNS, SNMP, and other UDP services
sudo nmap -sN target.com     # NULL scan — packet with no flags set
sudo nmap -sF target.com     # FIN scan — sets only the FIN flag
sudo nmap -sX target.com     # XMAS scan — sets FIN, PSH, and URG flags
```

**What these mean, conceptually:**
- **SYN scan** sends the first packet of a TCP handshake and reads the response without completing the connection — faster and, because the connection never fully opens, it's less likely to be logged by the *target application itself* (though it's still visible to firewalls/IDS at the network level).
- **NULL/FIN/XMAS scans** rely on how a host's TCP/IP stack is supposed to respond to malformed flag combinations per RFC 793. Some older or simplistic packet-filtering firewalls only inspect SYN packets, so these unusual flag combinations can occasionally slip through where a SYN scan would be blocked. Modern, properly configured firewalls generally catch these too.

> 📝 **Note:** None of these scan types make you "invisible." They change *what gets logged where* and *what a simple stateless filter catches*, not whether a competent monitoring setup will notice scanning activity.

### 🔹 NSE — Nmap Scripting Engine

NSE scripts are Lua programs that extend Nmap with service enumeration, vulnerability checks, and authentication testing. They live in `/usr/share/nmap/scripts/`.

```bash
nmap -sC target.com                  # run default safe scripts
nmap --script vuln target.com        # run vulnerability-check scripts
nmap --script auth target.com        # check for default/weak credentials
nmap --script discovery target.com   # broader service discovery scripts
nmap --script safe target.com        # restrict to scripts marked non-intrusive
```

> ⚠️ **Common Mistake:** Categories like `brute` (credential brute-forcing) and `exploit` (active exploitation attempts) can crash services or trigger account lockouts on production systems. **Never run these without explicit written permission**, and prefer `--script safe` when you just need enumeration, not exploitation.

### 🔹 Service-Specific NSE Scripts (Examples)

```bash
# HTTP
nmap --script http-title example.com        # page titles
nmap --script http-headers example.com      # response headers
nmap --script http-methods example.com      # allowed HTTP methods
nmap --script "http-vuln*" example.com      # all HTTP vulnerability checks

# FTP
nmap -p 21 --script ftp-anon example.com    # checks if anonymous login is allowed

# Database services
nmap -p 3306 --script mysql-empty-password example.com   # checks for blank MySQL root password
nmap -p 6379 --script redis-info target.com               # grabs Redis info if no auth required

# SMB / Windows
nmap --script smb-vuln-ms17-010 example.com  # checks for the MS17-010 (EternalBlue) vulnerability
nmap --script smb-enum-shares example.com    # enumerates accessible SMB shares

# SSL/TLS
nmap --script ssl-heartbleed example.com     # checks for the Heartbleed vulnerability (CVE-2014-0160)
nmap --script ssl-enum-ciphers example.com   # lists supported cipher suites, flags weak ones
```

Each of these is a **detection** script — it checks for a condition and reports it. None of them exploit anything; they're the equivalent of testing whether a door is unlocked, not opening it and walking through.

---

## 🛡️ Chapter 6 — Understanding Firewall/IDS Interaction

WAFs (Web Application Firewalls) and IDS/IPS systems are designed to flag or block scanning activity. Understanding *how* they detect scans is valuable defensive knowledge — it's the same logic that lets a defender tune their own detection rules, and it's also commonly discussed in authorized red-team engagements where the client wants their detection capability tested.

A few mechanisms worth understanding conceptually:

| Mechanism | What It Does | Defensive Takeaway |
|---|---|---|
| **Packet fragmentation** (`nmap -f`) | Splits probe packets into smaller pieces | A poorly configured IDS that doesn't reassemble fragments before inspection can miss signatures — proper IDS configurations reassemble before analysis |
| **Decoy scanning** (`nmap -D`) | Spoofs additional source IPs alongside the real one | Generates noisy logs with many apparent sources — defenders should correlate scan timing/pattern, not just single-source IP blocking |
| **Source port manipulation** (`--source-port 53`) | Sends probes from a port commonly trusted by firewalls (e.g., DNS) | Highlights why firewall rules should filter on more than just source port |
| **Timing/rate control** (`-T1`, `--scan-delay`) | Spreads probes out over a long period | Rate-based IDS thresholds alone are insufficient; defenders should also watch for sequential/low-and-slow probing patterns over time |
| **Host order randomization** (`--randomize-hosts`) | Scans targets in non-sequential order | Defeats simple "sequential IP" pattern-matching; defenders should look at aggregate traffic from a source rather than per-target sequence |

> 📝 **Why this matters in a legitimate engagement:** If you're conducting an authorized red-team assessment where the client specifically wants their detection/response capability evaluated, these techniques have a real purpose — testing whether defenses actually catch evasive traffic. Outside that explicit scope, the priority should always be **clean, well-logged, rate-limited scanning** so you don't trigger unnecessary incident response for a routine, authorized assessment.

> ⚠️ Using evasion techniques against a target where you only have *port-scanning* authorization but not specific permission to test detection evasion can itself be a scope violation — confirm what's covered before using any of these.

---

## 🧰 Chapter 7 — Authorized Testing Workflows

These are common patterns for structuring a scan once you have **explicit authorization or an in-scope bug bounty target**. The goal of staging it this way (quick → full → deep) is efficiency: don't run an expensive deep scan against ports that turn out to be closed.

### Workflow 1: Quick Initial Assessment
```bash
nmap -T4 -Pn -sV --open \
  --min-rate 5000 \
  example.com \
  -oN quick_scan.txt
```
Fast pass across the top 1000 ports with version detection. Typically completes in 1–3 minutes and gives you an immediate sense of what's exposed.

### Workflow 2: Full Port Scan
```bash
sudo nmap -T4 -Pn -p- -sV -sC \
  --min-rate 5000 \
  --max-retries 1 \
  example.com \
  -oA full_scan
```
Scans all 65,535 ports with version detection and default scripts. This is thorough but slow — often run as a background/overnight job on a confirmed in-scope target.

### Workflow 3: Scanning Multiple Hosts from a List
```bash
nmap -iL live_hosts.txt \
  -Pn \
  --min-rate 5000 \
  --max-retries 1 \
  --max-scan-delay 20ms \
  -T4 \
  --top-ports 1000 \
  --open \
  -oX nmap_mass.xml
```
Run after host discovery (Chapter 9) to efficiently sweep many confirmed-live, in-scope targets at once. `-oX` produces XML output that's easy to parse or import into reporting tools.

### Workflow 4: Targeted High-Value Port Scan
```bash
PORTS="21,22,23,25,53,80,110,111,135,139,143"
PORTS="$PORTS,443,445,993,995,1723,3306,3389"
PORTS="$PORTS,5900,6379,8080,8443,8888,9200"
PORTS="$PORTS,27017,28017,50000"

nmap -Pn -p $PORTS \
  -sV --open -T4 \
  example.com \
  -oN interesting_ports.txt
```
A faster middle ground between the quick scan and the full scan — focuses only on ports that historically carry the most security-relevant findings (see Chapter 8).

### Workflow 5: A Staged Pipeline Script

The general *shape* of an automated pipeline looks like this — quick scan to orient, full scan to make sure nothing is missed, then a deeper scan only against the ports confirmed open:

```bash
#!/bin/bash
TARGET=$1
DIR="nmap_${TARGET}"
mkdir -p "$DIR"

echo "[*] Phase 1: Quick scan"
nmap -T4 -Pn --open --min-rate 5000 "$TARGET" -oN "$DIR/quick.txt"

echo "[*] Phase 2: Full port scan"
nmap -T4 -Pn -p- --open --min-rate 5000 --max-retries 1 "$TARGET" -oN "$DIR/full_ports.txt"

OPEN_PORTS=$(grep "^[0-9]" "$DIR/full_ports.txt" | awk '{print $1}' | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
echo "[+] Open ports: $OPEN_PORTS"

echo "[*] Phase 3: Deep scan on confirmed open ports only"
sudo nmap -T4 -Pn -p "$OPEN_PORTS" -sV -sC --script vuln "$TARGET" -oA "$DIR/deep_scan"

echo "[*] Done — results saved in: $DIR/"
# Usage: chmod +x scan_pipeline.sh && ./scan_pipeline.sh example.com
```

> 💡 **The logic of this "funnel" approach:** Phase 1 orients you quickly. Phase 2 makes sure nothing is missed across the full port range. Phase 3 spends the expensive script/version-detection time only on ports you've already confirmed are open — saving significant time on large scopes.

---

## 💎 Chapter 8 — High-Value Ports Reference

Some services are disproportionately likely to be misconfigured in ways that matter for security — usually because they were never designed to be exposed to the internet, or because their defaults assume a trusted network. Knowing this list helps you prioritize *what to look at first* and helps defenders know *what to lock down first*.

| Port | Service | Typical Risk | Why It Matters |
|---|---|---|---|
| 21 | FTP | High | Anonymous login often left enabled; cleartext credentials |
| 22 | SSH | Medium | Weak/reused credentials, outdated versions with known CVEs |
| 23 | Telnet | Critical | Transmits credentials in plaintext — should essentially never be internet-facing |
| 25 | SMTP | Medium | Open relay misconfigurations, email spoofing potential |
| 53 | DNS | Medium | Zone transfer misconfigurations can leak internal naming/structure |
| 80 / 443 | HTTP / HTTPS | Standard | Web application vulnerabilities, TLS misconfigurations |
| 3306 | MySQL | High | Sometimes exposed with blank/default root password |
| 5432 | PostgreSQL | High | Default credentials, missing authentication |
| 6379 | Redis | Critical | Historically ships with **no authentication by default** — full data access if exposed |
| 8080 / 8443 | HTTP/HTTPS Alt | Medium | Often hosts admin panels or dev/staging instances |
| 9200 | Elasticsearch | Critical | No-auth-by-default in many versions — full index access if exposed |
| 27017 | MongoDB | Critical | Historically no-auth-by-default — full database access if exposed |
| 5900 | VNC | Critical | No password = full remote desktop access |
| 2375 | Docker API | Critical | Unauthenticated API access can equal full host compromise |
| 11211 | Memcached | High | Data exposure; also abusable for DDoS amplification |
| 50000 | Jenkins | Critical | Misconfigured instances can allow remote code execution |

> 🚨 **Critical Note:** Services like Redis, Elasticsearch, MongoDB, VNC, the Docker API, and Jenkins, when found **exposed with no authentication**, represent serious findings in any authorized assessment or bug bounty program — they typically qualify as high/critical severity because the impact (full data access or code execution) is severe even though the *technique* to discover them (a port scan) is trivial.
>
> If you discover one of these in an authorized scope: **do not interact with the data, modify anything, or attempt further access.** The responsible process is to confirm the service is unauthenticated (e.g., a connection banner confirming no auth was requested), stop there, and report the finding through the program's official disclosure channel with reproduction steps. Going further than "confirm the door is unlocked" risks turning a legitimate finding into unauthorized access to data you weren't asked to view.

---

## 📶 Chapter 9 — Host Discovery Techniques (Layer 2/3/4)

### 🧠 Theory

Before investing time in a deep port scan, it's efficient to first confirm a host is actually *alive*. Different discovery techniques operate at different layers of the network stack, which matters because firewalls often block some methods while allowing others.

### ARP Discovery (Layer 2 — local network only)
```bash
nmap -PR -sn 172.21.230.1/24 --reason -vv
```
| Flag | Meaning |
|---|---|
| `-PR` | Use ARP requests for discovery |
| `-sn` | Discovery only — skip the port scan |
| `--reason` | Explain why each host is considered up/down |
| `-vv` | Very verbose |

> 💡 ARP only works on the same local subnet, but within that subnet, it's essentially un-blockable by firewalls since ARP operates below the IP layer.

### ICMP Echo Discovery (traditional ping)
```bash
nmap -PE -sn 172.21.230.1/24 --reason
```
- `-PE` sends ICMP Echo requests. Fast, but many modern firewalls drop ICMP entirely, so absence of a reply doesn't guarantee the host is down.

### TCP SYN Discovery
```bash
nmap -PS -sn 172.21.230.1/24 --reason
```
- `-PS` sends a SYN packet to port 80 (or specified ports). A live host replies with SYN-ACK (port open) or RST (port closed) either of which confirms it's up — more reliable than ICMP when ping is blocked.

### TCP ACK Discovery
```bash
nmap -PA 172.21.230.1/24 --reason -sn -vv
```
- `-PA` sends ACK packets. Stateful firewalls that block unsolicited SYNs sometimes still let unsolicited ACKs through (since they don't look like a real connection attempt), which can reveal hosts that SYN discovery misses.

### UDP Discovery
```bash
nmap -PU -sn 172.21.230.1/24
```
- `-PU` sends UDP packets to closed ports; if the host responds with "ICMP port unreachable," it's confirmed alive. Slower, but catches hosts that only run UDP services (and might not respond to any TCP-based probe).

### Bulk Discovery Commands
```bash
nmap -iL allipaddress.txt -sn -vv                         # standard ping sweep across a list
masscan -iL allipaddress.txt --rate=50000 --ports 0-65535 -v  # fast full-port sweep
nmap -iL allipaddress.txt -sn -vv -T5                     # faster timing template
nmap -iL alllivedomain.txt -sn -PR                        # ARP-based sweep from a domain list
nmap 209.133.79.94 -Pn -sV -T4                            # detailed single-IP scan
nmap 209.133.79.94 -Pn -sV -T4 -A -p 0-65535               # full aggressive single-IP scan
```

---

## 🛰️ Chapter 10 — Shodan Recon

### 🧠 Theory

Shodan is a search engine that continuously scans the internet and indexes service banners, open ports, and metadata from internet-connected devices. For recon purposes, it lets you find exposed services **passively** — without sending a single packet to the target yourself.

### Search Workflow

| Step | Query | Purpose |
|---|---|---|
| 1 | `hostname:target.com` | Find all indexed IPs tied to the target domain |
| 2 | `hostname:apple.com -http.title:"Invalid URL"` | Filter out broken/error pages from results |
| 3 | `hostname:target.com port:8080` | Find services on non-standard ports |
| 4 | `hostname:target.com org:"Apple Inc"` | Filter by registered organization name |
| 5 | `hostname:target.com has_screenshot:true` | Surface exposed web interfaces that Shodan has screenshotted |

### After Shodan — Verify Before Touching Anything

```bash
# Step 1: Confirm IP ownership — is it really the target, or a CDN/cloud provider?
whois 16.65.101.114

# Step 2: Version detection
nmap -sV 16.65.101.114 -T4 -A

# Step 3: Rate-limited aggressive scan
nmap -sV 16.65.101.114 -T4 -A --min-rate 1000 --max-retries 3 -Pn

# Step 4: HTTP vulnerability checks
nmap 16.65.101.114 -T4 --script "http-vuln*"
```

> 🚨 **Important:** Shodan results frequently include IPs owned by **CDNs or cloud providers** (Cloudflare, AWS, Fastly, etc.) rather than the target organization itself. **Always run `whois` to confirm direct ownership before scanning** — testing an IP that happens to resolve to a shared cloud range, when only `target.com` is in scope, can violate the bug bounty program's rules even if the hostname matched.

---

## 🖧 Chapter 11 — Sandmap

**What it is:** An interactive, menu-driven frontend for Nmap that lets you select scan types from organized modules instead of memorizing flag combinations.

### Usage Guide

```bash
sandmap              # Step 1: launch the tool
help                 # Step 2: view available commands
list                 # Step 3: list all available modules
use port_scan        # Step 4: load a module (e.g., port scanning)
set dest 16.65.101.114   # Step 5: set the target
show                 # Step 6: review current configuration
init 1               # Step 7: run scan type #1 from the loaded module
main                 # Step 8: return to the main menu
```

> 💡 **Workflow summary:** `launch → help → list → use [module] → set dest [ip] → show → init [number]`. The number passed to `init` corresponds to a scan type listed when you run `list` after loading a module — always check that list first.

---

## 💣 Chapter 12 — ScanCannon

**What it is:** A bash script that automates a Masscan → Nmap pipeline against a list of CIDR ranges: fast discovery first, then detailed service detection on whatever Masscan finds open.

### Setup & Usage

```bash
# Step 1: Clone the repository
git clone https://github.com/johnnyxmas/scancannon
cd scancannon

# Step 2: Make it executable
chmod +x scancannon.sh

# Step 3: Add your authorized CIDR ranges to cidr.txt
nano cidr.txt
# Example contents (use only ranges you're authorized to test):
# 192.168.1.0/24
# 10.0.0.0/8
# 172.16.0.0/12

# Step 4: Run it
./scancannon.sh cidr.txt
```

> 📝 **Notes:**
> - Must be run from inside the `scancannon` directory — it looks for `cidr.txt` relative to itself.
> - Some scan types require root/sudo.
> - Results are saved within the script's directory for later review.

---

## 📋 Cheat Sheet

### ASN / CIDR / IP / DNS Tools

| Task | Command |
|---|---|
| Find ASN CIDR ranges | `asnmap -a AS996 > cidr.txt` |
| Multiple ASNs at once | `asnmap -a AS996,AS714 > multi_cidr.txt` |
| Expand CIDR file to IPs | `mapcidr -cidr cidr.txt > ips.txt` |
| Expand single CIDR | `mapcidr -cidr 82.24.0.0/22 > ips.txt` |
| Pipe CIDR expansion | `echo 82.24.0.0/22 \| mapcidr -silent` |
| IP → hostname (PTR) | `cat ips.txt \| dnsx -ptr -resp-only` |
| CIDR → hostnames | `mapcidr -cidr cidr.txt \| dnsx -ptr -resp-only` |

### Port Scanners

| Task | Command |
|---|---|
| Naabu — scan IP list | `naabu -l ips.txt` |
| Naabu — rate-limited | `naabu -l ips.txt -rate 3000 -retries 1 -c 50` |
| Masscan — all ports on CIDR | `masscan -p0-65535 192.168.1.0/24 --rate=50000` |
| Masscan — from file | `masscan -iL ips.txt --rate=50000 --ports 0-65535` |
| Rustscan — from file | `rustscan -a ips.txt -u 10000` |
| Rustscan — pipe to Nmap | `rustscan -a target.com --range 1-65535 -- -sV -sC` |

### Nmap — Basics

| Task | Command |
|---|---|
| Default top 1000 ports | `nmap target.com` |
| Specific ports | `nmap -p 80,443 target.com` |
| All 65,535 ports | `nmap -p- target.com` |
| Fast all ports | `nmap -p- --min-rate 5000 target.com` |
| Version + default scripts | `nmap -sV -sC -Pn target.com -oN out.txt` |
| Aggressive (all info) | `nmap -A target.com` |

### Nmap — Scan Types

| Task | Command |
|---|---|
| SYN stealth | `sudo nmap -sS target.com` |
| TCP connect | `nmap -sT target.com` |
| UDP scan | `sudo nmap -sU target.com` |
| NULL scan | `sudo nmap -sN target.com` |
| FIN scan | `sudo nmap -sF target.com` |
| XMAS scan | `sudo nmap -sX target.com` |

### Nmap — NSE Scripts

| Task | Command |
|---|---|
| Vulnerability check | `nmap --script vuln target.com` |
| All HTTP vuln checks | `nmap --script "http-vuln*" target.com` |
| Anonymous FTP check | `nmap -p 21 --script ftp-anon target.com` |
| Redis no-auth check | `nmap -p 6379 --script redis-info target.com` |
| MySQL empty password check | `nmap -p 3306 --script mysql-empty-password target.com` |
| EternalBlue (SMB) check | `nmap --script smb-vuln-ms17-010 target.com` |
| Heartbleed (SSL) check | `nmap --script ssl-heartbleed target.com` |

### Host Discovery

| Task | Command |
|---|---|
| ARP scan | `nmap -PR -sn 172.21.230.1/24 --reason -vv` |
| ICMP ping discovery | `nmap -PE -sn 172.21.230.1/24 --reason` |
| TCP SYN discovery | `nmap -PS -sn 172.21.230.1/24 --reason` |
| TCP ACK discovery | `nmap -PA 172.21.230.1/24 --reason -sn -vv` |
| UDP discovery | `nmap -PU -sn 172.21.230.1/24` |
| Ping sweep from file | `nmap -iL ips.txt -sn -vv` |

---

## 🔄 Complete Workflow Diagram

```
ASN Numbers        → [ASNMAP]              → CIDR Ranges
CIDR Ranges        → [MapCIDR]             → IP Addresses
IP Addresses        → [DNSX -ptr]           → Hostnames
IP Addresses        → [Naabu/Masscan/Rustscan] → Open Ports
Open Ports          → [Nmap -sV]            → Services & Versions
Services            → [Nmap NSE Scripts]    → Findings
Findings            → Responsible Disclosure → Verified Report
```

---

## ✅ Best Practices

- **Confirm scope before every scan.** Cross-check every IP/CIDR/hostname you intend to touch against the program's or client's documented scope — not just the organization's apparent ownership.
- **Start slow, then scale up.** Begin with conservative rate limits (`--rate=1000` or lower) and increase only if the program's rules permit it.
- **Stage your scans.** Quick scan → full port scan → deep scan on confirmed-open ports only. This saves enormous time on large scopes.
- **Use `--script safe` by default.** Reserve `brute` and `exploit` script categories for engagements where you have explicit permission to perform active exploitation.
- **Verify before deep-diving.** Always run `whois` on IPs discovered via passive sources (like Shodan) to confirm they belong to the target and not a CDN/cloud provider.
- **Stop at confirmation, not exploitation.** For critical no-auth findings (Redis, MongoDB, Elasticsearch, Jenkins, Docker API, VNC), confirm the exposure exists and report it — do not browse, modify, or extract data.
- **Keep organized records.** Save output from every phase (`-oN`, `-oX`, `-oA`) so your eventual report has full reproduction steps.
- **Respect rate limits and time-of-day restrictions** some programs specify, to avoid disrupting production systems.

---

## 📝 Notes

- Tools change quickly — always check a project's GitHub repo for the latest install instructions and flag syntax, as CLI options can change between versions.
- Most of the ProjectDiscovery tools (ASNMAP, MapCIDR, DNSX, Naabu) are designed to be piped together; learning their individual flags pays off across the whole toolchain.
- Nmap's NSE script library is enormous — running `nmap --script-help <name>` on any script shows its documentation and what it checks for before you run it.
- A scanner finding an open port or an exposed service is the *start* of an investigation, not a finding in itself — context (is it in scope, is it actually unauthenticated, what's the real impact) is what turns a scan result into a legitimate report.

---

## 📚 References

- [Nmap Official Documentation](https://nmap.org/book/man.html)
- [ProjectDiscovery Tools (GitHub)](https://github.com/projectdiscovery)
- [Shodan Search Filters](https://www.shodan.io/search/filters)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- StationX Nmap Cheat Sheet (community reference)

---

## ⚖️ Disclaimer

This document is provided **for educational purposes and authorized security testing only**.

- Always obtain **explicit written permission** before scanning, probing, or testing any system, network, or application you do not personally own.
- For bug bounty work, strictly follow the **published scope and rules of engagement** of the specific program — scanning outside scope can result in program bans and, in some cases, legal liability.
- Unauthorized scanning of computer systems is illegal in most jurisdictions, including under the U.S. Computer Fraud and Abuse Act (CFAA) and equivalent laws elsewhere.
- The author and any contributors to this document accept no liability for misuse of the information contained here.

> **When in doubt, don't scan it.** Ask the program operator, the asset owner, or a lawyer before proceeding.


👨‍💻 Author
Nitish Mukhiya
Cybersecurity Learner | Ethical Hacking Enthusiast | Security Research Aspirant

📧 Email: nitishbhaisocial@gmail.com

💻 GitHub: https://github.com/nitishmukhiyaji

🔗 LinkedIn: https://www.linkedin.com/in/nitishmukhiya/

🐦 X (Twitter): https://x.com/NITISHMUKHIYAJ

✍️ Medium: https://medium.com/@nitishmukhiya

🌐 Portfolio: https://portfolio-livid-iota-e4saycgr44.vercel.app/
