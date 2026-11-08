source: TryHackMe Protocols and Servers 2, structure only; content from RFCs, man pages, vendor docs
/ status: reference
---

# Securing Cleartext Protocols: Sniffing, MITM, Password Attacks, and Fixes

**TL;DR**
- The cleartext protocols from part 1 fail in three concrete ways: anyone on-path can read them (sniffing), anyone who can get on-path can force themselves there (MITM), and weak auth makes credentials guessable (password attack).
- Each failure has a direct, provable fix: encrypt (TLS/SSH), authenticate the network layer (static ARP, port security, 802.1X), and harden auth (lockouts, MFA, key-based login).
- Lab value: this is the one room where "read the RFC" isn't enough — you have to capture a cleartext login yourself, once, to actually believe port 23 and 80 are a problem.

---

## Part 1 — Sniffing: why cleartext fails on a shared network

### Concept
Ethernet/Wi-Fi is a broadcast-ish medium; a switch forwards based on MAC tables but anything that lands on your NIC in promiscuous mode is readable if it isn't encrypted. No exploit required — this is the protocol's design, not a vulnerability in the implementation.

### Commands & Syntax

```bash
ip link set <interface> promisc on         # put NIC into promiscuous mode (needs root); most sniffers do this for you
tcpdump -i <interface> -nn                 # -i interface, -nn = no DNS/port name resolution (faster, raw numbers)
tcpdump -i <interface> -nn -A              # -A = print packet payload as ASCII (readable cleartext creds)
tcpdump -i <interface> -nn -w <file.pcap>  # -w = write raw capture to disk instead of printing
tcpdump -r <file.pcap> -nn -A              # -r = read back a saved capture
tcpdump -i <interface> port 23 or port 21  # filter: only Telnet or FTP control-channel traffic
```

```bash
tshark -i <interface> -Y 'ftp.request.command=="PASS"'   # tshark = CLI Wireshark; -Y applies a display filter live
tshark -r <file.pcap> -z follow,tcp,ascii,<stream-id>     # reassemble one TCP stream as readable text (stream id from -z conv,tcp or the GUI)
```

| Tool | Best for |
|---|---|
| `tcpdump` | fast, scriptable, always-available CLI capture |
| Wireshark GUI → **Follow → TCP Stream** | reading a whole conversation as one block of text, no filter-writing needed |
| `tshark` | scripting Wireshark's filters/decoders without the GUI |

### Workflow: confirm a protocol is leaking credentials
1. Capture while a known-good login happens: `tcpdump -i <if> -nn -w creds.pcap port <service-port>`.
2. Open in Wireshark, right-click a packet in that stream → **Follow → TCP Stream**.
3. Read the plaintext; note which field carries the password (see part 1 note's filter table per protocol).
4. This is your own evidence for the finding — don't rely on "it's cleartext by spec" alone in a report.

### Defender view
- You cannot "patch" sniffing on a shared segment — you remove the payoff by encrypting (see Part 4).
- Network segmentation and switch port security reduce *who* can be on-path, which is a mitigating control, not a fix.

---

## Part 2 — Man-in-the-Middle: getting on-path

### Concept
Sniffing only works if you can see the traffic. On a switched network you usually can't, by default — so an attacker forces a redirect. The classic method is **ARP spoofing**: lie to the target about which MAC address owns the gateway's IP, so the target sends its traffic to the attacker first.

### Commands & Syntax

```bash
cat /proc/sys/net/ipv4/ip_forward          # must be 1 so your box forwards traffic instead of black-holing it
echo 1 > /proc/sys/net/ipv4/ip_forward      # enable IP forwarding (own lab host only)
```

```bash
ettercap -T -q -i <interface> -M arp:remote /<target-ip>// /<gateway-ip>//
# -T  text UI (no GUI)
# -q  quiet, less packet-dump noise
# -i  interface to listen/inject on
# -M arp:remote   MITM method = ARP poisoning, "remote" also captures traffic destined off-subnet (via gateway)
# /<target-ip>// and /<gateway-ip>//   the two hosts to poison between (empty slot = any MAC)
```

```bash
arp -a                                      # on the victim: inspect ARP cache; a poisoned entry shows the attacker's MAC for the gateway IP
arpwatch -i <interface>                      # ⚠️ defender tool: logs new/changed MAC-to-IP pairings for later review
```

| ettercap flag | Meaning |
|---|---|
| `-T` | text-only interface |
| `-M <method>` | MITM method, `arp:remote` is the common one |
| `-i <iface>` | capture/injection interface |
| `-w <file>` ⚠️ | write captured packets to file |
| `-P <plugin>` ⚠️ | load a plugin, e.g. for DNS spoofing |

### How it works, in one line
ARP has no authentication: whoever answers an ARP request last (or loudest) wins the cache entry. Poisoning both the victim and the gateway lets the attacker sit in the middle of a full-duplex conversation and feed it into the sniffer from Part 1.

### Defender view
- **Static ARP entries** on critical hosts/gateways (`arp -s <ip> <mac>`) stop spoofing but don't scale.
- **Dynamic ARP Inspection (DAI)** on managed switches validates ARP against DHCP snooping bindings. ⚠️ vendor-specific config, verify on your hardware.
- **802.1X port authentication** stops a rogue device from joining the segment at all.
- Detect: ARP storm/flood alerts, duplicate MAC-to-IP mappings, `arpwatch`/`arpalert` logs.
- None of this helps if the protocol itself is cleartext — MITM just gets you *onto* the wire; encryption denies you anything useful once you're there.

---

## Part 3 — Password attacks: when the auth itself is weak

### Concept
Cleartext transport is one failure mode; weak credentials are a separate, compounding one. Even over TLS, a guessable password is still a guessable password. This section is about testing *your own* lab service's resistance to brute force, not about running this against anything you don't own.

### Commands & Syntax

```bash
hydra -l <username> -P <wordlist> <target-ip> <service>
# -l   single username (lowercase L); -L <file> for a username list instead
# -P   password wordlist file; -p <single-password> for one guess
# <service>   ftp, ssh, pop3, imap, smtp, http-get, etc.
```

```bash
hydra -L <user-list> -P <wordlist> -t <threads> -f <target-ip> ssh
# -t <n>   parallel connection threads (default 16); lower it against fragile/rate-limited lab services
# -f       stop on first valid pair found (saves time once you have one hit)
```

```bash
hydra -l <username> -P <wordlist> -s <port> -V <target-ip> ftp
# -s <port>   non-default port
# -V          verbose: show every login attempt (useful while tuning, noisy at scale)
```

| Flag | What it does | Use when |
|---|---|---|
| `-l` / `-L` | single user / user list | known vs unknown username |
| `-p` / `-P` | single password / wordlist | targeted guess vs spray |
| `-t <n>` | thread count | tune for service stability |
| `-f` | stop at first success | you only need one proof-of-concept hit |
| `-s <port>` | override default port | non-standard listener |
| `-V` / `-vV` | verbose output | debugging why nothing matches |
| `-o <file>` ⚠️ | write results to file | scripted runs |

### Workflow: test your own lab service
1. Confirm the service and port (`nmap -sV -p <port> <lab-ip>`).
2. Build a small, deliberately-weak wordlist for a throwaway lab account you created for this purpose — never a shared/real credential.
3. Run Hydra with a conservative `-t`, watch for lockouts or rate-limiting kicking in (that's a finding too).
4. Record: time to first hit, whether the service rate-limited you, whether failed attempts were logged anywhere you can see.

### Defender view
- Account lockout / rate limiting after N failed attempts (fail2ban, native service lockout).
- MFA removes password-only brute force as a viable path even if it isn't blocked outright.
- Centralized auth logging + alerting on burst failed-login patterns (this is literally what Hydra traffic looks like in a SIEM: many auth attempts, one source IP, short window).

---

## Part 4 — The actual fix: SSH and TLS

### Concept
Parts 1–3 are the *problem* (visible, interceptable, guessable). This part is the *answer*: don't send credentials or data anywhere they could be sniffed, poisoned, or brute-forced without consequence.

### SSH — replaces Telnet/FTP for interactive & file access

```bash
ssh-keygen -t ed25519 -C "<comment>"        # generate a modern keypair; -C is just a label, not a password
ssh-copy-id -i ~/.ssh/<key>.pub <user>@<host>   # push your public key to the target's authorized_keys
ssh -i ~/.ssh/<key> <user>@<host>           # connect using that key instead of a password
```

```ini
# /etc/ssh/sshd_config  (server side; restart sshd after editing)
PasswordAuthentication no      # force key-based auth only
PermitRootLogin no             # no direct root login over SSH
```
```bash
sudo systemctl restart sshd                 # apply sshd_config changes
```

### TLS — replaces plaintext HTTP/FTP/SMTP/POP3/IMAP

```bash
openssl s_client -connect <host>:<tls-port>              # manually inspect a TLS handshake/cert (443, 465, 993, 995...)
openssl s_client -starttls <smtp|pop3|imap|ftp> -connect <host>:<port>   # verify STARTTLS upgrade works, not just advertised
```

| Protocol | Cleartext port | TLS replacement |
|---|---|---|
| Telnet | 23 | SSH 22 |
| HTTP | 80 | HTTPS 443 |
| FTP | 21 | FTPS (`AUTH TLS`, port 21) or SFTP (SSH, port 22) |
| SMTP | 25 | STARTTLS (587) or implicit TLS (465) |
| POP3 | 110 | POP3S 995 |
| IMAP | 143 | IMAPS 993 |

### Verifying the fix actually closes the gap
```bash
tcpdump -i <interface> -nn -A port <tls-port>   # repeat the Part 1 capture against the TLS port
# expected: unreadable binary/TLS record bytes, no plaintext credentials — this is your before/after evidence
```

---

## Pitfalls & Gotchas
- **ARP poisoning without `ip_forward=1`** silently breaks the victim's connectivity instead of relaying it — looks like a win, is actually a DoS.
- **Hydra against a rate-limited service** burns through lockout thresholds fast; a high `-t` can lock the account you're testing before you get a result.
- **STARTTLS without enforcement** can be stripped by an active MITM — confirm the server *requires* TLS, don't just confirm it *offers* it.
- **Sniffing "proves" a problem only for the capture window** — a one-time test isn't continuous monitoring; don't present it as such in a writeup.

## ATT&CK / CWE
- T1040 Network Sniffing, T1557 Adversary-in-the-Middle (ARP spoofing sub-technique ⚠️), T1110 Brute Force, T1621 Multi-Factor Authentication Request Generation ⚠️.
- CWE-319 Cleartext Transmission of Sensitive Information, CWE-307 Improper Restriction of Excessive Authentication Attempts, CWE-294 Authentication Bypass by Capture-replay ⚠️.
- ATT&CK version current at v19 per attack.mitre.org as of last check; re-confirm technique names before publishing.

## Cross-references
[[protocols-00-overview]] · [[protocols-telnet]] · [[protocols-http]] · [[protocols-ftp]] · [[protocols-smtp]] · [[protocols-pop3]] · [[protocols-imap]] · [[wireshark-display-filters]] · [[ssh-hardening]] · [[password-policy-and-mfa]]

## Sources
- tcpdump man page / cheatsheet https://www.ctr.unican.es/asignaturas/dec/Doc/tcpdump_cheatsheet.pdf (retrieved 2026-11-08)
- Hydra man page https://manpages.debian.org/hydra/hydra.1 (retrieved 2026-11-08)
- Ettercap man page https://man.archlinux.org/man/extra/ettercap-gtk/ettercap.8.en (retrieved 2026-11-08)
- OpenSSH key-based auth / sshd_config hardening — cross-checked across vendor/community guides; exact directive names ⚠️, verify against `man sshd_config` on your own system before publishing
- RFC 8314 (TLS for email submission/access) https://www.rfc-editor.org/rfc/rfc8314.html (retrieved 2026-10-25)
- RFC 4217 (FTP over TLS) https://datatracker.ietf.org/doc/html/rfc4217 (retrieved 2026-10-25)
- CWE-319, CWE-307, CWE-294 — https://cwe.mitre.org/
