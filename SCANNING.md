# Populating the AIMS DB — legal, meaty scan targets

> Operator playbook, not project docs. How to get 10–20 real internet hosts with rich,
> varied surface into the AIMS store — legally — and the nmap invocations that fill the most
> schema fields (OS / NSE / service / traceroute / TCP-sequence).
>
> **Rule zero:** only scan hosts you own or are explicitly authorized to scan. Everything below
> assumes that. The one path that is unambiguously legal *and* gives varied real-internet data
> is standing up your own fleet (§1).

## Conventions used in the snippets

```bash
# A target list, one host per line — comments and blank lines are fine in an -iL file.
targets='targets.txt'

# A single host, quoted so it survives spaces/globbing (belt and suspenders).
target='scanme.nmap.org'

# Timestamp helper for uniquely-named output files (safe in filenames, no colons).
stamp="$(date +%Y%m%dT%H%M%S)"
```

Always quote expansions (`"$target"`, `"$targets"`, `"$stamp"`) and prefer `-oX` to a
quoted, timestamped path so re-runs don't clobber each other.

---

## 1. Your own fleet (best signal, unambiguously legal)

Rent 10–20 cheap VPSs across providers/regions (Hetzner, DigitalOcean, Vultr, Linode, OVH,
Scaleway — €3–5/mo). Different ASNs and geos give different traceroute chains and default OS
fingerprints; a deliberately-mixed service loadout gives `-A -p-` something to find.

Put the fleet in a target file:

```bash
cat > "$targets" <<'EOF'
# fleet — one host per line
198.51.100.11    # hetzner-fsn  debian, nginx+TLS, openssh, postgres
198.51.100.12    # do-nyc       alpine, apache, redis, docker-registry
198.51.100.13    # vultr-ams    freebsd, sshd, smtp
203.0.113.20     # ovh-gra      ubuntu, mysql, old-service-image (vuln bait)
# ...fill out to 10-20...
EOF
```

Because you own these, you can run the aggressive NSE categories you'd never point elsewhere:

```bash
# Full aggressive sweep across the whole fleet, one Run, one host per box.
nmap -A -p- --osscan-guess --version-all --reason \
  -iL "$targets" \
  -oX "fleet-full-${stamp}.xml"

aims scan import -f "fleet-full-${stamp}.xml"
```

```bash
# Vuln/intrusive NSE — ONLY because you own these boxes.
nmap -sV -p- --script 'vuln,intrusive' --script-timeout '90s' \
  -iL "$targets" \
  -oX "fleet-vuln-${stamp}.xml"
```

Vary the OS per box (Debian / Alpine / FreeBSD / Windows Server trial) so you get a real
spread of `OSMatch` / `OSFingerprint` / `Uptime` / `TCPSequence` rows instead of 20 identical
Ubuntu prints.

---

## 2. Explicitly scan-permitted public hosts (free, limited)

A handful of hosts, shared and noisy, but sanctioned:

```bash
# nmap's own blessed test host — be gentle, it's one shared box.
nmap -A -p- --reason "$target" -oX "scanme-${stamp}.xml"
aims scan import -f "scanme-${stamp}.xml"
```

- `scanme.nmap.org` — nmap's sanctioned target.
- `scanme.sh` — similar community sandbox.
- Hosted labs you're licensed into (HackTheBox / TryHackMe machines while subscribed,
  PortSwigger targets) — these are *built* to be scanned; still check each ToS.

---

## 3. Your own home/lab network (zero ambiguity)

Not "out in the internet," but often the most varied surface you own — router, NAS, IoT junk,
printers, a Windows box:

```bash
lan='192.168.1.0/24'
nmap -A -p- --osscan-guess -oX "lan-${stamp}.xml" "$lan"
aims scan import -f "lan-${stamp}.xml"
```

Weird OS fingerprints and odd services (UPnP, mDNS, embedded HTTP) that clean VPSs won't have.

---

## Long-running scans that fill the most schema fields

The AIMS host model mirrors nmap's output, so the scans worth running are the ones that
populate fields a plain `-sT` leaves null.

```bash
# 1. Everything-scan: Host + OS + Port + Service + Trace + Script in one shot.
#    -A = OS detect + -sV + default NSE + --traceroute. -p- (all 65535 ports) = the long part.
#    --reason fills reason/reason_ttl; --version-all maxes Service.Product/Version/ExtraInfo.
nmap -A -p- -T4 --osscan-guess --version-all --reason \
  -iL "$targets" -oX "full-${stamp}.xml"
```

```bash
# 2. UDP — slow and genuinely different service set (SNMP, NTP, DNS, IKE, mDNS).
#    Great for `scan diff` since it surfaces ports TCP never sees.
nmap -sU -sV --top-ports '200' -T4 --reason \
  -iL "$targets" -oX "udp-${stamp}.xml"
```

```bash
# 3. Deep NSE by category — feeds the recursive Script/Table/Element tree.
nmap -sV -p- \
  --script 'default,discovery,safe,version' \
  --script-timeout '60s' \
  -iL "$targets" -oX "nse-${stamp}.xml"
```

Rich individual NSE producers worth naming (quote the comma-list as one arg):

```bash
nmap -sV -p '22,443,445' \
  --script 'ssl-enum-ciphers,ssh-hostkey,ssh2-enum-algos,http-enum,http-title,http-headers,smb-os-discovery' \
  -iL "$targets" -oX "nse-targeted-${stamp}.xml"
```

```bash
# 4. Fingerprint extras: TCPSequence / IPIDSequence / Uptime / OSMatch / full Hop/Trace.
#    These columns exist in host/pb but stay null without -O + --traceroute.
nmap -O --osscan-guess -sV --traceroute -p- \
  -iL "$targets" -oX "fingerprint-${stamp}.xml"
```

### Rotation for variety

| Goal              | Command                                            | Rough time |
|-------------------|----------------------------------------------------|------------|
| Broadest coverage | `-A -p- --osscan-guess --version-all`              | hours      |
| Different ports   | `-sU -sV --top-ports 200`                          | hours      |
| NSE depth         | `-sV -p- --script 'default,discovery,safe'`        | long       |
| Fingerprint fields| `-O -sV --traceroute -p-`                          | medium     |

---

## The drift loop (the payoff)

Re-run the **same definition** later and diff — new hosts, newly-open ports, changed service
versions all land in the right bucket:

```bash
a="full-${stamp}.xml"                 # today
# ...rebuild a box with a newer image, wait a day...
b="full-$(date +%Y%m%dT%H%M%S).xml"   # tomorrow

nmap -A -p- --osscan-guess -iL "$targets" -oX "$b"
aims scan import -f "$b"

# resolve the two run IDs (aims scan list), then:
aims scan diff "$run_a" "$run_b"
```

Rebuild a fleet box with a newer service image between runs and watch the version deltas
appear — that's the timestamped-Run + host-dedup model doing its job.
---

## Nuclei — findings that fold into the same store (mid-to-slow examples)

`aims scan run nuclei [nuclei args…]` runs nuclei **server-side** and folds its findings
into the DB just like the nmap paths above — everything after `nuclei` is passed straight
through, so any nuclei invocation works. Findings land as `Script`/`Table`/`Element` rows on
the matched host/service, so `scan diff` and the drift loop cover them too. Template/tag/
severity arguments complete live (`aims scan run nuclei -t <Tab>` browses the template tree).

Point these at your own devices only. Tune `-rl` (rate limit) and `-c` (concurrency) down if
IoT/router gear starts choking under load.

```bash
# 1. Default-credential checks — routers, NAS boxes, printers, cameras. Slow: many auth
#    attempts per host across the subnet. Point it at your IoT/router gear specifically.
aims scan run nuclei -t default-logins/ -target 192.168.1.0/24
```

```bash
# 2. Exposed-panels sweep — hundreds of path/panel signatures per host (admin UIs, login
#    pages for NAS/printers/routers). Moderate-slow, scales with how many devices respond.
aims scan run nuclei -tags exposed-panels -target 192.168.1.0/24
```

```bash
# 3. Vendor workflows (chained templates) — a detection template fires first, then a whole
#    battery of follow-ups only if the vendor matches. Naturally slower per host.
aims scan run nuclei -w workflows/synology-workflow.yaml -u <nas-ip>
```

```bash
# 4. Time-based / blind detection — DSL response-time matchers (`duration>=5`) deliberately
#    sleep; each match costs several real seconds. Slow by design, not by request volume.
aims scan run nuclei -tags blind,time-based -u <ip>
```

```bash
# 5. Brute-force network templates — SSH/FTP/Redis/MySQL weak-password checks, slow in
#    proportion to wordlist size. Tune the wordlist down for home use.
aims scan run nuclei -t network/ -u <ip> -var USER=admin -var PASS=passwords.txt
```

```bash
# 6. Kitchen-sink CVE pass — thousands of templates; a low rate-limit makes it deliberately
#    slow but thorough. A reasonable overnight run against a full home subnet.
aims scan run nuclei -t cve/ -target 192.168.1.0/24 -rl 20
```

