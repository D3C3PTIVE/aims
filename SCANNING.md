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

## Privileges (one-time)

The meaty scans below lean on **raw-packet** modes — UDP (`-sU`), SYN (`-sS`), IP-protocol
(`-sO`), OS detection (`-O`). These need `CAP_NET_RAW`; without it nmap quits with *"You
requested a scan type which requires root privileges. QUITTING!"* and AIMS records a **failed**
run (no longer a silent "done"). Grant it once — no root teamserver, no per-scan sudo:

```bash
aims init caps        # setcap nmap/masscan via sudo (one prompt); idempotent, re-run after upgrades
aims init caps --print # or just print the setcap command(s) to apply yourself
```

After that, `aims scan run nmap -sU …` (and the external `nmap -sU …`) just work — AIMS passes
`NMAP_PRIVILEGED=1` automatically when it detects the capability. Skip this and you can still run
connect scans (`-sT`, the default fallback); only the raw modes are gated.

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
