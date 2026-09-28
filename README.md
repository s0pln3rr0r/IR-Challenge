# Six Ways Out — Reproducible DFIR Lab

A Linux DFIR/IR CTF challenge simulating a compromised production server with six data exfiltration channels.

Two Ubuntu VMs are required:
- **Victim**: `10.10.20.15` / `prod-web-03`
- **Services/Capture**: `10.10.20.50`

Use an isolated host-only/internal network. **Do not expose these services to the Internet.**

## Architecture

The six logical destination IPs are configured as IP aliases on the services VM:

| Channel    | Destination     | Service        |
|------------|-----------------|----------------|
| HTTP       | `198.51.100.77` | Python HTTP    |
| DNS        | `203.0.113.53`  | Python DNS     |
| SMTP       | `203.0.113.25`  | Postfix        |
| ICMP       | `192.0.2.91`    | Scapy receiver |
| FTP        | `203.0.113.88`  | vsftpd         |
| WebSocket  | `203.0.113.123` | Python WS      |

## Full Run Order

### 1. Initial setup (both VMs)

```bash
cp config.env.example config.env
```

### 2. Victim setup

```bash
sudo ./setup/install_dependencies.sh victim
sudo ./setup/setup_victim.sh
```

### 3. Services/Capture setup

```bash
sudo ./setup/install_dependencies.sh attacker
sudo ./setup/setup_attacker.sh     # configures routing, FTP, Postfix
sudo ./attacker/start_services.sh  # starts HTTP, DNS, WebSocket receivers
sudo ./capture/start_capture.sh    # starts tcpdump
```

### 4. Run the attack simulation (on victim)

```bash
sudo ./victim/attacker_simulation.sh
```

### 5. Stop and collect (on services/capture)

```bash
sudo ./capture/stop_capture.sh
./collection/collect_zeek.sh
```

### 6. Verify and build

```bash
python3 verify/verify_payloads.py
python3 verify/verify_timeline.py
./collection/build_challenge.sh
```

### 7. Output

- `output/six_ways_out_player.zip` — Player challenge package
- `output/six_ways_out_full.zip` — Organizer package with answers

### 8. Reset (optional)

```bash
sudo ./reset_lab.sh
```

Removes runtime artifacts, PCAP, and generated logs without destroying source files.

## New/Modified Scripts

| Script | Purpose |
|--------|---------|
| `setup/configure_routing.sh` | Adds IP aliases for all 6 logical destinations |
| `setup/configure_ftp.sh` | Configures vsftpd with upload-only account |
| `setup/configure_postfix.sh` | Configures Postfix to accept SMTP from victim |
| `setup/generate_xlsx.py` | Generates a genuine XLSX with marker in cell B17 |
| `attacker/icmp_sender.py` | Scapy-based ICMP payload sender |
| `attacker/smtp_sender.py` | Sends 3 emails with real QR PNG MIME attachments |
| `attacker/stop_services.sh` | Stops all receiver services |
| `reset_lab.sh` | Removes all runtime artifacts for clean re-runs |

## Challenge Design

The simulation creates **real endpoint activity** and **real network traffic**. The PCAP contains genuine packets for all six channels. Players must correlate bash history, audit logs, Zeek logs, and the PCAP to reconstruct the exfiltrated data and build the final flag.

**The challenge package does not include the original sensitive files or organizer answer material.**
