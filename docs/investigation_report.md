# Investigation Report

Scenario: security analyst responding to an e-commerce client's report of possible customer-data leaks (customers reported phishing emails and vishing calls after contact with Sales). Scope and role come from the course lab; the evidence and analysis below are from my own rerun.

Phases follow NIST SP 800-61 Rev. 2.

## 1. Preparation
Isolated lab: Windows Server 2019 target (`WIN-MSITE54SFL9`, 10.10.1.5, gateway 10.10.1.1), Security Onion sensor (interface `ens32`; sensor VM clock is UTC), and an internal web server (192.168.1.111) generating normal HTTP traffic. Windows Event Viewer times are host-local and the time zone is not recorded, so they are not directly comparable to sensor UTC times.

## 2. Detection and analysis
- **Detection source:** The lab did not present a Security Onion alert for this traffic, and I could not check the alert console: the web console redirects to 192.168.10.22, which is unreachable from the lab VMs I had access to (`ERR_ADDRESS_UNREACHABLE`). The flow was identified through host checks and manual PCAP review. Whether an alert exists in the console is unverified.
- `netstat` showed one established connection from 10.10.1.5:49674 to `75.30.5.55:1337`; `netstat -ano | findstr 1337` tied it to PID 6068.
- `tasklist /v /fi "PID eq 6068"` identified the process as `WinT0Ols.exe`, running as the local `admin` user in the console session (~25 MB).
- Filtering the PCAP on the Windows host (`ip.addr == 10.10.1.5`) separates the 1337 flow (PSH/ACK segments of ~90-108 bytes) from normal HTTP browsing to 192.168.1.111.
- PCAP analysis (`traffic.pcap`):
  - Filtered view isolates the flow to `75.30.5.55:1337`.
  - Conversations: 9 records, 1,406 bytes on the wire.
  - Follow TCP Stream: 920 bytes payload, six categories of personal-data-style fields per record (name, sex, street address, email, phone, ID-formatted number), raw TCP, not HTTP.
  - Time-delta view: nine transmissions to 75.30.5.55:1337 from 2.72 s to 23.74 s (relative time), gaps of about 1-5 s with the first two back-to-back; capture elapsed 27 s (first packet 2023-11-01 18:07:33, last 18:08:00).
- Event ID 4720 in a saved Security log (`security_10-18.evtx`, 376 events, filtered to 4720, 1 match) shows local account `Adm1nistrator` created on 2023-10-18 14:55:03 (host local time). The creating subject was the existing `admin` account, which suggests `admin` was used or compromised. The lookalike name differs from the built-in `Administrator` by one character (`i` replaced with `1`).
- Account properties: password never expires; later disabled (see Containment).
- Note: the first `net user` listing (evidence 01) does not show `Adm1nistrator`, while later listings (evidence 05, 15) do. I did not determine the cause; the first capture may predate the account's appearance in the lab VM. Events and later captures are used as the evidence of the account.
- The PCAP's first packet (2023-11-01 18:07:33) is ~14 days after this event; the comparison is approximate because the Event Viewer time is host-local and the capture time is from the PCAP metadata.

## 3. Containment
- Ended `WinT0Ols` in Task Manager (End task).
- Disabled `Adm1nistrator` with `Disable-LocalUser -Name "Adm1nistrator"`; `Get-LocalUser` then showed Enabled = False.
- Validation on the host: `netstat` showed no active connections afterward. The account was disabled at this point, not yet deleted.
- Validation on the sensor: `sudo tcpdump -i ens32 -n host 75.30.5.55` returned 0 packets captured. (A positive control against the destination was not captured.)

## 4. Eradication and recovery
- Deleted the `WinT0Ols` executable from disk. A full-drive search (`Get-ChildItem -Path C:\ -Filter "WinT0*" -Recurse`) returned no results. It checks file names only, so a renamed copy would not appear.
- Removed the lookalike account with `Remove-LocalUser -Name "Adm1nistrator"` after disabling it. `Get-LocalUser` and `net user` afterward no longer list it (evidence 15).
- Outside the scope of this rerun: persistence checks and credential reset (including the `admin` account that created the lookalike). Listed under recommendations.

## 5. Post-incident review
See `grc/`.
