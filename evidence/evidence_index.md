# Evidence Index

All screenshots are my own captures from the lab rerun. The personal-data-style values in the packet payload are fictitious lab data; identifying values (names, street addresses, email names, phone and ID numbers) are redacted with black bars in file 10.

| File | What it shows | Report section |
|---|---|---|
| 01_host_netstat_ipconfig_netuser_wmic.png | Host IP (10.10.1.5), established connection to 75.30.5.55:1337, PID 6068 via `netstat -ano`, local accounts | Detection |
| 02_host_tasklist_pid_6068_wint0ols.png | `tasklist /v` identifying `WinT0Ols.exe`, PID 6068, user `admin` | Detection |
| 03_pcap_exfil_flow_filtered.png | Filter `ip.src == 10.10.1.5 && ip.dst == 75.30.5.55 && tcp.len > 0`: 9 of 147 packets, with Frame 28 details | Analysis |
| 04_eventviewer_4720_adm1nistrator_created.png | Event 4720: `Adm1nistrator` created by `admin` | Analysis |
| 05_lusrmgr_adm1nistrator_properties.png | Account properties: password never expires, disabled | Analysis / Containment |
| 06_containment_taskmanager_end_task.png | Ending the `WinT0Ols` process | Containment |
| 07_validation_netstat_no_connections.png | `netstat` shows no active connections | Validation |
| 08_validation_getprocess_wint0ols_not_found.png | `Get-Process -Name WinT0Ols` not found | Validation |
| 09_validation_tcpdump_zero_packets.png | Sensor `tcpdump` on 75.30.5.55: 0 packets | Validation |
| 10_pcap_follow_tcp_stream.png | Follow TCP Stream: 920 bytes, 9 client packets, 0 server packets (identifying values redacted) | Analysis |
| 11_pcap_beacon_timing_time_delta.png | Nine transmissions with per-packet time deltas | Analysis |
| 12_pcap_capture_file_properties.png | Capture 2023-11-01 18:07:33 to 18:08:00, 27 s elapsed | Analysis |
| 13_pcap_conversations_tcp.png | TCP conversations: 9 packets / 1,406 bytes client to 75.30.5.55:1337 | Analysis |
| 14_eradication_binary_deleted_verified.png | Full-drive search for `WinT0*` returns nothing after deletion (name match only) | Eradication |
| 15_eradication_account_removed_verified.png | `Disable-LocalUser`, `Remove-LocalUser`, then `Get-LocalUser` and `net user` no longer list `Adm1nistrator` | Eradication |
