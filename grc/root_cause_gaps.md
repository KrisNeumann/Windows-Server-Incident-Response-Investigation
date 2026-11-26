# Root-Cause / Policy Gaps
1. **No alerting on new local accounts.** Event 4720 was recorded but nothing prompted review, and the account was created by an existing user (`admin`) with no second-person approval.
2. **No alert on the exfiltration traffic.** Manual PCAP review found the flow; no alert was presented in the lab, and the alert console could not be reached to confirm. No detection was shown covering outbound connections to uncommon ports.
3. **No application allow-listing or integrity monitoring.** A typosquatted binary ran freely.
4. **No egress filtering.** Outbound traffic to an arbitrary external port was permitted.
5. **No eradication checklist.** Containment was validated, but nothing required persistence checks, or recording the binary path and hash before removal.
