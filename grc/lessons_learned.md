# Lessons Learned
- Verify containment with a positive control, not only an empty result.
- Keep one time zone across all artifacts. Sensor clock is UTC.
- Read the data, not the claim. The traffic was raw TCP on 1337, not HTTP, and the capture showed it.
- Hash evidence before deleting it. I deleted the executable and verified the removal with a drive-wide name search, but I did not record its path or hash first. Next time, capture both before removal.
- I relied on host checks and manual PCAP review because no alert was presented and the alert console was unreachable. Confirm monitoring tools are reachable and test detections against known-bad traffic.
## Recommendations
- Add detection for outbound connections to uncommon ports and for new local accounts (Event 4720).
- Check Run keys, scheduled tasks, services, and startup folders before closing the incident.
- Reset credentials, starting with the `admin` account that created the lookalike.
- Restrict egress and add application allow-listing.
