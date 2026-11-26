# Framework Crosswalk

Control IDs below were verified against official sources (NIST CSF 2.0, SP 800-53 Rev 5, CIS Controls v8, ISO/IEC 27001:2022 Annex A). Mapping is my analysis, not an audit.

| Finding | NIST CSF 2.0 | NIST SP 800-53 r5 | CIS v8 | ISO 27001:2022 |
|---|---|---|---|---|
| Unauthorized executable running (no allow-listing / integrity monitoring) | PR.PS-01, PR.PS-02 | CM-7, SI-7 | 2 | A.8.9 |
| Unauthorized account created and undetected ~14 days | ID.AM-01/02 | CM-8 | 1, 3 | A.5.9 |
| Unencrypted exfiltration over raw TCP to external host | PR.DS-02 | SC-8 | 3 | A.8.24 |
| Flaw/vulnerability that allowed initial access not tracked | ID.RA-01, ID.RA-07 | SI-2 | 7 | A.8.8, A.8.32 |

## Candidate mappings to verify before adding
Account management (CSF PR.AA, 800-53 AC-2, CIS 5), detection/monitoring (CSF DE.CM, 800-53 SI-4, CIS 13), incident response (CSF RS, 800-53 IR-4). Not published until checked against the official documents.
