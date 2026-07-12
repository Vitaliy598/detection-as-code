# Capstone Incident Report: Remote Download + Repeated Outbound Connections

## Incident Summary

- Incident ID: CAPSTONE-001
- Severity: HIGH
- Host: win-22
- User: user1
- Domain: cdn.example.test
- Destination IP: 203.0.113.88
- Detection: PAYLOAD_DOWNLOAD_PLUS_BEACONING

## Verdict

Confirmed suspicious network behavior.

The normalized evidence shows a successful remote download attributed to PowerShell followed by repeated outbound connections from the same host, user, domain, and destination IP within a short time window.

## Evidence

| Evidence | Source | Meaning |
|---|---|---|
| PowerShell-attributed remote download | data/network_events.psv | Possible remote content staging |
| Three outbound connections | data/network_events.psv | Repeated post-download network behavior |
| Same Host/User/Domain/IP | rules/network_payload_beacon_correlation.awk | Events belong to one entity chain |
| 85 second window | rules/network_payload_beacon_correlation.awk | Beaconing happened shortly after payload download |
| HIGH_ALERT result | tests/network_payload_beacon_test.sh | Detection matched expected result |
| Review checklist passed | reviews/network_payload_beacon_review.psv | Detection quality was reviewed |

## Why This Matters

A script-interpreter download followed by repeated outbound connections can indicate staging or callback behavior, but the normalized sequence alone does not prove malicious intent.

C2 means Command and Control: attacker-controlled infrastructure used to communicate with a compromised host.

## Recommended Actions

1. Isolate host win-22.
2. Block destination IP 203.0.113.88 and domain cdn.example.test if environment-owner validation confirms malicious activity.
3. Collect EDR process and network timeline.
4. Check whether payload.ps1 executed.
5. Check persistence locations such as scheduled tasks, services, registry run keys, and startup folders.
6. Review other hosts for the same domain/IP.

## Detection Quality

- Expected test passed.
- Benign cases remained NO_ALERT.
- Attack case produced HIGH_ALERT.
- Review checklist passed.
- KQL and Splunk conversion files exist.
- Sigma normalized atomic behaviors exist; full sequence correlation remains SIEM-specific.

## Limitations

This capstone is based on lab data. In a real environment, additional validation is required: domain reputation, proxy logs, DNS logs, EDR process tree, file hash, user context, and containment status.
