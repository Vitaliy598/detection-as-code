# Capstone Incident Report: Network Payload Download + Beaconing

## Incident Summary

- Incident ID: CAPSTONE-001
- Severity: HIGH
- Host: win-22
- User: user1
- Domain: cdn-security-update.com
- Destination IP: 203.0.113.88
- Detection: PAYLOAD_DOWNLOAD_PLUS_BEACONING

## Verdict

Confirmed suspicious network behavior.

The evidence shows an HTTP payload download followed by repeated beacon-style requests from the same host, user, domain, and destination IP within a short time window.

## Evidence

| Evidence | Source | Meaning |
|---|---|---|
| HTTP payload.ps1 download | data/network_events.psv | Possible payload staging |
| Three /beacon requests | data/network_events.psv | Repeated callback behavior |
| Same Host/User/Domain/IP | rules/network_payload_beacon_correlation.awk | Events belong to one entity chain |
| 85 second window | rules/network_payload_beacon_correlation.awk | Beaconing happened shortly after payload download |
| HIGH_ALERT result | tests/network_payload_beacon_test.sh | Detection matched expected result |
| Review checklist passed | reviews/network_payload_beacon_review.psv | Detection quality was reviewed |

## Why This Matters

A payload download followed by repeated beaconing can indicate possible C2 staging or malware callback behavior.

C2 means Command and Control: attacker-controlled infrastructure used to communicate with a compromised host.

## Recommended Actions

1. Isolate host win-22.
2. Block destination IP 203.0.113.88 and domain cdn-security-update.com.
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
- Sigma atomic indicators exist.

## Limitations

This capstone is based on lab data. In a real environment, additional validation is required: domain reputation, proxy logs, DNS logs, EDR process tree, file hash, user context, and containment status.
