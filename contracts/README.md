# Contracts

Shared data contracts both engineers build against. Agree these on Day 1.

- `scope.json`               - FQDN allow/deny-list, URL exclusions, env-class
- detection record schema    - normalized detection shape
- fingerprint formula         - rule_id + endpoint + parameter + payload_family
- `sample_zap_output.json`   - real ZAP output captured by hand; unblocks detections work
