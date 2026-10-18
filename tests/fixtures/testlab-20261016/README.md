# Testlab capture, 2026-10-16

Real output from the isolated test OPNsense 26.7 VM, captured right after the
first install of os-controlledburn-0.1 (testlab notes, `cb-data.txt`).

| File | Command |
|---|---|
| `pfctl.txt` | `pfctl -sr` |
| `leases.json` | `configctl dnsmasq list leases` |
| `ifconfig.json` | `configctl interface list ifconfig` |
| `rule_ids.json` | `configctl filter list rule_ids` |
| `non_mvc_rules.json` | `configctl filter list non_mvc_rules` (captured separately) |
| `ruleset.json` | generated: `python3 -I make_ruleset.py > ruleset.json` |
| `review_get_escaped.txt` | `/api/controlledburn/review/get` in a browser (2026-10-17, copied from its JSON viewer). Evidence that OPNsense HTML-escapes API output: stored edge ids come back with `&gt;` |

Not captured, reconstructed from the testlab notes:

- dnsmasq Hosts: `nas` .20 (with MAC), `media` .20 (no MAC), `clash` .41,
  `dtest` .42. These are in `tests/test_testlab_capture.php`.
- Interface keys/descriptions: vtnet0 = `lan`/LAN, vtnet1 = `wan`/WAN.
- pf tables (`sshlockout`, `virusprot`) are taken as empty.
  `make_ruleset.py` resolves them that way. Confirmed on the box:
  `pfctl -t sshlockout -T show` and `-t virusprot -T show` both returned
  nothing.

Known lab quirk kept on purpose: "Default allow LAN to any" is evaluated
before the user's quick block rules ("printer no outbound", "block ssh to
nas"), so those blocks can never match. Also, all devices share one subnet,
so device-to-device traffic never crosses the firewall anyway.
