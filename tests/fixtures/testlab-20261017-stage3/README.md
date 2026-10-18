# Testlab capture, 2026-10-17: Milestone 8 stage 3 (deviated config)

Real `pfctl -sr` from the test OPNsense 26.7 box with the IoT segment added
(testlab notes, `pf-stage3.txt`). The lab's "Block iot
to LAN" was created with destination **any** instead of *LAN net*, so both
IoT passes after it can never fire. That makes it a good real-world case:

- `pass ... to (self) port = domain`: dead behind the block-to-any;
- `pass ... to ! <net_rfc1918>`: dead too. This is an alias, i.e. a pf
  table, and is the case that table handling initially missed.

`pfctl_corrected.txt` is the re-run with the lab matching the spec (block to
*LAN net*). There the box first showed iot-cam reaching the firewall on
every port. Cause: the `net_rfc1918` alias had been saved but **not
applied**, so pf's table was empty and `to ! <net_rfc1918>` matched
everything. That was a real hole, correctly shown, and it motivated the
empty-alias warning. `ruleset_empty_alias.json` replays that state;
`ruleset_corrected.json` is after Apply.

`make_ruleset.py` resolves tables as on the box: `net_rfc1918` to the three
private ranges, `sshlockout`/`virusprot` empty.
