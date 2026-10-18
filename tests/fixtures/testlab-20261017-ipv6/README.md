# Testlab capture, 2026-10-17: IPv6 (Milestone 10)

Real output from the test OPNsense 26.7 box on plugin 0.3 (fb41766), from
the testlab notes (`cb-ipv6.txt`). LAN `fd00:77::/64`, IoT
`fd00:88::/64`, radvd "Unmanaged" (SLAAC, see `radvd.txt`); the CTs
autoconfigure EUI-64 addresses. WAN has link-local IPv6 only.

The IoT rules are in Milestone 8 stage 2, plus the deliberate
"IPv6 bypasses the IPv4 policy" hole: `pass in quick on vtnet2 inet6 from
(vtnet2:network) to (vtnet0:network)` (8d30a349) while "Block IoT to LAN"
is inet-only.

Note from the box: NDP only lists a device's SLAAC address after it has
talked to the firewall; this capture was taken after pinging, so all three
are present. The test also replays an empty NDP table, where the plugin
must assume the same addresses from the MACs (EUI-64).

Not captured: rule descriptions for the new rules (they fall back to pf
text) and non_mvc_rules (the 2026-10-16 file is reused).
