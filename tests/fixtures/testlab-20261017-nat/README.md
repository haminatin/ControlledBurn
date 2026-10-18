# Testlab capture, 2026-10-17: port forwards (Milestone 9b)

Real `pfctl -sn` / `pfctl -sr` from the test OPNsense 26.7 box, from
the testlab notes (`cb-nat.txt`). WAN is vtnet1, 10.100.59.2.

Two forwards (Firewall → NAT → Destination NAT; on 26.7 the old "Filter
rule association" is replaced by **Firewall Rule**: Manual / Pass):

- WAN tcp 8443 → nas 192.168.77.20:443, **Manual**:
  `rdr on vtnet1 … port = 8443 -> 192.168.77.20 port 443`, with no filter
  rule allowing it, so it is translated and then dropped (inert).
- WAN tcp 2222 → lab-dev01 192.168.77.191:22, **Pass**:
  `rdr pass on vtnet1 … port = 2222 -> 192.168.77.191 port 22`, which skips
  filter rules entirely.

Reconstructed, not captured: the Destination NAT config rows used by the
forward-config check (`tests/test_testlab_nat.php`), including the real
mistake from the box: 8443 entered as the SOURCE port with an empty
redirect target, which the GUI shows as enabled but which generates no
rdr at all.
