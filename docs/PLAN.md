# ControlledBurn — implementation plan

> **Design notes and build log.** The original plan was lost early on;
> this version was rebuilt on 2026-10-15 from the code and the testlab
> notes. Where the original's content couldn't be recovered, this file says
> **Unknown** rather than guessing. Section numbers were chosen so the existing code comments
> that cite them ("Strategy B", "Section 3.3", "Milestone 4/6") still point
> somewhere sensible. The original numbering may have differed.
>
> This file lives in the repo now, so it is version-controlled. Keep it
> updated as the source of truth for design decisions and build progress.

## 1. Goal

A native OPNsense plugin (PHP/Phalcon MVC) that renders an interactive
topology graph of discovered devices and firewall rules. The point is to
audit visually who can reach whom on the home network, including devices
that *could* reach something they shouldn't, not just active connections.

- Graph edges are **static rule-evaluation verdicts** (pass/block), not live
  traffic.
- Nodes are draggable, and the layout persists across sessions.
- The view can be filtered down to a chosen set of entities (per
  `pkg-descr`).

Non-goals (as far as can be reconstructed): live traffic/state-table
visualisation, editing firewall rules from the graph.

## 2. Data sources

### 2.1 Devices
- **dnsmasq DHCP leases**: via configd `dnsmasq list leases`. Keyed by
  lowercase MAC, falling back to IP.
- **dnsmasq host overrides**: `\OPNsense\Dnsmasq\Dnsmasq` model `hosts`.
  These override lease entries with the same key, keeping the lease's
  interface fields.
- dnsmasq is built into OPNsense core, so no `PLUGIN_DEPENDS` is needed.
- **Not covered:** Unbound host overrides. In the testlab, `printer` exists
  only as an Unbound override, so ControlledBurn won't discover it. Decide
  whether that's intended (see §7).

### 2.2 Interfaces
- `config.xml` `<interfaces>`: physical name (`igb0`/`vtnet0`) ↔ logical key
  (`lan`) ↔ description.
- Devices carry both: `if` (physical, used for rule matching because pf rule
  text names physical interfaces) and `interface`/`interface_descr`
  (logical, for display/filtering).

### 2.3 Firewall rules: Strategy B (pf text is ground truth)
- **Strategy A** (inferred, not used): evaluate rules from `config.xml`.
  Rejected because the loaded ruleset contains auto-generated rules
  (anti-lockout, NAT-implied passes, defaults) with no 1:1 `config.xml`
  entry. A security-audit tool must not silently miss them.
- **Strategy B** (chosen): `get_ruleset.py` (run via configd action
  `controlledburn get ruleset`) parses `pfctl -sr` in evaluation order into
  structured rules: action, direction, quick, interface, inet/inet6,
  protocol, source/destination lists, ports, label, raw text.
  - `<table>` references are expanded via `pfctl -t <table> -T show`. A table
    that fails to resolve becomes an `{table, unresolved: true}` marker, and
    the marker never matches (§3.1).
  - Lines that don't parse confidently go into `unparsed`, not guessed at.
    The API reports `unparsed_count` so the UI can warn.
- Token order in the regex mirrors OPNsense's own generator
  (`Firewall/FilterRule.php` `$procorder`).

### 2.4 Rule descriptions (label → description)
- Both the legacy `<filter><rule>` array and the newer UUID-based
  `\OPNsense\Firewall\Filter` model feed the live pf ruleset **at the same
  time** (confirmed in core's `plugins.inc.d/pf.inc`). This is normal, not a
  migration edge case, so both must be covered.
- pf labels (verified against core `b0504c9`, 2026-10-15):
  - Legacy rules: `Util::calcRuleHash(raw config row)`, an md5 (set in
    `filter.lib.inc`).
  - Newer-model rules: the rule's **UUID** (`FilterRuleContainerField::serialize()`
    sets `label` to it).
  - Auto-generated rules: an md5, computed *after* defaults are merged in,
    so it can't be reproduced PHP-side.
- **Approach (changed 2026-10-16):** use core's own configd action
  `filter list rule_ids`. It reads `label "<id>" # <descr>` from
  `/tmp/rules.debug` and covers all three kinds; Diagnostics → Firewall uses
  it too.
  - It only returns md5/UUID-shaped labels.
  - It fills an empty description with `"-- <id>"`, which we treat as no
    description.
  - The original PHP-side hash approach was dropped: `config_read_array()`
    isn't loaded in the API context, so it would have thrown an HTTP 500.
- A rule with no description keeps its raw pf text, so system rules stay
  identifiable.
- Testlab note: on 26.7 a fresh install can only create newer-model rules,
  so the legacy path won't be exercised unless a real config is imported.
  Confirmed 2026-10-16 on the testlab: config.xml had 0 legacy
  `<filter>` rules and 8 rules in the MVC `<OPNsense><Firewall><Filter>`
  section. Boxes that have run the 26.1 rule migration may have no legacy
  rules either (unverified). Most rules should therefore be UUID-labelled
  and linkable.

## 3. Rule-evaluation engine (`RuleEngine.php`)

It has no dependency on live OPNsense state, so it can be tested against
fixtures (§5, Milestone 4).

### 3.1 Matching
- **Interface:** exact physical-name match, or the rule is `any`, or the
  query leaves it unconstrained (`null`).
- **Protocol:** case-insensitive match, or `any`, or `null`.
- **Addresses:** `any`, a bare IPv4 address (/32) or an IPv4 CIDR. A query
  side of `null` means unconstrained and always matches.
- **Negation** (`from ! <spec>`, parsed as `source_not` /
  `destination_not`): inverted only if every entry in the spec can be
  evaluated. Otherwise it doesn't match.
- **Ports:** captured by the parser. Engine v1 ignores them; engine v2
  evaluates them (§3.3).
- **Conservative by design:** anything not confidently resolvable
  (unresolved tables, unknown spec shapes) does **not** match. A false
  PASS/BLOCK is worse than under-matching.

### 3.2 pf semantics
- The first matching `quick` rule wins. Otherwise the **last** matching rule
  wins. If nothing matches, the default is deny.
- **Direction (engine v2):** a pair query knows the packet path, so
  direction is no longer ignored. Traffic from A (interface `if1`) to B
  (interface `if2`) must pass **both**:
  - evaluation of `in` (and `any`-direction) rules on `if1`;
  - evaluation of `out` (and `any`-direction) rules on `if2`.

  OPNsense normally has a broad `pass out` default, so the second check
  rarely blocks, but floating `out` rules can.
- pf is stateful, so replies are allowed automatically. An allowed A → B
  flow means "A can start a connection to B". No reverse check is needed.
- Disabled rules never reach the engine, because `pfctl -sr` only shows
  loaded rules. Filtering is the caller's job.

### 3.3 Graph model (decided 2026-10-16): two layers, device-to-device

This replaces the original "O(devices × rules)" model, which routed edges
through rule nodes so it never evaluated every pair of devices. That
trade-off came before ports were a requirement. With ports, one rule per
device can't describe reachability (e.g. testlab lab-dev01 → nas is SMB
pass + SSH block). A home network has at most a few hundred devices, so
evaluating every pair is fine.

**Purpose:** expose potential holes in the firewall. **Ports are a hard
requirement.**

**Nodes**
- `device:<mac|ip>`: from leases and host overrides.
- `firewall`: the firewall itself. Its addresses are every interface IP
  (`(self)` in pf). This exposes "device can reach GUI/SSH" holes.
- `wan`: Internet/WAN. **Required, but implemented later (Milestone 9).**
  In the meantime the node exists in the data model and layout, and the
  engine's endpoint abstraction must not assume every endpoint is a single
  IP.
- Rules are no longer nodes. They are attached to edges as detail.

**Layer 1: overview edges**
- One directed edge A → B for every pair where A can start at least one
  flow to B.
- Each edge is labelled with what gets through (e.g. `tcp/445, tcp/22,
  icmp`). Hovering or clicking shows which rule allows each part.
- **Same-segment pairs** (both devices on the same interface/subnet) never
  cross the firewall, so no rule can block their traffic. They get a
  distinct edge style, `unfiltered: same network segment`. A flat network
  is itself a hole, so it is shown, not hidden. No rule evaluation happens
  for these pairs.
- Filterable by device, for busy networks such as the live box
  (Milestone 6).

**Layer 2: pair drill-down**
- For a selected pair or edge, the full breakdown, e.g.: "A → B: tcp/445
  pass (rule X), tcp/22 block (rule Y), everything else block (default
  deny)." This includes blocked ranges and the deciding rule for every
  slice.
- Later nice-to-have: flag rules that are shadowed (fully covered by an
  earlier quick rule, so they can never decide anything).

**Port-level evaluation (how a pair is computed)**
- Protocols evaluated: `tcp` and `udp` (split by port), `icmp`, and
  "other" (only rules with `proto any` can match it).
- For tcp/udp, collect every destination-port boundary mentioned by any
  candidate rule. That splits 0–65535 into slices, and each slice is
  evaluated with the §3.2 logic. Adjacent slices with the same verdict and
  rule are merged. Rulesets are small, so this is cheap.
- **Source ports:** a client picks its source port, so a rule restricted
  to a source port is a conditional match. v2 flags such rules on the
  slice ("conditional on source port") instead of splitting by source port
  as well. Revisit if real rulesets need more.
- **IP version:** a rule only applies if its `inet`/`inet6` matches the
  pair's address family. v2 evaluates IPv4. **IPv6 is required later**:
  IPv6 bypassing IPv4 rules is a classic hole. Devices with v6 leases are
  kept in the data so this can be added.
- **Dynamic addresses** are resolved from interface data instead of never
  matching:
  - `(self)` → all firewall interface IPs;
  - `(ifname)` → that interface's IP;
  - `(ifname:network)` → that interface's subnet.

  Check the exact forms against real `pfctl -sr` output from the testlab.
- Anything still unresolvable keeps the conservative rule: it doesn't
  match. The slice records which rule was skipped as undecidable, so the
  drill-down can say "verdict uncertain because of rule X" instead of
  hiding it.
  - Only undecidable rules whose action **differs from the final verdict**
    are recorded. An undecidable block on an already-blocked flow can't
    change anything. Without this, one unresolvable block table such as
    `<virusprot>` marked every pair as a maybe-hole. This showed up in the
    controller smoke test.
  - Overview edges are drawn for pairs where something is allowed **or**
    a slice is uncertain (maybe-holes), flagged `uncertain: true`.
- Unknown interface names in rules (probably interface groups) are
  undecidable, not non-matching.
- **Devices sharing an IP:** a MAC-less host override for an address that
  another device already has becomes an alias of it (testlab: `media` →
  `nas`), not a second node.
- **Firewall targets** are every firewall address, including the WAN
  address. LAN → firewall-WAN-IP traffic enters on the LAN interface, so
  LAN rules govern it.
- **Interface addresses** come from core's `interface list ifconfig` (live
  state, so DHCP, PPPoE and VIPs are covered), falling back to config.xml.
- **Scale** (synthetic benchmark, PHP 8.5 on a desktop): 50 devices/50 rules in
  0.07s; 100/100 in 0.34s; 200/150 in 1.8s. Fine for a home network. At
  200 devices most of the ~8,800 edges are same-segment `unfiltered` ones,
  so Milestone 6 needs the device filter and probably a way to collapse
  same-segment edges into one per segment.

### 3.4 Overview graph UI (Milestone 5, built 2026-10-16)

The design was iterated against a local preview (testlab-
shaped and three-segment example data), not on a box.

- **No graph library.** Self-contained SVG renderer in
  `www/js/ControlledBurn/topology.js` with `www/css/ControlledBurn/topology.css`.
  vis-network was tried first and dropped: it couldn't do orthogonal
  routing, rounded bends or animated dashes.
- **Nodes:** squircles (smoothed corners) with the name and IP inside.
  Firewall is solid red; WAN is a dashed placeholder; non-evaluable devices
  are greyed.
- **Layout:** one column per network segment inside a labelled container,
  wrapping past 8 rows into sub-columns 64px apart (a corridor, so devices
  in a middle sub-column stay reachable); firewall and WAN centred above.
- **Edges:** orthogonal (horizontal/vertical only), routed by A* over a
  grid with a high per-turn cost (fewest turns, no staircases), around
  nodes. Bends are rounded. Edges are bundled metro-map style ("lanes",
  2026-10-17): every edge keeps its own line, but edges through the same
  gap share a corridor and run in parallel lanes 8px apart.
  - Routing: running along a line another edge uses is cheap and cells
    near nodes cost extra, so edges gather on the middle line of each gap.
    Crossing costs per edge crossed, including through a shared run: join
    a run on one side and leave on the other (a "Z") crosses every edge
    running straight through it; joining and leaving on the same side
    (a "U") is free. Same-segment links route last, so they go round
    the other edges instead of boxing devices in.
  - Lanes (`assignLanes`): parallel runs that overlap within 6 grid lines
    form a corridor. Runs on different lines keep their order. Edges on
    one line are ordered by which side they part company on, ahead or
    else behind. Pairs that never part keep the same way round
    (lower id on the left of its direction of travel), so a pair doesn't
    swap sides at every bend.
  - Placement is per run, not per lane number. Each run has a feasible
    band: nodes beside it, and staying on the border of a node it ends at.
    The band narrows by a gap from every run it overlaps. Two packings
    from the routed positions (towards each side, both held in the bands)
    are averaged, which centres bundles and keeps every gap. The gap
    narrows from 8px if a band is empty, never below 3px.
  - No lanes on top of each other (v0.7 bug, seen on the box when
    dragging): a crowded corridor that spills into a neighbour is merged
    with it and laid out again. Runs that only meet end to end are
    checked after layout; any drawn on top of each other are kept apart
    on a second layout. The test suite drags nodes at random (seeded) and
    asserts no clashes.
  - Measured with `countCrossings` on the preview datasets (before → after):
    real testlab capture 15 → 5; three-segment example 60 → 48 (the 60 also had
    802px of edges drawn on top of each other, now 0); small IoT/NAT
    graphs 1 → 2, the second being a crossing that the old overlap hid.
    Tried and dropped: barycentre ordering of devices within a column
    (no measurable gain) and rip-up-and-reroute (made it worse).
  - Edges are 2px dashed lines whose dashes move source → destination
    (the direction a connection can start); same-segment links are static.
  - Small, bold arrowheads.
  - Motion stops under `prefers-reduced-motion`.
- **Labels:** allowed ports (first 3, then "+N", touching ranges merged
  across rules) on a 16px pill, 10px text. **"any"** when the engine
  reports every evaluated protocol allowed on every usable port
  (`allows_all` per family; "any (v4+v6)" for both). It must come from the
  engine: a protocol a rule blocks outright drops out of `allowed` unseen,
  so the UI can't infer it. Placed to avoid other labels and nodes,
  shortest routes first, trying every 8px along a run. Runs are tried in
  this order: horizontal runs that hold the pill (its line runs in one end
  and out the other), then other horizontal runs, then vertical runs. A dot
  in the edge's colour marks each point where its own line meets the pill's
  outline, so a pill lying across a bundle shows which lane it belongs to.
  On "any" (2026-10-17): cleaner, but may hide too much on the
  broad-rule testlab. Kept for now; revisit on a box with fewer broad
  rules. "any (v4+v6)" works well.
  Fit includes labels and routes, not just nodes.
- **Interaction:**
  - drag nodes (edges re-route live) and the background (pan);
  - scroll to zoom; Fit button;
  - hovering a node highlights its edges and fades the rest; clicking pins
    that (click again, another node, or the background to change);
  - hovering an edge shows ports with rule names (cut to 44 characters);
  - clicking an edge opens a detail card: full rule names (two lines, then
    an ellipsis; full name on hover) and an "Open rule" link.
- **Rule links:** `/ui/firewall/filter#search=<uuid>` for newer-model rules
  (pf label = uuid). Legacy and auto-generated rules (md5 labels) get no
  link. **Verified on the box 2026-10-16:** the links open the right rule.
- **On-box check (e2ebcab):** the lab-dev01 → Firewall card showed
  "Default allow LAN to any" (broad) plus anti-lockout as three rows
  (pf has three anti-lockout rules with distinct labels and the same
  description; kept as is, by choice) and DHCP (both "OPNsense
  default"), with the source-port note. "Mark as checked" works. Grouping
  card rows that share a description: not wanted for now; to revisit on
  a box with many more rules.
- **Audit colours:**
  - Blue = **intended**: every rule allowing the flow names the destination
    specifically: a host entry or host alias, the destination device's own
    segment network, or for the firewall `(self)` / one of its interface
    addresses (`RuleEngine::ruleTargets`).
  - Orange = allowed only via something broader (wider network, `any`):
    review these. In the three-segment example the only orange edge is
    Home Assistant → firewall, caught by an HA → IoT-subnet rule.
  - Green = **checked**: signed off by the user from the edge card. Saved on
    the firewall (`reviews` in the plugin model, `review/get` and
    `review/set`) with a fingerprint of what the edge allowed. If the rules
    change what it allows, the check lapses ("changed since you checked
    it").
  - Purple = **OPNsense default only** (added 2026-10-16): every rule
    allowing the edge is one OPNsense generates itself (anti-lockout, DHCP
    access, default deny, anti-spoofing, ...). Source: core's
    `filter list non_mvc_rules` (`is_automatic`, the same classification as
    the Rules page's "Automatically generated rules"); unlabelled rules count
    too. Decided: "Default allow LAN to any" is **not** a
    default (it's an editable rule the installer created, and the broadest
    rule on a typical box), and mixed edges keep blue/orange; the card
    badges each default rule "OPNsense default".
    **Verified 2026-10-16** on the testlab: 26 entries, all
    `is_automatic`, and their `uuid` values match all 26 md5 pf labels
    exactly (none missing either way). Now the real fixture.
  - Amber = uncertain; grey = same segment.
  - Precedence: checked > uncertain > default > intended > broad.
- **Theme:** dark by default for testing (`opts.theme`); a full light
  palette exists. Proper light/dark switching is still to do.

### 3.5 Dead (shadowed) rule detection (built 2026-10-16)

A rule is **dead** when another rule always gets the final say whenever it
would match (`RuleEngine::deadRules`):
- a quick rule is dead if an **earlier quick** rule covers it;
- a non-quick rule is dead if an earlier quick rule covers it, or **any
  later** rule does (last match wins).

"Covers" means it matches at least every packet the other rule matches,
provably, on every dimension: direction, address family, interface
(including `on ! X`), protocol, destination and source ports, and
source/destination addresses (CIDR containment, `any`).
- **Contradicted** = the covering rule has the opposite action ("Block
  never applies" / "Pass never applies"). This is the dangerous kind.
- **Redundant** = same action, so harmless clutter.

Conservative by design (only flags what it can prove):
- pf tables (every OPNsense alias is one, as are lockout lists) can change
  at runtime. A rule using one is judged only where the covering rule says
  `any` on that side, so the table's contents can't matter; a covering
  rule's own tables never count as proof. (Originally all table rules were
  skipped. Milestone 8 on the box showed that hid a real dead rule:
  `pass … to ! <net_rfc1918>` below a quick block-to-any. Changed
  2026-10-17.)
- rules with conditions the parser doesn't capture (`icmp-type`,
  `tagged`, `user`, ...) are never used as covers;
- negations only count when identical;
- one OPNsense rule (label) can be several pf lines; it's dead only if
  all its lines are.
- **Known gap:** a rule covered only by *several* rules together, not by
  any single one, isn't detected.

UI: a collapsible **Rule check** bar above the graph, with:
- a summary ("2 rules never take effect · 3 redundant");
- the user's own rules listed contradicted-first, each with the
  shadowing rule and links to both;
- OPNsense's automatic rules in a separate, collapsed sub-list.
- Hovering a card highlights the flows that rule was written for
  (`RuleEngine::rulePairs`: every source device → destination node it
  would match, ignoring protocol and ports) and fades everything else.
  Clicking pins that, sharing the pin with node clicks: click the card
  again, another card, a node, the graph background or elsewhere on the
  page to change or clear it. Rules matching no discovered device say so
  instead (testlab: "printer no outbound", since the printer isn't a
  device). On the
  testlab those are the six anti-spoofing rules, always overridden by the
  later non-quick default deny: technically dead, expected.

**Verified on the box 2026-10-16** (85fe0c1, testlab screenshots):
- before: exactly the prediction below;
- after moving the two blocks above "Default allow LAN to any":
  "3 redundant", with the two blocks gone.

Wording fix after that run: non-quick rules overridden by a *later* rule
(the anti-spoof rules vs the later default deny) now say "always
overridden by the later rule … without quick, the last matching rule
wins", not "decides first" (`by_position`).

Real testlab result (fixture test):
- "printer no outbound" and "block ssh to nas" never apply, shadowed by
  "Default allow LAN to any";
- "lab-dev to nas" and "labdev01 to nas" are redundant behind it;
- "firewall gui" is redundant behind the anti-lockout rule.

### 3.6 Milestone 6: saved state, filter, stale checks (built and verified on the box 2026-10-17)

- **Saved layout:** each drag saves every node's centre (`layout/set`,
  merged with saved positions of nodes currently hidden by the filter);
  loading passes them to `render()` as `opts.positions`. New nodes fall
  back to the default layout. **Reset layout** (`layout/reset`) clears
  them, behind core's `stdDialogConfirm` "Are you sure?".
- **Checks:** already saved (`review/*`); now each check also stores a
  plain-text **snapshot** of what the edge allowed (model `snapshot` field,
  capped at 4000 characters with a UTF-8-safe regex, since `mbstring`
  isn't guaranteed on OPNsense). **Clear all checks** (`review/reset`)
  sits behind a confirm step that states how many checks it will clear.
- **Changed since checked:** a checked edge whose fingerprint no longer
  matches keeps a green line with an amber dashed "changed · …" label
  (not a silent revert). Its card shows "When you checked it" (the
  snapshot) next to what it allows now, with **Re-confirm as checked** or
  **Clear the old check**. The Rule check bar counts them ("N checked edges
  changed") and lists each with hover/click highlighting.
  Precedence: checked > changed > uncertain > default > intended > broad.
- **No config-history spam:** layout and check saves use
  `Config::save(null, false)` (`QuietSave` trait). They still write
  config.xml, so the state is in later backups, but they create no
  revision in System → Configuration → History and fire no config-changed
  event. Previously every check click created a revision, and OPNsense
  keeps a limited number of them.
- **Device filter:** a text box (name / IP / alias, case-insensitive) plus
  a checkbox per segment with device counts. The firewall and WAN always
  stay. Remembered per browser (localStorage, wrapped in try/catch).

### 3.7 Milestone 8: the "IoT allow-all" mistake (predicted 2026-10-17)

**Why a second segment:** all current testlab devices share one subnet,
so device-to-device traffic never crosses the firewall and no rule mistake
between them can show. The classic mistake needs an inter-segment rule.

**Testlab setup:**
1. Hypervisor: a new isolated bridge (no physical ports), added to the
   OPNsense VM as a third NIC.
2. OPNsense: assign it (vtnet2) as OPT1, rename **IoT**, static
   `192.168.88.1/24`, enable.
3. dnsmasq: DHCP on IoT (e.g. `.100-.199`), plus a host reservation
   `iot-cam` → `192.168.88.50` for the device's fixed MAC.
4. A fake-device container `iot-cam` on that bridge with that fixed
   MAC.
5. **Stage 1, the mistake.** IoT tab rules, in this order:
   1. pass, source *IoT net*, destination *any*: "Allow IoT to internet"
   2. block, source *IoT net*, destination *LAN net*: "Block IoT to LAN"
6. **Stage 2, the naive fix:** move the block above the pass.
7. **Stage 3, the proper fix:** keep the block; replace the pass-any with:
   - pass, *IoT net* → *This Firewall*, UDP 53: "IoT DNS to firewall"
   - pass, *IoT net* → **not** an alias of the private ranges
     (10/8, 172.16/12, 192.168/16; *invert destination*): "Allow IoT to
     internet (not private networks)".
     This alias becomes a pf table, which the parser expands via
     `pfctl -t`, so the edges evaluate. Dead-rule checks skip table rules
     by design.

**Predicted** (engine, `tests/fixtures/make_scenario_iot.php`, asserted in
`tests/test_scenario_iot.php`):

| Stage | iot-cam → LAN devices | iot-cam → Firewall | Rule check |
|---|---|---|---|
| 1 mistake | everything (orange) | everything incl. GUI/SSH (orange) | "Block IoT to LAN" never applies, shadowed by "Allow IoT to internet"; its card highlights iot-cam → lab-dev01, nas **and the firewall** ("LAN net" includes the firewall's LAN address) |
| 2 naive fix | none | still everything (orange): the second hole | clean |
| 3 proper fix | none | udp/53 only, **blue** | clean |

In every stage, LAN → iot-cam stays orange via "Default allow LAN to any":
arguably intended (the LAN managing IoT), but the tool makes you decide.

### 3.8 Milestone 9a: WAN outbound (built 2026-10-17)

- **WAN interfaces:** config keys `wan` / `wan<N>`. With none, the WAN node
  stays "not evaluated". Multi-WAN: the first WAN's out-rules are used
  (policy routing via `route-to` is not modelled).
- **Device → WAN** = in on the device's interface, out on the WAN, like
  device-to-device. Devices on a WAN segment get no WAN edge.
- **"The internet"** is evaluated at a general stand-in address plus each
  specific public network named in a rule destination ("regions", up to
  20: a blocked range, a GeoIP alias's networks, a single public host).
  - The stand-in is the first documentation address (198.51.100.10,
    203.0.113.10, 192.0.2.10, 198.18.0.10) not inside any named network,
    so a specific rule can't skew the general verdict.
  - Private, CGNAT, loopback, link-local and multicast ranges, `0/0`, and
    the firewall's own addresses are never regions.
  - The edge summarises the general internet; regions whose result differs
    are listed in the card as exceptions ("198.18.0.0/15: Blocked").
- **Colour:** "anything except the private ranges" (`to ! <rfc1918>` or
  the three ranges negated) explicitly targets the internet, so it's blue;
  `any` stays orange (broad), as elsewhere.
- **Checks:** WAN exceptions are part of the fingerprint only when present,
  so existing checks on non-WAN edges keep their fingerprints. Snapshots
  include the exceptions.
- Expected on the testlab: every device → WAN orange via "Default allow LAN
  to any"; in Milestone 8 stage 3, iot-cam → WAN blue via the `! <rfc1918>`
  pass.
- **Not yet:** inbound (port forwards: pf `rdr` rules from `pfctl -sn`, and
  the WAN rules that pass them). Outbound NAT is irrelevant for filtering
  verdicts here.

### 3.10 Loopback is not a firewall address (fixed 2026-10-17)

After Apply, iot-cam → Firewall still showed tcp via `to ! <net_rfc1918>`.
Cause (found on the testlab): recent OPNsense lists **loopback**
(`lo0`, 127.0.0.1) as a configured interface. The plugin counted 127.0.0.1
as a Firewall address; it's outside the private ranges, so the rule
"reached" it. A packet arriving on a real interface for 127/8 is dropped
by the kernel (martian), so it can never be a real destination. Fix:
`interfaceMap()` skips `lo*` interfaces, and `firewallTargets()` never
returns 127/8. The test fixtures previously had no `lo0` in the configured
interfaces, which is why the off-box replay came out clean; they include
it now.

### 3.9 Empty aliases (added 2026-10-17, from a real testlab hole)

During Milestone 8 stage 3 the box showed iot-cam reaching the firewall on
every port. The `net_rfc1918` alias was correct in the GUI but had been
**saved without Apply**, so pf's table was empty, and `to ! <net_rfc1918>`
matched everything. The graph was right, but nothing explained it.

- `get_ruleset.py` reports every referenced pf table's entry count
  (`tables`); the graph API returns `empty_tables`
  (`RuleEngine::emptyTableFindings`).
- The Rule check lists each empty table with the rules using it:
  - **"Empty alias: matches everything"** when used negated (`! alias`):
    red, the dangerous case;
  - **"Empty alias: matches nothing"** when used plainly;
  - the hint: "If you just edited the alias, it may not have been applied
    (Firewall → Aliases → Apply)."
- Lockout/overload tables that are normally empty (`sshlockout`,
  `virusprot`) are never reported.
- Real fixtures: `testlab-20261017-stage3/ruleset_empty_alias.json` (the
  box's state) and `ruleset_corrected.json` (after Apply).

### 3.11 Milestone 10: IPv6 (built 2026-10-17)

- **Addresses:** family-aware helpers (`inCidr`, `networkCidr`,
  `cidrInside`, `canonical`), with zone ids stripped and families never
  matching each other. Interface maps carry `ipv6` (`linklocal` flagged);
  `(self)`, `(if)` and `(if:network)` expand to both families.
- **Device IPv6:** from the firewall's NDP table (`configctl interface
  list ndp json`, MAC → address; most IPv6 is SLAAC, so not in leases).
  Link-local addresses are skipped. A DHCPv6-only lease entry (no MAC) is
  merged into the device NDP says owns it. Devices use their first
  global/ULA address per family.
- **Evaluation:** every pair is evaluated per family the endpoints have.
  `inet` rules only see IPv4, `inet6` only IPv6. Firewall IPv6 targets are
  global/ULA addresses plus link-local on the source's own segment. The
  IPv6 internet stand-in is `2001:db8::10`; ULA, link-local and multicast
  are never "internet"; "! fc00::/7" counts as explicitly internet (blue).
- **Output:** allowed entries carry `family: inet6` **only** for IPv6, so
  IPv4 output and saved check fingerprints are unchanged.
- **Display:** families never merge. Labels show the IPv4 summary, plus
  `· v6: …` when IPv6 differs, or `v6: …` when only IPv6 is allowed. The
  tooltip warns "IPv6 allows more than IPv4 here" (the classic bypass).
  Card ports are prefixed `v6`. Node tooltips list IPv6 addresses, and
  the filter matches them.
- **Scenario:** `tests/fixtures/make_scenario_ipv6.php`: IPv4 blocks IoT →
  LAN, an IPv6 allow-all lets it through. The edge reads "v6: tcp/any, …".
- **Real capture (2026-10-17):** devices got their EUI-64 SLAAC addresses
  from NDP. The deliberate bypass (`pass … vtnet2 inet6 … to
  (vtnet0:network)` with "Block IoT to LAN" inet-only) shows as IPv6-only
  iot-cam → lab-dev01/nas edges. It also reaches the **firewall's LAN ULA**
  `fd00:77::1` (inside LAN net), a real extra finding beyond the bypass.
- **Idle devices:** NDP only lists a SLAAC address once the device has
  talked to the firewall. Devices with a MAC but no known IPv6, on a
  segment with an IPv6 /64, get an **assumed EUI-64 address**
  (`ipv6_assumed`, shown in the tooltip). That reproduced all three real
  addresses exactly; for privacy-address hosts it still lands in the right
  prefix for network-based rules.
- **No IPv6 internet without it:** IPv6 → WAN is only evaluated if the WAN
  has a global (non-link-local, non-ULA) IPv6 address. The testlab WAN has
  link-local only.
- **Limits:** a device's first global/ULA address stands for all of them
  (privacy addresses rotate); the protocol class "icmp" covers ICMPv6 too.

### 3.12 Milestone 9b: inbound from the internet (built 2026-10-17)

Real capture: `tests/fixtures/testlab-20261017-nat`
(`tests/test_testlab_nat.php`). On 26.7 the Destination NAT "Filter rule
association" is replaced by **Firewall Rule**: Manual (default) / Pass
(the model also has "Register rule").

- **Parser:** `get_ruleset.py` also reads `pfctl -sn` and returns ordered
  `redirects`: `rdr` / `rdr pass` / `no rdr`, interface, protocol,
  external ports, target and target port. Lines with unknown trailing
  options go to `unparsed`. pf prints redirects without labels.
- **Forwards** (`RuleEngine::forwardsTo`): rdr on the WAN targeting a
  device. pf maps an external range onto the target port onward. An
  earlier rdr / `no rdr` covering the same ports takes precedence (first
  match wins), e.g. the anti-lockout `no rdr` lines.
- **Evaluation** (`evaluateInbound`): an internet stand-in source; filter
  rules after translation, as pf does (in on the WAN, out on the device's
  segment).
  - `rdr pass` skips filtering and is credited to the forward itself
    (`fwd-<n>`, "Port forward (Firewall Rule: Pass)"), counting as
    explicit (blue).
  - A Manual forward is live only if a WAN rule allows it; otherwise it is
    **inert** and reported, not drawn.
- **Direct inbound** without a forward only for publicly routable device
  addresses: global IPv6 (no NAT in IPv6), when the WAN has global IPv6.
- **WAN → firewall:** what the internet reaches on the firewall's own WAN
  address (e.g. GUI or SSH exposed on WAN).
- **Rule check:**
  - "Port forward does nothing" (inert; hover highlights WAN → device);
  - "Port forward looks wrong" from the DNat model: enabled entries with
    no redirect target, or a source port with no destination port. Real
    case: the external port typed as the *source* port, target left
    empty; the GUI shows it enabled but no rdr is generated.
- **Card:** a "Port forwards" section, e.g. "WAN tcp 2222 → 22, Firewall
  Rule: Pass (skips filter rules)".
- Not modelled: NAT reflection, outbound NAT, 1:1 NAT (binat), IPv6
  forwards.

### 3.13 Milestone 7: pair drill-down (built 2026-10-17)

- **Opening it:** an edge card's "Full breakdown" button; **shift-click**
  two nodes (works for pairs with no edge, e.g. to confirm a block holds);
  or the From/To pickers (with swap) in the panel itself.
- **Backend:** `RuleEngine::pairBreakdown`, with `topology/pair` as a
  thin wrapper. Covers device → device/firewall/WAN and WAN (internet) →
  device/firewall; traffic started by the firewall itself is refused with
  a reason. It returns per-target slices, rule descriptions (incl. port
  forwards), forwards, and the in/out interfaces.
- **Panel:** slides over the right of the graph. One section per family
  and target address ("IPv4 · 192.168.77.1"), each with every
  protocol/port range: allowed or blocked, the deciding rule (linked;
  "OPNsense default" badge where relevant; "No rule matched (default
  deny)" if none) and where it was decided ("in on LAN", "out on IoT",
  "port forward"), plus uncertainty and source-port notes.
  - Same-segment pairs say "unfiltered".
  - Internet → device lists only forwarded ports, with a note saying so.
- Firewall address sections name their interface ("(WAN address)").
  Reaching the WAN address from an inside device gets a note: correct pf
  behaviour, but services listening on WAN (GUI, SSH) are reachable that
  way, which surprises people (raised during testing).
- **Tests:** breakdowns on the real NAT capture
  (`tests/test_testlab_nat.php`); `tests/fixtures/pairs_nat.json` holds
  all 20 ordered pairs (`make_pairs_nat.php`) for the JS tests and the
  preview.

### 3.16 Public demo and CI (2026-10-18)

- **Demo:** `docs/demo/index.html`, for GitHub Pages (source: main,
  `/docs`; `docs/.nojekyll` keeps Jekyll from processing markdown;
  `docs/index.html` redirects to `demo/`). It's built by
  `scripts/build_demo.py` from `docs/demo/template.html`, the plugin's own
  `topology.js`/`.css`, and data:
  - the testlab captures, re-evaluated by the current engine through the
    capture tests' `CB_DUMP_GRAPH` hook;
  - port-forward pair breakdowns (`make_pairs_nat.php`);
  - the scenario and example fixtures;
  - `docs/demo/make_five_vlans.php`: a made-up five-VLAN home lab with a
    realistic ruleset, run through the engine, so its colours and findings
    are genuine. It has blue/orange/purple/amber/grey, a shadowed rule, an
    inert forward, the guests' "web only" rule opening the firewall GUI,
    and rules to a whole network reaching the firewall's address in it.
  Sample data only, no external requests, checks and positions held in
  memory. JSON is embedded with `</` escaped. Smoke-tested in jsdom: every
  dataset, both layouts, no errors.
- **CI:** `.github/workflows/tests.yml` runs all nine suites plus
  `build_demo.py --check` on every push and pull request. It uses
  preinstalled PHP/Python/Node and `actions/checkout@v4` only, with a
  read-only token, no secrets and no persisted credentials. Pinning the
  checkout action to a commit SHA is an option.

### 3.15 Star layout, square hubs, "This Firewall" (2026-10-18)

- **Layout:** star by default, columns as a per-browser option
  (localStorage). Star puts the firewall in the middle, each segment's box
  on one side, and WAN in the middle of the top side. One segment goes
  below; with more, the order is left, right, below, above, then round
  again. Order measured, averaged over 30 jittered layouts each:
  - columns: port forwards 2.0, IoT 2.0, testlab 6.6, three segments 60,
    five VLANs 181 crossings;
  - star with 128px squares: 1.6, 0.6, 4.3, 40, 125;
  - the first order tried (below, left, right, above) made two-segment
    networks worse than columns.
  Bends rise slightly on small graphs (~13 -> 16).
- **Firewall and WAN** are 128px squares, icon above the name: a shield and
  a globe, as 24px line paths drawn in the node's colour. Tinted
  translucent fill with a coloured outline: firewall red, WAN cyan (the
  nearest hue no edge colour uses; dashed outline kept). No drop shadow,
  which would show through the fill.
- **Columns cost.** In the columns layout the squares cost crossings on the
  busy example (48 -> 75; jittered average ~71 vs 60). Accepted: columns is
  the alternative, and consistent nodes matter more.
- **Naming.** The firewall node is "This Firewall" (OPNsense's own name
  for the box's addresses in rules), with the hostname underneath (graph
  API `hostname`).
- **Dragging.** Drag a segment's box or name to move all its devices.
- **Saved positions per layout.** Field `layout` (model 1.4.0; not
  Required, since older rows have none and a failed validation would block
  every save). Old rows count as columns and are normalised on the next
  layout save. Set and reset act on one layout; switching never scrambles
  either.
- **Tried and dropped:**
  - full-width bars across the top, with internet edges drawn through the
    firewall: too easy to misread which edges end at the firewall;
  - around the ends: no gain;
  - a 300px-wide firewall: helped single-column networks, hurt multi-column
    ones (the width took the open space above the middle column).

### 3.14 Security audit (2026-10-18)

Threat model: the plugin runs on the firewall, so a hole is a firewall
hole. Untrusted inputs are device-chosen DHCP hostnames (any device on any
segment), then rule descriptions, alias contents and API requests from
logged-in users. The configd script runs as root.

Verified sound:
- **Device-supplied text.** Hostnames, rule descriptions, aliases and
  snapshots are inserted with `textContent`/jQuery `.text()`, never parsed as
  HTML. The two `innerHTML` uses only clear a container.
- **Links.** Rule links are built only for strict-UUID labels, to a fixed
  local path, URL-encoded.
- **No command execution.** No shell, `eval` or exec in PHP. The configd
  action takes no parameters. `get_ruleset.py` calls `pfctl` with argument
  lists (no shell) and only reads.
- **API input.** Every configd call is a fixed command. The drill-down's
  `src`/`dst` are matched against known node ids only. Regexes built from
  data use `preg_quote`.
- **Writes.** All writes are POST-only (core rejects POSTs without a valid
  CSRF token; checked in core's ApiControllerBase), refused for read-only
  users, and model-validated.
- **No outbound contact.** No external URLs, fonts, CDNs or telemetry.
  `deploy.sh` is dev-only, not packaged, and guarded to testlab hosts.

Fixed 2026-10-18:
1. **Config bloat by a user granted only this page (medium).** Layout and
   review saves were unbounded. Now: at most 2,000 positions (over that is
   refused, old layout kept); node ids `[A-Za-z0-9:._-]{1,200}` (odd ones
   skipped and reported, the rest saved); at most 5,000 checks (re-checking
   or unchecking still works at the limit); edge ids
   `[A-Za-z0-9:._|>-]{1,300}`. Ids are checked in the controllers, not
   model Masks, so an unexpected stored value can't block every later save.
   The page now drops saved positions for nodes no longer in the graph
   (devices gone, randomised MACs), so the layout can't grow forever and
   hit the cap by accident.
2. **DHCP flood (low-medium).** Server measured off the box: 250 fake
   devices on one segment take 1.9s (63k edges); 190 cross-segment take 1.4s.
   Browser routing is the choke: 480 edges take 1.7s, 960 take 4.6s,
   1,600 take 11s. Now:
   - over 500 devices, the graph isn't evaluated (`too_many_devices`) and
     the page explains, pointing at DHCP leases;
   - over 400 edges, same-segment links are hidden unless the user ticks
     them;
   - over 1,000 edges, nothing is drawn until filtered (Rule check still
     shown).

Notes: the page privilege exposes the whole security posture (README says
admin-only). Device names are claims; trust IP/MAC. Out of scope:
OPNsense, PHP, pf. Suggested on-box check: a device hostname like
`<b>x</b>` must show as literal text (dnsmasq may reject it first).

## 4. Backend API

Endpoints all live under `api/controlledburn/`. The ACL covers
`ui/controlledburn/*` and `api/controlledburn/*`. The menu entry is
Firewall → ControlledBurn.

| Endpoint | Purpose |
|---|---|
| `topology/interfaces` | Interface list (key, physical if, descr, v4/v6 addr+subnet) |
| `topology/devices` | Merged lease + host-override device list |
| `topology/rules` | Parsed pf rules with descriptions + `unparsed_count` |
| `topology/graph` | v2: `{nodes, edges, unparsed_count}`. Nodes are devices + firewall + wan. Edges are directed pairs with `kind: filtered\|unfiltered` and an `allowed` summary |
| `review/get` | Saved audit sign-offs: `{reviews: {edge_id: fingerprint}, snapshots: {edge_id: text}}` |
| `review/set` (POST) | `edge_id` + `fingerprint` (+ `snapshot`) to mark checked, or `checked=0` to clear |
| `review/reset` (POST) | Clear every sign-off |
| `layout/reset` (POST) | Clear every saved position |
| (all) | Responses to browsers are HTML-escaped by core: decode with `decodeApi()` |
| `topology/pair?src=&dst=` | v2, new: full slice-by-slice breakdown for one pair (layer 2). `src`/`dst` are graph node ids (`device:<id>`, `firewall`). Returns `{status, kind, targets: [{ip, slices}], rules: {label: {descr, text}}}` |
| `layout/get` | Saved node positions |
| `layout/set` (POST) | Replace the **whole** layout in one call |

- The layout model (`//controlledburn`) stores `positions` as an ArrayField
  of `{node_id, node_type, x, y}`. v2 adds the `firewall` and `wan` node
  types. `rule` is kept for compatibility but no longer used.
- Full replace instead of per-node updates means internal row UUIDs never
  need to go to the client. The frontend always posts its complete position
  set (Milestone 6).

## 5. Build order

Grouping of M0–M4 reconstructed from the commit and code comments. The exact
original split of M1–M3 is **Unknown**. Milestones from 4b onwards were
re-planned on 2026-10-16.

| # | Milestone | Status |
|---|---|---|
| 0 | Plugin skeleton: Makefile, pkg-descr, model, ACL, menu, index page, xmlrpc sync stub | Done, unverified |
| 1–3 | Device/interface discovery, `get_ruleset.py` + configd action, rule descriptions, RuleEngine v1, Topology + Layout API controllers | Done, unverified. Fixes applied 2026-10-16 |
| 4 | RuleEngine fixture tests (`php tests/run_rule_engine_tests.php`) | Written, **never run** (needs `php-cli`) |
| 4a | Parser fixture tests (`python3 -I tests/test_get_ruleset.py`) | Passing on hand-written lines |
| 4b | **Engine v2** (§3.3): port matching (operators/ranges), port-slice pair evaluation, in/out on both interfaces, inet/inet6 filtering, dynamic address resolution, firewall endpoint, same-segment detection; `graph` v2 + `pair` endpoints; tests | **Done 2026-10-16.** Engine tests 82/82 (checked by deliberately breaking the engine five ways; each break was caught). Controller smoke test 15/15 against stubbed OPNsense classes. Not yet run on a real box |
| 4c | **Done 2026-10-16.** Install on testlab. Package install via the README route verified 2026-10-16 on the testlab (26.7): `make upgrade` built and installed `os-controlledburn-0.1` cleanly, configd restarted, model migrated 0.0.0 → 1.2.0, no errors (testlab install log). Still to check: hit every endpoint, capture real `pfctl -sr` + `/tmp/rules.debug` as fixtures, fix parser/engine against them | **Done.** Install, graph, edge cards, audit colours, "Mark as checked" (review saving), Rule check and "Open rule" links all verified on the box (e2ebcab) |
| 5 | Overview graph (§3.4): device/firewall/wan nodes, directed edges labelled with allowed ports, distinct unfiltered style, `unparsed_count` warning. Grew to include rule names + links, and audit colours/checks | **Done 2026-10-16**, verified on the testlab box |
| 6 | Saved layout + "Reset layout", device filter, "Clear all checks", visible "changed since checked" (see §3.6) | **Done 2026-10-17**, verified on the box (layout save/reset, filter incl. alias search, checks + clear all, changed-since-checked) |
| 7 | Pair drill-down panel (layer 2), §3.13 | **Done 2026-10-17**, verified on the box (iot-cam → lab-dev01 IPv4 blocked / IPv6 bypass allowed; WAN → lab-dev01 via the Pass forward; lab-dev01 → firewall per address). Box finding: dropdown arrows tiled. That was our CSS shorthand resetting background-repeat under the theme's !important caret image, not an OPNsense bug (the theme's `background: #fff !important` that first looked guilty is print-only). Fixed in b4e99b8 |
| 8 | **"Common mistake" hole scenario** on the testlab (§3.7): "IoT allow-all" above "block IoT → LAN" on a new IoT segment, in three stages | **Done 2026-10-17** on the box (0.2 · 791a906). All three stages matched the prediction, after fixing what the run exposed: alias tables skipped by dead-rule detection (§3.5), an unapplied empty alias (a real hole, now warned about, §3.9) and loopback counted as a firewall address (§3.10). The empty-alias warning was also verified live (table flushed, then re-applied) |
| 9 | **WAN node** (required): outbound (§3.8) and inbound / port forwards (§3.12) | Outbound verified on the box. **Inbound built 2026-10-17** (v0.4) against a real port-forward capture; on-screen check pending |
| 10 | **IPv6** evaluation (required), §3.11 | **Built 2026-10-17** (v0.3) and checked against a **real** testlab IPv6 capture (fixture `testlab-20261017-ipv6`, `tests/test_testlab_ipv6.php`). On-screen check of the new build pending |
| 5b | Dead (shadowed) rule detection + Rule check bar (§3.5) | **Done 2026-10-16** (off-box, incl. real-capture fixture) |
| later | Union-coverage dead rules; real-config import to exercise legacy `<filter>` rules | Not started |

## 6. Build and test environment

- **Which build is installed:** the page footer shows "ControlledBurn
  <version> · <commit>", read from the package's version file
  (`/usr/local/opnsense/version/controlledburn`, written by the plugins
  build with `product_hash` = the git commit). Dev deploys via
  `scripts/deploy.sh` have no such file and show "development build".
  Bump `PLUGIN_VERSION` at each milestone; the commit distinguishes builds
  in between. (Added after two debugging rounds lost time to "which build
  is the box on?".)
- **Versions:** the package version (`PLUGIN_VERSION` in the Makefile, now
  0.2) and the model version (`<version>` in `ControlledBurn.xml`, now
  1.2.0) are deliberately independent. OPNsense runs settings migrations
  by model version, so bump it only when the settings schema changes.

- **Dev deploy:** `scripts/deploy.sh [install|remove]` (env `CB_HOST`,
  default `opnsense-testlab`). It copies `src/` into `/usr/local` over SSH,
  then restarts configd, runs model migrations, reloads plugin
  configuration and clears the menu/template caches. This mirrors
  `opnsense/plugins` `make install` plus the package hooks. It refuses
  hosts whose hostname doesn't contain `testlab` unless `CB_FORCE=1`.
  **Never run yet.** It needs SSH to the isolated lab (e.g. via a
  ProxyJump host), and whether root's login shell on OPNsense runs
  commands over SSH is unverified.

- The `Makefile` `.include "../../Mk/plugins.mk"` only resolves at
  `plugins/net/controlledburn/` inside a real `opnsense/plugins` checkout,
  so the plugin can't be build-tested standalone.
- Never test on a production firewall. Testing happens on an isolated
  test VM: bridges with no physical ports, dnsmasq DHCP on
  192.168.77.0/24, fake-device containers, five LAN test rules.
- Importing a real config onto the test VM would give realistic data and
  also exercise the legacy `<filter>` rule path.

## 7. Open issues and risks

Status as of 2026-10-16. "Verified" means checked against core source
(`b0504c9`) or by the Python parser tests; nothing has run on a live box
yet.

### Engine design: decided 2026-10-16, see §3.3, built in Milestone 4b
1. Ports are ignored → port-slice evaluation.
2. Unconstrained evaluation picks narrow rules → replaced by per-pair
   evaluation.
3. `ipprotocol` is ignored → family filtering. IPv4 first, IPv6 in
   Milestone 10.
4. Dynamic address forms never match → resolved from interface data.
5. Same-segment traffic → `unfiltered` edge style.

### Open: next feature candidates
- Dead-rule detection: **done** (§3.5). Possible extension: detect rules
  covered only by a union of earlier rules.

### Open: UI ideas
- **"Highway" edge bundling** (idea, 2026-10-17): **built** as lanes,
  see §UI Edges. Still open: thinning repeated identical labels (e.g. many
  "tcp/any, udp/any, icmp +1" from broad rules), seen in the Milestone 8
  screenshots; and big segments, where all-pairs same-segment links
  (n(n-1)/2) dominate and cross everything: 20 devices give 190 links.
  Could be shown by the container alone.

### Open: product
6. **Unbound host overrides** aren't a device source. Decide whether they
   should be. Testlab findings (2026-10-16): dnsmasq Hosts entries reach
   Unbound even with dnsmasq's DNS port set to 0; when a name exists in
   both, the Unbound override wins; a dnsmasq host with a non-system domain
   didn't resolve at all. Testlab `printer` (.30) exists only as an Unbound
   override with no real device, so it won't appear today. Arguably
   correct, since there's nothing at that address.

### Open: needs the testlab
7. The parser is tested on hand-written lines only (Milestone 4c). Capture real
   `pfctl -sr` and `/tmp/rules.debug` from the VM and add them as fixtures.
   In particular, check:
   - whether pf ever prints `{ }` lists in `-sr` (it may expand them into
     separate rules);
   - whether port names print as `= ssh` or `= 22`;
   - whether `log` ever prints with options like `log (all)`, which the
     parser doesn't handle. Such lines would land in `unparsed`, not be
     misread.
8. PHP has never been executed. Run the RuleEngine tests (needs `php-cli`)
   and install the plugin on the testlab.

### First on-box findings (testlab 26.7, 2026-10-16), fixed same day
Real capture kept as a regression fixture: `tests/fixtures/testlab-20261016/`
(`tests/test_testlab_capture.php`).
- **Source-port rules were treated as full matches.** OPNsense's
  auto-generated `block drop in log quick inet proto tcp from any port = 0
  to any` therefore blocked *all* TCP/UDP, so every device → firewall edge
  showed only `icmp, other protocols`. Now a client is assumed free to pick
  any usable source port (1-65535):
  - a block covering only some source ports (or none, like port 0) can be
    dodged and doesn't stop the flow;
  - a pass covering some still allows it, flagged *conditional*;
  - a rule covering every usable source port behaves as unrestricted.
- **7 rules unparsed:**
  - 1 was `scrub`, not a filter rule; non-filter lines are now skipped,
    not counted.
  - 6 were OPNsense's **unlabelled** anti-spoofing rules (some with a
    negated interface, `on ! vtnet0`). Labels are now optional (synthetic
    `nolabel-<seq>`), `on ! <if>` is supported, and clauses may end the
    line.
  - Result: 82/82 filter rules parse.
- **Which lines were skipped wasn't visible.** The graph API now returns
  the unparsed lines, and the warning has an expandable list.
- **Merged names were dropped from display.** `media` (MAC-less dnsmasq
  host, same IP as `nas`) was merged correctly but its name vanished. Node
  tooltips now show "Also known as".
- **Edge labels fragmented** once several rules carve up a protocol
  (`tcp/1-21, tcp/22, tcp/23-79 +9`). Labels now merge touching ranges
  (`tcp/any, udp/any, icmp +1`); the tooltip and card group by rule, each
  with its own ports.
- Confirmed formats: lease records `{expire, hwaddr, iaid, address,
  hostname, client_id, if}`; `rule_ids` as expected; ifconfig `ipv4` list
  as expected; ports printed by service name (`port = ssh`,
  `microsoft-ds`, `bootpc`); pf tables appear as `<sshlockout>`.

- **Blank page after a plugin upgrade** (85fe0c1 on the box): core's
  `cache_safe()` versions asset URLs by core's own `index.php` mtime, so a
  plugin upgrade doesn't change `?v=` and browsers kept the old
  `topology.js`, which lacked the new `renderFindings()`. Fixed in 6551a3e:
  assets are versioned by the plugin's own file mtimes, and drawing errors
  now show a "reload with Ctrl+Shift+R" warning instead of a blank page.

### Fixed 2026-10-16 (before the box)
- **Rule descriptions:** `config_read_array()` would have thrown an HTTP 500,
  and hashing newer-model rules matched nothing (their label is the UUID).
  Replaced with core's `filter list rule_ids` (§2.4).
- **Layout save:** skipped the read-only check, and held the config lock on
  validation failure. Now calls `throwReadOnly()` up front, uses
  `validate()`/`save()`, and unlocks on failure. The response shape now
  follows core's: `{result: "saved"}` or `{result: "failed", validations}`.
- **Parser:**
  - `port = 80` style captured `=` only, and a source port swallowed the
    destination.
  - Negation captured `!` as the address.
  - Floating rules with no `on` clause went to `unparsed`; they now get
    `interface: any`.
  - Address lists only split on commas.
  - Added a safety check: if `on`/`proto`/`from`/`to` appears in a line but
    its group didn't capture, the line is rejected instead of silently read
    as `any`.
  - Parsing logic moved into a `parse_line()` function so it can be tested.
- **Engine:** honours `source_not` / `destination_not`.
- **Leases:** hostname `*` is treated as empty.

### Verified OK
- `dnsmasq list leases` output shape. Its `if` field is the physical name,
  as assumed (it can also be missing).
- Dnsmasq `hosts` fields and methods.
- Interface reading from config.xml.
- configd action naming.
- The model API used by LayoutController.
- `//controlledburn` mount (precedent: `net/wol`).
- Makefile, Menu and ACL shape.
- Cosmetic only: ACL key `page-net-…` vs the Firewall menu entry.

## 8. Next actions

**Milestone 6** (agreed 2026-10-16), requirements:
1. **Save node positions across reloads.** After a drag, post the full
   position set to `layout/set`; on load, pass `layout/get` positions to
   `render()` (`opts.positions`, already supported). Nodes without a saved
   position (new devices) fall back to the default layout.
2. **"Reset layout" with confirmation.** A button that clears all saved
   positions and returns every node to the default layout, behind an
   in-page "Are you sure?" step. Needs a clear path in the API, e.g.
   `layout/set` with an empty set (validate that works) or a dedicated
   `layout/reset`.
3. **Checked edges: blanket reset.** Checks already persist (review/get +
   review/set, saved on the firewall). Add "Clear all checks" behind the
   same kind of "Are you sure?" step; needs a `review/reset` (or similar)
   endpoint that clears every entry.
4. **Device filter** for busy networks (the live box): choose which
   devices/segments to show; probably also collapse same-segment links
   into one per segment at scale.

**Bug RESOLVED 2026-10-17, verified on the box** (checks persist through Re-evaluate and page refresh; details kept below for the record). Cause:
OPNsense's `Response::send()` passes every JSON body sent to a browser (no
`Authorization` header) through `htmlspecialchars(..., ENT_NOQUOTES)`, so
stored edge ids `…>firewall` came back as `…&gt;firewall` and never matched.
The save worked and the fingerprint matched (`acc484bb`). Fix:
`ControlledBurn.decodeApi()` decodes `&lt; &gt; &amp;` in every string *and
object key* of the graph and review responses. That also fixes latent
display bugs: rule descriptions, hostnames and skipped pf lines containing
`& < >` would have shown as entities. Evidence:
`tests/fixtures/testlab-20261016/review_get_escaped.txt`. **Rule for future
endpoints:** decode every API response with `decodeApi()` before use.

**Layout save failure, NOT reproducible (2026-10-17):** after the IoT segment
was added, dragging gave "Could not save the layout" every time (the node
moved, but reverted on refresh). It stopped after later updates, though
none touched the layout save. It didn't come back when the config was
recreated during the Milestone 8 re-run. Most plausible trigger: the node
set at the time (duplicate IoT_cam/iot-cam). Ruled out: config history
limit (it only prunes old backups, and layout saves never create entries),
stale page (pre-M6 scripts had no layout save), negative or zero
coordinates. Warnings now include the server's reason (aaea5ae); if it
recurs, that text is the lead.

**Original report (2026-10-16):** on the box, pressing
Re-evaluate turned a checked (green) edge back to orange, **with no rule
changes in between**, so it's a bug, not the lapse-on-change design. Code
review (2026-10-17) found nothing wrong in save or read-back. Re-evaluate
re-reads `review/get` before drawing, so a check should survive unless the
edge's allowed set changed (fingerprint mismatch, by design). Next step:
check an edge, then open `/api/controlledburn/review/get`:
- empty `reviews` means the save is failing (ReviewController / model
  validation);
- edge present means read-back matching is wrong (edge id or fingerprint).
- also note whether the red "Could not save the checked status" warning
  appeared when checking.
Ruled out: TextField allows special characters (`>` in edge ids) and
`Request::getPost` doesn't sanitise without a filter.

**Design change agreed in principle (2026-10-16):** re-evaluating
after rule changes must not silently wipe checks. Keep green on unchanged
edges; give lapsed ("changed since checked") edges a visible style, not a
revert to orange; show what changed in the card with one-click re-confirm;
count them in the Rule check bar. (Built in Milestone 6: §3.6.)

Later: 7 pair drill-down, 8 "common mistake" hole on the testlab, 9 WAN
(required), 10 IPv6 (required).

Test commands:
- `php tests/run_rule_engine_tests.php`
- `php tests/smoke_topology_controller.php`
- `php tests/test_testlab_capture.php` (real 26.7 output)
- `php tests/test_state_controllers.php` (layout + review saving)
- `php tests/test_scenario_iot.php` (Milestone 8 predictions + IPv6 bypass)
- `php tests/test_testlab_ipv6.php` (real IPv6 capture)
- `php tests/test_testlab_nat.php` (real port-forward capture)
- `python3 -I tests/test_get_ruleset.py`
- `node tests/test_topology_js.js`

Fixture regeneration:
- `python3 -I tests/fixtures/make_smoke_ruleset.py > tests/fixtures/smoke_ruleset.json`
- `CB_DUMP_GRAPH=tests/fixtures/smoke_graph.json php tests/smoke_topology_controller.php`
- `php tests/fixtures/make_example_graph.php > tests/fixtures/example_graph.json`
- `python3 -I tests/fixtures/testlab-20261016/make_ruleset.py > tests/fixtures/testlab-20261016/ruleset.json`
