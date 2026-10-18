<?php

namespace OPNsense\ControlledBurn;

/**
 * Static reachability engine (v2, see docs/PLAN.md section 3.3): given the
 * ordered, pf-text-parsed ruleset from get_ruleset.py (see that script's
 * docblock for why pf text is the source of truth rather than config.xml),
 * works out which flows one endpoint can initiate to another - per
 * protocol and destination-port range - and which rule decides each one,
 * independent of whether that traffic is actually occurring.
 *
 * Deliberately has no dependency on live OPNsense state (Config, Backend,
 * etc.): callers pass in the rules and an interface map, so it can be
 * tested against static fixtures before ever being wired to a live box.
 *
 * Interface map shape used throughout ($ifaces), keyed by physical name:
 *   ['vtnet0' => ['key' => 'lan', 'descr' => 'LAN',
 *                 'ipv4' => [['ipaddr' => '192.168.77.1', 'subnetbits' => 24], ...],
 *                 'ipv6' => [['ipaddr' => 'fd00:77::1', 'subnetbits' => 64, 'linklocal' => false], ...]], ...]
 * (the ipv4 list mirrors core's `interface list ifconfig` output).
 *
 * Matching is tri-state throughout: true (matches), false (doesn't), null
 * (can't be decided - unresolved table, interface group, unparseable port
 * spec, ...). A null rule is never treated as a match - a false PASS/BLOCK
 * is worse than under-matching in a security-audit tool - but it IS
 * recorded on the result as `uncertain`, so the UI can say "this verdict
 * might be wrong because of rule X" instead of hiding it.
 */
class RuleEngine
{
    public const VERDICT_PASS = 'pass';
    public const VERDICT_BLOCK = 'block';

    public const EDGE_FILTERED = 'filtered';
    public const EDGE_UNFILTERED = 'unfiltered';

    public const NODE_FIREWALL = 'firewall';
    public const NODE_WAN = 'wan';

    /** protocol class for "any protocol not otherwise named in the ruleset" */
    public const PROTO_OTHER = 'other';

    private const PORT_MIN = 0;
    private const PORT_MAX = 65535;

    /**
     * Source ports a client can actually originate from. Clients pick
     * their own source port, and port 0 isn't usable, so a flow "can start"
     * if it is allowed from any port in this range.
     */
    private const SRC_PORT_MIN = 1;

    /** how a rule's source-port restriction relates to SRC_PORT_MIN..PORT_MAX */
    private const SRC_ALL = 'all';          // no restriction, or covers every usable port
    private const SRC_PARTIAL = 'partial';  // covers some usable ports
    private const SRC_NONE = 'none';        // covers no usable port (e.g. "port = 0")

    /**
     * Attach a human-readable description to each pf-parsed rule by its
     * label (label => descr map from core's `filter list rule_ids`). Rules
     * with no match keep their raw pf rule text as a fallback description,
     * so every rule that can affect a verdict is still identifiable in the
     * UI even if it's an auto-generated system rule.
     *
     * @param array $pfRules   rules as emitted by get_ruleset.py's 'rules' list
     * @param array $descrMap  label => descr
     * @return array pfRules with a 'descr' key added to each entry
     */
    public static function attachDescriptions(array $pfRules, array $descrMap)
    {
        foreach ($pfRules as &$rule) {
            $rule['descr'] = $descrMap[$rule['label']] ?? $rule['text'];
        }
        return $pfRules;
    }

    /**
     * Flag rules OPNsense generates itself (anti-lockout, DHCP access,
     * port-0 blocks, default deny, ...) as automatic: drawn in their own
     * colour so they aren't mistaken for the user's own decisions.
     *
     * @param array $rules
     * @param array $automaticLabels label => true, from core's
     *              `filter list non_mvc_rules` (is_automatic)
     * @return array rules with an 'automatic' flag
     */
    public static function markAutomatic(array $rules, array $automaticLabels)
    {
        foreach ($rules as &$rule) {
            // unlabelled rules (synthetic nolabel-N, e.g. anti-spoofing) are
            // always system-generated: user rules always carry a label
            $rule['automatic'] = isset($automaticLabels[$rule['label']]) || strpos($rule['label'], 'nolabel-') === 0;
        }
        return $rules;
    }

    // ------------------------------------------------------------------
    // Addresses
    // ------------------------------------------------------------------

    // ---- family-aware address helpers (IPv4 and IPv6)

    /** IPv6 zone ids ("fe80::1%vtnet0") aren't part of the address */
    private static function stripZone($ip)
    {
        $pos = strpos($ip, '%');
        return $pos === false ? $ip : substr($ip, 0, $pos);
    }

    /** 4, 6, or null for an address (no prefix length) */
    public static function ipFamily($ip)
    {
        $ip = self::stripZone((string)$ip);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return 4;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return 6;
        }
        return null;
    }

    /** first $bits bits of a packed address, as a comparable string */
    private static function prefixBits($packed, $bits)
    {
        $out = '';
        $full = intdiv($bits, 8);
        $out = substr($packed, 0, $full);
        $rest = $bits % 8;
        if ($rest) {
            $out .= chr(ord($packed[$full]) & (0xff << (8 - $rest)) & 0xff);
        }
        return $out;
    }

    /**
     * Is address $ip inside $cidr ("net/bits", or a bare address = host)?
     * Works for IPv4 and IPv6; different families never match.
     */
    private static function inCidr($ip, $cidr)
    {
        $parts = explode('/', $cidr, 2);
        $ip = self::stripZone((string)$ip);
        $net = self::stripZone($parts[0]);
        $fam = self::ipFamily($ip);
        if ($fam === null || $fam !== self::ipFamily($net)) {
            return false;
        }
        $max = $fam === 4 ? 32 : 128;
        $bits = isset($parts[1]) ? (int)$parts[1] : $max;
        if ($bits <= 0) {
            return true;
        }
        $bits = min($bits, $max);
        return self::prefixBits(inet_pton($ip), $bits) === self::prefixBits(inet_pton($net), $bits);
    }

    private static function isIpv4Spec($entry)
    {
        $addr = explode('/', $entry, 2)[0];
        return filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    private static function isIpv6Spec($entry)
    {
        $addr = explode('/', $entry, 2)[0];
        return filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    /**
     * Network address in CIDR form for an interface address (IPv4 or IPv6).
     */
    private static function networkCidr($ipaddr, $bits)
    {
        $ipaddr = self::stripZone($ipaddr);
        $bits = (int)$bits;
        if (self::ipFamily($ipaddr) === 4) {
            $mask = $bits <= 0 ? 0 : ($bits >= 32 ? -1 : (-1 << (32 - $bits)));
            return long2ip(ip2long($ipaddr) & $mask) . '/' . $bits;
        }
        $packed = inet_pton($ipaddr);
        $prefix = self::prefixBits($packed, max(0, min(128, $bits)));
        return inet_ntop(str_pad($prefix, 16, "\0")) . '/' . $bits;
    }

    /**
     * Expand pf's dynamic address forms into concrete IPv4 specs using the
     * interface map: (self) / self -> every firewall address; (ifname) and
     * (ifname:0) -> that interface's addresses; (ifname:network),
     * (ifname:network:0) and bare ifname:network -> its subnets. Anything
     * else (unknown interface, :broadcast, :peer, no-route, ...) is left
     * untouched, and so later evaluates as undecidable rather than guessed.
     *
     * @param string $entry
     * @param array $ifaces interface map (see class docblock)
     * @return string[]|null concrete specs, or null if $entry isn't a dynamic form we resolve
     */
    public static function resolveDynamicAddr($entry, array $ifaces)
    {
        if ($entry === '(self)' || $entry === 'self') {
            $result = [];
            foreach ($ifaces as $if) {
                foreach (self::ifaceAddrs($if) as $addr) {
                    $result[] = $addr['ipaddr'];
                }
            }
            return $result;
        }
        if (!preg_match('/^\(?([A-Za-z0-9_.]+)(?::(network))?(?::0)?\)?$/', $entry, $m)) {
            return null;
        }
        $parenthesised = $entry[0] === '(';
        $isNetwork = !empty($m[2]);
        // a bare word with no parens and no :network is just a hostname/
        // keyword, not an interface reference
        if (!$parenthesised && !$isNetwork) {
            return null;
        }
        if (!isset($ifaces[$m[1]])) {
            return null;
        }
        $result = [];
        foreach (self::ifaceAddrs($ifaces[$m[1]]) as $addr) {
            $result[] = $isNetwork ? self::networkCidr($addr['ipaddr'], $addr['subnetbits']) : $addr['ipaddr'];
        }
        return $result;
    }

    private static function hasGlobalIpv6(array $if)
    {
        foreach ($if['ipv6'] ?? [] as $addr) {
            if (empty($addr['linklocal']) && !self::inCidr($addr['ipaddr'], self::ULA6)) {
                return true;
            }
        }
        return false;
    }

    /** an interface's IPv4 and IPv6 addresses, as one list */
    private static function ifaceAddrs(array $if)
    {
        return array_merge($if['ipv4'] ?? [], $if['ipv6'] ?? []);
    }

    /**
     * Tri-state match of one IPv4 address against one side of a rule,
     * honouring pf's "from ! <spec>" / "to ! <spec>" negation.
     *
     * - 'any' and IPv4 address/CIDR entries are evaluated.
     * - IPv6 entries can never match an IPv4 address: definite false.
     * - Anything else (unresolved table marker, unresolved dynamic form,
     *   unknown keyword) is undecidable.
     *
     * Non-negated: true if any evaluable entry matches; else null if any
     * entry was undecidable; else false. Negated: false if any evaluable
     * entry matches; else null if any entry was undecidable; else true.
     *
     * @param array $spec list of address entries for one side of a rule
     * @param bool $negated
     * @param string $ip IPv4 address
     * @return bool|null
     */
    public static function matchSide(array $spec, $negated, $ip)
    {
        $undecidable = false;
        $matched = false;
        foreach ($spec as $entry) {
            if (!is_string($entry)) {
                $undecidable = true;
            } elseif ($entry === 'any') {
                $matched = true;
            } elseif (self::isIpv4Spec($entry) || self::isIpv6Spec($entry)) {
                // the other family simply never matches
                $matched = $matched || self::inCidr($ip, $entry);
            } else {
                $undecidable = true;
            }
            if ($matched) {
                break;
            }
        }
        if ($matched) {
            return !$negated;
        }
        if ($undecidable) {
            return null;
        }
        return (bool)$negated;
    }

    // ------------------------------------------------------------------
    // Ports
    // ------------------------------------------------------------------

    private static function portNumber($token, $protocol)
    {
        if (ctype_digit($token)) {
            $n = (int)$token;
            return $n <= self::PORT_MAX ? $n : false;
        }
        if (in_array($protocol, ['tcp', 'udp'], true)) {
            $n = getservbyname($token, $protocol);
            if ($n !== false) {
                return $n;
            }
        }
        return false;
    }

    /**
     * Parse a pf port spec as captured by get_ruleset.py into inclusive
     * [lo, hi] ranges.
     *
     * Forms: "= 80", "!= 80", "< 1024", "<= 1024", "> 1024", ">= 1024",
     * "1000:2000" (inclusive), "1000 >< 2000" (exclusive between),
     * "1000 <> 2000" (outside), bare "80", "{ 80 443 }", and service names
     * ("= ssh") resolved via the system services database.
     *
     * @param string|null $spec
     * @param string $protocol 'tcp' or 'udp' (for service-name lookup)
     * @return array|null|false list of [lo, hi]; null = no port constraint; false = unparseable
     */
    public static function parsePortSpec($spec, $protocol)
    {
        if ($spec === null) {
            return null;
        }
        $spec = trim($spec);
        if ($spec === '') {
            return null;
        }

        if ($spec[0] === '{' && substr($spec, -1) === '}') {
            $ranges = [];
            foreach (preg_split('/[\s,]+/', trim(substr($spec, 1, -1)), -1, PREG_SPLIT_NO_EMPTY) as $item) {
                $sub = self::parsePortSpec($item, $protocol);
                if (!is_array($sub)) {
                    return false;
                }
                $ranges = array_merge($ranges, $sub);
            }
            return $ranges ?: false;
        }

        if (preg_match('/^(!=|<=|>=|=|<|>)\s*(\S+)$/', $spec, $m)) {
            $n = self::portNumber($m[2], $protocol);
            if ($n === false) {
                return false;
            }
            switch ($m[1]) {
                case '=':
                    return [[$n, $n]];
                case '!=':
                    return array_values(array_filter([
                        [self::PORT_MIN, $n - 1],
                        [$n + 1, self::PORT_MAX],
                    ], function ($r) {
                        return $r[0] <= $r[1];
                    }));
                case '<':
                    return $n > self::PORT_MIN ? [[self::PORT_MIN, $n - 1]] : false;
                case '<=':
                    return [[self::PORT_MIN, $n]];
                case '>':
                    return $n < self::PORT_MAX ? [[$n + 1, self::PORT_MAX]] : false;
                case '>=':
                    return [[$n, self::PORT_MAX]];
            }
        }

        if (preg_match('/^(\S+)\s*(><|<>)\s*(\S+)$/', $spec, $m)) {
            $a = self::portNumber($m[1], $protocol);
            $b = self::portNumber($m[3], $protocol);
            if ($a === false || $b === false) {
                return false;
            }
            if ($m[2] === '><') {
                return $a + 1 <= $b - 1 ? [[$a + 1, $b - 1]] : false;
            }
            return array_values(array_filter([
                [self::PORT_MIN, $a - 1],
                [$b + 1, self::PORT_MAX],
            ], function ($r) {
                return $r[0] <= $r[1];
            }));
        }

        if (preg_match('/^(\S+):(\S+)$/', $spec, $m)) {
            $a = self::portNumber($m[1], $protocol);
            $b = self::portNumber($m[2], $protocol);
            if ($a === false || $b === false || $a > $b) {
                return false;
            }
            return [[$a, $b]];
        }

        $n = self::portNumber($spec, $protocol);
        return $n === false ? false : [[$n, $n]];
    }

    // ------------------------------------------------------------------
    // Rule preparation
    // ------------------------------------------------------------------

    /**
     * Normalise parsed rules for evaluation, once per request: resolve
     * dynamic address forms against the interface map and parse port specs
     * into ranges. Must be called before any evaluation below.
     *
     * @param array $rules descr-attached rules from attachDescriptions()
     * @param array $ifaces interface map
     * @return array
     */
    public static function prepareRules(array $rules, array $ifaces)
    {
        foreach ($rules as &$rule) {
            foreach (['source', 'destination'] as $side) {
                $resolved = [];
                foreach ($rule[$side] as $entry) {
                    $dyn = is_string($entry) ? self::resolveDynamicAddr($entry, $ifaces) : null;
                    if ($dyn === null) {
                        $resolved[] = $entry;
                    } else {
                        $resolved = array_merge($resolved, $dyn);
                    }
                }
                $rule[$side] = $resolved;
            }
            $proto = strtolower($rule['protocol'] ?? 'any');
            $rule['to_ports'] = self::parsePortSpec($rule['to_port'] ?? null, $proto);
            $rule['from_ports'] = self::parsePortSpec($rule['from_port'] ?? null, $proto);
            $rule['src_cover'] = self::sourceCover($rule['from_ports']);
        }
        return $rules;
    }

    /**
     * Classify a parsed source-port set against the usable source ports.
     *
     * @param array|null|false $ranges from parsePortSpec()
     * @return string|null SRC_* constant; null = unparseable (undecidable)
     */
    private static function sourceCover($ranges)
    {
        if ($ranges === null) {
            return self::SRC_ALL;
        }
        if ($ranges === false) {
            return null;
        }
        $covered = 0;
        foreach ($ranges as [$lo, $hi]) {
            $lo = max($lo, self::SRC_PORT_MIN);
            if ($hi >= $lo) {
                $covered += $hi - $lo + 1;
            }
        }
        if ($covered === 0) {
            return self::SRC_NONE;
        }
        // ranges from one spec don't overlap, so a full count means full cover
        return $covered >= self::PORT_MAX - self::SRC_PORT_MIN + 1 ? self::SRC_ALL : self::SRC_PARTIAL;
    }

    // ------------------------------------------------------------------
    // Evaluation
    // ------------------------------------------------------------------

    /**
     * Tri-state: does $rule match query $q?
     *
     * $q keys: if (physical), dir ('in'|'out'), src, dst (IPv4), and
     * optionally proto + port_lo/port_hi. A missing 'proto' means "any
     * protocol/port" - used for candidate pre-filtering, where only the
     * address/interface/direction/family dimensions are checked.
     *
     * Port slices are built from every rule boundary (see sliceBoundaries),
     * so a slice is always entirely inside or entirely outside a rule's
     * port set; checking port_lo is enough, port_hi is checked for safety.
     *
     * @param array $rule prepared rule
     * @param array $q
     * @param array $ifaces interface map (for recognising interface names)
     * @return bool|null
     */
    public static function matchRule(array $rule, array $q, array $ifaces)
    {
        // inet rules only see IPv4 traffic, inet6 rules only IPv6
        $family = self::ipFamily($q['src']) ?? 4;
        $ruleFamily = $rule['ipprotocol'] ?? 'any';
        if (($ruleFamily === 'inet6' && $family === 4) || ($ruleFamily === 'inet' && $family === 6)) {
            return false;
        }
        if (($rule['direction'] ?? 'any') !== 'any' && $rule['direction'] !== $q['dir']) {
            return false;
        }

        $undecidable = false;

        if ($rule['interface'] !== 'any') {
            $known = isset($ifaces[$rule['interface']]);
            $same = $rule['interface'] === $q['if'];
            if (!$known && !$same) {
                // not a physical interface we know: likely an interface group
                // (which may include $q['if']) - can't tell
                $undecidable = true;
            } elseif (!empty($rule['interface_not']) ? $same : !$same) {
                // "on X" on another interface, or "on ! X" on X itself
                return false;
            }
        }

        if (isset($q['proto'])) {
            $rproto = strtolower($rule['protocol'] ?? 'any');
            if ($rproto !== 'any' && $rproto !== $q['proto']) {
                return false;
            }
            if (isset($q['port_lo'])) {
                // source port: the client chooses it, so a rule that only
                // covers some source ports can be dodged. A block covering
                // only some (or no usable) source ports therefore never
                // stops the flow; a pass covering some still allows it
                // (flagged conditional in evaluate()).
                $cover = array_key_exists('src_cover', $rule) ? $rule['src_cover'] : self::SRC_ALL;
                if ($cover === null) {
                    $undecidable = true;
                } elseif ($cover === self::SRC_NONE) {
                    return false;
                } elseif ($cover === self::SRC_PARTIAL && $rule['action'] === self::VERDICT_BLOCK) {
                    return false;
                }
                if ($rule['to_ports'] === false) {
                    $undecidable = true;
                } elseif (is_array($rule['to_ports'])) {
                    $inside = false;
                    foreach ($rule['to_ports'] as [$lo, $hi]) {
                        if ($q['port_lo'] >= $lo && $q['port_hi'] <= $hi) {
                            $inside = true;
                            break;
                        }
                    }
                    if (!$inside) {
                        return false;
                    }
                }
            }
        }

        foreach ([['source', 'source_not', 'src'], ['destination', 'destination_not', 'dst']] as [$side, $not, $key]) {
            $m = self::matchSide($rule[$side], !empty($rule[$not]), $q[$key]);
            if ($m === false) {
                return false;
            }
            if ($m === null) {
                $undecidable = true;
            }
        }

        return $undecidable ? null : true;
    }

    /**
     * Walk the ordered ruleset applying pf's real semantics: first `quick`
     * match wins; otherwise the LAST matching rule wins; otherwise default
     * deny. $rules must be in pf evaluation order (get_ruleset.py 'seq').
     *
     * Undecidable rules encountered before the deciding point are collected
     * in 'uncertain' (labels) - but only those whose action differs from
     * the final verdict. If an undecidable rule did match, the most it
     * could do is make the verdict its own action, so an undecidable block
     * on an already-blocked flow (or pass on a passed one) can't change
     * the answer. Without this, one unresolvable block table would mark
     * every flow on the box as a possible hole.
     * 'conditional' is set when the deciding rule only matches particular
     * source ports - clients choose their source port, so the flow is only
     * possible under that condition.
     *
     * @return array{verdict: string, rule: array|null, uncertain: string[], conditional: bool}
     */
    public static function evaluate(array $rules, array $q, array $ifaces)
    {
        $verdict = self::VERDICT_BLOCK;
        $matchingRule = null;
        $uncertain = [];

        foreach ($rules as $rule) {
            $m = self::matchRule($rule, $q, $ifaces);
            if ($m === false) {
                continue;
            }
            if ($m === null) {
                $uncertain[$rule['label']] = $rule['action'] === self::VERDICT_BLOCK ? self::VERDICT_BLOCK : self::VERDICT_PASS;
                continue;
            }
            $verdict = $rule['action'] === self::VERDICT_BLOCK ? self::VERDICT_BLOCK : self::VERDICT_PASS;
            $matchingRule = $rule;
            if (!empty($rule['quick'])) {
                break;
            }
        }

        return [
            'verdict' => $verdict,
            'rule' => $matchingRule,
            'uncertain' => array_keys(array_filter($uncertain, function ($action) use ($verdict) {
                return $action !== $verdict;
            })),
            'conditional' => $matchingRule !== null && ($matchingRule['src_cover'] ?? self::SRC_ALL) === self::SRC_PARTIAL,
        ];
    }

    /**
     * Rules that could possibly match traffic for $q on some protocol/port,
     * i.e. matchRule() with protocol and ports left open isn't false.
     * Order is preserved.
     */
    private static function candidates(array $rules, array $q, array $ifaces)
    {
        return array_values(array_filter($rules, function ($rule) use ($q, $ifaces) {
            return self::matchRule($rule, $q, $ifaces) !== false;
        }));
    }

    /**
     * Protocol classes worth evaluating for a set of candidate rules: tcp,
     * udp and icmp always, every other protocol explicitly named by a
     * candidate, and PROTO_OTHER for "any other protocol" (only `proto any`
     * rules can decide that one).
     *
     * @return string[]
     */
    private static function protocolClasses(array $rules)
    {
        $classes = ['tcp' => true, 'udp' => true, 'icmp' => true];
        foreach ($rules as $rule) {
            $p = strtolower($rule['protocol'] ?? 'any');
            if ($p !== 'any') {
                $classes[$p] = true;
            }
        }
        $classes[self::PROTO_OTHER] = true;
        return array_keys($classes);
    }

    /**
     * Split 0-65535 into [lo, hi] slices at every port boundary any rule
     * for $proto mentions, so each slice is uniformly inside or outside
     * every rule's port set.
     *
     * @return array list of [lo, hi]
     */
    private static function sliceBoundaries(array $rules, $proto)
    {
        $cuts = [self::PORT_MIN => true, self::PORT_MAX + 1 => true];
        foreach ($rules as $rule) {
            if (strtolower($rule['protocol'] ?? 'any') !== $proto || !is_array($rule['to_ports'])) {
                continue;
            }
            foreach ($rule['to_ports'] as [$lo, $hi]) {
                $cuts[$lo] = true;
                $cuts[$hi + 1] = true;
            }
        }
        $cuts = array_keys($cuts);
        sort($cuts);
        $slices = [];
        for ($i = 0; $i < count($cuts) - 1; $i++) {
            $slices[] = [$cuts[$i], $cuts[$i + 1] - 1];
        }
        return $slices;
    }

    /**
     * Full slice-by-slice evaluation of flows from $src to one target
     * address.
     *
     * $src: ['ip' => ..., 'if' => physical]. Traffic is checked against
     * `in` rules on the source's interface. If $dstIf is given (a device
     * behind another interface), allowed traffic must ALSO pass `out` rules
     * on that interface; if null (the firewall itself is the target), only
     * the inbound check applies.
     *
     * @return array list of slices: {proto, from, to, verdict, rule, stage,
     *               uncertain, conditional}; from/to are null for
     *               non-port protocols. 'rule' is the deciding rule label
     *               (null = default deny); 'stage' is 'in' or 'out'.
     */
    public static function evaluateFlows(array $rules, array $src, $dstIp, $dstIf, array $ifaces)
    {
        $qIn = ['if' => $src['if'], 'dir' => 'in', 'src' => $src['ip'], 'dst' => $dstIp];
        $qOut = $dstIf !== null ? ['if' => $dstIf, 'dir' => 'out', 'src' => $src['ip'], 'dst' => $dstIp] : null;

        $inRules = self::candidates($rules, $qIn, $ifaces);
        $outRules = $qOut !== null ? self::candidates($rules, $qOut, $ifaces) : [];
        $all = array_merge($inRules, $outRules);

        $slices = [];
        foreach (self::protocolClasses($all) as $proto) {
            $ranges = in_array($proto, ['tcp', 'udp'], true)
                ? self::sliceBoundaries($all, $proto)
                : [[null, null]];
            foreach ($ranges as [$lo, $hi]) {
                $extra = ['proto' => $proto];
                if ($lo !== null) {
                    $extra['port_lo'] = $lo;
                    $extra['port_hi'] = $hi;
                }
                $in = self::evaluate($inRules, $qIn + $extra, $ifaces);
                $result = $in;
                $stage = 'in';
                if ($in['verdict'] === self::VERDICT_PASS && $qOut !== null) {
                    $out = self::evaluate($outRules, $qOut + $extra, $ifaces);
                    if ($out['verdict'] === self::VERDICT_BLOCK) {
                        // blocked on the way out: the inbound stage's
                        // uncertain rules are all blocks (filtered against
                        // its pass verdict), so they can't change this
                        $result = $out;
                        $stage = 'out';
                    } else {
                        $result['uncertain'] = array_merge($in['uncertain'], $out['uncertain']);
                        $result['conditional'] = $in['conditional'] || $out['conditional'];
                    }
                }
                $slices[] = [
                    'proto' => $proto,
                    'from' => $lo,
                    'to' => $hi,
                    'verdict' => $result['verdict'],
                    'rule' => $result['rule']['label'] ?? null,
                    'stage' => $stage,
                    'uncertain' => array_values(array_unique($result['uncertain'])),
                    'conditional' => $result['conditional'],
                ];
            }
        }

        return self::mergeSlices($slices);
    }

    /**
     * Merge adjacent port slices of the same protocol with identical
     * outcome, so "tcp 0-444 block, 445 pass, 446-65535 block" stays three
     * entries however many unrelated boundaries other rules introduced.
     */
    private static function mergeSlices(array $slices)
    {
        $merged = [];
        foreach ($slices as $slice) {
            $last = end($merged);
            if (
                $last !== false
                && $last['proto'] === $slice['proto']
                && $last['from'] !== null
                && $last['to'] + 1 === $slice['from']
                && $last['verdict'] === $slice['verdict']
                && $last['rule'] === $slice['rule']
                && $last['stage'] === $slice['stage']
                && $last['uncertain'] === $slice['uncertain']
                && $last['conditional'] === $slice['conditional']
            ) {
                $merged[count($merged) - 1]['to'] = $slice['to'];
            } else {
                $merged[] = $slice;
            }
        }
        return $merged;
    }

    // ------------------------------------------------------------------
    // Dead (shadowed) rules
    // ------------------------------------------------------------------

    public const DEAD_CONTRADICTED = 'contradicted'; // covered by a rule with the opposite action
    public const DEAD_REDUNDANT = 'redundant';       // covered by a rule with the same action

    /**
     * pf keywords that restrict a rule beyond what get_ruleset.py parses.
     * A rule carrying one matches less than its parsed fields suggest, so it
     * can't be used to prove it covers another rule.
     */
    private const UNPARSED_RESTRICTIONS = ['icmp-type', 'icmp6-type', 'tagged', 'user', 'group', 'os', 'tos', 'probability', 'received-on'];

    /** rules using pf tables (OPNsense aliases, lockout lists, ...) */
    private static function usesTable(array $rule)
    {
        return strpos($rule['text'] ?? '', '<') !== false;
    }

    /**
     * Which sides of a rule reference a pf table, from its pf text (after
     * table expansion the parsed fields no longer say). Table contents can
     * change at runtime, so a side with a table can only be judged covered
     * by a rule that says 'any' there - then the contents don't matter.
     *
     * @return array{source: bool, destination: bool}
     */
    private static function tableSides(array $rule)
    {
        $text = $rule['text'] ?? '';
        return [
            'source' => (bool)preg_match('/\sfrom\s+(?:!\s*)?<[^>]+>/', $text),
            'destination' => (bool)preg_match('/\sto\s+(?:!\s*)?<[^>]+>/', $text),
        ];
    }

    private static function hasUnparsedRestriction(array $rule)
    {
        foreach (self::UNPARSED_RESTRICTIONS as $kw) {
            if (preg_match('/\s' . preg_quote($kw, '/') . '\s/', $rule['text'] ?? '')) {
                return true;
            }
        }
        return false;
    }

    /** is IPv4 spec entry $inner (address or CIDR) inside $outer? */
    private static function cidrInside($inner, $outer)
    {
        $ip = explode('/', $inner, 2);
        $op = explode('/', $outer, 2);
        $fam = self::ipFamily($ip[0]);
        if ($fam === null || $fam !== self::ipFamily($op[0])) {
            return false;
        }
        $max = $fam === 4 ? 32 : 128;
        $ibits = isset($ip[1]) ? (int)$ip[1] : $max;
        $obits = isset($op[1]) ? (int)$op[1] : $max;
        return $obits <= $ibits && self::inCidr($ip[0], $outer);
    }

    /**
     * Does address spec A (one side of a rule) definitely include every
     * address spec B can match? Conservative: anything unresolved, any
     * negation other than identical negations, or IPv6 entries not covered
     * by 'any' (or an identical entry) means "can't prove it" = false.
     */
    private static function sideCovers(array $a, $aNot, array $b, $bNot)
    {
        $aAny = in_array('any', $a, true) && !$aNot;
        if ($aAny) {
            return true;
        }
        if ($aNot || $bNot) {
            return $aNot && $bNot && $a == $b;
        }
        if (empty($b)) {
            return false;
        }
        foreach ($b as $entry) {
            if (!is_string($entry) || $entry === 'any') {
                return false;
            }
            $inside = false;
            foreach ($a as $outer) {
                if (!is_string($outer)) {
                    continue;
                }
                if ($outer === $entry) {
                    $inside = true;
                } elseif ((self::isIpv4Spec($entry) && self::isIpv4Spec($outer))
                    || (self::isIpv6Spec($entry) && self::isIpv6Spec($outer))) {
                    $inside = self::cidrInside($entry, $outer);
                }
                if ($inside) {
                    break;
                }
            }
            if (!$inside) {
                return false;
            }
        }
        return true;
    }

    /** do port ranges A include every port in B? (null = all ports) */
    private static function portsCover($a, $b)
    {
        if ($a === null) {
            return true;
        }
        if ($a === false || $b === false) {
            return false;
        }
        $b = $b ?? [[self::PORT_MIN, self::PORT_MAX]];
        foreach ($b as [$lo, $hi]) {
            $covered = false;
            foreach ($a as [$alo, $ahi]) {
                if ($alo <= $lo && $hi <= $ahi) {
                    $covered = true;
                    break;
                }
            }
            if (!$covered) {
                return false;
            }
        }
        return true;
    }

    /**
     * Does rule A match (at least) every packet rule B matches? Every
     * dimension must be provably covered; unknowns answer false.
     */
    public static function ruleCovers(array $a, array $b, array $ifaces)
    {
        if (self::usesTable($a) || self::hasUnparsedRestriction($a)) {
            return false;
        }
        // direction
        if ($a['direction'] !== 'any' && $a['direction'] !== $b['direction']) {
            return false;
        }
        // address family
        $af = $a['ipprotocol'] ?? 'any';
        if ($af !== 'any' && $af !== ($b['ipprotocol'] ?? 'any')) {
            return false;
        }
        // interface
        if ($a['interface'] !== 'any') {
            if ($b['interface'] === 'any') {
                return false;
            }
            $aNot = !empty($a['interface_not']);
            $bNot = !empty($b['interface_not']);
            if (!$aNot && !$bNot) {
                if ($a['interface'] !== $b['interface']) {
                    return false;
                }
            } elseif ($aNot && !$bNot) {
                // "all but X" covers "Y" only for a known Y that isn't X
                if ($a['interface'] === $b['interface'] || !isset($ifaces[$b['interface']])) {
                    return false;
                }
            } elseif ($aNot && $bNot) {
                if ($a['interface'] !== $b['interface']) {
                    return false;
                }
            } else {
                return false;
            }
        }
        // protocol and ports
        $ap = strtolower($a['protocol'] ?? 'any');
        if ($ap !== 'any' && $ap !== strtolower($b['protocol'] ?? 'any')) {
            return false;
        }
        if (!self::portsCover($a['to_ports'], $b['to_ports']) || !self::portsCover($a['from_ports'], $b['from_ports'])) {
            return false;
        }
        // addresses; a side where B uses a table is covered only by 'any',
        // since the table's contents can change
        $bTables = self::tableSides($b);
        foreach (['source', 'destination'] as $side) {
            if ($bTables[$side]) {
                if (!in_array('any', $a[$side], true) || !empty($a[$side . '_not'])) {
                    return false;
                }
            } elseif (!self::sideCovers($a[$side], !empty($a[$side . '_not']), $b[$side], !empty($b[$side . '_not']))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Find rules that can never decide anything because another rule always
     * gets the final say first, under pf semantics:
     *   - a quick rule is dead if an EARLIER quick rule covers it;
     *   - a non-quick rule is dead if an earlier quick rule covers it, or
     *     ANY later rule does (last match wins).
     * One OPNsense rule (label) can expand to several pf lines; it's dead
     * only if every line is. pf tables (OPNsense aliases, lockout lists)
     * can change at runtime: a rule using one is judged only where the
     * covering rule says 'any' on that side, and a covering rule's own
     * tables never count as proof. Known gap: a rule covered only by
     * several rules together, not by any single one, isn't detected.
     *
     * @param array $rules prepared rules, in pf order
     * @return array label => ['by' => label of the (first) covering rule,
     *               'kind' => DEAD_CONTRADICTED|DEAD_REDUNDANT,
     *               'position' => 'earlier' (a quick rule before it decides
     *               first) | 'later' (a later rule overrides this non-quick
     *               rule: last match wins)]
     */
    public static function deadRules(array $rules, array $ifaces)
    {
        $lineVerdicts = []; // label => list of covering rule per line (null = alive)
        $n = count($rules);
        for ($i = 0; $i < $n; $i++) {
            $b = $rules[$i];
            $cover = null;
            {
                $candidates = [];
                for ($j = 0; $j < $i; $j++) {
                    if (!empty($rules[$j]['quick'])) {
                        $candidates[] = $j;
                    }
                }
                if (empty($b['quick'])) {
                    for ($j = $i + 1; $j < $n; $j++) {
                        $candidates[] = $j;
                    }
                }
                foreach ($candidates as $j) {
                    $a = $rules[$j];
                    if ($a['label'] !== $b['label'] && self::ruleCovers($a, $b, $ifaces)) {
                        $cover = $a + ['_position' => $j < $i ? 'earlier' : 'later'];
                        break;
                    }
                }
            }
            $lineVerdicts[$b['label']][] = $cover;
        }

        $dead = [];
        foreach ($rules as $rule) {
            $label = $rule['label'];
            if (isset($dead[$label]) || !isset($lineVerdicts[$label]) || in_array(null, $lineVerdicts[$label], true)) {
                continue;
            }
            $contradicted = false;
            foreach ($lineVerdicts[$label] as $cover) {
                if ($cover['action'] !== $rule['action']) {
                    $contradicted = true;
                }
            }
            $dead[$label] = [
                'by' => $lineVerdicts[$label][0]['label'],
                'kind' => $contradicted ? self::DEAD_CONTRADICTED : self::DEAD_REDUNDANT,
                'position' => $lineVerdicts[$label][0]['_position'],
            ];
        }
        return $dead;
    }

    /**
     * The graph pairs a rule was written for: every (source device,
     * destination node) whose traffic the rule would match, ignoring
     * protocol and ports. For a dead rule these are the flows it was meant
     * to affect but never does - used to highlight them on the graph.
     * Undecidable matches count (better to show a maybe than hide it).
     *
     * @param array $lines prepared pf lines sharing one label
     * @param array $devices placed devices
     * @return array list of [fromNodeId, toNodeId]
     */
    public static function rulePairs(array $lines, array $devices, array $ifaces)
    {
        $evaluable = array_values(array_filter($devices, [self::class, 'evaluable']));
        $wans = self::wanInterfaces($ifaces);
        $pairs = [];
        foreach ($evaluable as $src) {
            foreach ([4, 6] as $family) {
                $srcAddr = self::deviceAddr($src, $family);
                if ($srcAddr === null) {
                    continue;
                }
                $dests = [];
                foreach ($evaluable as $dst) {
                    $dstAddr = self::deviceAddr($dst, $family);
                    if ($dst['id'] !== $src['id'] && $dstAddr !== null && $dstAddr !== $srcAddr) {
                        $dests[] = ['node' => 'device:' . $dst['id'], 'ip' => $dstAddr, 'if' => $dst['if']];
                    }
                }
                foreach (self::firewallTargets($ifaces, $family, $src['if']) as $t) {
                    $dests[] = ['node' => self::NODE_FIREWALL, 'ip' => $t['ip'], 'if' => null];
                }
                if (!empty($wans) && !in_array($src['if'], $wans, true)) {
                    $internet = self::internetTargets($lines, $ifaces, $family);
                    $dests[] = ['node' => self::NODE_WAN, 'ip' => $internet['general'], 'if' => $wans[0]];
                    foreach ($internet['regions'] as $ip) {
                        $dests[] = ['node' => self::NODE_WAN, 'ip' => $ip, 'if' => $wans[0]];
                    }
                }
                foreach ($dests as $dst) {
                    $key = 'device:' . $src['id'] . '>' . $dst['node'];
                    if (isset($pairs[$key])) {
                        continue;
                    }
                    foreach ($lines as $line) {
                        if (($line['direction'] ?? 'any') === 'out') {
                            if ($dst['if'] === null) {
                                continue; // traffic to the firewall itself never leaves via out
                            }
                            $q = ['if' => $dst['if'], 'dir' => 'out'];
                        } else {
                            $q = ['if' => $src['if'], 'dir' => 'in'];
                        }
                        $q['src'] = $srcAddr;
                        $q['dst'] = $dst['ip'];
                        if (self::matchRule($line, $q, $ifaces) !== false) {
                            $pairs[$key] = ['device:' . $src['id'], $dst['node']];
                            break;
                        }
                    }
                }
            }
        }
        return array_values($pairs);
    }

    /**
     * deadRules() as a list for the UI: one entry per dead rule with its
     * own and its shadowing rule's description, action and automatic flag,
     * and the graph pairs it was written for (rulePairs()).
     */
    public static function deadRuleFindings(array $rules, array $ifaces, array $devices = [])
    {
        $byLabel = [];
        foreach ($rules as $rule) {
            if (!isset($byLabel[$rule['label']])) {
                $byLabel[$rule['label']] = $rule;
            }
        }
        $out = [];
        foreach (self::deadRules($rules, $ifaces) as $label => $d) {
            $rule = $byLabel[$label];
            $by = $byLabel[$d['by']];
            $lines = array_values(array_filter($rules, function ($r) use ($label) {
                return $r['label'] === $label;
            }));
            $out[] = [
                'label' => $label,
                'descr' => $rule['descr'] ?? $rule['text'],
                'action' => $rule['action'],
                'automatic' => !empty($rule['automatic']),
                'kind' => $d['kind'],
                'by' => $d['by'],
                'by_descr' => $by['descr'] ?? $by['text'],
                'by_action' => $by['action'],
                'by_position' => $d['position'],
                'pairs' => self::rulePairs($lines, $devices, $ifaces),
            ];
        }
        return $out;
    }

    /**
     * pf tables that are normally empty (lockout/overload lists filled at
     * runtime), so an empty one is no sign of a problem.
     */
    private const NORMALLY_EMPTY_TABLES = ['sshlockout', 'virusprot'];

    /**
     * Rules that reference a pf table which was EMPTY when the ruleset was
     * read. With OPNsense this usually means an alias saved but not applied
     * (pf's table only fills on Apply). Real case, testlab 2026-10-17:
     * `to ! <net_rfc1918>` with an unapplied alias matched everything,
     * letting IoT reach the firewall on every port.
     *   - "! table" (negated) then matches EVERYTHING - the dangerous case
     *   - "table" matches nothing
     *
     * @param array $rules rules with 'text' and 'descr'
     * @param array $tables table name => entry count (null = unreadable)
     * @return array [{name, negated: bool, rules: [{label, descr, negated}]}],
     *               negated tables first
     */
    public static function emptyTableFindings(array $rules, array $tables)
    {
        $out = [];
        foreach ($tables as $name => $count) {
            if ($count !== 0 || in_array($name, self::NORMALLY_EMPTY_TABLES, true)) {
                continue;
            }
            $users = [];
            foreach ($rules as $rule) {
                if (!preg_match_all('/(!\s*)?<' . preg_quote($name, '/') . '>/', $rule['text'] ?? '', $m)) {
                    continue;
                }
                $negated = in_array(true, array_map(function ($bang) {
                    return trim($bang) === '!';
                }, $m[1]), true);
                $label = $rule['label'];
                if (!isset($users[$label])) {
                    $users[$label] = ['label' => $label, 'descr' => $rule['descr'] ?? $rule['text'], 'negated' => $negated];
                } else {
                    $users[$label]['negated'] = $users[$label]['negated'] || $negated;
                }
            }
            if (empty($users)) {
                continue;
            }
            $users = array_values($users);
            $out[] = [
                'name' => $name,
                'negated' => in_array(true, array_column($users, 'negated'), true),
                'rules' => $users,
            ];
        }
        usort($out, function ($a, $b) {
            return (int)$b['negated'] - (int)$a['negated'];
        });
        return $out;
    }

    // ------------------------------------------------------------------
    // Inbound from the internet: port forwards (rdr) and direct
    // ------------------------------------------------------------------

    /**
     * Normalise parsed redirects (get_ruleset.py 'redirects', pf order):
     * resolve (ifname) forms, parse port specs.
     */
    public static function prepareRedirects(array $redirects, array $ifaces)
    {
        foreach ($redirects as &$r) {
            foreach (['source', 'destination', 'target'] as $side) {
                $out = [];
                foreach ($r[$side] ?? [] as $entry) {
                    $dyn = is_string($entry) ? self::resolveDynamicAddr($entry, $ifaces) : null;
                    $out = $dyn === null ? array_merge($out, [$entry]) : array_merge($out, $dyn);
                }
                $r[$side] = $out;
            }
            $proto = $r['protocol'] === 'any' ? 'tcp' : $r['protocol'];
            $r['to_ports'] = self::parsePortSpec($r['to_port'] ?? null, $proto);
            $r['target_ports'] = self::parsePortSpec($r['target_port'] ?? null, $proto);
        }
        return $redirects;
    }

    /** label used for an rdr pass forward in the graph's rule map */
    private static function forwardLabel(array $r)
    {
        return 'fwd-' . $r['seq'];
    }

    /**
     * Port forwards on the WAN that send traffic to one of $addresses, each
     * with its external and internal port range. An earlier rdr or no rdr
     * covering the same protocol and ports takes precedence (pf uses the
     * first matching redirect), so such a forward is left out.
     *
     * @return array [{redirect, proto, ext: [lo, hi]|null, int: [lo, hi]|null, target}]
     */
    public static function forwardsTo(array $redirects, array $addresses, array $ifaces)
    {
        $wans = self::wanInterfaces($ifaces);
        $out = [];
        foreach ($redirects as $i => $r) {
            if ($r['no'] || ($r['interface'] !== 'any' && !in_array($r['interface'], $wans, true))) {
                continue;
            }
            $target = null;
            foreach ($r['target'] as $t) {
                if (is_string($t) && in_array(self::canonical($t), array_map([self::class, 'canonical'], $addresses), true)) {
                    $target = $t;
                    break;
                }
            }
            if ($target === null) {
                continue;
            }
            $shadowed = false;
            for ($j = 0; $j < $i; $j++) {
                $e = $redirects[$j];
                if (($e['interface'] === 'any' || $e['interface'] === $r['interface'])
                    && ($e['protocol'] === 'any' || $e['protocol'] === $r['protocol'])
                    && self::portsCover($e['to_ports'], $r['to_ports'])
                    && in_array('any', $e['source'], true) && !$e['destination_not']
                    && (in_array('any', $e['destination'], true) || array_intersect($e['destination'], $r['destination']))) {
                    $shadowed = true;
                    break;
                }
            }
            if ($shadowed) {
                continue;
            }
            $protos = $r['protocol'] === 'any' ? ['tcp', 'udp'] : [$r['protocol']];
            $extRanges = is_array($r['to_ports']) ? $r['to_ports'] : [null];
            foreach ($protos as $proto) {
                foreach ($extRanges as $ext) {
                    $int = $ext;
                    if (is_array($r['target_ports']) && $ext !== null) {
                        // pf maps an external range onto the target port onward
                        $base = $r['target_ports'][0][0];
                        $int = [$base, $base + ($ext[1] - $ext[0])];
                    }
                    $out[] = ['redirect' => $r, 'proto' => $proto, 'ext' => $ext, 'int' => $int, 'target' => $target];
                }
            }
        }
        return $out;
    }

    /** slices restricted to one protocol and (optionally) a port range */
    private static function slicesWithin(array $slices, $proto, $range)
    {
        $out = [];
        foreach ($slices as $s) {
            if ($s['proto'] !== $proto) {
                continue;
            }
            if ($range === null || $s['from'] === null) {
                $out[] = $s;
                continue;
            }
            $lo = max($s['from'], $range[0]);
            $hi = min($s['to'], $range[1]);
            if ($lo <= $hi) {
                $out[] = ['from' => $lo, 'to' => $hi] + $s;
            }
        }
        return $out;
    }

    /**
     * What the internet can reach on a device: through port forwards, and
     * directly where its address is publicly routable (in practice global
     * IPv6 - IPv6 has no NAT). Filter rules are evaluated after
     * translation, as pf does: in on the WAN, then out on the device's
     * segment. "rdr pass" forwards skip filtering.
     *
     * @return array{targets: array, forwards: array} targets in the same
     *         shape as evaluatePair (for summarisePair); forwards for the
     *         card / findings: [{label, text, pass, proto, ext, int, target,
     *         allowed: bool}]
     */
    public static function evaluateInbound(array $rules, array $redirects, array $dst, array $ifaces)
    {
        $wans = self::wanInterfaces($ifaces);
        $result = ['targets' => [], 'forwards' => []];
        if (empty($wans) || in_array($dst['if'], $wans, true)) {
            return $result;
        }
        $wan = $wans[0];
        $internet4 = self::internetTargets($rules, $ifaces, 4)['general'];

        // port forwards (IPv4)
        $addr4 = self::deviceAddr($dst, 4);
        if ($addr4 !== null) {
            $after = self::evaluateFlows($rules, ['ip' => $internet4, 'if' => $wan], $addr4, $dst['if'], $ifaces);
            $slices = [];
            foreach (self::forwardsTo($redirects, [$addr4], $ifaces) as $f) {
                $r = $f['redirect'];
                if ($r['pass']) {
                    $parts = [[
                        'proto' => $f['proto'], 'from' => $f['int'][0] ?? null, 'to' => $f['int'][1] ?? null,
                        'verdict' => self::VERDICT_PASS, 'rule' => self::forwardLabel($r), 'stage' => 'in',
                        'uncertain' => [], 'conditional' => false,
                    ]];
                } else {
                    $parts = self::slicesWithin($after, $f['proto'], $f['int']);
                }
                $allowed = false;
                foreach ($parts as $p) {
                    $slices[] = $p;
                    $allowed = $allowed || $p['verdict'] === self::VERDICT_PASS;
                }
                $result['forwards'][] = [
                    'label' => self::forwardLabel($r),
                    'text' => $r['text'],
                    'pass' => $r['pass'],
                    'proto' => $f['proto'],
                    'ext' => $f['ext'],
                    'int' => $f['int'],
                    'target' => $f['target'],
                    'allowed' => $allowed,
                ];
            }
            if (!empty($slices)) {
                $result['targets'][] = ['ip' => $addr4, 'family' => 'inet', 'slices' => $slices];
            }
        }

        // direct (no translation) to a publicly routable address: global IPv6
        $addr6 = self::deviceAddr($dst, 6);
        if ($addr6 !== null && !self::inCidr($addr6, self::ULA6) && self::hasGlobalIpv6($ifaces[$wan] ?? [])) {
            $internet6 = self::internetTargets($rules, $ifaces, 6)['general'];
            $result['targets'][] = [
                'ip' => $addr6, 'family' => 'inet6',
                'slices' => self::evaluateFlows($rules, ['ip' => $internet6, 'if' => $wan], $addr6, $dst['if'], $ifaces),
            ];
        }
        return $result;
    }

    /**
     * What the internet can reach on the firewall itself: its own WAN
     * addresses (e.g. the web GUI or SSH exposed on WAN).
     */
    public static function evaluateInboundFirewall(array $rules, array $ifaces)
    {
        $wans = self::wanInterfaces($ifaces);
        if (empty($wans)) {
            return ['targets' => []];
        }
        $wan = $wans[0];
        $targets = [];
        foreach ([4, 6] as $family) {
            if ($family === 6 && !self::hasGlobalIpv6($ifaces[$wan] ?? [])) {
                continue;
            }
            $src = self::internetTargets($rules, $ifaces, $family)['general'];
            foreach (self::firewallTargets($ifaces, $family, null) as $t) {
                if ($t['if'] !== $wan) {
                    continue;
                }
                $targets[] = [
                    'ip' => $t['ip'], 'family' => $family === 6 ? 'inet6' : 'inet',
                    'slices' => self::evaluateFlows($rules, ['ip' => $src, 'if' => $wan], $t['ip'], null, $ifaces),
                ];
            }
        }
        return ['targets' => $targets];
    }

    /**
     * Port forwards that do nothing: the redirect exists, but no filter
     * rule allows the translated traffic ("Firewall Rule: Manual" with no
     * matching WAN rule), so it is translated and then dropped.
     */
    public static function inertForwards(array $rules, array $redirects, array $devices, array $ifaces)
    {
        $out = [];
        foreach ($devices as $device) {
            if (!self::evaluable($device)) {
                continue;
            }
            foreach (self::evaluateInbound($rules, $redirects, $device, $ifaces)['forwards'] as $f) {
                if (!$f['allowed']) {
                    $out[] = $f + ['device' => 'device:' . $device['id'], 'device_name' => $device['hostname'] ?: $device['ip']];
                }
            }
        }
        return $out;
    }

    // ------------------------------------------------------------------
    // Pair drill-down (layer 2)
    // ------------------------------------------------------------------

    /**
     * Everything one node can and can't reach on another, slice by slice:
     * per address family and target address, every protocol/port range with
     * its verdict, the deciding rule and where it was decided (in on the
     * source's interface, or out on the destination's). Covers device ->
     * device/firewall/WAN and WAN (the internet) -> device/firewall.
     *
     * @param string $srcId graph node id ("device:<id>", "wan")
     * @param string $dstId graph node id ("device:<id>", "firewall", "wan")
     * @return array {status, kind, targets, rules, forwards, in_if, out_if}
     *               or {status: failed, error_msg}
     */
    public static function pairBreakdown(array $rules, array $redirects, array $devices, array $ifaces, $srcId, $dstId)
    {
        $fail = function ($msg) {
            return ['status' => 'failed', 'error_msg' => $msg];
        };
        $byNode = [];
        foreach ($devices as $device) {
            $byNode['device:' . $device['id']] = $device;
        }
        $known = function ($id) use ($byNode) {
            return $id === self::NODE_FIREWALL || $id === self::NODE_WAN || isset($byNode[$id]);
        };
        if (!$known($srcId) || !$known($dstId)) {
            return $fail('unknown src or dst node');
        }
        if ($srcId === $dstId) {
            return $fail('pick two different nodes');
        }
        if ($srcId === self::NODE_FIREWALL) {
            return $fail('traffic started by the firewall itself is not evaluated');
        }
        $ifInfo = function ($physical) use ($ifaces) {
            return $physical === null ? null
                : ['if' => $physical, 'descr' => $ifaces[$physical]['descr'] ?? $physical];
        };
        $wans = self::wanInterfaces($ifaces);
        $forwards = [];

        if ($srcId === self::NODE_WAN) {
            if (empty($wans)) {
                return $fail('no WAN interface');
            }
            if ($dstId === self::NODE_FIREWALL) {
                $pair = ['kind' => self::EDGE_FILTERED] + self::evaluateInboundFirewall($rules, $ifaces);
                $outIf = null;
            } else {
                $dst = $byNode[$dstId];
                if (empty($dst['if'])) {
                    return $fail('device has no known interface');
                }
                $in = self::evaluateInbound($rules, $redirects, $dst, $ifaces);
                $pair = ['kind' => self::EDGE_FILTERED, 'targets' => $in['targets']];
                $forwards = $in['forwards'];
                $outIf = $dst['if'];
            }
            $inIf = $wans[0];
        } else {
            $src = $byNode[$srcId];
            if (empty($src['if'])) {
                return $fail('device has no known interface');
            }
            $dst = $dstId === self::NODE_FIREWALL || $dstId === self::NODE_WAN ? $dstId : $byNode[$dstId];
            if (is_array($dst) && empty($dst['if'])) {
                return $fail('device has no known interface');
            }
            $pair = self::evaluatePair($rules, $src, $dst, $ifaces);
            $inIf = $src['if'];
            $outIf = is_array($dst) ? $dst['if'] : ($dst === self::NODE_WAN ? ($wans[0] ?? null) : null);
        }

        // descriptions for every rule the slices refer to
        $referenced = [];
        foreach ($pair['targets'] as $target) {
            foreach ($target['slices'] as $slice) {
                foreach (array_merge([$slice['rule']], $slice['uncertain']) as $label) {
                    if ($label !== null) {
                        $referenced[$label] = true;
                    }
                }
            }
        }
        $ruleInfo = [];
        foreach ($rules as $rule) {
            if (isset($referenced[$rule['label']]) && !isset($ruleInfo[$rule['label']])) {
                $ruleInfo[$rule['label']] = [
                    'descr' => $rule['descr'] ?? $rule['text'],
                    'text' => $rule['text'],
                    'automatic' => !empty($rule['automatic']),
                ];
            }
        }
        foreach ($forwards as $f) {
            if (isset($referenced[$f['label']])) {
                $ruleInfo[$f['label']] = ['descr' => 'Port forward (Firewall Rule: Pass): ' . $f['text'], 'text' => $f['text'], 'automatic' => false];
            }
        }

        // which interface each firewall address belongs to, so the panel can
        // say e.g. "(WAN address)" - reaching the WAN address from inside is
        // correct pf behaviour but surprises people
        foreach ($pair['targets'] as &$target) {
            if (!empty($target['if'])) {
                $target['if_descr'] = $ifaces[$target['if']]['descr'] ?? $target['if'];
                $target['on_wan'] = in_array($target['if'], $wans, true);
            }
        }
        unset($target);

        return [
            'status' => 'ok',
            'src' => $srcId,
            'dst' => $dstId,
            'kind' => $pair['kind'],
            'targets' => $pair['targets'],
            'rules' => $ruleInfo,
            'forwards' => $forwards,
            'in_if' => $ifInfo($inIf),
            'out_if' => $ifInfo($outIf),
        ];
    }

    // ------------------------------------------------------------------
    // Endpoints and graph
    // ------------------------------------------------------------------

    /** private (RFC1918) ranges: "anything but these" = the internet */
    private const PRIVATE_NETS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

    /** never part of "the internet" for our purposes */
    private const NON_PUBLIC = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
    ];

    /**
     * Stand-ins for "somewhere on the internet", in order of preference:
     * documentation ranges (RFC 5737/2544) that real rules almost never
     * name, so the general verdict isn't skewed by a specific rule.
     */
    private const INTERNET_CANDIDATES = ['198.51.100.10', '203.0.113.10', '192.0.2.10', '198.18.0.10'];

    /** IPv6 stand-ins: the documentation prefix (RFC 3849) */
    private const INTERNET_CANDIDATES6 = ['2001:db8::10', '2001:db8:1::10', '2001:db8:2::10'];

    /** never part of "the internet" in IPv6 */
    private const NON_PUBLIC6 = ['::/128', '::1/128', '::ffff:0:0/96', 'fc00::/7', 'fe80::/10', 'ff00::/8'];

    /** IPv6's private-ish range: "anything but ULA" targets the internet */
    private const ULA6 = 'fc00::/7';

    /** most specific public networks reported separately per WAN edge */
    private const MAX_INTERNET_REGIONS = 20;

    /**
     * WAN interfaces (physical names): configured with key "wan" (or
     * "wan<N>" for extra WANs). Outbound flows to the internet leave here.
     */
    public static function wanInterfaces(array $ifaces)
    {
        $out = [];
        foreach ($ifaces as $physical => $if) {
            if (preg_match('/^wan\d*$/', $if['key'] ?? '')) {
                $out[] = $physical;
            }
        }
        return $out;
    }

    private static function isPublicSpec($entry, $family = 4)
    {
        if (!is_string($entry) || !($family === 6 ? self::isIpv6Spec($entry) : self::isIpv4Spec($entry))) {
            return false;
        }
        $bits = strpos($entry, '/') !== false ? (int)explode('/', $entry, 2)[1] : ($family === 6 ? 128 : 32);
        if ($bits < 1) {
            return false; // 0.0.0.0/0 or ::/0 is just "any"
        }
        foreach ($family === 6 ? self::NON_PUBLIC6 : self::NON_PUBLIC as $net) {
            if (self::cidrInside($entry, $net)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Addresses to evaluate for "the internet": a general stand-in, plus
     * one per specific public network named in a rule destination (e.g. a
     * block to a range, or a GeoIP alias), so exceptions can be reported.
     *
     * @return array{general: string, regions: array} regions: cidr => address
     */
    public static function internetTargets(array $rules, array $ifaces, $family = 4)
    {
        $firewall = array_column(self::firewallTargets($ifaces, $family), 'ip');
        $regions = [];
        foreach ($rules as $rule) {
            foreach ($rule['destination'] as $entry) {
                if (!self::isPublicSpec($entry, $family) || in_array(explode('/', $entry, 2)[0], $firewall, true)) {
                    continue;
                }
                $cidr = strpos($entry, '/') !== false ? $entry : $entry . ($family === 6 ? '/128' : '/32');
                if (!isset($regions[$cidr]) && count($regions) < self::MAX_INTERNET_REGIONS) {
                    // representative address: first host of the network
                    [$net, $bits] = explode('/', $cidr);
                    $regions[$cidr] = self::firstHost($net, (int)$bits);
                }
            }
        }
        $candidates = $family === 6 ? self::INTERNET_CANDIDATES6 : self::INTERNET_CANDIDATES;
        $general = $candidates[0];
        foreach ($candidates as $candidate) {
            $named = false;
            foreach (array_keys($regions) as $cidr) {
                if (self::inCidr($candidate, $cidr)) {
                    $named = true;
                    break;
                }
            }
            if (!$named) {
                $general = $candidate;
                break;
            }
        }
        return ['general' => $general, 'regions' => $regions];
    }

    /**
     * The SLAAC address a device with this MAC would take in a /64 using
     * EUI-64 (flip the universal/local bit, insert ff:fe). Used when the
     * NDP table hasn't seen the device yet - devices only appear there once
     * they've talked to the firewall over IPv6 (testlab, 2026-10-17). Exact
     * for EUI-64 hosts; for privacy-address hosts it still lands in the
     * right prefix, which is what network-based rules look at.
     *
     * @return string|null
     */
    public static function eui64Address($prefixCidr, $mac)
    {
        $parts = explode('/', $prefixCidr, 2);
        $hex = preg_replace('/[^0-9a-f]/', '', strtolower((string)$mac));
        if ((int)($parts[1] ?? 0) !== 64 || strlen($hex) !== 12 || self::ipFamily($parts[0]) !== 6) {
            return null;
        }
        $b = array_map('hexdec', str_split($hex, 2));
        $b[0] ^= 0x02;
        $iid = sprintf('%02x%02x:%02xff:fe%02x:%02x%02x', $b[0], $b[1], $b[2], $b[3], $b[4], $b[5]);
        $net = inet_pton(explode('/', self::networkCidr($parts[0], 64))[0]);
        $host = inet_pton('::' . $iid);
        return inet_ntop(substr($net, 0, 8) . substr($host, 8, 8));
    }

    /**
     * Fill in assumed IPv6 addresses (EUI-64) for devices with a MAC but no
     * known IPv6, on segments that have an IPv6 /64. Flags them
     * 'ipv6_assumed' so the UI can say so.
     */
    public static function assumeIpv6(array $devices, array $ifaces)
    {
        foreach ($devices as &$device) {
            if (!empty($device['ipv6']) || empty($device['if']) || empty($device['mac'])) {
                continue;
            }
            foreach ($ifaces[$device['if']]['ipv6'] ?? [] as $addr) {
                if (!empty($addr['linklocal'])) {
                    continue;
                }
                $guess = self::eui64Address(self::networkCidr($addr['ipaddr'], $addr['subnetbits']), $device['mac']);
                if ($guess !== null) {
                    $device['ipv6'] = [$guess];
                    $device['ipv6_assumed'] = true;
                    break;
                }
            }
        }
        return $devices;
    }

    /** a representative address for a network: its first host */
    private static function firstHost($net, $bits)
    {
        $fam = self::ipFamily($net);
        $max = $fam === 6 ? 128 : 32;
        if ($bits >= $max - 1) {
            return $net;
        }
        $packed = inet_pton(explode('/', self::networkCidr($net, $bits))[0]);
        // add one to the last byte (network addresses end in zero bits)
        $packed[strlen($packed) - 1] = chr(ord($packed[strlen($packed) - 1]) | 1);
        return inet_ntop($packed);
    }

    /**
     * Physical interface whose subnet contains $ip, or null.
     */
    public static function interfaceForIp($ip, array $ifaces)
    {
        foreach ($ifaces as $physical => $if) {
            foreach (self::ifaceAddrs($if) as $addr) {
                // link-local networks (fe80::/64) exist on every interface,
                // so they say nothing about where a device is
                if (!empty($addr['linklocal'])) {
                    continue;
                }
                if (self::inCidr($ip, self::networkCidr($addr['ipaddr'], $addr['subnetbits']))) {
                    return $physical;
                }
            }
        }
        return null;
    }

    /**
     * A device's address in one family: 'ip' when it's that family, else
     * the first of 'ipv6' (global/ULA addresses, e.g. from the NDP table).
     *
     * @param int $family 4 or 6
     * @return string|null
     */
    public static function deviceAddr(array $device, $family)
    {
        if (!empty($device['ip']) && self::ipFamily($device['ip']) === $family) {
            return $device['ip'];
        }
        if ($family === 6) {
            foreach ($device['ipv6'] ?? [] as $ip) {
                if (self::ipFamily($ip) === 6) {
                    return $ip;
                }
            }
        }
        return null;
    }

    /**
     * Every firewall address as a flow target: [['ip' => ..., 'if' => physical], ...].
     */
    public static function firewallTargets(array $ifaces, $family = 4, $srcIf = null)
    {
        $targets = [];
        if ($family === 6) {
            foreach ($ifaces as $physical => $if) {
                foreach ($if['ipv6'] ?? [] as $addr) {
                    // link-local addresses are only reachable from their own
                    // segment; ::1 never from a device
                    if ($addr['ipaddr'] === '::1' || (!empty($addr['linklocal']) && $physical !== $srcIf)) {
                        continue;
                    }
                    $targets[] = ['ip' => self::stripZone($addr['ipaddr']), 'if' => $physical];
                }
            }
            return $targets;
        }
        foreach ($ifaces as $physical => $if) {
            foreach ($if['ipv4'] ?? [] as $addr) {
                // loopback is never reachable from a device: the kernel
                // drops 127/8 arriving on a real interface. Counting it let a
                // "to ! <private ranges>" rule appear to reach the firewall
                // (testlab, 2026-10-17).
                if (self::inCidr($addr['ipaddr'], '127.0.0.0/8')) {
                    continue;
                }
                $targets[] = ['ip' => $addr['ipaddr'], 'if' => $physical];
            }
        }
        return $targets;
    }

    /**
     * Is this device evaluable yet? IPv4 with a known interface. (IPv6 is
     * required later - docs/PLAN.md Milestone 10.)
     */
    private static function evaluable(array $device)
    {
        return !empty($device['if'])
            && (self::deviceAddr($device, 4) !== null || self::deviceAddr($device, 6) !== null);
    }

    /**
     * Fill in a device's physical interface from its IP when discovery
     * didn't provide one (e.g. a host override with no lease).
     */
    public static function placeDevices(array $devices, array $ifaces)
    {
        foreach ($devices as &$device) {
            if (empty($device['if'])) {
                $addr = self::deviceAddr($device, 4) ?? self::deviceAddr($device, 6);
                if ($addr !== null) {
                    $device['if'] = self::interfaceForIp($addr, $ifaces);
                }
            }
        }
        return $devices;
    }

    /**
     * Pair evaluation for one source device against one destination node
     * (a device, or the firewall). Shared by the overview graph (layer 1)
     * and the pair drill-down (layer 2).
     *
     * @param array $rules prepared rules
     * @param array $src evaluable device
     * @param array|string $dst evaluable device, or NODE_FIREWALL
     * @param array $ifaces
     * @return array{kind: string, targets: array} kind is EDGE_UNFILTERED
     *         (same segment, never crosses the firewall - no slices) or
     *         EDGE_FILTERED with per-target-address slices
     */
    public static function evaluatePair(array $rules, array $src, $dst, array $ifaces)
    {
        // same segment: never crosses the firewall, in either family
        if (is_array($dst) && $src['if'] === $dst['if']) {
            return ['kind' => self::EDGE_UNFILTERED, 'targets' => []];
        }

        // evaluate each address family the source has (and, for a device
        // destination, the destination too); targets carry their family so
        // an IPv6 path that bypasses the IPv4 policy shows up
        $targets = [];
        foreach ([4, 6] as $family) {
            $srcAddr = self::deviceAddr($src, $family);
            if ($srcAddr === null) {
                continue;
            }
            $from = ['ip' => $srcAddr, 'if' => $src['if']];
            $tag = $family === 6 ? 'inet6' : 'inet';

            if ($dst === self::NODE_WAN) {
                // outbound to the internet: in on the device's interface,
                // out on the WAN; the general internet, plus the specific
                // public networks rules name (exceptions)
                $wans = self::wanInterfaces($ifaces);
                if (empty($wans) || in_array($src['if'], $wans, true)) {
                    continue;
                }
                // no IPv6 internet without a global IPv6 address on the WAN
                // (link-local only = no upstream IPv6), whatever rules say
                if ($family === 6 && !self::hasGlobalIpv6($ifaces[$wans[0]] ?? [])) {
                    continue;
                }
                $internet = self::internetTargets($rules, $ifaces, $family);
                $targets[] = [
                    'ip' => $internet['general'],
                    'family' => $tag,
                    'region' => null,
                    'slices' => self::evaluateFlows($rules, $from, $internet['general'], $wans[0], $ifaces),
                ];
                foreach ($internet['regions'] as $cidr => $ip) {
                    $targets[] = [
                        'ip' => $ip,
                        'family' => $tag,
                        'region' => $cidr,
                        'slices' => self::evaluateFlows($rules, $from, $ip, $wans[0], $ifaces),
                    ];
                }
            } elseif ($dst === self::NODE_FIREWALL) {
                foreach (self::firewallTargets($ifaces, $family, $src['if']) as $t) {
                    $targets[] = [
                        'ip' => $t['ip'],
                        'if' => $t['if'],
                        'family' => $tag,
                        'slices' => self::evaluateFlows($rules, $from, $t['ip'], null, $ifaces),
                    ];
                }
            } else {
                $dstAddr = self::deviceAddr($dst, $family);
                if ($dstAddr === null) {
                    continue;
                }
                $targets[] = [
                    'ip' => $dstAddr,
                    'family' => $tag,
                    'slices' => self::evaluateFlows($rules, $from, $dstAddr, $dst['if'], $ifaces),
                ];
            }
        }
        return ['kind' => self::EDGE_FILTERED, 'targets' => $targets];
    }

    /**
     * Collapse a pair evaluation into what an overview edge needs: the
     * allowed protocol/port ranges (deduplicated across target addresses),
     * each with the label(s) of the rule(s) that allow it, and whether any
     * slice - allowed or blocked - was uncertain, with the rules responsible.
     * 'allows_all' (only when non-empty) lists the families ('inet',
     * 'inet6') in which every protocol evaluated passes on every usable
     * port, so the UI can say "any" without guessing: a protocol a rule
     * blocks outright would be missing from 'allowed', not visibly blocked.
     *
     * @return array{allowed: array, uncertain: bool, uncertain_rules: string[], conditional: bool, allows_all?: string[]}
     */
    public static function summarisePair(array $pair)
    {
        // a WAN pair's extra targets are specific public networks: summarise
        // the general internet, and report the networks that differ
        $regionTargets = array_values(array_filter($pair['targets'], function ($t) {
            return !empty($t['region']);
        }));
        if (!empty($regionTargets)) {
            $general = array_values(array_filter($pair['targets'], function ($t) {
                return empty($t['region']);
            }));
            $summary = self::summarisePair(['targets' => $general]);
            $key = function ($s) {
                return array_map(function ($a) {
                    return ($a['family'] ?? 'inet') . ':' . $a['proto'] . ':' . $a['from'] . ':' . $a['to'];
                }, $s['allowed']);
            };
            $summary['regions'] = [];
            foreach ($regionTargets as $t) {
                // summarise this network on its own (untagged, or this
                // branch would recurse forever), against the general
                // internet of the same family
                $r = self::summarisePair(['targets' => [['region' => null] + $t]]);
                $fam = $t['family'] ?? 'inet';
                $sameFamily = ['allowed' => array_values(array_filter($summary['allowed'], function ($a) use ($fam) {
                    return ($a['family'] ?? 'inet') === $fam;
                }))];
                if ($key($r) !== $key($sameFamily)) {
                    $summary['regions'][] = ['cidr' => $t['region'], 'allowed' => $r['allowed']];
                }
            }
            return $summary;
        }
        $allowed = [];
        $uncertainRules = [];
        $conditional = false;
        $passing = [];   // family => proto => passing [from, to] ranges, or true
        foreach ($pair['targets'] as $target) {
            $fam = $target['family'] ?? 'inet';
            foreach ($target['slices'] as $s) {
                foreach ($s['uncertain'] as $label) {
                    $uncertainRules[$label] = true;
                }
                if (!isset($passing[$fam][$s['proto']])) {
                    $passing[$fam][$s['proto']] = $s['from'] === null ? false : [];
                }
                if ($s['verdict'] !== self::VERDICT_PASS) {
                    continue;
                }
                if ($s['from'] === null) {
                    $passing[$fam][$s['proto']] = true;
                } else {
                    $passing[$fam][$s['proto']][] = [$s['from'], $s['to']];
                }
                $conditional = $conditional || $s['conditional'];
                $v6 = ($target['family'] ?? 'inet') === 'inet6';
                $key = ($v6 ? '6:' : '') . $s['proto'] . ':' . $s['from'] . ':' . $s['to'];
                if (!isset($allowed[$key])) {
                    $allowed[$key] = ['proto' => $s['proto'], 'from' => $s['from'], 'to' => $s['to'], 'rules' => []];
                    // only IPv6 entries carry a family, so IPv4 output (and
                    // saved check fingerprints) stay exactly as before
                    if ($v6) {
                        $allowed[$key]['family'] = 'inet6';
                    }
                }
                // a pass verdict always has a deciding rule (default is deny)
                if ($s['rule'] !== null && !in_array($s['rule'], $allowed[$key]['rules'], true)) {
                    $allowed[$key]['rules'][] = $s['rule'];
                }
            }
        }
        $summary = [
            'allowed' => array_values($allowed),
            'uncertain' => !empty($uncertainRules),
            'uncertain_rules' => array_keys($uncertainRules),
            'conditional' => $conditional,
        ];
        $all = [];
        foreach ($passing as $fam => $protos) {
            $every = true;
            foreach ($protos as $p) {
                $every = $every && (is_array($p) ? self::coversUsablePorts($p) : $p);
            }
            if ($every) {
                $all[] = $fam;
            }
        }
        if (!empty($all)) {
            $summary['allows_all'] = $all;
        }
        return $summary;
    }

    /** whether [from, to] ranges (any order, may overlap) cover ports 1-65535 */
    private static function coversUsablePorts(array $ranges)
    {
        usort($ranges, function ($a, $b) {
            return $a[0] <=> $b[0];
        });
        $next = self::SRC_PORT_MIN;
        foreach ($ranges as [$lo, $hi]) {
            if ($lo > $next) {
                return false;
            }
            $next = max($next, $hi + 1);
        }
        return $next > self::PORT_MAX;
    }

    /**
     * Does a rule's destination name this destination node specifically,
     * rather than catching it in something broader? Used to tell flows the
     * rule was written for ("intended", drawn blue) from flows a wide rule
     * lets through incidentally - e.g. a rule to the IoT subnet also
     * covering the firewall's own IoT address.
     *
     * Specific means one of: a host entry equal to one of the node's
     * addresses (bare IP or /32; host aliases arrive as expanded table
     * entries, and (self)/(ifname) resolve to the firewall's addresses);
     * or, for a device, its own segment's network ("IoT net" for an IoT
     * device). Wider networks, `any` and negated destinations are not.
     *
     * @param array $rule prepared rule
     * @param array|string $dst device array or NODE_FIREWALL
     * @param array $ifaces
     * @return bool
     */
    public static function ruleTargets(array $rule, $dst, array $ifaces)
    {
        if ($dst === self::NODE_WAN) {
            // the internet is targeted explicitly by "anything except the
            // private ranges" (e.g. to ! <rfc1918>, or ! fc00::/7 in IPv6);
            // plain 'any' is broad
            if (empty($rule['destination_not'])) {
                return false;
            }
            foreach ($rule['destination'] as $entry) {
                if (is_string($entry) && self::isIpv6Spec($entry) && self::cidrInside(self::ULA6, $entry)) {
                    return true;
                }
            }
            foreach (self::PRIVATE_NETS as $net) {
                $covered = false;
                foreach ($rule['destination'] as $entry) {
                    if (is_string($entry) && self::isIpv4Spec($entry) && self::cidrInside($net, $entry)) {
                        $covered = true;
                        break;
                    }
                }
                if (!$covered) {
                    return false;
                }
            }
            return true;
        }
        if (!empty($rule['destination_not'])) {
            return false;
        }
        $hosts = [];
        $segmentNets = [];
        if ($dst === self::NODE_FIREWALL) {
            foreach ($ifaces as $if) {
                foreach (self::ifaceAddrs($if) as $addr) {
                    $hosts[] = self::canonical($addr['ipaddr']);
                }
            }
        } else {
            foreach (array_merge([$dst['ip']], $dst['ipv6'] ?? []) as $ip) {
                $hosts[] = self::canonical($ip);
            }
            foreach (self::ifaceAddrs($ifaces[$dst['if']] ?? []) as $addr) {
                if (empty($addr['linklocal'])) {
                    $segmentNets[] = self::canonical(self::networkCidr($addr['ipaddr'], $addr['subnetbits']));
                }
            }
        }
        foreach ($rule['destination'] as $entry) {
            if (!is_string($entry)) {
                continue;
            }
            $host = preg_replace('#/(32|128)$#', '', $entry);
            if (in_array(self::canonical($host), $hosts, true) || in_array(self::canonical($entry), $segmentNets, true)) {
                return true;
            }
        }
        return false;
    }

    /** one spelling per address/CIDR (IPv6 has many), zone id dropped */
    private static function canonical($spec)
    {
        $parts = explode('/', self::stripZone((string)$spec), 2);
        $packed = @inet_pton($parts[0]);
        $addr = $packed === false ? $parts[0] : inet_ntop($packed);
        return isset($parts[1]) ? $addr . '/' . $parts[1] : $addr;
    }

    /**
     * Inbound variant of markIntended: a port forward (rdr pass) names the
     * device explicitly, so it counts as intended; filter rules are judged
     * by ruleTargets as usual.
     */
    private static function markIntendedInbound(array $summary, array $dst, array $rulesByLabel, array $ifaces)
    {
        foreach ($summary['allowed'] as $a) {
            foreach ($a['rules'] as $label) {
                if (strpos($label, 'fwd-') === 0 && !isset($rulesByLabel[$label])) {
                    $rulesByLabel[$label] = ['destination' => [self::deviceAddr($dst, 4)], 'destination_not' => false, 'automatic' => false];
                }
            }
        }
        return self::markIntended($summary, $dst, $rulesByLabel, $ifaces);
    }

    /**
     * Mark each allowed range of an edge summary as intended (every rule
     * allowing it targets $dst specifically - see ruleTargets()), and the
     * edge as a whole intended when all of its allowed ranges are and
     * nothing about it is uncertain.
     */
    private static function markIntended(array $summary, $dst, array $rulesByLabel, array $ifaces)
    {
        $all = !empty($summary['allowed']) && !$summary['uncertain'];
        $allDefault = $all;
        foreach ($summary['allowed'] as &$a) {
            $a['intended'] = !empty($a['rules']);
            $a['default'] = !empty($a['rules']);
            foreach ($a['rules'] as $label) {
                if (!isset($rulesByLabel[$label]) || !self::ruleTargets($rulesByLabel[$label], $dst, $ifaces)) {
                    $a['intended'] = false;
                }
                if (empty($rulesByLabel[$label]['automatic'])) {
                    $a['default'] = false;
                }
            }
            $all = $all && $a['intended'];
            $allDefault = $allDefault && $a['default'];
        }
        $summary['intended'] = $all;
        // allowed only by OPNsense's own automatic rules (drawn purple)
        $summary['default'] = $allDefault;
        return $summary;
    }

    /**
     * Build the layer-1 overview graph: device, firewall and WAN nodes, and
     * one directed edge for every (source device, destination) pair where
     * the source can start at least one flow, plus every same-segment pair
     * (EDGE_UNFILTERED), plus pairs whose only result is uncertain - a
     * maybe-hole is still worth showing in an audit tool.
     *
     * The WAN node is a placeholder until Milestone 9 (required; no edges
     * yet). Devices that aren't evaluable yet (IPv6-only, or no known
     * interface) are still nodes, flagged, with no edges.
     *
     * @param array $devices placed devices: [{id, ip, hostname, if, ...}]
     * @param array $rules prepared rules
     * @param array $ifaces
     * @return array{nodes: array, edges: array, rules: array} 'rules' maps
     *         every rule label an edge refers to => {descr}
     */
    public static function buildGraph(array $devices, array $rules, array $ifaces, array $redirects = [])
    {
        $nodes = [];
        $edges = [];

        foreach ($devices as $device) {
            $nodes[] = [
                'id' => 'device:' . $device['id'],
                'type' => 'device',
                'label' => ($device['hostname'] ?: $device['ip']) . "\n" . $device['ip'],
                'if' => $device['if'] ?? null,
                // other names for the same address (e.g. a MAC-less dnsmasq
                // host merged into the device that owns that IP)
                'aliases' => array_values($device['aliases'] ?? []),
                'ipv6' => array_values($device['ipv6'] ?? []),
                'ipv6_assumed' => !empty($device['ipv6_assumed']),
                'evaluable' => self::evaluable($device),
            ];
        }
        // OPNsense's name for the box's own addresses in rules
        $nodes[] = ['id' => self::NODE_FIREWALL, 'type' => self::NODE_FIREWALL, 'label' => 'This Firewall', 'evaluable' => true];
        $hasWan = !empty(self::wanInterfaces($ifaces));
        // outbound is evaluated; inbound (port forwards) is still to come
        $nodes[] = ['id' => self::NODE_WAN, 'type' => self::NODE_WAN, 'label' => 'WAN', 'evaluable' => $hasWan, 'pending' => !$hasWan];

        $evaluable = array_values(array_filter($devices, [self::class, 'evaluable']));
        $rulesByLabel = [];
        foreach ($rules as $rule) {
            $rulesByLabel[$rule['label']] = $rule;
        }

        foreach ($evaluable as $src) {
            $dests = $evaluable;
            $dests[] = self::NODE_FIREWALL;
            if ($hasWan) {
                $dests[] = self::NODE_WAN;
            }
            foreach ($dests as $dst) {
                if (is_array($dst) && ($dst['id'] === $src['id'] || $dst['ip'] === $src['ip'])) {
                    continue;
                }
                $pair = self::evaluatePair($rules, $src, $dst, $ifaces);
                $to = is_array($dst) ? 'device:' . $dst['id'] : $dst;
                if ($pair['kind'] === self::EDGE_UNFILTERED) {
                    $edges[] = ['from' => 'device:' . $src['id'], 'to' => $to, 'kind' => self::EDGE_UNFILTERED];
                    continue;
                }
                if (empty($pair['targets'])) {
                    continue;
                }
                $summary = self::summarisePair($pair);
                if (empty($summary['allowed']) && !$summary['uncertain'] && empty($summary['regions'])) {
                    continue;
                }
                $summary = self::markIntended($summary, $dst, $rulesByLabel, $ifaces);
                $edges[] = [
                    'from' => 'device:' . $src['id'],
                    'to' => $to,
                    'kind' => self::EDGE_FILTERED,
                ] + $summary;
            }
        }

        if ($hasWan) {
            $forwardRules = [];
            foreach ($evaluable as $dst) {
                $in = self::evaluateInbound($rules, $redirects, $dst, $ifaces);
                if (empty($in['targets'])) {
                    continue;
                }
                $summary = self::summarisePair(['targets' => $in['targets']]);
                // only draw what actually gets through; an inert forward is
                // reported by the Rule check instead (inertForwards)
                if (empty($summary['allowed']) && !$summary['uncertain']) {
                    continue;
                }
                $summary = self::markIntendedInbound($summary, $dst, $rulesByLabel, $ifaces);
                $edges[] = ['from' => self::NODE_WAN, 'to' => 'device:' . $dst['id'], 'kind' => self::EDGE_FILTERED]
                    + $summary + ['forwards' => $in['forwards']];
                foreach ($in['forwards'] as $f) {
                    $forwardRules[$f['label']] = 'Port forward (Firewall Rule: Pass): ' . $f['text'];
                }
            }
            $fwIn = self::summarisePair(self::evaluateInboundFirewall($rules, $ifaces));
            if (!empty($fwIn['allowed']) || $fwIn['uncertain']) {
                $edges[] = ['from' => self::NODE_WAN, 'to' => self::NODE_FIREWALL, 'kind' => self::EDGE_FILTERED]
                    + self::markIntended($fwIn, self::NODE_FIREWALL, $rulesByLabel, $ifaces);
            }
        }

        $referenced = [];
        foreach ($edges as $edge) {
            foreach ($edge['allowed'] ?? [] as $a) {
                foreach ($a['rules'] as $label) {
                    $referenced[$label] = true;
                }
            }
            foreach ($edge['uncertain_rules'] ?? [] as $label) {
                $referenced[$label] = true;
            }
            foreach ($edge['regions'] ?? [] as $region) {
                foreach ($region['allowed'] as $a) {
                    foreach ($a['rules'] as $label) {
                        $referenced[$label] = true;
                    }
                }
            }
        }
        $ruleInfo = [];
        foreach ($rules as $rule) {
            if (isset($referenced[$rule['label']])) {
                $ruleInfo[$rule['label']] = [
                    'descr' => $rule['descr'] ?? $rule['text'],
                    'automatic' => !empty($rule['automatic']),
                ];
            }
        }
        // rdr pass forwards act as their own "rule" (no filter rule involved)
        foreach ($forwardRules ?? [] as $label => $descr) {
            if (isset($referenced[$label])) {
                $ruleInfo[$label] = ['descr' => $descr, 'automatic' => false];
            }
        }

        return ['nodes' => $nodes, 'edges' => $edges, 'rules' => $ruleInfo];
    }
}
