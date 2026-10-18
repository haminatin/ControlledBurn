<?php

/**
 * Standalone fixture tests for RuleEngine (v2), runnable without any
 * OPNsense runtime (no Config/Backend/Phalcon dependency).
 *
 * Fixture rules are hand-built in get_ruleset.py's output shape, not
 * captured from a live box - extend with real testlab output (Milestone 4c).
 *
 * Run: php tests/run_rule_engine_tests.php
 */

require_once __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/ControlledBurn/RuleEngine.php';

use OPNsense\ControlledBurn\RuleEngine;

$failures = 0;
$passed = 0;

function check($label, $condition)
{
    global $failures, $passed;
    if ($condition) {
        $passed++;
    } else {
        $failures++;
        fwrite(STDERR, "FAIL: {$label}\n");
    }
}

// Two-segment lab: LAN (vtnet0) and OPT1 (vtnet2).
$IFACES = [
    'vtnet0' => ['key' => 'lan', 'descr' => 'LAN', 'ipv4' => [['ipaddr' => '192.168.77.1', 'subnetbits' => 24]]],
    'vtnet2' => ['key' => 'opt1', 'descr' => 'OPT1', 'ipv4' => [['ipaddr' => '10.0.10.1', 'subnetbits' => 24]]],
];

function rule($overrides)
{
    static $seq = 0;
    return array_merge([
        'seq' => $seq++,
        'label' => 'r',
        'action' => 'pass',
        'direction' => 'in',
        'quick' => true,
        'interface' => 'vtnet0',
        'ipprotocol' => 'inet',
        'protocol' => 'any',
        'source' => ['any'],
        'source_not' => false,
        'destination' => ['any'],
        'destination_not' => false,
        'from_port' => null,
        'to_port' => null,
        'text' => 'fixture rule',
        'descr' => 'fixture rule',
    ], $overrides);
}

function prep(array $rules)
{
    global $IFACES;
    return RuleEngine::prepareRules($rules, $IFACES);
}

/** find the slice covering $proto/$port in a slice list */
function sliceFor(array $slices, $proto, $port = null)
{
    foreach ($slices as $s) {
        if ($s['proto'] !== $proto) {
            continue;
        }
        if ($port === null || ($s['from'] <= $port && $port <= $s['to'])) {
            return $s;
        }
    }
    return null;
}

$laptop = ['id' => 'aa', 'ip' => '192.168.77.191', 'hostname' => 'lab-dev01', 'if' => 'vtnet0'];
$nas = ['id' => 'bb', 'ip' => '10.0.10.20', 'hostname' => 'nas', 'if' => 'vtnet2'];
$printer = ['id' => 'cc', 'ip' => '192.168.77.30', 'hostname' => 'printer', 'if' => 'vtnet0'];

// ---------------------------------------------------------------- descriptions
$described = RuleEngine::attachDescriptions(
    [['label' => 'h1', 'text' => 'pass ... "h1"'], ['label' => 'h2', 'text' => 'pass ... "h2"']],
    ['h1' => 'Allow LAN to WAN']
);
check('known label gets descr', $described[0]['descr'] === 'Allow LAN to WAN');
check('unknown label falls back to raw pf text', $described[1]['descr'] === $described[1]['text']);

// ---------------------------------------------------------------- ports
check('= 445', RuleEngine::parsePortSpec('= 445', 'tcp') === [[445, 445]]);
check('bare 445', RuleEngine::parsePortSpec('445', 'tcp') === [[445, 445]]);
check('!= 22', RuleEngine::parsePortSpec('!= 22', 'tcp') === [[0, 21], [23, 65535]]);
check('< 1024', RuleEngine::parsePortSpec('< 1024', 'tcp') === [[0, 1023]]);
check('<= 1024', RuleEngine::parsePortSpec('<= 1024', 'tcp') === [[0, 1024]]);
check('> 1024', RuleEngine::parsePortSpec('> 1024', 'tcp') === [[1025, 65535]]);
check('>= 1024', RuleEngine::parsePortSpec('>= 1024', 'tcp') === [[1024, 65535]]);
check('1000:2000 inclusive', RuleEngine::parsePortSpec('1000:2000', 'tcp') === [[1000, 2000]]);
check('1000 >< 2000 exclusive', RuleEngine::parsePortSpec('1000 >< 2000', 'tcp') === [[1001, 1999]]);
check('1000 <> 2000 outside', RuleEngine::parsePortSpec('1000 <> 2000', 'tcp') === [[0, 999], [2001, 65535]]);
check('{ 80 443 } list', RuleEngine::parsePortSpec('{ 80 443 }', 'tcp') === [[80, 80], [443, 443]]);
check('null = unconstrained', RuleEngine::parsePortSpec(null, 'tcp') === null);
check('garbage = unparseable', RuleEngine::parsePortSpec('= notaport', 'tcp') === false);
check('out of range = unparseable', RuleEngine::parsePortSpec('= 70000', 'tcp') === false);
if (getservbyname('ssh', 'tcp') === 22) {
    check('service name = ssh', RuleEngine::parsePortSpec('= ssh', 'tcp') === [[22, 22]]);
} else {
    fwrite(STDERR, "SKIP: no services database, service-name test not run\n");
}

// ---------------------------------------------------------------- dynamic addresses
check('(self) -> all firewall IPs', RuleEngine::resolveDynamicAddr('(self)', $IFACES) === ['192.168.77.1', '10.0.10.1']);
check('(vtnet0) -> interface IP', RuleEngine::resolveDynamicAddr('(vtnet0)', $IFACES) === ['192.168.77.1']);
check('(vtnet0:network) -> subnet', RuleEngine::resolveDynamicAddr('(vtnet0:network)', $IFACES) === ['192.168.77.0/24']);
check('(vtnet0:network:0) -> subnet', RuleEngine::resolveDynamicAddr('(vtnet0:network:0)', $IFACES) === ['192.168.77.0/24']);
check('bare vtnet2:network -> subnet', RuleEngine::resolveDynamicAddr('vtnet2:network', $IFACES) === ['10.0.10.0/24']);
check('unknown interface is left alone', RuleEngine::resolveDynamicAddr('(igb7:network)', $IFACES) === null);
check('bare word is not an interface reference', RuleEngine::resolveDynamicAddr('vtnet0', $IFACES) === null);
check('(vtnet0:broadcast) not resolved', RuleEngine::resolveDynamicAddr('(vtnet0:broadcast)', $IFACES) === null);

// ---------------------------------------------------------------- address matching (tri-state)
check('in CIDR', RuleEngine::matchSide(['10.0.0.0/24'], false, '10.0.0.5') === true);
check('outside CIDR', RuleEngine::matchSide(['10.0.0.0/24'], false, '10.0.1.5') === false);
check("'any'", RuleEngine::matchSide(['any'], false, '203.0.113.1') === true);
check('negated, outside range', RuleEngine::matchSide(['10.0.0.0/24'], true, '10.0.1.5') === true);
check('negated, inside range', RuleEngine::matchSide(['10.0.0.0/24'], true, '10.0.0.5') === false);
check('unresolved table = undecidable', RuleEngine::matchSide([['table' => 't', 'unresolved' => true]], false, '10.0.0.5') === null);
check('unresolved dynamic = undecidable', RuleEngine::matchSide(['(igb7:network)'], false, '10.0.0.5') === null);
check('negated unresolved = undecidable', RuleEngine::matchSide(['(self)'], true, '10.0.0.5') === null);
check('IPv6 entry never matches IPv4: definite false', RuleEngine::matchSide(['2001:db8::/32'], false, '10.0.0.5') === false);
check('definite match beats undecidable sibling', RuleEngine::matchSide([['table' => 't'], '10.0.0.0/8'], false, '10.0.0.5') === true);

// ---------------------------------------------------------------- pf semantics
$q = ['if' => 'vtnet0', 'dir' => 'in', 'src' => '192.168.77.191', 'dst' => '10.0.10.20', 'proto' => 'tcp', 'port_lo' => 80, 'port_hi' => 80];

$r = RuleEngine::evaluate([], $q, $IFACES);
check('default deny', $r['verdict'] === 'block' && $r['rule'] === null);

$r = RuleEngine::evaluate(prep([rule(['label' => 'a', 'action' => 'block']), rule(['label' => 'b'])]), $q, $IFACES);
check('first quick match wins', $r['verdict'] === 'block' && $r['rule']['label'] === 'a');

$r = RuleEngine::evaluate(prep([rule(['label' => 'a', 'quick' => false]), rule(['label' => 'b', 'action' => 'block', 'quick' => false])]), $q, $IFACES);
check('last non-quick match wins', $r['verdict'] === 'block' && $r['rule']['label'] === 'b');

$r = RuleEngine::evaluate(prep([
    rule(['label' => 'a', 'action' => 'block', 'quick' => false]),
    rule(['label' => 'b']),
    rule(['label' => 'c', 'action' => 'block', 'quick' => false]),
]), $q, $IFACES);
check('quick match stops evaluation', $r['verdict'] === 'pass' && $r['rule']['label'] === 'b');

$r = RuleEngine::evaluate(prep([
    rule(['label' => 'u', 'source' => [['table' => 't', 'unresolved' => true]]]),
    rule(['label' => 'b', 'action' => 'block']),
]), $q, $IFACES);
check('undecidable rule recorded, not matched', $r['rule']['label'] === 'b' && $r['uncertain'] === ['u']);

$r = RuleEngine::evaluate(prep([
    rule(['label' => 'b', 'action' => 'block']),
    rule(['label' => 'u', 'source' => [['table' => 't', 'unresolved' => true]]]),
]), $q, $IFACES);
check('undecidable rule after quick match is irrelevant', $r['uncertain'] === []);

$r = RuleEngine::evaluate(prep([
    rule(['label' => 'ub', 'action' => 'block', 'source' => [['table' => 't', 'unresolved' => true]]]),
]), $q, $IFACES);
check('undecidable block on a blocked flow is not uncertain', $r['verdict'] === 'block' && $r['uncertain'] === []);

$r = RuleEngine::evaluate(prep([
    rule(['label' => 'ub', 'action' => 'block', 'source' => [['table' => 't', 'unresolved' => true]]]),
    rule(['label' => 'p']),
]), $q, $IFACES);
check('undecidable block before a pass IS uncertain', $r['verdict'] === 'pass' && $r['uncertain'] === ['ub']);

// ---------------------------------------------------------------- rule matching dimensions
$m = RuleEngine::matchRule(prep([rule(['ipprotocol' => 'inet6'])])[0], $q, $IFACES);
check('inet6 rule never matches IPv4', $m === false);
$m = RuleEngine::matchRule(prep([rule(['ipprotocol' => 'any'])])[0], $q, $IFACES);
check('family-less rule matches IPv4', $m === true);
$m = RuleEngine::matchRule(prep([rule(['direction' => 'out'])])[0], $q, $IFACES);
check('out rule does not match inbound query', $m === false);
$m = RuleEngine::matchRule(prep([rule(['direction' => 'any'])])[0], $q, $IFACES);
check('direction-less rule matches inbound', $m === true);
$m = RuleEngine::matchRule(prep([rule(['interface' => 'vtnet2'])])[0], $q, $IFACES);
check('other known interface: no match', $m === false);
$m = RuleEngine::matchRule(prep([rule(['interface' => 'lan_group'])])[0], $q, $IFACES);
check('unknown interface (group?): undecidable', $m === null);
$m = RuleEngine::matchRule(prep([rule(['interface' => 'any'])])[0], $q, $IFACES);
check('floating any-interface rule matches', $m === true);
$m = RuleEngine::matchRule(prep([rule(['protocol' => 'udp'])])[0], $q, $IFACES);
check('protocol mismatch', $m === false);
$m = RuleEngine::matchRule(prep([rule(['protocol' => 'tcp', 'to_port' => '= 443'])])[0], $q, $IFACES);
check('port outside rule ports', $m === false);
$m = RuleEngine::matchRule(prep([rule(['protocol' => 'tcp', 'to_port' => '= 80'])])[0], $q, $IFACES);
check('port inside rule ports', $m === true);
$m = RuleEngine::matchRule(prep([rule(['protocol' => 'tcp', 'to_port' => '= nonsense'])])[0], $q, $IFACES);
check('unparseable port: undecidable', $m === null);
$m = RuleEngine::matchRule(prep([rule(['source' => ['(vtnet0:network)']])])[0], $q, $IFACES);
check('LAN-net source resolved and matched', $m === true);

// ---------------------------------------------------------------- port-sliced flows
// testlab-style: lab-dev01 -> nas SMB pass, SSH block, broad pass out
$rules = prep([
    rule(['label' => 'smb', 'protocol' => 'tcp', 'source' => ['192.168.77.191'], 'destination' => ['10.0.10.20'], 'to_port' => '= 445']),
    rule(['label' => 'ssh', 'action' => 'block', 'protocol' => 'tcp', 'source' => ['192.168.77.191'], 'destination' => ['10.0.10.20'], 'to_port' => '= 22']),
    rule(['label' => 'out', 'direction' => 'out', 'interface' => 'any', 'quick' => false]),
]);
$slices = RuleEngine::evaluateFlows($rules, $laptop, $nas['ip'], $nas['if'], $IFACES);
$smb = sliceFor($slices, 'tcp', 445);
check('tcp/445 passes via smb rule', $smb && $smb['verdict'] === 'pass' && $smb['rule'] === 'smb' && $smb['from'] === 445 && $smb['to'] === 445);
$ssh = sliceFor($slices, 'tcp', 22);
check('tcp/22 blocked by ssh rule', $ssh && $ssh['verdict'] === 'block' && $ssh['rule'] === 'ssh');
$other = sliceFor($slices, 'tcp', 8080);
check('tcp/8080 default deny', $other && $other['verdict'] === 'block' && $other['rule'] === null);
check('adjacent default-deny slices merged', $other['from'] === 446 && $other['to'] === 65535);
check('udp default deny', sliceFor($slices, 'udp')['verdict'] === 'block');
check('icmp default deny', sliceFor($slices, 'icmp')['verdict'] === 'block');
check('other-protocol class present', sliceFor($slices, RuleEngine::PROTO_OTHER) !== null);

// outbound block on the destination interface overrides an inbound pass
$rules = prep([
    rule(['label' => 'any', 'protocol' => 'tcp']),
    rule(['label' => 'noout', 'action' => 'block', 'direction' => 'out', 'interface' => 'vtnet2', 'protocol' => 'tcp', 'to_port' => '= 445']),
    rule(['label' => 'out', 'direction' => 'out', 'interface' => 'any', 'quick' => false]),
]);
$slices = RuleEngine::evaluateFlows($rules, $laptop, $nas['ip'], $nas['if'], $IFACES);
$s = sliceFor($slices, 'tcp', 445);
check('out-stage block decides', $s['verdict'] === 'block' && $s['rule'] === 'noout' && $s['stage'] === 'out');
check('other tcp ports still pass', sliceFor($slices, 'tcp', 80)['verdict'] === 'pass');

// no out-direction pass at all: inbound pass alone is not enough
$rules = prep([rule(['label' => 'any'])]);
$slices = RuleEngine::evaluateFlows($rules, $laptop, $nas['ip'], $nas['if'], $IFACES);
check('without an out pass, traffic to another segment is blocked', sliceFor($slices, 'tcp', 80)['verdict'] === 'block');

// source-port-restricted pass is flagged conditional
$rules = prep([
    rule(['label' => 'sp', 'protocol' => 'udp', 'from_port' => '= 68', 'to_port' => '= 67']),
    rule(['label' => 'out', 'direction' => 'out', 'interface' => 'any', 'quick' => false]),
]);
$slices = RuleEngine::evaluateFlows($rules, $laptop, $nas['ip'], $nas['if'], $IFACES);
$s = sliceFor($slices, 'udp', 67);
check('source-port rule match is conditional', $s['verdict'] === 'pass' && $s['conditional'] === true);

// source-port semantics (real 26.7 auto rule: "block ... from any port = 0 to any")
$rules = prep([
    rule(['label' => 'port0', 'action' => 'block', 'protocol' => 'tcp', 'from_port' => '= 0']),
    rule(['label' => 'any', 'protocol' => 'tcp']),
    rule(['label' => 'out', 'direction' => 'out', 'interface' => 'any', 'quick' => false]),
]);
$s = sliceFor(RuleEngine::evaluateFlows($rules, $laptop, $nas['ip'], $nas['if'], $IFACES), 'tcp', 443);
check('block on source port 0 does not block real traffic', $s['verdict'] === 'pass' && $s['rule'] === 'any' && $s['conditional'] === false);

$rules = prep([
    rule(['label' => 'sp-block', 'action' => 'block', 'protocol' => 'tcp', 'from_port' => '= 1234']),
    rule(['label' => 'any', 'protocol' => 'tcp']),
    rule(['label' => 'out', 'direction' => 'out', 'interface' => 'any', 'quick' => false]),
]);
$s = sliceFor(RuleEngine::evaluateFlows($rules, $laptop, $nas['ip'], $nas['if'], $IFACES), 'tcp', 443);
check('block on one source port can be dodged', $s['verdict'] === 'pass' && $s['rule'] === 'any');

$rules = prep([
    rule(['label' => 'all-src', 'action' => 'block', 'protocol' => 'tcp', 'from_port' => '1:65535']),
    rule(['label' => 'any', 'protocol' => 'tcp']),
]);
$s = sliceFor(RuleEngine::evaluateFlows($rules, $laptop, $nas['ip'], $nas['if'], $IFACES), 'tcp', 443);
check('block covering every usable source port does block', $s['verdict'] === 'block' && $s['rule'] === 'all-src');

// negated interface ("on ! X"): OPNsense anti-spoofing
$rules = prep([rule(['label' => 'spoof', 'action' => 'block', 'interface' => 'vtnet2', 'interface_not' => true, 'source' => ['10.0.10.0/24']])]);
$q2 = ['if' => 'vtnet0', 'dir' => 'in', 'src' => '10.0.10.5', 'dst' => '192.168.77.5'];
check('"on ! vtnet2" matches on vtnet0', RuleEngine::matchRule($rules[0], $q2, $IFACES) === true);
$q2['if'] = 'vtnet2';
check('"on ! vtnet2" does not match on vtnet2', RuleEngine::matchRule($rules[0], $q2, $IFACES) === false);

// specific non-tcp/udp/icmp protocol gets its own class
$rules = prep([
    rule(['label' => 'gre', 'protocol' => 'gre']),
    rule(['label' => 'out', 'direction' => 'out', 'interface' => 'any', 'quick' => false]),
]);
$slices = RuleEngine::evaluateFlows($rules, $laptop, $nas['ip'], $nas['if'], $IFACES);
check('gre class passes', sliceFor($slices, 'gre')['verdict'] === 'pass');
check("gre pass doesn't open 'other'", sliceFor($slices, RuleEngine::PROTO_OTHER)['verdict'] === 'block');

// ---------------------------------------------------------------- pairs
$pair = RuleEngine::evaluatePair(prep([rule([])]), $laptop, $printer, $IFACES);
check('same-segment pair is unfiltered', $pair['kind'] === 'unfiltered' && $pair['targets'] === []);

// allows_all: every evaluated protocol passes on every usable port
$out = rule(['label' => 'out', 'direction' => 'out', 'interface' => 'any', 'quick' => false]);
$allOf = function (array $rules) use ($laptop, $nas, $IFACES) {
    return RuleEngine::summarisePair(RuleEngine::evaluatePair(prep($rules), $laptop, $nas, $IFACES))['allows_all'] ?? [];
};
check('allows_all: pass any', $allOf([rule(['label' => 'any']), $out]) === ['inet']);
check(
    'allows_all: not when one tcp port is blocked first',
    $allOf([rule(['label' => 'no-ssh', 'action' => 'block', 'protocol' => 'tcp', 'to_port' => '= 22']), rule(['label' => 'any']), $out]) === []
);
check(
    'allows_all: not when a protocol a rule names is blocked (it drops out of the list unseen)',
    $allOf([rule(['label' => 'no-esp', 'action' => 'block', 'protocol' => 'esp']), rule(['label' => 'any']), $out]) === []
);
check(
    'allows_all: still when several rules together cover every port',
    $allOf([
        rule(['label' => 'lo', 'protocol' => 'tcp', 'to_port' => '1:1000']),
        rule(['label' => 'hi', 'protocol' => 'tcp', 'to_port' => '1001:65535']),
        rule(['label' => 'rest-udp', 'protocol' => 'udp']),
        rule(['label' => 'rest-icmp', 'protocol' => 'icmp']),
        rule(['label' => 'rest', 'action' => 'block', 'protocol' => 'tcp', 'to_port' => '= 0']),
        rule(['label' => 'any']),
        $out,
    ]) === ['inet']
);
check('allows_all: absent when nothing passes everything', $allOf([rule(['label' => 'web', 'protocol' => 'tcp', 'to_port' => '= 443']), $out]) === []);

$rules = prep([
    rule(['label' => 'gui', 'protocol' => 'tcp', 'source' => ['(vtnet0:network)'], 'destination' => ['(self)'], 'to_port' => '= 443']),
]);
$pair = RuleEngine::evaluatePair($rules, $laptop, RuleEngine::NODE_FIREWALL, $IFACES);
check('firewall pair evaluates every firewall address', count($pair['targets']) === 2);
$summary = RuleEngine::summarisePair($pair);
check(
    'firewall GUI reachable, deduplicated across addresses',
    $summary['allowed'] === [['proto' => 'tcp', 'from' => 443, 'to' => 443, 'rules' => ['gui']]]
);

// ---------------------------------------------------------------- graph
$rules = prep([
    rule(['label' => 'smb', 'protocol' => 'tcp', 'source' => ['192.168.77.191'], 'destination' => ['10.0.10.20'], 'to_port' => '= 445']),
    rule(['label' => 'out', 'direction' => 'out', 'interface' => 'any', 'quick' => false]),
]);
$v6only = ['id' => 'dd', 'ip' => '2001:db8::5', 'hostname' => 'v6thing', 'if' => 'vtnet0'];
$graph = RuleEngine::buildGraph([$laptop, $nas, $printer, $v6only], $rules, $IFACES);

$nodeIds = array_column($graph['nodes'], 'id');
check('firewall and wan nodes present', in_array('firewall', $nodeIds, true) && in_array('wan', $nodeIds, true));
$v6node = $graph['nodes'][array_search('device:dd', $nodeIds, true)];
check('IPv6-only device is evaluable now (IPv6 support)', $v6node['evaluable'] === true);

$edgeKey = function ($e) {
    return $e['from'] . '>' . $e['to'];
};
$edges = array_combine(array_map($edgeKey, $graph['edges']), $graph['edges']);
check('laptop -> nas filtered edge with tcp/445 via the smb rule', isset($edges['device:aa>device:bb'])
    && $edges['device:aa>device:bb']['kind'] === 'filtered'
    && $edges['device:aa>device:bb']['allowed'] === [['proto' => 'tcp', 'from' => 445, 'to' => 445, 'rules' => ['smb'], 'intended' => true, 'default' => false]]
    && $edges['device:aa>device:bb']['intended'] === true);
check('graph carries descriptions for referenced rules only', array_keys($graph['rules']) === ['smb']
    && $graph['rules']['smb']['descr'] === 'fixture rule');
check('nas -> laptop has no edge (nothing allowed)', !isset($edges['device:bb>device:aa']));
check('laptop <-> printer unfiltered both ways', isset($edges['device:aa>device:cc']) && isset($edges['device:cc>device:aa'])
    && $edges['device:aa>device:cc']['kind'] === 'unfiltered');
check('IPv6-only device: same-segment links only (no other device has IPv6 here)', array_values(array_unique(array_map(function ($e) {
    return $e['kind'];
}, array_filter($graph['edges'], function ($e) {
    return $e['from'] === 'device:dd' || $e['to'] === 'device:dd';
})))) === ['unfiltered']);
check('wan has no edges yet', !array_filter($graph['edges'], function ($e) {
    return $e['to'] === 'wan' || $e['from'] === 'wan';
}));

// uncertain-only pair still produces an edge (maybe-hole)
$rules = prep([
    rule(['label' => 'u', 'source' => [['table' => 't', 'unresolved' => true]]]),
    rule(['label' => 'out', 'direction' => 'out', 'interface' => 'any', 'quick' => false]),
]);
$graph = RuleEngine::buildGraph([$laptop, $nas], $rules, $IFACES);
$edges = array_combine(array_map($edgeKey, $graph['edges']), $graph['edges']);
check('uncertain-only pair still gets an edge', isset($edges['device:aa>device:bb'])
    && $edges['device:aa>device:bb']['uncertain'] === true
    && $edges['device:aa>device:bb']['uncertain_rules'] === ['u']
    && $edges['device:aa>device:bb']['allowed'] === []);

// an unresolvable block table must not turn every pair into a maybe-hole
$rules = prep([
    rule(['label' => 'virusprot', 'action' => 'block', 'source' => [['table' => 'virusprot', 'unresolved' => true]]]),
    rule(['label' => 'out', 'direction' => 'out', 'interface' => 'any', 'quick' => false]),
]);
$graph = RuleEngine::buildGraph([$laptop, $nas], $rules, $IFACES);
check('unresolved block table adds no edges', !array_filter($graph['edges'], function ($e) {
    return $e['to'] !== 'firewall';
}));

// out-stage block discards inbound-stage uncertainty
$rules = prep([
    rule(['label' => 'ub', 'action' => 'block', 'source' => [['table' => 't', 'unresolved' => true]]]),
    rule(['label' => 'any', 'protocol' => 'tcp']),
    rule(['label' => 'noout', 'action' => 'block', 'direction' => 'out', 'interface' => 'vtnet2']),
]);
$s = sliceFor(RuleEngine::evaluateFlows($rules, $laptop, $nas['ip'], $nas['if'], $IFACES), 'tcp', 80);
check('out-stage block: no leftover inbound uncertainty', $s['verdict'] === 'block' && $s['stage'] === 'out' && $s['uncertain'] === []);

// ---------------------------------------------------------------- intended vs incidental
$ha = ['id' => 'ha', 'ip' => '10.0.10.22', 'hostname' => 'ha', 'if' => 'vtnet2'];
$tv = ['id' => 'tv', 'ip' => '192.168.77.50', 'hostname' => 'tv', 'if' => 'vtnet0'];
$base = ['action' => 'pass', 'direction' => 'in', 'quick' => true, 'interface' => 'vtnet2', 'protocol' => 'tcp', 'source' => ['10.0.10.22'], 'source_not' => false, 'destination_not' => false];
$t = function ($dest, $node, $extra = []) use ($IFACES, $base) {
    return RuleEngine::ruleTargets(prep([rule(array_merge($base, ['destination' => $dest], $extra))])[0], $node, $IFACES);
};
check('host entry targets that device', $t(['192.168.77.50'], $tv) === true);
check('/32 entry targets that device', $t(['192.168.77.50/32'], $tv) === true);
check("device's own segment network targets it", $t(['192.168.77.0/24'], $tv) === true);
check('(ifname:network) of its segment targets it', $t(['(vtnet0:network)'], $tv) === true);
check('wider network does not', $t(['192.168.0.0/16'], $tv) === false);
check("'any' does not", $t(['any'], $tv) === false);
check('negated destination does not', $t(['192.168.77.0/24'], $tv, ['destination_not' => true]) === false);
check('(self) targets the firewall', $t(['(self)'], RuleEngine::NODE_FIREWALL) === true);
check('interface address targets the firewall', $t(['(vtnet0)'], RuleEngine::NODE_FIREWALL) === true);
check("segment subnet does NOT target the firewall (the HA case)", $t(['192.168.77.0/24'], RuleEngine::NODE_FIREWALL) === false);

$rules = prep([
    rule(array_merge($base, ['label' => 'ha-iot', 'destination' => ['192.168.77.0/24'], 'to_port' => '80:443'])),
    rule(['label' => 'out', 'direction' => 'out', 'interface' => 'any', 'quick' => false]),
]);
$graph = RuleEngine::buildGraph([$ha, $tv], $rules, $IFACES);
$edges = array_combine(array_map($edgeKey, $graph['edges']), $graph['edges']);
check('HA -> device on the targeted segment is intended', $edges['device:ha>device:tv']['intended'] === true
    && $edges['device:ha>device:tv']['allowed'][0]['intended'] === true);
check('HA -> firewall via the same rule is NOT intended', $edges['device:ha>firewall']['intended'] === false
    && $edges['device:ha>firewall']['allowed'][0]['intended'] === false);

// ---------------------------------------------------------------- OPNsense default (automatic) rules
$marked = RuleEngine::markAutomatic([rule(['label' => 'sys']), rule(['label' => 'mine']), rule(['label' => 'nolabel-3'])], ['sys' => true]);
check('automatic label flagged', $marked[0]['automatic'] === true);
check('user rule not flagged', $marked[1]['automatic'] === false);
check('unlabelled (synthetic) rule counts as automatic', $marked[2]['automatic'] === true);

$rules = prep(RuleEngine::markAutomatic([
    rule(['label' => 'lockout', 'protocol' => 'tcp', 'destination' => ['(self)'], 'to_port' => '= 443']),
    rule(['label' => 'lan-any', 'protocol' => 'tcp', 'to_port' => '= 8080']),
], ['lockout' => true]));
$graph = RuleEngine::buildGraph([$laptop], $rules, $IFACES);
$fwEdge = array_values(array_filter($graph['edges'], function ($e) { return $e['to'] === 'firewall'; }))[0];
check('mixed default + user rules: edge not default', $fwEdge['default'] === false);
check('per-range default flag', array_column($fwEdge['allowed'], 'default') === [true, false]);
check('graph rule map carries the automatic flag', $graph['rules']['lockout']['automatic'] === true && $graph['rules']['lan-any']['automatic'] === false);

$rules = prep(RuleEngine::markAutomatic([
    rule(['label' => 'lockout', 'protocol' => 'tcp', 'destination' => ['(self)'], 'to_port' => '= 443']),
], ['lockout' => true]));
$fwEdge = array_values(array_filter(RuleEngine::buildGraph([$laptop], $rules, $IFACES)['edges'], function ($e) { return $e['to'] === 'firewall'; }))[0];
check('allowed only by default rules: edge is default', $fwEdge['default'] === true);

// ---------------------------------------------------------------- dead (shadowed) rules
$covers = function ($a, $b) use ($IFACES) {
    [$pa, $pb] = prep([rule($a), rule($b)]);
    return RuleEngine::ruleCovers($pa, $pb, $IFACES);
};
check('subnet covers host', $covers(['source' => ['192.168.77.0/24']], ['source' => ['192.168.77.30']]) === true);
check('host does not cover subnet', $covers(['source' => ['192.168.77.30']], ['source' => ['192.168.77.0/24']]) === false);
check('wider /24 is not covered by a /25 with the same start', $covers(['source' => ['192.168.77.0/25']], ['source' => ['192.168.77.0/24']]) === false);
check('narrower /25 inside /24 is covered', $covers(['source' => ['192.168.77.0/24']], ['source' => ['192.168.77.0/25']]) === true);
check("'any' covers everything", $covers([], ['source' => ['10.0.0.1'], 'destination' => ['10.0.0.2'], 'protocol' => 'tcp', 'to_port' => '= 22']) === true);
check('protocol any covers tcp', $covers(['protocol' => 'any'], ['protocol' => 'tcp']) === true);
check('tcp does not cover any', $covers(['protocol' => 'tcp'], ['protocol' => 'any']) === false);
check('port range covers single port', $covers(['protocol' => 'tcp', 'to_port' => '1:1024'], ['protocol' => 'tcp', 'to_port' => '= 22']) === true);
check('single port does not cover all ports', $covers(['protocol' => 'tcp', 'to_port' => '= 22'], ['protocol' => 'tcp']) === false);
check('other interface does not cover', $covers(['interface' => 'vtnet2'], []) === false);
check('floating covers an interface rule', $covers(['interface' => 'any'], []) === true);
check('interface rule does not cover floating', $covers([], ['interface' => 'any']) === false);
check('"! vtnet2" covers vtnet0', $covers(['interface' => 'vtnet2', 'interface_not' => true], []) === true);
check('direction any covers in', $covers(['direction' => 'any'], []) === true);
check('out does not cover in', $covers(['direction' => 'out'], []) === false);
check('inet6 does not cover inet', $covers(['ipprotocol' => 'inet6'], []) === false);
check('negated source is not used to prove cover', $covers(['source' => ['10.0.0.0/8'], 'source_not' => true], ['source' => ['192.168.77.5']]) === false);
check('rule with icmp-type is not used to prove cover', $covers(['text' => 'pass in quick inet proto icmp all icmp-type echoreq'], []) === false);
check('rule using a pf table is not used to prove cover', $covers(['text' => 'block in quick from <abuse> to any'], []) === false);

// the testlab mistake: allow-all before specific blocks
$rules = prep([
    rule(['label' => 'allow-lan', 'source' => ['(vtnet0:network)']]),
    rule(['label' => 'printer-block', 'action' => 'block', 'source' => ['192.168.77.30']]),
    rule(['label' => 'ssh-block', 'action' => 'block', 'protocol' => 'tcp', 'source' => ['(vtnet0:network)'], 'destination' => ['192.168.77.20'], 'to_port' => '= ssh']),
    rule(['label' => 'dup-pass', 'protocol' => 'tcp', 'source' => ['192.168.77.191'], 'destination' => ['192.168.77.20']]),
    rule(['label' => 'other-if', 'action' => 'block', 'interface' => 'vtnet2']),
]);
$dead = RuleEngine::deadRules($rules, $IFACES);
check('block after allow-all is contradicted', ($dead['printer-block'] ?? null) === ['by' => 'allow-lan', 'kind' => 'contradicted', 'position' => 'earlier']);
check('port block after allow-all is contradicted', ($dead['ssh-block']['kind'] ?? null) === 'contradicted');
check('pass after allow-all is redundant', ($dead['dup-pass'] ?? null) === ['by' => 'allow-lan', 'kind' => 'redundant', 'position' => 'earlier']);
check('rule on another interface is alive', !isset($dead['other-if']));
check('the covering rule itself is alive', !isset($dead['allow-lan']));

// order matters: specific block BEFORE allow-all is fine
$rules = prep([
    rule(['label' => 'printer-block', 'action' => 'block', 'source' => ['192.168.77.30']]),
    rule(['label' => 'allow-lan', 'source' => ['(vtnet0:network)']]),
]);
check('block before allow-all is alive', RuleEngine::deadRules($rules, $IFACES) === []);

// non-quick: overridden by any later rule; quick: only by earlier quick
$rules = prep([
    rule(['label' => 'nq-block', 'action' => 'block', 'quick' => false]),
    rule(['label' => 'later-pass', 'quick' => false]),
]);
check('non-quick rule overridden by a later covering rule is dead', (RuleEngine::deadRules($rules, $IFACES)['nq-block']['kind'] ?? null) === 'contradicted');
check('...and is reported as overridden by a LATER rule', (RuleEngine::deadRules($rules, $IFACES)['nq-block']['position'] ?? null) === 'later');
$rules = prep([
    rule(['label' => 'q-block', 'action' => 'block']),
    rule(['label' => 'later-pass']),
]);
check('quick rule is not killed by a later rule', !isset(RuleEngine::deadRules($rules, $IFACES)['q-block']));
$rules = prep([
    rule(['label' => 'nq-early', 'quick' => false]),
    rule(['label' => 'q-target', 'action' => 'block']),
]);
$dead = RuleEngine::deadRules($rules, $IFACES);
check('earlier NON-quick rule does not shadow a quick rule', !isset($dead['q-target']));
check('...but that non-quick rule is itself dead (the later quick rule always wins)', ($dead['nq-early']['kind'] ?? null) === 'contradicted');

// one OPNsense rule = several pf lines: dead only if all lines are
$rules = prep([
    rule(['label' => 'allow-lan', 'source' => ['(vtnet0:network)']]),
    rule(['label' => 'multi', 'action' => 'block', 'source' => ['192.168.77.30']]),
    rule(['label' => 'multi', 'action' => 'block', 'interface' => 'vtnet2', 'source' => ['10.0.10.5']]),
]);
check('rule with one live line is alive', !isset(RuleEngine::deadRules($rules, $IFACES)['multi']));
// pf tables (aliases): judged only where the covering rule says 'any' on
// that side - whatever the table holds, it's covered
$rules = prep([
    rule(['label' => 'allow-all']),
    rule(['label' => 'blk', 'action' => 'block', 'text' => 'block in quick from <sshlockout> to any', 'source' => ['10.9.9.9']]),
]);
check('table rule covered by an "any" rule is dead', (RuleEngine::deadRules($rules, $IFACES)['blk']['kind'] ?? null) === 'contradicted');
$rules = prep([
    rule(['label' => 'lan-only', 'source' => ['10.0.0.0/8']]),
    rule(['label' => 'blk', 'action' => 'block', 'text' => 'block in quick from <sshlockout> to any', 'source' => ['10.9.9.9']]),
]);
check('table side is NOT judged covered by a specific network (contents can change)', RuleEngine::deadRules($rules, $IFACES) === []);
// the testlab stage-3 case: pass to ! <net_rfc1918> below a quick block-to-any
$rules = prep([
    rule(['label' => 'iot-block', 'action' => 'block', 'interface' => 'vtnet2', 'source' => ['(vtnet2:network)']]),
    rule(['label' => 'iot-inet', 'interface' => 'vtnet2', 'source' => ['(vtnet2:network)'],
        'destination' => ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'], 'destination_not' => true,
        'text' => 'pass in quick on vtnet2 inet from (vtnet2:network) to ! <net_rfc1918> flags S/SA keep state']),
]);
check('negated alias rule below a block-to-any is reported dead', (RuleEngine::deadRules($rules, $IFACES)['iot-inet']['by'] ?? null) === 'iot-block');
$rules = prep([
    rule(['label' => 'cover', 'text' => 'pass in quick from <trusted> to any', 'source' => ['192.168.77.0/24']]),
    rule(['label' => 'target', 'action' => 'block', 'source' => ['192.168.77.30']]),
]);
check('a covering rule\'s own table never counts as proof', RuleEngine::deadRules($rules, $IFACES) === []);

$findings = RuleEngine::deadRuleFindings(prep(RuleEngine::markAutomatic([
    rule(['label' => 'allow-lan', 'descr' => 'Default allow LAN', 'source' => ['(vtnet0:network)']]),
    rule(['label' => 'printer-block', 'descr' => 'printer no outbound', 'action' => 'block', 'source' => ['192.168.77.30']]),
], [])), $IFACES);
check('findings carry names and actions of both rules', $findings === [[
    'label' => 'printer-block', 'descr' => 'printer no outbound', 'action' => 'block', 'automatic' => false,
    'kind' => 'contradicted', 'by' => 'allow-lan', 'by_descr' => 'Default allow LAN', 'by_action' => 'pass',
    'by_position' => 'earlier', 'pairs' => [],
]]);

// the pairs a dead rule was written for (highlighted on the graph)
$lan2 = ['id' => 'lan2', 'ip' => '192.168.77.40', 'hostname' => 'lan2', 'if' => 'vtnet0'];
$rules = prep([
    rule(['label' => 'allow-lan', 'source' => ['(vtnet0:network)']]),
    rule(['label' => 'ssh-nas', 'action' => 'block', 'protocol' => 'tcp', 'source' => ['(vtnet0:network)'], 'destination' => ['10.0.10.20'], 'to_port' => '= ssh']),
    rule(['label' => 'to-gui', 'protocol' => 'tcp', 'source' => ['192.168.77.191'], 'destination' => ['192.168.77.1'], 'to_port' => '= 443']),
]);
$f = [];
foreach (RuleEngine::deadRuleFindings($rules, $IFACES, [$laptop, $nas, $lan2]) as $x) {
    $f[$x['label']] = $x['pairs'];
}
check('dead block: every LAN device -> nas', $f['ssh-nas'] === [['device:aa', 'device:bb'], ['device:lan2', 'device:bb']]);
check('dead pass to the firewall GUI: laptop -> firewall', $f['to-gui'] === [['device:aa', 'firewall']]);
check('nas is not a source for a LAN-sourced rule', !in_array(['device:bb', 'device:bb'], $f['ssh-nas'], true));

// ---------------------------------------------------------------- WAN (outbound to the internet)
$WIFACES = $IFACES + ['vtnet1' => ['key' => 'wan', 'descr' => 'WAN', 'ipv4' => [['ipaddr' => '203.0.113.2', 'subnetbits' => 24]]]];
$outAll = rule(['label' => 'out', 'direction' => 'out', 'interface' => 'any', 'quick' => false]);
check('WAN interface found by key', RuleEngine::wanInterfaces($WIFACES) === ['vtnet1']);

$rules = prep([rule(['label' => 'lan-any', 'source' => ['(vtnet0:network)']]), $outAll]);
$g = RuleEngine::buildGraph([$laptop], $rules, $WIFACES);
$wanEdge = array_values(array_filter($g['edges'], function ($e) { return $e['to'] === 'wan'; }))[0] ?? null;
check('device -> WAN edge exists when a LAN-to-any rule allows it', $wanEdge !== null && sliceFor([], 'tcp') === null);
check('LAN-to-any reaching the internet is broad (orange)', $wanEdge['intended'] === false);
check('WAN node is evaluable when a WAN exists', array_values(array_filter($g['nodes'], function ($n) { return $n['id'] === 'wan'; }))[0]['evaluable'] === true);
check('no WAN interface: no WAN edges, node pending', !array_filter(RuleEngine::buildGraph([$laptop], $rules, $IFACES)['edges'], function ($e) { return $e['to'] === 'wan'; }));

// "anything except private ranges" explicitly targets the internet (blue)
$rules = prep([rule(['label' => 'inet', 'source' => ['(vtnet0:network)'], 'destination' => ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'], 'destination_not' => true]), $outAll]);
$wanEdge = array_values(array_filter(RuleEngine::buildGraph([$laptop], $rules, $WIFACES)['edges'], function ($e) { return $e['to'] === 'wan'; }))[0];
check('pass to ! RFC1918 reaches the internet and is intended (blue)', $wanEdge['intended'] === true && !empty($wanEdge['allowed']));
$g2 = RuleEngine::buildGraph([$laptop, $nas], $rules, $WIFACES);
check('...and does not reach a device on another private segment', !array_filter($g2['edges'], function ($e) { return $e['from'] === 'device:aa' && $e['to'] === 'device:bb'; }));

// a specific public network blocked: reported as a region exception
$rules = prep([
    rule(['label' => 'block-bad', 'action' => 'block', 'source' => ['(vtnet0:network)'], 'destination' => ['198.18.0.0/15']]),
    rule(['label' => 'lan-any', 'source' => ['(vtnet0:network)']]),
    $outAll,
]);
$t = RuleEngine::internetTargets($rules, $WIFACES);
check('general internet stand-in avoids networks named in rules', !in_array($t['general'], ['198.18.0.10'], true) && isset($t['regions']['198.18.0.0/15']));
$wanEdge = array_values(array_filter(RuleEngine::buildGraph([$laptop], $rules, $WIFACES)['edges'], function ($e) { return $e['to'] === 'wan'; }))[0];
check('general internet still allowed', !empty($wanEdge['allowed']));
check('blocked public network listed as an exception with nothing allowed', $wanEdge['regions'] === [['cidr' => '198.18.0.0/15', 'allowed' => []]]);

// outbound block on the WAN interface stops it
$rules = prep([
    rule(['label' => 'lan-any', 'source' => ['(vtnet0:network)']]),
    rule(['label' => 'no-out', 'action' => 'block', 'direction' => 'out', 'interface' => 'vtnet1']),
    $outAll,
]);
check('block out on the WAN interface: no internet edge', !array_filter(RuleEngine::buildGraph([$laptop], $rules, $WIFACES)['edges'], function ($e) { return $e['to'] === 'wan'; }));

// private destinations and the firewall's own addresses are never "regions"
$rules = prep([rule(['label' => 'x', 'destination' => ['192.168.5.0/24', '203.0.113.2', '8.8.8.8']]), $outAll]);
check('only public, non-firewall networks become regions', array_keys(RuleEngine::internetTargets($rules, $WIFACES)['regions']) === ['8.8.8.8/32']);

// ---------------------------------------------------------------- empty pf tables (unapplied aliases)
$tr = [
    rule(['label' => 'neg', 'descr' => 'Allow IoT to internet', 'text' => 'pass in quick on vtnet2 inet from (vtnet2:network) to ! <net_rfc1918> flags S/SA']),
    rule(['label' => 'pos', 'descr' => 'Block bad', 'text' => 'block in quick from <badhosts> to any']),
    rule(['label' => 'lock', 'descr' => 'sshlockout', 'text' => 'block in quick from <sshlockout> to (self)']),
    rule(['label' => 'full', 'descr' => 'uses full', 'text' => 'pass in quick from <fullset> to any']),
];
$et = RuleEngine::emptyTableFindings($tr, ['net_rfc1918' => 0, 'badhosts' => 0, 'sshlockout' => 0, 'fullset' => 4, 'unread' => null]);
check('empty tables reported, negated use first', array_column($et, 'name') === ['net_rfc1918', 'badhosts']);
check('"! table" use flagged as matching everything', $et[0]['negated'] === true && $et[0]['rules'] === [['label' => 'neg', 'descr' => 'Allow IoT to internet', 'negated' => true]]);
check('plain use flagged as matching nothing', $et[1]['negated'] === false);
check('normally-empty lockout tables and non-empty/unreadable ones are not reported', count($et) === 2);
check('unreferenced empty table not reported', RuleEngine::emptyTableFindings($tr, ['orphan' => 0]) === []);

// loopback is never a reachable firewall address
$LIFACES = $IFACES + ['lo0' => ['key' => 'lo0', 'descr' => 'Loopback', 'ipv4' => [['ipaddr' => '127.0.0.1', 'subnetbits' => 8]]]];
check('firewall targets exclude loopback', !in_array('127.0.0.1', array_column(RuleEngine::firewallTargets($LIFACES), 'ip'), true));
$rules = prep([rule(['label' => 'inet', 'interface' => 'vtnet0', 'source' => ['(vtnet0:network)'],
    'destination' => ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'], 'destination_not' => true])]);
check('"to ! <private>" does not reach the firewall via 127.0.0.1', !array_filter(
    RuleEngine::buildGraph([$laptop], $rules, $LIFACES)['edges'], function ($e) { return $e['to'] === 'firewall'; }));

// ---------------------------------------------------------------- IPv6
$IF6 = [
    'vtnet0' => ['key' => 'lan', 'descr' => 'LAN', 'ipv4' => [['ipaddr' => '192.168.77.1', 'subnetbits' => 24]],
        'ipv6' => [['ipaddr' => 'fd00:77::1', 'subnetbits' => 64, 'linklocal' => false], ['ipaddr' => 'fe80::1%vtnet0', 'subnetbits' => 64, 'linklocal' => true]]],
    'vtnet2' => ['key' => 'opt1', 'descr' => 'IoT', 'ipv4' => [['ipaddr' => '192.168.88.1', 'subnetbits' => 24]],
        'ipv6' => [['ipaddr' => 'fd00:88::1', 'subnetbits' => 64, 'linklocal' => false], ['ipaddr' => 'fe80::2%vtnet2', 'subnetbits' => 64, 'linklocal' => true]]],
    'vtnet1' => ['key' => 'wan', 'descr' => 'WAN', 'ipv4' => [['ipaddr' => '203.0.113.2', 'subnetbits' => 24]],
        'ipv6' => [['ipaddr' => '2001:db8:ffff::2', 'subnetbits' => 64, 'linklocal' => false]]],
];
$lan6 = ['id' => 'l', 'ip' => '192.168.77.10', 'ipv6' => ['fd00:77::10'], 'hostname' => 'lan6', 'if' => 'vtnet0'];
$iot6 = ['id' => 'i', 'ip' => '192.168.88.50', 'ipv6' => ['fd00:88::50'], 'hostname' => 'iot6', 'if' => 'vtnet2'];
$p6 = function ($o) {
    return rule($o);
};
$out6 = rule(['label' => 'out', 'direction' => 'out', 'interface' => 'any', 'quick' => false, 'ipprotocol' => 'any']);

check('deviceAddr picks per family', RuleEngine::deviceAddr($lan6, 4) === '192.168.77.10' && RuleEngine::deviceAddr($lan6, 6) === 'fd00:77::10');
check('(vtnet0:network) expands to both families', RuleEngine::resolveDynamicAddr('(vtnet0:network)', $IF6) === ['192.168.77.0/24', 'fd00:77::/64', 'fe80::/64']);
check('IPv6 placement ignores link-local networks', RuleEngine::interfaceForIp('fd00:88::77', $IF6) === 'vtnet2' && RuleEngine::interfaceForIp('fe80::99', $IF6) === null);
check('IPv6 firewall targets: global/ULA everywhere, link-local only on the source segment',
    array_column(RuleEngine::firewallTargets($IF6, 6, 'vtnet2'), 'ip') === ['fd00:77::1', 'fd00:88::1', 'fe80::2', '2001:db8:ffff::2']);

// the classic hole: IPv4 blocks IoT -> LAN, IPv6 doesn't
$rules = ([
    rule(['label' => 'v4-block', 'action' => 'block', 'interface' => 'vtnet2', 'ipprotocol' => 'inet', 'source' => ['(vtnet2:network)'], 'destination' => ['(vtnet0:network)']]),
    rule(['label' => 'v6-any', 'interface' => 'vtnet2', 'ipprotocol' => 'inet6', 'source' => ['(vtnet2:network)']]),
    $out6,
]);
$rules = RuleEngine::prepareRules($rules, $IF6);
$g6 = RuleEngine::buildGraph([$lan6, $iot6], $rules, $IF6);
$e6 = [];
foreach ($g6['edges'] as $e) {
    $e6[$e['from'] . '>' . $e['to']] = $e;
}
$iotLan = $e6['device:i>device:l'] ?? null;
check('IPv6 bypass: iot -> lan edge exists although IPv4 blocks it', $iotLan !== null);
check('...and every allowed entry on it is IPv6', $iotLan !== null && !array_filter($iotLan['allowed'], function ($a) {
    return ($a['family'] ?? 'inet') !== 'inet6';
}));
check('IPv4 entries carry no family field (output and fingerprints unchanged)', !array_filter($g['edges'] ?? [], function ($e) {
    foreach ($e['allowed'] ?? [] as $a) {
        if (isset($a['family'])) {
            return true;
        }
    }
    return false;
}));

// IPv6 internet: stand-in, ULA never "internet", "! fc00::/7" is intended
$t6 = RuleEngine::internetTargets(RuleEngine::prepareRules([rule(['destination' => ['fd00::/8', '2001:db8:aaaa::/48']])], $IF6), $IF6, 6);
check('IPv6 internet stand-in avoids named networks; ULA is never a region', $t6['general'] === '2001:db8::10' && array_keys($t6['regions']) === ['2001:db8:aaaa::/48']);
$rules = RuleEngine::prepareRules(([
    rule(['label' => 'v6-inet', 'interface' => 'vtnet0', 'ipprotocol' => 'inet6', 'source' => ['(vtnet0:network)'], 'destination' => ['fc00::/7'], 'destination_not' => true]),
    $out6,
]), $IF6);
$wan6 = array_values(array_filter(RuleEngine::buildGraph([$lan6], $rules, $IF6)['edges'], function ($e) { return $e['to'] === 'wan'; }))[0] ?? null;
check('IPv6 "! fc00::/7" reaches the internet and is intended (blue)', $wan6 !== null && $wan6['intended'] === true
    && ($wan6['allowed'][0]['family'] ?? null) === 'inet6');

// dead rules work across families
$rules = RuleEngine::prepareRules(([
    rule(['label' => 'v6-all', 'interface' => 'vtnet2', 'ipprotocol' => 'inet6', 'source' => ['(vtnet2:network)']]),
    rule(['label' => 'v6-block', 'action' => 'block', 'interface' => 'vtnet2', 'ipprotocol' => 'inet6', 'source' => ['fd00:88::50']]),
    rule(['label' => 'v4-block', 'action' => 'block', 'interface' => 'vtnet2', 'ipprotocol' => 'inet', 'source' => ['192.168.88.50']]),
]), $IF6);
$d6 = RuleEngine::deadRules($rules, $IF6);
check('IPv6 block behind an IPv6 allow-all is dead', ($d6['v6-block']['kind'] ?? null) === 'contradicted');
check('IPv4 block is not shadowed by an IPv6-only rule', !isset($d6['v4-block']));

// ---------------------------------------------------------------- inbound (port forwards)
$NIF = [
    'vtnet0' => ['key' => 'lan', 'descr' => 'LAN', 'ipv4' => [['ipaddr' => '192.168.77.1', 'subnetbits' => 24]],
        'ipv6' => [['ipaddr' => '2001:db8:77::1', 'subnetbits' => 64, 'linklocal' => false]]],
    'vtnet1' => ['key' => 'wan', 'descr' => 'WAN', 'ipv4' => [['ipaddr' => '203.0.113.2', 'subnetbits' => 24]],
        'ipv6' => [['ipaddr' => '2001:db8:ffff::2', 'subnetbits' => 64, 'linklocal' => false]]],
];
$srv = ['id' => 's', 'ip' => '192.168.77.20', 'ipv6' => ['2001:db8:77::20'], 'hostname' => 'srv', 'if' => 'vtnet0'];
$rdr = function ($o) {
    return array_merge(['seq' => 0, 'no' => false, 'pass' => false, 'interface' => 'vtnet1', 'interface_not' => false,
        'ipprotocol' => 'inet', 'protocol' => 'tcp', 'source' => ['any'], 'source_not' => false, 'from_port' => null,
        'destination' => ['(vtnet1)'], 'destination_not' => false, 'to_port' => null, 'target' => ['192.168.77.20'],
        'target_port' => null, 'text' => 'rdr test'], $o);
};
$nr = function ($list) use ($NIF) {
    return RuleEngine::prepareRedirects($list, $NIF);
};
$nRules = function ($list) use ($NIF) {
    return RuleEngine::prepareRules($list, $NIF);
};
$outN = rule(['label' => 'out', 'direction' => 'out', 'interface' => 'any', 'quick' => false, 'ipprotocol' => 'any']);

$f = RuleEngine::forwardsTo($nr([$rdr(['to_port' => '8000:8010', 'target_port' => '9000'])]), ['192.168.77.20'], $NIF);
check('range forward maps onto the target port onward', $f[0]['ext'] === [8000, 8010] && $f[0]['int'] === [9000, 9010]);
$f = RuleEngine::forwardsTo($nr([
    $rdr(['seq' => 0, 'no' => true, 'to_port' => '= 443', 'target' => []]),
    $rdr(['seq' => 1, 'to_port' => '= 443', 'target_port' => '443']),
]), ['192.168.77.20'], $NIF);
check('a forward behind an earlier "no rdr" for the same port is not active', $f === []);

// manual forward made live by a WAN rule allowing the translated traffic
$rules = $nRules([
    rule(['label' => 'wan-https', 'interface' => 'vtnet1', 'protocol' => 'tcp', 'destination' => ['192.168.77.20'], 'to_port' => '= 443']),
    $outN,
]);
$in = RuleEngine::evaluateInbound($rules, $nr([$rdr(['to_port' => '= 8443', 'target_port' => '443'])]), $srv, $NIF);
check('manual forward + WAN rule: reachable on the internal port via that rule', $in['forwards'][0]['allowed'] === true
    && RuleEngine::summarisePair(['targets' => array_values(array_filter($in['targets'], function ($t) { return $t['family'] === 'inet'; }))])['allowed'][0]['rules'] === ['wan-https']);
$in = RuleEngine::evaluateInbound($nRules([$outN]), $nr([$rdr(['to_port' => '= 8443', 'target_port' => '443'])]), $srv, $NIF);
check('manual forward without a rule is not allowed (inert)', $in['forwards'][0]['allowed'] === false);
check('inertForwards reports it', count(RuleEngine::inertForwards($nRules([$outN]), $nr([$rdr(['to_port' => '= 8443', 'target_port' => '443'])]), [$srv], $NIF)) === 1);

// direct IPv6 inbound to a global address (no NAT in IPv6)
$rules = $nRules([
    rule(['label' => 'wan-v6-ssh', 'interface' => 'vtnet1', 'ipprotocol' => 'inet6', 'protocol' => 'tcp', 'destination' => ['2001:db8:77::20'], 'to_port' => '= 22']),
    $outN,
]);
$g = RuleEngine::buildGraph([$srv], $rules, $NIF, []);
$wanSrv = array_values(array_filter($g['edges'], function ($e) { return $e['from'] === 'wan' && $e['to'] === 'device:s'; }))[0] ?? null;
check('direct IPv6 inbound to a global address shows as WAN -> device', $wanSrv !== null
    && $wanSrv['allowed'][0]['family'] === 'inet6' && $wanSrv['allowed'][0]['from'] === 22);

// the firewall's GUI exposed on WAN
$rules = $nRules([rule(['label' => 'gui-wan', 'interface' => 'vtnet1', 'protocol' => 'tcp', 'destination' => ['(self)'], 'to_port' => '= 443']), $outN]);
$g = RuleEngine::buildGraph([$srv], $rules, $NIF, []);
$wanFw = array_values(array_filter($g['edges'], function ($e) { return $e['from'] === 'wan' && $e['to'] === 'firewall'; }))[0] ?? null;
check('GUI exposed on WAN: WAN -> firewall tcp/443', $wanFw !== null && $wanFw['allowed'][0]['proto'] === 'tcp' && $wanFw['allowed'][0]['from'] === 443);

// placement: host override with no interface gets one from its subnet
$placed = RuleEngine::placeDevices([['id' => 'x', 'ip' => '10.0.10.99', 'if' => null]], $IFACES);
check('device placed onto interface by subnet', $placed[0]['if'] === 'vtnet2');

echo "{$passed} passed, {$failures} failed\n";
exit($failures > 0 ? 1 : 0);
