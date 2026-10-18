<?php

/**
 * Regression test against REAL output from the test OPNsense 26.7 box
 * (tests/fixtures/testlab-20261016, see its README for what's captured and
 * what's reconstructed). Runs the actual TopologyController on it.
 *
 * Guards the first on-box findings: unlabelled anti-spoof rules and scrub
 * lines, and the "block ... from any port = 0" auto rule that used to
 * swallow all TCP/UDP to the firewall.
 *
 * Run: php tests/test_testlab_capture.php
 */

$dir = __DIR__ . '/fixtures/testlab-20261016';
$GLOBALS['CB_FIXTURE'] = [
    'configd' => [
        'interface list ifconfig' => file_get_contents("$dir/ifconfig.json"),
        'dnsmasq list leases' => file_get_contents("$dir/leases.json"),
        'interface list ndp' => '[]',
        'filter list rule_ids' => file_get_contents("$dir/rule_ids.json"),
        'controlledburn get ruleset' => file_get_contents("$dir/ruleset.json"),
        'filter list non_mvc_rules' => file_get_contents("$dir/non_mvc_rules.json"),
    ],
    'interfaces' => [
        'lan' => ['if' => 'vtnet0', 'descr' => 'LAN', 'ipaddr' => '192.168.77.1', 'subnet' => '24'],
        'wan' => ['if' => 'vtnet1', 'descr' => 'WAN', 'ipaddr' => 'dhcp'],
        // recent OPNsense lists loopback as a configured interface
        'lo0' => ['if' => 'lo0', 'descr' => 'Loopback', 'ipaddr' => '127.0.0.1', 'subnet' => '8'],
    ],
    'hosts' => [
        ['nas', ['192.168.77.20'], ['bc:24:11:77:03:02']],
        ['media', ['192.168.77.20'], []],
        ['clash', ['192.168.77.41'], []],
        ['dtest', ['192.168.77.42'], []],
    ],
];
require __DIR__ . '/lib/opnsense_stubs.php';

$c = cb_controller();
$graph = $c->graphAction();
if (getenv('CB_DUMP_GRAPH')) {
    file_put_contents(getenv('CB_DUMP_GRAPH'), json_encode($graph, JSON_UNESCAPED_SLASHES) . "\n");
}

check('every filter rule parses (scrub skipped, unlabelled anti-spoof rules included)', $graph['unparsed_count'] === 0 && $graph['unparsed'] === []);

$nodes = [];
foreach ($graph['nodes'] as $n) {
    $nodes[$n['id']] = $n;
}
$nas = 'device:bc:24:11:77:03:02';
$lab = 'device:bc:24:11:00:ef:67';
check('devices: nas, lab-dev01, clash, dtest (+ firewall, wan)', count($nodes) === 6
    && isset($nodes[$nas], $nodes[$lab], $nodes['device:192.168.77.41'], $nodes['device:192.168.77.42']));
check('media merged into nas and kept as an alias', $nodes[$nas]['aliases'] === ['media']);

$edges = [];
foreach ($graph['edges'] as $e) {
    $edges[$e['from'] . '>' . $e['to']] = $e;
}
check('devices on the one LAN segment are unfiltered to each other', ($edges["$lab>$nas"]['kind'] ?? null) === 'unfiltered');

$fw = $edges["$lab>firewall"];
$byKey = [];
foreach ($fw['allowed'] as $a) {
    $byKey[$a['proto'] . ':' . $a['from'] . '-' . $a['to']] = $a;
}
$descr = function ($a) use ($graph) {
    return $graph['rules'][$a['rules'][0]]['descr'];
};
check('source-port-0 block no longer swallows TCP to the firewall', isset($byKey['tcp:22-22'], $byKey['tcp:444-65535']));
check('tcp/22, 80, 443 to the firewall come from the anti-lockout rule', $descr($byKey['tcp:22-22']) === 'anti-lockout rule'
    && $descr($byKey['tcp:80-80']) === 'anti-lockout rule' && $descr($byKey['tcp:443-443']) === 'anti-lockout rule');
check('the rest of tcp comes from Default allow LAN to any', $descr($byKey['tcp:444-65535']) === 'Default allow LAN to any rule');
check('anti-lockout (to self) is intended, LAN-to-any is broad', $byKey['tcp:22-22']['intended'] === true && $byKey['tcp:444-65535']['intended'] === false);
check('so the edge as a whole is not intended (orange)', $fw['intended'] === false);
check('anti-lockout is flagged as an OPNsense default rule', $graph['rules'][$byKey['tcp:22-22']['rules'][0]]['automatic'] === true
    && $byKey['tcp:22-22']['default'] === true);
check('"Default allow LAN to any" is NOT a default (editable user rule)', $graph['rules'][$byKey['tcp:444-65535']['rules'][0]]['automatic'] === false);
check('mixed default + user rules: edge not purple', $fw['default'] === false);
check('tcp port 0 itself stays blocked', !array_filter($fw['allowed'], function ($a) {
    return $a['proto'] === 'tcp' && $a['from'] === 0;
}));
check('udp/67 to the firewall is the DHCP rule, conditional on source port 68', $descr($byKey['udp:67-67']) === 'allow access to DHCP server' && $fw['conditional'] === true);
check('empty pf tables (sshlockout, virusprot) cause no uncertainty', $fw['uncertain'] === false);

$dead = [];
foreach ($graph['dead_rules'] as $d) {
    $dead[$d['descr']] = $d;
}
check('dead: "printer no outbound" never applies, shadowed by Default allow LAN to any',
    ($dead['printer no outbound']['kind'] ?? null) === 'contradicted' && $dead['printer no outbound']['by_descr'] === 'Default allow LAN to any rule');
check('dead: "block ssh to nas" never applies, shadowed by Default allow LAN to any',
    ($dead['block ssh to nas']['kind'] ?? null) === 'contradicted' && $dead['block ssh to nas']['by_descr'] === 'Default allow LAN to any rule');
check('dead: the two lab-dev01 -> nas passes are redundant', ($dead['lab-dev to nas']['kind'] ?? null) === 'redundant'
    && ($dead['labdev01 to nas']['kind'] ?? null) === 'redundant');
check('dead: "firewall gui" is redundant behind the anti-lockout rule', ($dead['firewall gui']['by_descr'] ?? null) === 'anti-lockout rule');
check('dead: "Default allow LAN to any" itself is alive', !isset($dead['Default allow LAN to any rule']));
check('dead "block ssh to nas" highlights every other LAN device -> nas', $dead['block ssh to nas']['pairs'] === [
    [$lab, $nas], ['device:192.168.77.41', $nas], ['device:192.168.77.42', $nas]]);
check('dead "printer no outbound" matches no device on the graph (printer not discovered)', $dead['printer no outbound']['pairs'] === []);
check('dead "firewall gui" highlights lab-dev01 -> firewall', $dead['firewall gui']['pairs'] === [[$lab, 'firewall']]);
check('dead: anti-spoof (unlabelled) rules are flagged as automatic, not as the user\'s', count(array_filter($graph['dead_rules'], function ($d) {
    return strpos($d['label'], 'nolabel-') === 0 && $d['automatic'] === true;
})) === 6);
check('dead: exactly 5 of the user\'s own rules are dead', count(array_filter($graph['dead_rules'], function ($d) {
    return !$d['automatic'];
})) === 5);
check('dead: anti-spoof rules are overridden by the LATER default deny (non-quick, last match wins)', count(array_filter($graph['dead_rules'], function ($d) {
    return strpos($d['label'], 'nolabel-') === 0 && $d['by_position'] === 'later' && $d['by_descr'] === 'Default deny / state violation rule';
})) === 6);
check('dead: the user\'s blocks are shadowed by an EARLIER quick rule', $dead['block ssh to nas']['by_position'] === 'earlier');
check('dead: sshlockout/virusprot (pf tables) are never judged', !array_filter($graph['dead_rules'], function ($d) {
    return in_array($d['descr'], ['sshlockout', 'virusprot overload table'], true);
}));

$wan = $edges["$lab>wan"] ?? null;
check('WAN: lab-dev01 reaches the internet via "Default allow LAN to any"', $wan !== null
    && $graph['rules'][$wan['allowed'][0]['rules'][0]]['descr'] === 'Default allow LAN to any rule');
check('WAN: that is broad (orange), not explicitly internet-targeted', $wan['intended'] === false);
check('WAN: the node is evaluable now', $nodes['wan']['evaluable'] === true);

$c->request->q = ['src' => $lab, 'dst' => 'firewall'];
$pair = $c->pairAction();
check('firewall pair covers both firewall addresses (LAN and WAN)', array_column($pair['targets'], 'ip') === ['192.168.77.1', '10.100.59.2']);

// a DHCP flood (or a huge network): past 500 devices the graph isn't
// evaluated; the page explains instead of grinding for minutes
$leases = json_decode($GLOBALS['CB_FIXTURE']['configd']['dnsmasq list leases'], true);
for ($i = 0; $i < 501; $i++) {
    $leases['records'][] = ['address' => '192.168.77.' . (10 + $i % 240), 'hwaddr' => sprintf('02:00:00:00:%02x:%02x', intdiv($i, 256), $i % 256), 'hostname' => 'f' . $i, 'if' => 'vtnet0'];
}
$GLOBALS['CB_FIXTURE']['configd']['dnsmasq list leases'] = json_encode($leases);
$flood = $c->graphAction();
check('over 500 devices: graph not evaluated, count and limit reported', ($flood['too_many_devices'] ?? 0) === 503
    && $flood['device_limit'] === 500 && !isset($flood['edges']));

echo "{$passed} passed, {$failures} failed\n";
exit($failures > 0 ? 1 : 0);
