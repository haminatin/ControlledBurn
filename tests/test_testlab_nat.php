<?php

/**
 * Milestone 9b regression test on REAL port-forward output from the test
 * box (tests/fixtures/testlab-20261017-nat): an rdr pass forward opens a
 * device to the internet with no filter rule involved; a Manual forward
 * with no rule is inert; a misconfigured forward entry is flagged.
 *
 * Run: php tests/test_testlab_nat.php
 */

$dir = __DIR__ . '/fixtures/testlab-20261017-nat';
$old = __DIR__ . '/fixtures/testlab-20261016';
// same-day capture of the same box, which has the IoT segment (vtnet2)
$same = __DIR__ . '/fixtures/testlab-20261017-ipv6';
$GLOBALS['CB_FIXTURE'] = [
    'configd' => [
        'interface list ifconfig' => file_get_contents("$same/ifconfig.json"),
        'dnsmasq list leases' => file_get_contents("$same/leases.json"),
        'interface list ndp' => '[]',
        'filter list rule_ids' => file_get_contents("$old/rule_ids.json"),
        'controlledburn get ruleset' => file_get_contents("$dir/ruleset.json"),
        'filter list non_mvc_rules' => file_get_contents("$old/non_mvc_rules.json"),
    ],
    'interfaces' => [
        'lan' => ['if' => 'vtnet0', 'descr' => 'LAN', 'ipaddr' => '192.168.77.1', 'subnet' => '24'],
        'wan' => ['if' => 'vtnet1', 'descr' => 'WAN', 'ipaddr' => 'dhcp'],
        'opt1' => ['if' => 'vtnet2', 'descr' => 'IoT', 'ipaddr' => '192.168.88.1', 'subnet' => '24'],
        'lo0' => ['if' => 'lo0', 'descr' => 'Loopback', 'ipaddr' => '127.0.0.1', 'subnet' => '8'],
    ],
    'hosts' => [],
    // reconstructed Destination NAT rows (see the fixture README)
    'dnat' => [
        ['descr' => 'nas https', 'target' => '192.168.77.20', 'destination_port' => '8443', 'local-port' => '443'],
        ['descr' => 'lab ssh', 'target' => '192.168.77.191', 'destination_port' => '2222', 'local-port' => '22'],
        ['descr' => 'first try', 'target' => '', 'source_port' => '8443', 'destination_port' => ''],
        ['descr' => 'old, disabled', 'target' => '', 'disabled' => '1'],
    ],
];
require __DIR__ . '/lib/opnsense_stubs.php';

$g = cb_controller()->graphAction();
if (getenv('CB_DUMP_GRAPH')) {
    file_put_contents(getenv('CB_DUMP_GRAPH'), json_encode($g, JSON_UNESCAPED_SLASHES) . "\n");
}
$edges = [];
foreach ($g['edges'] as $e) {
    $edges[$e['from'] . '>' . $e['to']] = $e;
}
$lab = 'device:bc:24:11:00:ef:67';
$nas = 'device:bc:24:11:77:03:02';

check('all rules and redirects parse', $g['unparsed_count'] === 0);
$in = $edges["wan>$lab"] ?? null;
check('rdr pass: the internet reaches lab-dev01', $in !== null);
check('...on tcp/22 only (the forward\'s internal port)', $in !== null
    && array_map(function ($a) { return $a['proto'] . '/' . $a['from'] . '-' . $a['to']; }, $in['allowed']) === ['tcp/22-22']);
check('...credited to the forward itself, not a filter rule', $in !== null
    && strpos($in['allowed'][0]['rules'][0], 'fwd-') === 0
    && strpos($g['rules'][$in['allowed'][0]['rules'][0]]['descr'], 'Port forward (Firewall Rule: Pass): rdr pass on vtnet1') === 0);
check('...and explicit (blue): a forward names its target', $in !== null && $in['intended'] === true);
check('...the card has the external -> internal mapping', $in !== null && $in['forwards'][0]['ext'] === [2222, 2222]
    && $in['forwards'][0]['int'] === [22, 22] && $in['forwards'][0]['pass'] === true);

check('Manual forward with no rule: no internet -> nas edge', !isset($edges["wan>$nas"]));
check('...reported as inert', count($g['inert_forwards']) === 1 && $g['inert_forwards'][0]['device'] === $nas
    && $g['inert_forwards'][0]['ext'] === [8443, 8443] && $g['inert_forwards'][0]['int'] === [443, 443]);

check('the internet reaches nothing on the firewall itself', !isset($edges['wan>firewall']));
check('anti-lockout "no rdr" lines are not forwards', count(array_filter($g['inert_forwards'], function ($f) {
    return strpos($f['text'], 'no rdr') === 0;
})) === 0);

check('forward config: the source-port mistake is flagged twice (empty target, port in the wrong field)',
    array_column($g['forward_config'], 'descr') === ['first try', 'first try']);
check('forward config: disabled entries are ignored', !in_array('old, disabled', array_column($g['forward_config'], 'descr'), true));

// ---- pair drill-down (Milestone 7)
$pair = function ($src, $dst) {
    $c = cb_controller();
    $c->request->q = ['src' => $src, 'dst' => $dst];
    return $c->pairAction();
};
$slicesOf = function ($p) {
    $out = [];
    foreach ($p['targets'] as $t) {
        foreach ($t['slices'] as $s) {
            $out[] = $s + ['ip' => $t['ip']];
        }
    }
    return $out;
};
$b = $pair('wan', $lab);
$s = $slicesOf($b);
check('breakdown internet -> lab-dev01: one slice, tcp/22 allowed by the Pass forward', count($s) === 1
    && $s[0]['verdict'] === 'pass' && $s[0]['from'] === 22 && strpos($b['rules'][$s[0]['rule']]['descr'], 'Port forward') === 0);
check('...decided in on WAN, delivered out on LAN', $b['in_if']['descr'] === 'WAN' && $b['out_if']['descr'] === 'LAN');
$b = $pair('wan', $nas);
$s = $slicesOf($b);
// on OPNsense the default deny is a real rule, so it gets the credit
check('breakdown internet -> nas: the inert forward shows as tcp/443 blocked by the default deny rule', count($s) === 1
    && $s[0]['verdict'] === 'block' && $s[0]['from'] === 443
    && $b['rules'][$s[0]['rule']]['descr'] === 'Default deny / state violation rule'
    && $b['forwards'][0]['allowed'] === false && $b['forwards'][0]['ext'] === [8443, 8443]);
$b = $pair('wan', 'firewall');
check('breakdown internet -> firewall: everything blocked on the WAN address', $b['status'] === 'ok'
    && !array_filter($slicesOf($b), function ($s) { return $s['verdict'] === 'pass'; })
    && array_column($b['targets'], 'ip') === ['10.100.59.2']);
check('breakdown refuses traffic from the firewall itself', $pair('firewall', $lab)['status'] === 'failed');
check('breakdown refuses identical nodes', $pair($lab, $lab)['status'] === 'failed');
$b = $pair($lab, 'wan');
check('breakdown lab-dev01 -> internet: decided in on LAN, out on WAN', $b['status'] === 'ok' && $b['in_if']['descr'] === 'LAN' && $b['out_if']['descr'] === 'WAN'
    && count(array_filter($slicesOf($b), function ($s) { return $s['verdict'] === 'pass' && $s['proto'] === 'tcp'; })) > 0);

echo "{$passed} passed, {$failures} failed\n";
exit($failures > 0 ? 1 : 0);
