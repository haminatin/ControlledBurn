<?php

/**
 * Generates tests/fixtures/pairs_nat.json: the pair breakdown (topology/pair)
 * for every ordered node pair of the real port-forward capture, through the
 * real controller with the same stand-ins as tests/test_testlab_nat.php.
 * Used by tests/test_topology_js.js and the offline preview.
 *
 * Run: php tests/fixtures/make_pairs_nat.php > tests/fixtures/pairs_nat.json
 */

$dir = __DIR__ . '/testlab-20261017-nat';
$old = __DIR__ . '/testlab-20261016';
$same = __DIR__ . '/testlab-20261017-ipv6';
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
    ],
    'hosts' => [],
];
require __DIR__ . '/../lib/opnsense_stubs.php';

$ids = array_column(cb_controller()->graphAction()['nodes'], 'id');
$out = [];
foreach ($ids as $src) {
    foreach ($ids as $dst) {
        if ($src === $dst) {
            continue;
        }
        $c = cb_controller();
        $c->request->q = ['src' => $src, 'dst' => $dst];
        $out[$src . '>' . $dst] = $c->pairAction();
    }
}
echo json_encode($out, JSON_UNESCAPED_SLASHES) . "\n";
