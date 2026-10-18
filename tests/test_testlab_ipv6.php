<?php

/**
 * Milestone 10 regression test on REAL IPv6 output from the test box
 * (tests/fixtures/testlab-20261017-ipv6): devices get IPv6 from NDP (or an
 * assumed EUI-64 address when NDP hasn't seen them), and the deliberate
 * "IPv6 bypasses the IPv4 policy" hole shows up as IPv6-only edges.
 *
 * Run: php tests/test_testlab_ipv6.php
 */

$dir = __DIR__ . '/fixtures/testlab-20261017-ipv6';
$old = __DIR__ . '/fixtures/testlab-20261016';
function fixture($ndp)
{
    global $dir, $old;
    return [
        'configd' => [
            'interface list ifconfig' => file_get_contents("$dir/ifconfig.json"),
            'dnsmasq list leases' => file_get_contents("$dir/leases.json"),
            'interface list ndp' => $ndp,
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
    ];
}
$GLOBALS['CB_FIXTURE'] = fixture(file_get_contents("$dir/ndp.json"));
require __DIR__ . '/lib/opnsense_stubs.php';

$lab = 'device:bc:24:11:00:ef:67';
$nas = 'device:bc:24:11:77:03:02';
$cam = 'device:bc:24:11:88:03:03';
$bypass = '8d30a349-cab5-4601-a724-7ca3d096673a';

function graphOf()
{
    $g = cb_controller()->graphAction();
    $nodes = [];
    foreach ($g['nodes'] as $n) {
        $nodes[$n['id']] = $n;
    }
    $edges = [];
    foreach ($g['edges'] as $e) {
        $edges[$e['from'] . '>' . $e['to']] = $e;
    }
    return [$g, $nodes, $edges];
}
function families($edge)
{
    return array_values(array_unique(array_map(function ($a) {
        return $a['family'] ?? 'inet';
    }, $edge['allowed'] ?? [])));
}

[$g, $nodes, $edges] = graphOf();
check('every filter rule parses', $g['unparsed_count'] === 0);
check('devices get their SLAAC addresses from NDP', $nodes[$lab]['ipv6'] === ['fd00:77::be24:11ff:fe00:ef67']
    && $nodes[$nas]['ipv6'] === ['fd00:77::be24:11ff:fe77:302'] && $nodes[$cam]['ipv6'] === ['fd00:88::be24:11ff:fe88:303']);
check('...not assumed', !$nodes[$lab]['ipv6_assumed']);
check('IPv6 bypass: iot-cam -> lab-dev01 exists, IPv6 only', families($edges["$cam>$lab"] ?? []) === ['inet6']);
check('IPv6 bypass: iot-cam -> nas exists, IPv6 only', families($edges["$cam>$nas"] ?? []) === ['inet6']);
check('...via the IoT inet6 rule', in_array($bypass, $edges["$cam>$lab"]['allowed'][0]['rules'] ?? [], true));
check('LAN -> iot-cam allowed in both families (Default allow LAN / LAN IPv6)', families($edges["$lab>$cam"] ?? []) === ['inet', 'inet6']);
check('no IPv6 to the internet: the WAN has no global IPv6', !in_array('inet6', families($edges["$lab>wan"] ?? []), true)
    && in_array('inet', families($edges["$lab>wan"] ?? []), true));
$camFw6 = array_values(array_filter($edges["$cam>firewall"]['allowed'] ?? [], function ($a) {
    return ($a['family'] ?? 'inet') === 'inet6';
}));
check('the bypass rule also reaches the firewall\'s LAN ULA (fd00:77::1 is in LAN net)', !empty($camFw6)
    && in_array($bypass, $camFw6[0]['rules'], true));

// the box's observation: idle devices aren't in NDP yet
$GLOBALS['CB_FIXTURE'] = fixture('[]');
[$g2, $nodes2, $edges2] = graphOf();
check('empty NDP: addresses assumed from the MACs (EUI-64), identical to the real ones',
    $nodes2[$lab]['ipv6'] === $nodes[$lab]['ipv6'] && $nodes2[$cam]['ipv6'] === $nodes[$cam]['ipv6']);
check('...and flagged as assumed', $nodes2[$lab]['ipv6_assumed'] === true);
check('...so the IPv6 bypass is still shown', families($edges2["$cam>$lab"] ?? []) === ['inet6']);

echo "{$passed} passed, {$failures} failed\n";
exit($failures > 0 ? 1 : 0);
