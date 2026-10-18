<?php

/**
 * Milestone 10 scenario: the classic "IPv6 bypasses the IPv4 policy" hole.
 * Same layout as the Milestone 8 IoT scenario, plus ULA prefixes: IPv4
 * correctly blocks IoT -> LAN, but an IPv6 "allow IoT to any" on the IoT
 * tab lets IoT reach the LAN anyway. Run through the real RuleEngine.
 *
 * Run: php tests/fixtures/make_scenario_ipv6.php > tests/fixtures/scenario_ipv6_bypass.json
 */

require __DIR__ . '/../../src/opnsense/mvc/app/library/OPNsense/ControlledBurn/RuleEngine.php';

use OPNsense\ControlledBurn\RuleEngine;

$ifaces = [
    'vtnet0' => ['key' => 'lan', 'descr' => 'LAN', 'ipv4' => [['ipaddr' => '192.168.77.1', 'subnetbits' => 24]],
        'ipv6' => [['ipaddr' => 'fd00:77::1', 'subnetbits' => 64, 'linklocal' => false]]],
    'vtnet1' => ['key' => 'wan', 'descr' => 'WAN', 'ipv4' => [['ipaddr' => '10.100.59.2', 'subnetbits' => 24]], 'ipv6' => []],
    'vtnet2' => ['key' => 'opt1', 'descr' => 'IoT', 'ipv4' => [['ipaddr' => '192.168.88.1', 'subnetbits' => 24]],
        'ipv6' => [['ipaddr' => 'fd00:88::1', 'subnetbits' => 64, 'linklocal' => false]]],
];
$devices = [
    ['id' => 'bc:24:11:00:ef:67', 'ip' => '192.168.77.191', 'ipv6' => ['fd00:77::191'], 'hostname' => 'lab-dev01', 'if' => 'vtnet0'],
    ['id' => 'bc:24:11:77:03:02', 'ip' => '192.168.77.20', 'ipv6' => ['fd00:77::20'], 'hostname' => 'nas', 'if' => 'vtnet0'],
    ['id' => 'bc:24:11:88:03:03', 'ip' => '192.168.88.50', 'ipv6' => ['fd00:88::50'], 'hostname' => 'iot-cam', 'if' => 'vtnet2'],
];
$seq = 0;
$r = function ($label, $descr, $o) use (&$seq) {
    return array_merge([
        'seq' => $seq++, 'label' => $label, 'descr' => $descr, 'action' => 'pass', 'direction' => 'in',
        'quick' => true, 'interface' => 'vtnet0', 'interface_not' => false, 'ipprotocol' => 'inet',
        'protocol' => 'any', 'source' => ['any'], 'source_not' => false, 'destination' => ['any'],
        'destination_not' => false, 'from_port' => null, 'to_port' => null, 'text' => 'scenario',
    ], $o);
};
$rules = [
    $r('11111111-0000-4000-8000-000000000001', 'Default allow LAN to any rule', ['source' => ['(vtnet0:network)']]),
    $r('11111111-0000-4000-8000-000000000011', 'Default allow LAN IPv6 to any rule', ['ipprotocol' => 'inet6', 'source' => ['(vtnet0:network)']]),
    $r('33333333-0000-4000-8000-000000000003', 'Block IoT to LAN', ['action' => 'block', 'interface' => 'vtnet2', 'source' => ['(vtnet2:network)'], 'destination' => ['(vtnet0:network)']]),
    $r('66666666-0000-4000-8000-000000000006', 'Allow IoT IPv6 to any', ['interface' => 'vtnet2', 'ipprotocol' => 'inet6', 'source' => ['(vtnet2:network)']]),
    $r('fae559338f65e11c53669fc3642c93c2', 'let out anything from firewall host itself', ['direction' => 'out', 'interface' => 'any', 'quick' => false, 'ipprotocol' => 'any']),
];
$rules = RuleEngine::prepareRules(RuleEngine::markAutomatic($rules, ['fae559338f65e11c53669fc3642c93c2' => true]), $ifaces);
$g = RuleEngine::buildGraph($devices, $rules, $ifaces);
$g['interfaces'] = array_map(function ($i) {
    return ['key' => $i['key'], 'descr' => $i['descr']];
}, $ifaces);
$g['unparsed_count'] = 0;
$g['unparsed'] = [];
$g['dead_rules'] = RuleEngine::deadRuleFindings($rules, $ifaces, $devices);
$g['empty_tables'] = [];
echo json_encode($g, JSON_UNESCAPED_SLASHES) . "\n";
