<?php

/**
 * Milestone 8 scenario: the classic "IoT allow-all" mistake, in three
 * stages, run through the real RuleEngine to predict what the graph and Rule
 * check should show on the testlab once it's set up the same way:
 *
 *   mistake  - IoT tab: "pass IoT net -> any" ABOVE "block IoT net -> LAN net"
 *   reorder  - the block moved first (the naive fix)
 *   fixed    - block IoT -> LAN, pass IoT -> firewall DNS only, pass IoT ->
 *              anything that isn't private (internet), so not the firewall
 *
 * Testlab layout assumed: LAN vtnet0 192.168.77.0/24 (lab-dev01 .191,
 * nas .20), WAN vtnet1, IoT vtnet2 192.168.88.0/24 (iot-cam .50).
 * pf forms mirror what OPNsense generates: "LAN net" = (vtnet0:network),
 * "IoT net" = (vtnet2:network), "This Firewall" = (self).
 *
 * Run: php tests/fixtures/make_scenario_iot.php <mistake|reorder|fixed>
 */

require __DIR__ . '/../../src/opnsense/mvc/app/library/OPNsense/ControlledBurn/RuleEngine.php';

use OPNsense\ControlledBurn\RuleEngine;

$stage = $argv[1] ?? 'mistake';

$ifaces = [
    'vtnet0' => ['key' => 'lan', 'descr' => 'LAN', 'ipv4' => [['ipaddr' => '192.168.77.1', 'subnetbits' => 24]]],
    'vtnet1' => ['key' => 'wan', 'descr' => 'WAN', 'ipv4' => [['ipaddr' => '10.100.59.2', 'subnetbits' => 24]]],
    'vtnet2' => ['key' => 'opt1', 'descr' => 'IoT', 'ipv4' => [['ipaddr' => '192.168.88.1', 'subnetbits' => 24]]],
];
$devices = [
    ['id' => 'bc:24:11:00:ef:67', 'ip' => '192.168.77.191', 'hostname' => 'lab-dev01', 'if' => 'vtnet0'],
    ['id' => 'bc:24:11:77:03:02', 'ip' => '192.168.77.20', 'hostname' => 'nas', 'if' => 'vtnet0'],
    ['id' => 'bc:24:11:88:03:03', 'ip' => '192.168.88.50', 'hostname' => 'iot-cam', 'if' => 'vtnet2'],
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

$lanAllow = $r('11111111-0000-4000-8000-000000000001', 'Default allow LAN to any rule', ['source' => ['(vtnet0:network)']]);
$iotAny = $r('22222222-0000-4000-8000-000000000002', 'Allow IoT to internet', ['interface' => 'vtnet2', 'source' => ['(vtnet2:network)']]);
$iotBlockLan = $r('33333333-0000-4000-8000-000000000003', 'Block IoT to LAN', ['action' => 'block', 'interface' => 'vtnet2', 'source' => ['(vtnet2:network)'], 'destination' => ['(vtnet0:network)']]);
$iotDns = $r('44444444-0000-4000-8000-000000000004', 'IoT DNS to firewall', ['interface' => 'vtnet2', 'protocol' => 'udp', 'source' => ['(vtnet2:network)'], 'destination' => ['(self)'], 'to_port' => '= domain']);
$iotInternet = $r('55555555-0000-4000-8000-000000000005', 'Allow IoT to internet (not private networks)', ['interface' => 'vtnet2', 'source' => ['(vtnet2:network)'], 'destination' => ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'], 'destination_not' => true]);
$passOut = $r('fae559338f65e11c53669fc3642c93c2', 'let out anything from firewall host itself', ['direction' => 'out', 'interface' => 'any', 'quick' => false, 'ipprotocol' => 'any']);

switch ($stage) {
    case 'mistake':
        $rules = [$lanAllow, $iotAny, $iotBlockLan, $passOut];
        break;
    case 'reorder':
        $rules = [$lanAllow, $iotBlockLan, $iotAny, $passOut];
        break;
    case 'fixed':
        $rules = [$lanAllow, $iotBlockLan, $iotDns, $iotInternet, $passOut];
        break;
    default:
        fwrite(STDERR, "unknown stage $stage\n");
        exit(2);
}
foreach ($rules as $i => &$rule) {
    $rule['seq'] = $i;
}
unset($rule);

$rules = RuleEngine::prepareRules(RuleEngine::markAutomatic($rules, ['fae559338f65e11c53669fc3642c93c2' => true]), $ifaces);
$g = RuleEngine::buildGraph($devices, $rules, $ifaces);
$g['interfaces'] = array_map(function ($i) {
    return ['key' => $i['key'], 'descr' => $i['descr']];
}, $ifaces);
$g['unparsed_count'] = 0;
$g['unparsed'] = [];
$g['dead_rules'] = RuleEngine::deadRuleFindings($rules, $ifaces, $devices);
echo json_encode($g, JSON_UNESCAPED_SLASHES) . "\n";
