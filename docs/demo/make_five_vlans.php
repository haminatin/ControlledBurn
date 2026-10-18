<?php

/**
 * The demo's "Five VLANs" network: a made-up home lab with a realistic
 * ruleset, run through the real RuleEngine so every colour, port list and
 * Rule check finding is what the plugin would show. Not real data.
 *
 * Covers: explicit rules (blue), broad ones (orange), OPNsense's automatic
 * rules (purple), an alias that didn't resolve (amber), a rule shadowed by
 * "allow LAN to any", a working port forward and one that does nothing, a
 * VLAN with no internet, and a classic mistake: the guests' "web only"
 * rule (any destination, ports 80/443) also opens the firewall's own GUI
 * to them.
 *
 * Run by scripts/build_demo.py (prints the graph as JSON).
 */

require __DIR__ . '/../../src/opnsense/mvc/app/library/OPNsense/ControlledBurn/RuleEngine.php';

use OPNsense\ControlledBurn\RuleEngine;

$ifaces = [
    'vtnet0' => ['key' => 'lan', 'descr' => 'LAN', 'ipv4' => [['ipaddr' => '192.168.1.1', 'subnetbits' => 24]]],
    'vtnet1' => ['key' => 'wan', 'descr' => 'WAN', 'ipv4' => [['ipaddr' => '203.0.113.2', 'subnetbits' => 24]]],
    'vtnet2' => ['key' => 'opt1', 'descr' => 'IoT', 'ipv4' => [['ipaddr' => '192.168.20.1', 'subnetbits' => 24]]],
    'vtnet3' => ['key' => 'opt2', 'descr' => 'Guest', 'ipv4' => [['ipaddr' => '192.168.30.1', 'subnetbits' => 24]]],
    'vtnet4' => ['key' => 'opt3', 'descr' => 'Servers', 'ipv4' => [['ipaddr' => '10.0.10.1', 'subnetbits' => 24]]],
    'vtnet5' => ['key' => 'opt4', 'descr' => 'Cameras', 'ipv4' => [['ipaddr' => '192.168.40.1', 'subnetbits' => 24]]],
];

$d = function ($id, $ip, $name, $if) {
    return ['id' => $id, 'ip' => $ip, 'hostname' => $name, 'if' => $if, 'aliases' => []];
};
$devices = [
    $d('lan-desktop', '192.168.1.10', 'desktop', 'vtnet0'),
    $d('lan-laptop', '192.168.1.11', 'laptop', 'vtnet0'),
    $d('lan-phone', '192.168.1.12', 'phone', 'vtnet0'),
    $d('iot-tv', '192.168.20.10', 'smart-tv', 'vtnet2'),
    $d('iot-thermostat', '192.168.20.11', 'thermostat', 'vtnet2'),
    $d('iot-speaker', '192.168.20.12', 'speaker', 'vtnet2'),
    $d('iot-doorbell', '192.168.20.13', 'doorbell', 'vtnet2'),
    $d('guest-phone', '192.168.30.50', 'guest-phone', 'vtnet3'),
    $d('guest-laptop', '192.168.30.51', 'guest-laptop', 'vtnet3'),
    $d('srv-nas', '10.0.10.20', 'nas', 'vtnet4'),
    $d('srv-media', '10.0.10.21', 'media-server', 'vtnet4'),
    $d('srv-ha', '10.0.10.22', 'home-assistant', 'vtnet4'),
    $d('srv-nvr', '10.0.10.23', 'nvr', 'vtnet4'),
    $d('cam-front', '192.168.40.10', 'cam-front', 'vtnet5'),
    $d('cam-back', '192.168.40.11', 'cam-back', 'vtnet5'),
    $d('cam-garage', '192.168.40.12', 'cam-garage', 'vtnet5'),
];

$seq = 0;
// uuid-shaped labels, like newer-model OPNsense rules (so they link)
$r = function ($o) use (&$seq) {
    return array_merge([
        'seq' => $seq,
        'label' => sprintf('00000000-0000-4000-8000-%012d', ++$seq),
        'action' => 'pass', 'direction' => 'in', 'quick' => true, 'interface' => 'vtnet0',
        'ipprotocol' => 'inet', 'protocol' => 'any',
        'source' => ['any'], 'source_not' => false, 'destination' => ['any'], 'destination_not' => false,
        'from_port' => null, 'to_port' => null, 'text' => 'pass', 'descr' => '',
    ], $o);
};
// OPNsense's own rules carry md5-style labels and are flagged automatic
$auto = [];
$a = function ($name, $o) use ($r, &$auto) {
    $label = md5($name);
    $auto[$label] = true;
    return $r(['label' => $label] + $o);
};
$dhcp = function ($if, $net) use ($a) {
    return $a("dhcp $if", ['interface' => $if, 'protocol' => 'udp', 'source' => ['any'], 'from_port' => '= bootpc',
        'destination' => ['(self)'], 'to_port' => '= bootps', 'descr' => 'allow access to DHCP server']);
};
$private = ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'];

$rules = [
    // LAN
    $a('anti-lockout', ['protocol' => 'tcp', 'destination' => ['(self)'], 'to_port' => '{ 22 80 443 }', 'descr' => 'Anti-Lockout Rule']),
    $dhcp('vtnet0', '(vtnet0:network)'),
    $r(['source' => ['(vtnet0:network)'], 'descr' => 'Default allow LAN to any rule']),
    // never fires: the broad rule above already allows it
    $r(['protocol' => 'tcp', 'source' => ['(vtnet0:network)'], 'destination' => ['10.0.10.20'], 'to_port' => '= 445', 'descr' => 'LAN to NAS SMB shares']),

    // IoT: DNS to the firewall, the TV to the media server, internet only
    $dhcp('vtnet2', '(vtnet2:network)'),
    $r(['interface' => 'vtnet2', 'protocol' => 'udp', 'source' => ['(vtnet2:network)'], 'destination' => ['(vtnet2)'], 'to_port' => '= 53', 'descr' => 'IoT DNS to firewall']),
    $r(['interface' => 'vtnet2', 'protocol' => 'tcp', 'source' => ['192.168.20.10'], 'destination' => ['10.0.10.21'], 'to_port' => '= 8096', 'descr' => 'Smart TV to media server']),
    // the casting-devices alias didn't load on this box: which IoT devices
    // it covers is unknown, so their access to the media server is too
    $r(['interface' => 'vtnet2', 'protocol' => 'tcp', 'source' => [['table' => 'cast_devices', 'unresolved' => true]], 'destination' => ['10.0.10.21'],
        'to_port' => '= 8009', 'text' => 'pass in quick on vtnet2 inet proto tcp from <cast_devices> to 10.0.10.21 port = 8009', 'descr' => 'Casting devices to media server']),
    $r(['interface' => 'vtnet2', 'action' => 'block', 'source' => ['(vtnet2:network)'], 'destination' => ['(self)'], 'descr' => 'Block IoT to the firewall']),
    $r(['interface' => 'vtnet2', 'action' => 'block', 'source' => ['(vtnet2:network)'], 'destination' => $private, 'descr' => 'Block IoT to private networks']),
    $r(['interface' => 'vtnet2', 'source' => ['(vtnet2:network)'], 'descr' => 'Allow IoT to internet']),

    // Guest: DNS, then web only, never the private networks
    $dhcp('vtnet3', '(vtnet3:network)'),
    $r(['interface' => 'vtnet3', 'protocol' => 'udp', 'source' => ['(vtnet3:network)'], 'destination' => ['(vtnet3)'], 'to_port' => '= 53', 'descr' => 'Guest DNS to firewall']),
    $r(['interface' => 'vtnet3', 'action' => 'block', 'source' => ['(vtnet3:network)'], 'destination' => $private, 'descr' => 'Block guests from private networks']),
    $r(['interface' => 'vtnet3', 'protocol' => 'tcp', 'source' => ['(vtnet3:network)'], 'to_port' => '{ 80 443 }', 'descr' => 'Guest web access']),

    // Servers: Home Assistant controls IoT, the NVR pulls camera streams
    $dhcp('vtnet4', '(vtnet4:network)'),
    $r(['interface' => 'vtnet4', 'protocol' => 'tcp', 'source' => ['10.0.10.22'], 'destination' => ['(vtnet2:network)'], 'to_port' => '80:443', 'descr' => 'Home Assistant to IoT devices']),
    $r(['interface' => 'vtnet4', 'protocol' => 'tcp', 'source' => ['10.0.10.23'], 'destination' => ['(vtnet5:network)'], 'to_port' => '= 554', 'descr' => 'NVR to cameras (RTSP)']),
    $r(['interface' => 'vtnet4', 'action' => 'block', 'source' => ['(vtnet4:network)'], 'destination' => ['(self)'], 'descr' => 'Block servers to the firewall']),
    $r(['interface' => 'vtnet4', 'action' => 'block', 'source' => ['(vtnet4:network)'], 'destination' => $private, 'descr' => 'Block servers to private networks']),
    $r(['interface' => 'vtnet4', 'source' => ['(vtnet4:network)'], 'descr' => 'Servers to internet']),

    // Cameras: events to the NVR, nothing else (only OPNsense's own DHCP
    // rule lets them reach the firewall)
    $dhcp('vtnet5', '(vtnet5:network)'),
    $r(['interface' => 'vtnet5', 'protocol' => 'tcp', 'source' => ['(vtnet5:network)'], 'destination' => ['10.0.10.23'], 'to_port' => '= 5000', 'descr' => 'Camera events to NVR']),
    $r(['interface' => 'vtnet5', 'action' => 'block', 'source' => ['(vtnet5:network)'], 'descr' => 'Cameras: nothing else']),

    // WAN: OPNsense's default deny, and everything may leave
    $a('default deny', ['action' => 'block', 'quick' => false, 'interface' => 'any', 'ipprotocol' => 'any', 'descr' => 'Default deny / state violation rule']),
    $r(['direction' => 'out', 'interface' => 'any', 'quick' => false, 'ipprotocol' => 'any', 'descr' => 'Default allow out']),
];
$rules = RuleEngine::markAutomatic($rules, $auto);

// port forwards: remote access to Home Assistant (rdr pass: no filter rule
// needed), and an old NAS forward with no rule letting it through
$fw = function ($seq, $pass, $port, $target, $targetPort) {
    return [
        'seq' => $seq, 'no' => false, 'pass' => $pass, 'interface' => 'vtnet1', 'interface_not' => false,
        'ipprotocol' => 'inet', 'protocol' => 'tcp', 'source' => ['any'], 'source_not' => false, 'from_port' => null,
        'destination' => ['(vtnet1)'], 'destination_not' => false, 'to_port' => '= ' . $port,
        'target' => [$target], 'target_port' => (string)$targetPort,
        'text' => sprintf('rdr%s on vtnet1 inet proto tcp from any to (vtnet1) port = %d -> %s port %d', $pass ? ' pass' : '', $port, $target, $targetPort),
    ];
};
$redirects = [$fw(0, true, 8123, '10.0.10.22', 8123), $fw(1, false, 8443, '10.0.10.20', 443)];

$prepared = RuleEngine::prepareRules($rules, $ifaces);
$preparedRedirects = RuleEngine::prepareRedirects($redirects, $ifaces);
$devices = RuleEngine::placeDevices($devices, $ifaces);

$g = RuleEngine::buildGraph($devices, $prepared, $ifaces, $preparedRedirects);
$g['interfaces'] = array_map(function ($i) {
    return ['key' => $i['key'], 'descr' => $i['descr']];
}, $ifaces);
$g['unparsed_count'] = 0;
$g['unparsed'] = [];
$g['dead_rules'] = RuleEngine::deadRuleFindings($prepared, $ifaces, $devices);
$g['empty_tables'] = [];
$g['inert_forwards'] = RuleEngine::inertForwards($prepared, $preparedRedirects, $devices, $ifaces);
$g['forward_config'] = [];
echo json_encode($g, JSON_UNESCAPED_SLASHES) . "\n";
