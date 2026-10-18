<?php

/**
 * Generates tests/fixtures/example_graph.json: a made-up three-segment
 * network (LAN / IoT / Servers) run through the real RuleEngine, used by
 * tests/test_topology_js.js to exercise routing and label placement on
 * something busier than the smoke-test graph. Not real data.
 *
 * Run: php tests/fixtures/make_example_graph.php > tests/fixtures/example_graph.json
 */

require __DIR__ . '/../../src/opnsense/mvc/app/library/OPNsense/ControlledBurn/RuleEngine.php';
use OPNsense\ControlledBurn\RuleEngine;
$ifaces = [
  'vtnet0' => ['key' => 'lan', 'descr' => 'LAN', 'ipv4' => [['ipaddr' => '192.168.1.1', 'subnetbits' => 24]]],
  'vtnet2' => ['key' => 'opt1', 'descr' => 'IoT', 'ipv4' => [['ipaddr' => '192.168.20.1', 'subnetbits' => 24]]],
  'vtnet3' => ['key' => 'opt2', 'descr' => 'Servers', 'ipv4' => [['ipaddr' => '10.0.10.1', 'subnetbits' => 24]]],
  'vtnet1' => ['key' => 'wan', 'descr' => 'WAN', 'ipv4' => [['ipaddr' => '203.0.113.2', 'subnetbits' => 24]]],
];
$d = function ($id, $ip, $name, $if) { return ['id' => $id, 'ip' => $ip, 'hostname' => $name, 'if' => $if]; };
$devices = [
  $d('l1', '192.168.1.10', 'desktop', 'vtnet0'), $d('l2', '192.168.1.11', 'laptop', 'vtnet0'), $d('l3', '192.168.1.12', 'phone', 'vtnet0'),
  $d('i1', '192.168.20.10', 'smart-tv', 'vtnet2'), $d('i2', '192.168.20.11', 'thermostat', 'vtnet2'), $d('i3', '192.168.20.12', 'camera', 'vtnet2'),
  $d('s1', '10.0.10.20', 'nas', 'vtnet3'), $d('s2', '10.0.10.21', 'media-server', 'vtnet3'), $d('s3', '10.0.10.22', 'home-assistant', 'vtnet3'),
];
$seq = 0;
// uuid-shaped labels, like newer-model OPNsense rules, so rule links render
$r = function ($o) use (&$seq) { return array_merge(['seq' => $seq, 'label' => sprintf('00000000-0000-4000-8000-%012d', ++$seq), 'action' => 'pass', 'direction' => 'in', 'quick' => true,
  'interface' => 'vtnet0', 'ipprotocol' => 'inet', 'protocol' => 'any', 'source' => ['any'], 'source_not' => false,
  'destination' => ['any'], 'destination_not' => false, 'from_port' => null, 'to_port' => null, 'text' => 't', 'descr' => 'd'], $o); };
$rules = [
  // LAN: GUI, SMB + web to servers, HA from LAN
  $r(['protocol' => 'tcp', 'source' => ['(vtnet0:network)'], 'destination' => ['(self)'], 'to_port' => '= 443', 'descr' => 'LAN to firewall GUI']),
  $r(['protocol' => 'tcp', 'source' => ['(vtnet0:network)'], 'destination' => ['10.0.10.20'], 'to_port' => '= 445', 'descr' => 'LAN to NAS SMB shares']),
  $r(['protocol' => 'tcp', 'source' => ['(vtnet0:network)'], 'destination' => ['10.0.10.21'], 'to_port' => '= 8096', 'descr' => 'LAN to media server']),
  $r(['protocol' => 'tcp', 'source' => ['(vtnet0:network)'], 'destination' => ['10.0.10.22'], 'to_port' => '= 8123', 'descr' => 'LAN to Home Assistant dashboard']),
  // IoT: DNS to firewall, TV to media server, everything else to private nets blocked
  $r(['interface' => 'vtnet2', 'protocol' => 'udp', 'source' => ['(vtnet2:network)'], 'destination' => ['(vtnet2)'], 'to_port' => '= 53', 'descr' => 'IoT DNS to firewall only']),
  $r(['interface' => 'vtnet2', 'protocol' => 'tcp', 'source' => ['192.168.20.10'], 'destination' => ['10.0.10.21'], 'to_port' => '= 8096', 'descr' => 'Smart TV to media server (Jellyfin) - added after the TV app stopped finding the library, revisit when the TV is replaced']),
  $r(['interface' => 'vtnet2', 'action' => 'block', 'source' => ['(vtnet2:network)'], 'destination' => ['192.168.0.0/16', '10.0.0.0/8'], 'descr' => 'Block IoT to all private networks']),
  // Servers: HA can reach the IoT thermostat + camera
  $r(['interface' => 'vtnet3', 'protocol' => 'tcp', 'source' => ['10.0.10.22'], 'destination' => ['192.168.20.0/24'], 'to_port' => '80:443', 'descr' => 'Home Assistant to IoT devices for local control']),
  // OPNsense's automatic DHCP access rule on Servers (md5-style label, flagged automatic below)
  $r(['label' => '56d97e04b8ce723a8524bdda932fe056', 'interface' => 'vtnet3', 'protocol' => 'udp', 'from_port' => '= bootpc', 'destination' => ['(self)'], 'to_port' => '= bootps', 'descr' => 'allow access to DHCP server']),
  // broad pass out
  $r(['direction' => 'out', 'interface' => 'any', 'quick' => false, 'ipprotocol' => 'any', 'descr' => 'Default allow out']),
];
$rules = RuleEngine::markAutomatic($rules, ['56d97e04b8ce723a8524bdda932fe056' => true]);
$g = RuleEngine::buildGraph($devices, RuleEngine::prepareRules($rules, $ifaces), $ifaces);
$g['interfaces'] = array_map(function ($i) { return ['key' => $i['key'], 'descr' => $i['descr']]; }, $ifaces);
echo json_encode($g);
