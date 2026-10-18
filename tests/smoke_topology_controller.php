<?php

/**
 * Off-box smoke test for TopologyController: stubs the OPNsense classes it
 * touches (see tests/lib/opnsense_stubs.php) with canned testlab-like data - LAN vtnet0 192.168.77.0/24, Servers vtnet2 10.0.10.0/24, WAN
 * vtnet1 - and checks devices/graph/pair end to end. Not a substitute for
 * the testlab (Milestone 4c): the stubs only mimic shapes verified against
 * core source.
 *
 * Run: php tests/smoke_topology_controller.php
 * Regenerate the JS test fixture:
 *   CB_DUMP_GRAPH=tests/fixtures/smoke_graph.json php tests/smoke_topology_controller.php
 */
$GLOBALS['CB_FIXTURE'] = [
    'configd' => [
        'interface list ifconfig' => json_encode([
            'vtnet0' => ['ipv4' => [['ipaddr' => '192.168.77.1', 'subnetbits' => 24, 'tunnel' => false]]],
            'vtnet2' => ['ipv4' => [['ipaddr' => '10.0.10.1', 'subnetbits' => 24, 'tunnel' => false]]],
            'vtnet1' => ['ipv4' => [['ipaddr' => '203.0.113.2', 'subnetbits' => 24, 'tunnel' => false]]]]),
        'dnsmasq list leases' => json_encode(['records' => [
            ['address' => '192.168.77.191', 'hwaddr' => 'BC:24:11:77:03:01', 'hostname' => 'lab-dev01', 'if' => 'vtnet0'],
            ['address' => '10.0.10.20', 'hwaddr' => 'BC:24:11:77:03:02', 'hostname' => '*', 'if' => 'vtnet2'],
            ['address' => 'fd00::5', 'hwaddr' => '', 'hostname' => 'v6', 'if' => 'vtnet0']]]),
        'interface list ndp' => json_encode([['mac' => 'bc:24:11:77:03:01', 'ip' => 'fd00::5', 'intf' => 'vtnet0', 'manufacturer' => '']]),
        'filter list rule_ids' => json_encode([
            ['id' => '11111111-1111-1111-1111-111111111111', 'descr' => 'LAN to GUI'],
            ['id' => '22222222-2222-2222-2222-222222222222', 'descr' => 'Block SSH to nas'],
            ['id' => '33333333-3333-3333-3333-333333333333', 'descr' => 'SMB to nas'],
            ['id' => '44444444444444444444444444444444', 'descr' => '-- 44444444444444444444444444444444']]),
        'controlledburn get ruleset' => file_get_contents(__DIR__ . '/fixtures/smoke_ruleset.json'),
        'filter list non_mvc_rules' => json_encode([
            ['uuid' => '44444444444444444444444444444444', 'is_automatic' => true, 'legacy' => true],
            ['uuid' => '55555555555555555555555555555555', 'is_automatic' => true, 'legacy' => true]]),
    ],
    'interfaces' => [
        'lan' => ['if' => 'vtnet0', 'descr' => 'LAN', 'ipaddr' => '192.168.77.1', 'subnet' => '24'],
        'wan' => ['if' => 'vtnet1', 'ipaddr' => 'dhcp'],
        'opt1' => ['if' => 'vtnet2', 'descr' => 'Servers', 'ipaddr' => '10.0.10.1', 'subnet' => '24'],
    ],
    'hosts' => [
        ['nas', ['10.0.10.20'], ['BC:24:11:77:03:02']],
        ['media', ['10.0.10.20'], []],
        ['printer', ['192.168.77.30'], []],
    ],
];
require __DIR__ . '/lib/opnsense_stubs.php';

$c = cb_controller();

  $devices = [];
  foreach ($c->devicesAction()['devices'] as $d) {
      $devices[$d['id']] = $d;
  }
  check('MAC-less override with a known IP becomes an alias', $devices['bc:24:11:77:03:02']['aliases'] === ['media'] && !isset($devices['10.0.10.20']));
  check("'*' hostname replaced by override name", $devices['bc:24:11:77:03:02']['hostname'] === 'nas');
  check('override-only device placed by subnet', $devices['192.168.77.30']['if'] === 'vtnet0' && $devices['192.168.77.30']['interface_descr'] === 'LAN');

  $graph = $c->graphAction();
  if (getenv('CB_DUMP_GRAPH')) {
      // regenerates the fixture tests/test_topology_js.js reads
      file_put_contents(getenv('CB_DUMP_GRAPH'), json_encode($graph, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
  }
  $edges = [];
  foreach ($graph['edges'] as $e) {
      $edges[$e['from'] . '>' . $e['to']] = $e;
  }
  $lab = 'device:bc:24:11:77:03:01';
  $nas = 'device:bc:24:11:77:03:02';
  $printer = 'device:192.168.77.30';
check('graph nodes carry aliases', array_values(array_filter($graph['nodes'], function ($n) { return $n['id'] === 'device:bc:24:11:77:03:02'; }))[0]['aliases'] === ['media']);
check('graph lists unparsed lines (none here)', $graph['unparsed'] === []);
  check('lab-dev01 -> nas allows only tcp/445', array_map(function ($a) { unset($a['rules'], $a['intended'], $a['default']); return $a; }, $edges["$lab>$nas"]['allowed'] ?? []) === [['proto' => 'tcp', 'from' => 445, 'to' => 445]]);
  check('unresolved block table does not create uncertainty', empty($edges["$lab>$nas"]['uncertain']));
  check('lab-dev01 <-> printer unfiltered', ($edges["$lab>$printer"]['kind'] ?? null) === 'unfiltered');
  check('printer -> nas: no edge', !isset($edges["$printer>$nas"]));
  check('lab-dev01 -> firewall tcp/443', array_map(function ($a) { unset($a['rules'], $a['intended'], $a['default']); return $a; }, $edges["$lab>firewall"]['allowed'] ?? []) === [['proto' => 'tcp', 'from' => 443, 'to' => 443]]);
  check('edge names the allowing rule by description', $graph['rules'][$edges["$lab>$nas"]['allowed'][0]['rules'][0]]['descr'] === 'SMB to nas');
  check('WAN interface address used for firewall targets', $graph['interfaces']['vtnet1']['descr'] === 'WAN');

  $c->request->q = ['src' => $lab, 'dst' => $nas];
  $pair = $c->pairAction();
  $byPort = [];
  foreach ($pair['targets'][0]['slices'] as $s) {
      if ($s['proto'] === 'tcp') {
          $byPort[$s['from']] = $s;
      }
  }
  check('pair: tcp/22 blocked by named rule', $byPort[22]['verdict'] === 'block' && $pair['rules'][$byPort[22]['rule']]['descr'] === 'Block SSH to nas');
  check('pair: tcp/445 passes', $byPort[445]['verdict'] === 'pass');
  check('pair: "-- id" placeholder falls back to pf text', !isset($pair['rules']['44444444444444444444444444444444'])
      || str_starts_with($pair['rules']['44444444444444444444444444444444']['descr'], 'pass out'));

  $c->request->q = ['src' => $lab, 'dst' => 'firewall'];
  check('pair: firewall has one target per firewall address', count($c->pairAction()['targets']) === 3);

  $c->request->q = ['src' => 'device:nope', 'dst' => 'firewall'];
  check('pair: unknown node rejected', $c->pairAction()['status'] === 'failed');
check('NDP: the DHCPv6-only entry fd00::5 is merged into lab-dev01 (same MAC)', !isset($devices['fd00::5'])
    && $devices['bc:24:11:77:03:01']['ipv6'] === ['fd00::5'] && in_array('v6', $devices['bc:24:11:77:03:01']['aliases'], true));

  echo "{$passed} passed, {$failures} failed\n";
  exit($failures > 0 ? 1 : 0);
