<?php

/**
 * Milestone 8: what ControlledBurn should show for the classic "IoT
 * allow-all" mistake, in three stages (see tests/fixtures/make_scenario_iot.php).
 * These are the predictions to compare against the testlab once it's set up
 * the same way; they also guard the engine against regressions.
 *
 * Run: php tests/test_scenario_iot.php
 */

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

$cam = 'device:bc:24:11:88:03:03';
$lab = 'device:bc:24:11:00:ef:67';
$nas = 'device:bc:24:11:77:03:02';

function stage($name)
{
    $gen = __DIR__ . '/fixtures/make_scenario_iot.php';
    $fresh = shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($gen) . ' ' . escapeshellarg($name));
    $saved = file_get_contents(__DIR__ . "/fixtures/scenario_iot_{$name}.json");
    check("fixture scenario_iot_{$name}.json is up to date", trim($fresh) === trim($saved));
    $g = json_decode($fresh, true);
    $edges = [];
    foreach ($g['edges'] as $e) {
        $edges[$e['from'] . '>' . $e['to']] = $e;
    }
    $dead = [];
    foreach ($g['dead_rules'] as $d) {
        $dead[$d['descr']] = $d;
    }
    return [$edges, $dead];
}

function allowsAllTcp($edge)
{
    foreach ($edge['allowed'] ?? [] as $a) {
        if ($a['proto'] === 'tcp' && $a['from'] <= 1 && $a['to'] === 65535) {
            return true;
        }
    }
    return false;
}

// ---- 1. the mistake: allow-all above the block
[$e, $dead] = stage('mistake');
check('mistake: iot-cam reaches lab-dev01 (broad)', allowsAllTcp($e["$cam>$lab"] ?? []) && $e["$cam>$lab"]['intended'] === false);
check('mistake: iot-cam reaches nas (broad)', allowsAllTcp($e["$cam>$nas"] ?? []));
check('mistake: iot-cam reaches the firewall on every port (broad)', allowsAllTcp($e["$cam>firewall"] ?? []) && $e["$cam>firewall"]['intended'] === false);
check('mistake: Rule check says "Block IoT to LAN" never applies, shadowed by the allow-all',
    ($dead['Block IoT to LAN']['kind'] ?? null) === 'contradicted' && $dead['Block IoT to LAN']['by_descr'] === 'Allow IoT to internet');
// "LAN net" includes the firewall's own LAN address, so the block was also
// meant to stop iot-cam -> firewall (on 192.168.77.1)
check('mistake: the dead block highlights iot-cam -> both LAN devices and the firewall',
    ($dead['Block IoT to LAN']['pairs'] ?? null) === [[$cam, $lab], [$cam, $nas], [$cam, 'firewall']]);

check('mistake: iot-cam reaches the internet via the allow-all (broad)', allowsAllTcp($e["$cam>wan"] ?? []) && $e["$cam>wan"]['intended'] === false);

// ---- 2. the naive fix: block moved first
[$e, $dead] = stage('reorder');
check('reorder: iot-cam no longer reaches the LAN', !isset($e["$cam>$lab"]) && !isset($e["$cam>$nas"]));
check('reorder: Rule check is clean', $dead === []);
check('reorder: but iot-cam still reaches the firewall on every port (the second hole)', allowsAllTcp($e["$cam>firewall"] ?? []));

// ---- 3. the proper fix
[$e, $dead] = stage('fixed');
check('fixed: iot-cam no longer reaches the LAN', !isset($e["$cam>$lab"]) && !isset($e["$cam>$nas"]));
$fw = $e["$cam>firewall"] ?? null;
check('fixed: iot-cam reaches the firewall for DNS only', $fw !== null
    && array_map(function ($a) {
        return $a['proto'] . '/' . $a['from'] . '-' . $a['to'];
    }, $fw['allowed']) === ['udp/53-53']);
check('fixed: and that DNS flow is explicitly targeted (blue)', $fw['intended'] === true);
check('fixed: Rule check is clean', $dead === []);
check('fixed: iot-cam still reaches the internet, explicitly (blue: "anything but private")', allowsAllTcp($e["$cam>wan"] ?? [])
    && $e["$cam>wan"]['intended'] === true);

// ---- all stages: the LAN allow-all still lets the LAN reach IoT
foreach (['mistake', 'reorder', 'fixed'] as $st) {
    [$e] = stage($st);
    check("$st: LAN -> iot-cam stays broad (Default allow LAN to any)", allowsAllTcp($e["$lab>$cam"] ?? []) && $e["$lab>$cam"]['intended'] === false);
}

// ---- real stage-3 capture from the box (deviated config: block to ANY)
require_once __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/ControlledBurn/RuleEngine.php';
$ifaces = [
    'vtnet0' => ['key' => 'lan', 'descr' => 'LAN', 'ipv4' => [['ipaddr' => '192.168.77.1', 'subnetbits' => 24]]],
    'vtnet1' => ['key' => 'wan', 'descr' => 'WAN', 'ipv4' => [['ipaddr' => '10.100.59.2', 'subnetbits' => 24]]],
    'vtnet2' => ['key' => 'opt1', 'descr' => 'IoT', 'ipv4' => [['ipaddr' => '192.168.88.1', 'subnetbits' => 24]]],
];
$real = json_decode(file_get_contents(__DIR__ . '/fixtures/testlab-20261017-stage3/ruleset.json'), true);
check('real stage 3: every filter rule parses', $real['unparsed'] === []);
$deadReal = OPNsense\ControlledBurn\RuleEngine::deadRules(
    OPNsense\ControlledBurn\RuleEngine::prepareRules($real['rules'], $ifaces), $ifaces);
check('real stage 3: "iot dns to firewall" never applies (block to any above it)',
    ($deadReal['fda6989b-85c2-4b1e-a8a2-45f06d75ace8']['by'] ?? null) === 'c786e94b-c712-421e-add2-5848e156dc7a');
check('real stage 3: the "! <net_rfc1918>" alias pass never applies either',
    ($deadReal['5f9c6310-53a8-4221-9e99-ff14f88a5831']['kind'] ?? null) === 'contradicted');

// the box's actual mistake: net_rfc1918 saved but not applied (empty table)
$empty = json_decode(file_get_contents(__DIR__ . '/fixtures/testlab-20261017-stage3/ruleset_empty_alias.json'), true);
$er = OPNsense\ControlledBurn\RuleEngine::prepareRules($empty['rules'], $ifaces);
$cam3 = ['id' => 'cam', 'ip' => '192.168.88.50', 'hostname' => 'iot-cam', 'if' => 'vtnet2'];
$fwPair = OPNsense\ControlledBurn\RuleEngine::evaluatePair($er, $cam3, 'firewall', $ifaces);
$tcpPass = false;
foreach ($fwPair['targets'] as $t) {
    foreach ($t['slices'] as $sl) {
        $tcpPass = $tcpPass || ($sl['proto'] === 'tcp' && $sl['verdict'] === 'pass' && $sl['rule'] === '5f9c6310-53a8-4221-9e99-ff14f88a5831');
    }
}
check('empty alias: "! <net_rfc1918>" really lets iot-cam reach the firewall on tcp (the hole the box showed)', $tcpPass);
$ef = OPNsense\ControlledBurn\RuleEngine::emptyTableFindings($er, $empty['tables']);
check('empty alias: Rule check names net_rfc1918 as empty, used negated by that rule', ($ef[0]['name'] ?? null) === 'net_rfc1918'
    && $ef[0]['negated'] === true && $ef[0]['rules'][0]['label'] === '5f9c6310-53a8-4221-9e99-ff14f88a5831');
$corr = json_decode(file_get_contents(__DIR__ . '/fixtures/testlab-20261017-stage3/ruleset_corrected.json'), true);
check('applied alias: no empty-alias finding', OPNsense\ControlledBurn\RuleEngine::emptyTableFindings($corr['rules'], $corr['tables']) === []);
$cr = OPNsense\ControlledBurn\RuleEngine::prepareRules($corr['rules'], $ifaces);
$allowed = [];
foreach (OPNsense\ControlledBurn\RuleEngine::evaluatePair($cr, $cam3, 'firewall', $ifaces)['targets'] as $t) {
    foreach ($t['slices'] as $sl) {
        if ($sl['verdict'] === 'pass') {
            $allowed[$sl['proto'] . '/' . $sl['from']] = true;
        }
    }
}
ksort($allowed);
check('applied alias (real corrected stage 3): iot-cam reaches the firewall on udp/53 and udp/67 only', array_keys($allowed) === ['udp/53', 'udp/67']);
// the box lists loopback as an interface: it must not change that answer
$ifacesLo = $ifaces + ['lo0' => ['key' => 'lo0', 'descr' => 'Loopback', 'ipv4' => [['ipaddr' => '127.0.0.1', 'subnetbits' => 8]]]];
$allowedLo = [];
foreach (OPNsense\ControlledBurn\RuleEngine::evaluatePair(OPNsense\ControlledBurn\RuleEngine::prepareRules($corr['rules'], $ifacesLo), $cam3, 'firewall', $ifacesLo)['targets'] as $t) {
    foreach ($t['slices'] as $sl) {
        if ($sl['verdict'] === 'pass') {
            $allowedLo[$sl['proto'] . '/' . $sl['from']] = true;
        }
    }
}
ksort($allowedLo);
check('with lo0 present (as on the box): still udp/53 and udp/67 only', array_keys($allowedLo) === ['udp/53', 'udp/67']);

// ---- Milestone 10: IPv6 bypasses the IPv4 policy
$v6 = json_decode(shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/fixtures/make_scenario_ipv6.php')), true);
check('fixture scenario_ipv6_bypass.json is up to date', json_encode($v6) === json_encode(json_decode(file_get_contents(__DIR__ . '/fixtures/scenario_ipv6_bypass.json'), true)));
$v6e = [];
foreach ($v6['edges'] as $e) {
    $v6e[$e['from'] . '>' . $e['to']] = $e;
}
$camLab = $v6e["$cam>$lab"] ?? null;
check('IPv6 bypass: iot-cam reaches lab-dev01 although IPv4 blocks IoT -> LAN', $camLab !== null);
check('...only over IPv6 (every allowed entry is inet6)', $camLab !== null && !array_filter($camLab['allowed'], function ($a) {
    return ($a['family'] ?? 'inet') !== 'inet6';
}));
check('...via the IoT IPv6 allow-all', $camLab !== null && $v6['rules'][$camLab['allowed'][0]['rules'][0]]['descr'] === 'Allow IoT IPv6 to any');
$labCam = $v6e["$lab>$cam"] ?? null;
check('LAN -> iot-cam allowed in both families', $labCam !== null
    && count(array_filter($labCam['allowed'], function ($a) { return ($a['family'] ?? 'inet') === 'inet6'; })) > 0
    && count(array_filter($labCam['allowed'], function ($a) { return !isset($a['family']); })) > 0);

echo "{$passed} passed, {$failures} failed\n";
exit($failures > 0 ? 1 : 0);
