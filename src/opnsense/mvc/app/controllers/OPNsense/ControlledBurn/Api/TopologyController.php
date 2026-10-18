<?php

namespace OPNsense\ControlledBurn\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\ControlledBurn\RuleEngine;
use OPNsense\Dnsmasq\Dnsmasq;

class TopologyController extends ApiControllerBase
{
    /**
     * Devices beyond which the graph isn't evaluated: the work grows with
     * the square of the device count (250 on one segment took 1.9s off the
     * box, so 500 is roughly 8s) and the edges far outnumber what a browser
     * can draw. A sudden jump past this usually means something is flooding
     * DHCP with made-up addresses.
     */
    private const MAX_DEVICES = 500;
    /**
     * Interface map in the shape RuleEngine expects, keyed by physical name
     * (e.g. igb0 - the form pf rule text uses):
     *   ['igb0' => ['key' => 'lan', 'descr' => 'LAN', 'ipv4' => [['ipaddr', 'subnetbits'], ...]]]
     *
     * Addresses come from core's `interface list ifconfig` (live state), so
     * DHCP/PPPoE interfaces and VIPs are covered - config.xml only holds
     * "dhcp" for those. Falls back to a static config.xml address if the
     * live lookup has nothing for an interface.
     */
    private function interfaceMap()
    {
        $ifconfig = json_decode((new Backend())->configdRun('interface list ifconfig'), true) ?? [];
        $map = [];
        foreach (Config::getInstance()->object()->interfaces->children() as $key => $if) {
            $physical = (string)$if->if;
            // recent OPNsense lists loopback (lo0, 127.0.0.1) as a configured
            // interface; it's no network segment and no address a device can
            // reach (the kernel drops 127/8 arriving on a real interface)
            if ($physical === '' || preg_match('/^lo\d+$/', $physical)) {
                continue;
            }
            $ipv4 = [];
            foreach ($ifconfig[$physical]['ipv4'] ?? [] as $addr) {
                if (!empty($addr['ipaddr']) && empty($addr['tunnel'])) {
                    $ipv4[] = ['ipaddr' => $addr['ipaddr'], 'subnetbits' => (int)$addr['subnetbits']];
                }
            }
            if (empty($ipv4) && filter_var((string)$if->ipaddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ipv4[] = ['ipaddr' => (string)$if->ipaddr, 'subnetbits' => (int)(string)$if->subnet];
            }
            $ipv6 = [];
            foreach ($ifconfig[$physical]['ipv6'] ?? [] as $addr) {
                if (!empty($addr['ipaddr']) && empty($addr['tunnel']) && $addr['ipaddr'] !== '::1') {
                    $ipv6[] = [
                        'ipaddr' => $addr['ipaddr'],
                        'subnetbits' => (int)($addr['subnetbits'] ?? 64),
                        'linklocal' => !empty($addr['link-local']),
                    ];
                }
            }
            $map[$physical] = [
                'key' => (string)$key,
                'descr' => (string)$if->descr !== '' ? (string)$if->descr : strtoupper((string)$key),
                'ipv4' => $ipv4,
                'ipv6' => $ipv6,
            ];
        }
        return $map;
    }

    public function interfacesAction()
    {
        $result = [];
        foreach (Config::getInstance()->object()->interfaces->children() as $key => $if) {
            $result[] = [
                'key' => (string)$key,
                'if' => (string)$if->if,
                'descr' => (string)$if->descr !== '' ? (string)$if->descr : strtoupper((string)$key),
                'ipaddr' => (string)$if->ipaddr,
                'subnet' => (string)$if->subnet,
                'ipaddrv6' => (string)$if->ipaddrv6,
                'subnetv6' => (string)$if->subnetv6,
            ];
        }
        return ['interfaces' => $result];
    }

    /**
     * @param array $ifmap interface map from interfaceMap()
     * @return array merged, placed device list
     */
    private function discoverDevices(array $ifmap)
    {
        $devices = [];

        $backend = new Backend();
        $leases = json_decode($backend->configdpRun('dnsmasq list leases'), true) ?? [];
        foreach ($leases['records'] ?? [] as $record) {
            if (empty($record['address'])) {
                continue;
            }
            $mac = strtolower($record['hwaddr'] ?? '');
            $key = $mac !== '' ? $mac : $record['address'];
            $devices[$key] = [
                'id' => $key,
                'ip' => $record['address'],
                'mac' => $record['hwaddr'] ?? '',
                // dnsmasq reports '*' when the client sent no hostname
                'hostname' => ($record['hostname'] ?? '') === '*' ? '' : ($record['hostname'] ?? ''),
                'aliases' => [],
                'source' => 'lease',
                // physical interface name (e.g. igb0) - matches how pf's own
                // rule text names interfaces, used by RuleEngine for matching.
                // May be missing (no matching subnet); placeDevices() retries.
                'if' => $record['if'] ?? null,
            ];
        }

        foreach ((new Dnsmasq())->hosts->iterateItems() as $host) {
            $hwaddrs = $host->hwaddr->isEmpty() ? [] : $host->hwaddr->getValues();
            $ips = $host->ip->isEmpty() ? [] : $host->ip->getValues();
            $mac = !empty($hwaddrs) ? strtolower($hwaddrs[0]) : '';
            foreach ($ips as $ip) {
                $key = $mac !== '' ? $mac : $ip;
                if (!isset($devices[$key]) && $mac === '') {
                    // a MAC-less override for an address some other device
                    // already has is a second name for it (e.g. testlab
                    // "media" for nas), not a separate machine
                    foreach ($devices as $other => $device) {
                        if ($device['ip'] === $ip) {
                            $devices[$other]['aliases'][] = (string)$host->host;
                            continue 2;
                        }
                    }
                }
                $existing = $devices[$key] ?? [];
                $devices[$key] = [
                    'id' => $key,
                    'ip' => $ip,
                    'mac' => $mac,
                    'hostname' => (string)$host->host,
                    'aliases' => $existing['aliases'] ?? [],
                    'source' => 'host_override',
                    'if' => $existing['if'] ?? null,
                ];
            }
        }

        $devices = $this->attachIpv6(array_values($devices));
        $devices = RuleEngine::placeDevices($devices, $ifmap);
        // devices NDP hasn't seen yet (idle over IPv6): assume EUI-64
        $devices = RuleEngine::assumeIpv6($devices, $ifmap);
        foreach ($devices as &$device) {
            // logical key (e.g. lan) + description, for display/filtering
            $device['interface'] = $ifmap[$device['if'] ?? '']['key'] ?? null;
            $device['interface_descr'] = $ifmap[$device['if'] ?? '']['descr'] ?? null;
        }
        return $devices;
    }

    /**
     * Give devices their IPv6 addresses. Most IPv6 addresses are chosen by
     * the device itself (SLAAC), so they're in no DHCP lease; the firewall's
     * neighbour (NDP) table maps them to MACs. Link-local addresses are
     * skipped (they never cross the firewall). A device seen only through a
     * DHCPv6 lease (no MAC, keyed by its address) is merged into the device
     * NDP says owns that address.
     */
    private function attachIpv6(array $devices)
    {
        $ndp = json_decode((new Backend())->configdpRun('interface list ndp', ['json']), true) ?? [];
        $byMac = [];
        $macOf = [];
        foreach ($ndp as $entry) {
            $ip = preg_replace('/%.*$/', '', (string)($entry['ip'] ?? ''));
            $mac = strtolower((string)($entry['mac'] ?? ''));
            if ($ip === '' || $mac === '' || stripos($ip, 'fe80:') === 0
                || !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                continue;
            }
            $byMac[$mac][] = $ip;
            $macOf[$ip] = $mac;
        }
        $index = [];
        foreach ($devices as $i => &$device) {
            $device['ipv6'] = array_values(array_unique($byMac[$device['id']] ?? []));
            $index[$device['id']] = $i;
        }
        unset($device);
        foreach ($devices as $i => $device) {
            $ip = $device['ip'];
            $owner = $macOf[$ip] ?? null;
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && $owner !== null
                && $owner !== $device['id'] && isset($index[$owner])) {
                $o = $index[$owner];
                if (!in_array($ip, $devices[$o]['ipv6'], true)) {
                    $devices[$o]['ipv6'][] = $ip;
                }
                if ($device['hostname'] !== '' && $device['hostname'] !== $devices[$o]['hostname']) {
                    $devices[$o]['aliases'][] = $device['hostname'];
                }
                unset($devices[$i]);
            }
        }
        return array_values($devices);
    }

    public function devicesAction()
    {
        return ['devices' => $this->discoverDevices($this->interfaceMap())];
    }

    /**
     * pf label -> description for every rule in the live ruleset, via core's
     * own `filter list rule_ids` action (the same one Diagnostics ->
     * Firewall uses). It reads `label "<id>" # <descr>` pairs straight out
     * of /tmp/rules.debug, so it covers legacy <filter><rule> entries (md5
     * labels), \OPNsense\Firewall\Filter model rules (uuid labels) and
     * auto-generated rules alike - none of which can be reliably reproduced
     * PHP-side (legacy config_read_array() isn't loaded in the API context,
     * and auto-generated rules are hashed after defaults are merged in).
     *
     * Only labels that look like an md5 or uuid are returned; anything else
     * falls back to raw pf text in RuleEngine::attachDescriptions().
     */
    private function ruleDescriptionMap()
    {
        $map = [];
        $items = json_decode((new Backend())->configdpRun('filter list rule_ids'), true) ?? [];
        foreach ($items as $item) {
            if (empty($item['id'])) {
                continue;
            }
            // core substitutes "-- <id>" for an empty description; treat
            // that as no description so the raw pf text is shown instead
            if (($item['descr'] ?? '') === '' || $item['descr'] === '-- ' . $item['id']) {
                continue;
            }
            $map[$item['id']] = $item['descr'];
        }
        return $map;
    }

    /**
     * label => true for every rule OPNsense generates itself, via core's
     * `filter list non_mvc_rules` (what the Rules page uses for its
     * "Automatically generated rules" groups): non-MVC rules with no
     * 'updated' timestamp are flagged is_automatic; legacy user rules aren't.
     * The pf label arrives in the 'uuid' field.
     */
    private function automaticRuleLabels()
    {
        $labels = [];
        $items = json_decode((new Backend())->configdRun('filter list non_mvc_rules'), true) ?? [];
        foreach ($items as $item) {
            if (!empty($item['is_automatic']) && !empty($item['uuid'])) {
                $labels[$item['uuid']] = true;
            }
        }
        return $labels;
    }

    /**
     * Destination NAT (port-forward) entries that are enabled but can't do
     * what was probably meant. Real case (testlab, 26.7): the external port
     * entered as the SOURCE port and the redirect target left empty - the
     * GUI shows the entry as enabled, but no rdr is generated at all.
     *
     * @return array [{descr, problem}]
     */
    private function forwardConfigFindings()
    {
        if (!class_exists('\OPNsense\Firewall\DNat')) {
            return []; // older OPNsense without the MVC port-forward model
        }
        $out = [];
        foreach ((new \OPNsense\Firewall\DNat())->rule->iterateItems() as $rule) {
            if ((string)$rule->disabled === '1' || (string)$rule->nordr === '1') {
                continue;
            }
            $descr = (string)$rule->descr;
            $problems = [];
            if (trim((string)$rule->target) === '') {
                $problems[] = 'no redirect target, so it redirects nowhere and pf drops the entry';
            }
            if (trim((string)$rule->source->port) !== '' && trim((string)$rule->destination->port) === '') {
                $problems[] = 'a source port is set but no destination port: the external port usually belongs in the destination port';
            }
            foreach ($problems as $problem) {
                $out[] = ['descr' => $descr !== '' ? $descr : '(no description)', 'problem' => $problem];
            }
        }
        return $out;
    }

    public function rulesAction()
    {
        $backend = new Backend();
        $raw = json_decode($backend->configdpRun('controlledburn get ruleset'), true) ?? [];

        $rules = RuleEngine::attachDescriptions($raw['rules'] ?? [], $this->ruleDescriptionMap());
        $rules = RuleEngine::markAutomatic($rules, $this->automaticRuleLabels());

        $unparsed = array_column($raw['unparsed'] ?? [], 'text');
        return [
            'rules' => $rules,
            'unparsed_count' => count($unparsed),
            // the lines themselves, so the UI can show exactly what was skipped
            'unparsed' => array_slice($unparsed, 0, 100),
            // pf table name => entry count when read (null = unreadable)
            'tables' => $raw['tables'] ?? [],
            // port forwards (rdr / no rdr from pfctl -sn), pf order
            'redirects' => $raw['redirects'] ?? [],
        ];
    }

    /**
     * Everything an evaluation needs, gathered once per request.
     */
    private function context()
    {
        $ifmap = $this->interfaceMap();
        $rulesResult = $this->rulesAction();
        return [
            'ifaces' => $ifmap,
            'devices' => $this->discoverDevices($ifmap),
            'rules' => RuleEngine::prepareRules($rulesResult['rules'], $ifmap),
            'unparsed_count' => $rulesResult['unparsed_count'],
            'unparsed' => $rulesResult['unparsed'],
            'tables' => $rulesResult['tables'],
            'redirects' => RuleEngine::prepareRedirects($rulesResult['redirects'], $ifmap),
        ];
    }

    /**
     * Layer 1 overview graph (docs/PLAN.md section 3.3).
     */
    public function graphAction()
    {
        $ctx = $this->context();
        if (count($ctx['devices']) > self::MAX_DEVICES) {
            return ['too_many_devices' => count($ctx['devices']), 'device_limit' => self::MAX_DEVICES];
        }
        $graph = RuleEngine::buildGraph($ctx['devices'], $ctx['rules'], $ctx['ifaces'], $ctx['redirects']);
        // which box "This Firewall" is
        $system = Config::getInstance()->object()->system ?? null;
        $graph['hostname'] = $system !== null
            ? trim((string)$system->hostname . '.' . (string)$system->domain, '.')
            : '';
        $graph['interfaces'] = array_map(function ($if) {
            return ['key' => $if['key'], 'descr' => $if['descr']];
        }, $ctx['ifaces']);
        $graph['unparsed_count'] = $ctx['unparsed_count'];
        $graph['unparsed'] = $ctx['unparsed'];
        // rules that can never take effect (shadowed by another rule)
        $graph['dead_rules'] = RuleEngine::deadRuleFindings($ctx['rules'], $ctx['ifaces'], $ctx['devices']);
        // aliases/tables empty in the live firewall (e.g. saved, not applied)
        $graph['empty_tables'] = RuleEngine::emptyTableFindings($ctx['rules'], $ctx['tables']);
        // port forwards that do nothing, and forward entries that look wrong
        $graph['inert_forwards'] = RuleEngine::inertForwards($ctx['rules'], $ctx['redirects'], $ctx['devices'], $ctx['ifaces']);
        $graph['forward_config'] = $this->forwardConfigFindings();
        return $graph;
    }

    /**
     * Layer 2 drill-down: every protocol/port slice between two nodes,
     * allowed and blocked, with the rule that decides each
     * (RuleEngine::pairBreakdown).
     *
     * GET ?src=<node id>&dst=<node id> using the graph's node ids
     * ("device:<id>", "firewall", "wan").
     */
    public function pairAction()
    {
        $ctx = $this->context();
        $result = RuleEngine::pairBreakdown(
            $ctx['rules'],
            $ctx['redirects'],
            $ctx['devices'],
            $ctx['ifaces'],
            (string)$this->request->getQuery('src'),
            (string)$this->request->getQuery('dst')
        );
        $result['unparsed_count'] = $ctx['unparsed_count'];
        return $result;
    }
}
