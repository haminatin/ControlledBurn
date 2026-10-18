<?php

/**
 * Minimal stand-ins for the OPNsense classes TopologyController touches
 * (configd Backend, Config, the Dnsmasq model, the API base class), so the
 * real controller can run off the box. Shapes follow core source; data comes
 * from $GLOBALS['CB_FIXTURE'], set by the test before requiring this file:
 *
 *   'configd'    => ['interface list ifconfig' => '<json>', ...]  raw output per command
 *   'interfaces' => ['lan' => ['if' => 'vtnet0', 'descr' => 'LAN', 'ipaddr' => ..., 'subnet' => ...], ...]
 *   'hosts'      => [['nas', ['192.168.77.20'], ['bc:24:...']], ...]  dnsmasq Hosts: name, IPs, MACs
 */

namespace OPNsense\Base {
    class ApiControllerBase
    {
        public $request;
    }
}

namespace OPNsense\Core {
    class Backend
    {
        public function configdRun($c)
        {
            return $this->configdpRun($c);
        }

        public function configdpRun($c, $p = [])
        {
            if (!array_key_exists($c, $GLOBALS['CB_FIXTURE']['configd'])) {
                throw new \Exception("unexpected configd call: $c");
            }
            return $GLOBALS['CB_FIXTURE']['configd'][$c];
        }
    }

    class Config
    {
        public static function getInstance()
        {
            return new self();
        }

        public function object()
        {
            $ifs = [];
            foreach ($GLOBALS['CB_FIXTURE']['interfaces'] as $key => $if) {
                $ifs[$key] = (object)array_merge(['if' => '', 'descr' => '', 'ipaddr' => '', 'subnet' => ''], $if);
            }
            return (object)['interfaces' => new class ($ifs) {
                public function __construct(public $c)
                {
                }

                public function children()
                {
                    return $this->c;
                }
            }];
        }
    }
}

namespace OPNsense\Firewall {
    /** Destination NAT model: rows from $GLOBALS['CB_FIXTURE']['dnat'] */
    class DNat
    {
        public $rule;

        public function __construct()
        {
            $this->rule = new class {
                public function iterateItems()
                {
                    foreach ($GLOBALS['CB_FIXTURE']['dnat'] ?? [] as $row) {
                        $o = (object)array_merge(['disabled' => '0', 'nordr' => '0', 'descr' => '', 'target' => ''], $row);
                        $o->source = (object)['port' => $row['source_port'] ?? ''];
                        $o->destination = (object)['port' => $row['destination_port'] ?? ''];
                        yield $o;
                    }
                }
            };
        }
    }
}

namespace OPNsense\Dnsmasq {
    class StubField
    {
        public function __construct(public $v)
        {
        }

        public function isEmpty()
        {
            return !$this->v;
        }

        public function getValues()
        {
            return $this->v;
        }
    }

    class StubHost
    {
        public $host;
        public $ip;
        public $hwaddr;

        public function __construct($host, $ips, $macs)
        {
            $this->host = $host;
            $this->ip = new StubField($ips);
            $this->hwaddr = new StubField($macs);
        }
    }

    class Dnsmasq
    {
        public $hosts;

        public function __construct()
        {
            $this->hosts = new class {
                public function iterateItems()
                {
                    foreach ($GLOBALS['CB_FIXTURE']['hosts'] as [$name, $ips, $macs]) {
                        yield new StubHost($name, $ips, $macs);
                    }
                }
            };
        }
    }
}

namespace {
    function cb_controller()
    {
        $root = __DIR__ . '/../..';
        require_once $root . '/src/opnsense/mvc/app/library/OPNsense/ControlledBurn/RuleEngine.php';
        require_once $root . '/src/opnsense/mvc/app/controllers/OPNsense/ControlledBurn/Api/TopologyController.php';
        $c = new OPNsense\ControlledBurn\Api\TopologyController();
        $c->request = new class {
            public $q = [];

            public function getQuery($k)
            {
                return $this->q[$k] ?? null;
            }
        };
        return $c;
    }

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
}
