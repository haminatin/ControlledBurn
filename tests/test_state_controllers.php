<?php

/**
 * Off-box test of LayoutController and ReviewController (saved layout and
 * audit checks) against minimal stand-ins for OPNsense's model and Config.
 * Checks what they store, that resets clear everything, and that every save
 * skips the configuration history (Config::save(null, false)).
 *
 * Run: php tests/test_state_controllers.php
 */

namespace OPNsense\Core {
    class Config
    {
        public static $saves = [];
        public static $locks = 0;
        public static $unlocks = 0;
        private static $instance;

        public static function getInstance()
        {
            return self::$instance ?? (self::$instance = new self());
        }

        public function lock()
        {
            self::$locks++;
        }

        public function unlock()
        {
            self::$unlocks++;
        }

        public function save($revision = null, $backup = true)
        {
            self::$saves[] = ['revision' => $revision, 'backup' => $backup];
        }
    }
}

namespace OPNsense\Base {
    /** one row of an ArrayField: plain properties */
    class StubRow
    {
        public function __toString()
        {
            return '';
        }

        /** a field never set reads empty, as a real model field would */
        public function __get($name)
        {
            return '';
        }
    }

    class StubArrayField
    {
        public $rows = [];
        private $n = 0;

        public function add()
        {
            $uuid = 'uuid-' . (++$this->n);
            return $this->rows[$uuid] = new StubRow();
        }

        public function del($uuid)
        {
            unset($this->rows[$uuid]);
        }

        public function getNodes()
        {
            return $this->rows;
        }

        public function iterateItems()
        {
            foreach ($this->rows as $uuid => $row) {
                yield $uuid => $row;
            }
        }
    }

    class StubModel
    {
        public $positions;
        public $reviews;
        public $serialized = 0;
        public static $instance;

        public function __construct()
        {
            $this->positions = new StubArrayField();
            $this->reviews = new StubArrayField();
        }

        public function serializeToConfig()
        {
            $this->serialized++;
        }
    }

    class ApiMutableModelControllerBase
    {
        public $request;
        public static $readOnly = false;

        protected function getModel()
        {
            return StubModel::$instance;
        }

        protected function validate()
        {
            return ['result' => ''];
        }

        protected function throwReadOnly()
        {
            if (self::$readOnly) {
                throw new \Exception('read only');
            }
        }
    }
}

namespace {
    $root = __DIR__ . '/..';
    require $root . '/src/opnsense/mvc/app/library/OPNsense/ControlledBurn/QuietSave.php';
    require $root . '/src/opnsense/mvc/app/controllers/OPNsense/ControlledBurn/Api/LayoutController.php';
    require $root . '/src/opnsense/mvc/app/controllers/OPNsense/ControlledBurn/Api/ReviewController.php';

    use OPNsense\Base\StubModel;
    use OPNsense\Core\Config;

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

    function request(array $post)
    {
        return new class ($post) {
            public function __construct(private array $post)
            {
            }

            public function isPost()
            {
                return true;
            }

            public function getPost($name, $filter = null, $default = null)
            {
                return $this->post[$name] ?? $default;
            }
        };
    }

    function call($class, $action, array $post = [])
    {
        $c = new $class();
        $c->request = request($post);
        return $c->{$action . 'Action'}();
    }

    StubModel::$instance = new StubModel();
    $L = 'OPNsense\ControlledBurn\Api\LayoutController';
    $R = 'OPNsense\ControlledBurn\Api\ReviewController';

    // ---- layout
    $r = call($L, 'set', ['positions' => [
        ['node_id' => 'device:aa', 'node_type' => 'device', 'x' => -120, 'y' => 40],
        ['node_id' => 'firewall', 'node_type' => 'firewall', 'x' => 300, 'y' => -80],
        ['node_id' => '', 'node_type' => 'device', 'x' => 1, 'y' => 1],
    ]]);
    check('layout save reports saved', $r === ['result' => 'saved']);
    $got = call($L, 'get')['positions'];
    check('layout stores valid positions, skips blank ids, keeps negatives', count($got) === 2
        && $got[0] === ['node_id' => 'device:aa', 'node_type' => 'device', 'x' => -120, 'y' => 40, 'layout' => 'columns']);
    call($L, 'set', ['positions' => [['node_id' => 'wan', 'node_type' => 'wan', 'x' => 5, 'y' => 6]]]);
    check('layout set replaces the whole set', array_column(call($L, 'get')['positions'], 'node_id') === ['wan']);
    call($L, 'reset');
    check('layout reset clears every position', call($L, 'get')['positions'] === []);
    check('layout rejects a non-array', call($L, 'set', ['positions' => 'nope'])['status'] === 'failed');

    // ---- reviews
    call($R, 'set', ['edge_id' => 'f:device:aa>firewall', 'fingerprint' => 'acc484bb', 'snapshot' => "tcp 22 \u{2014} anti-lockout rule"]);
    call($R, 'set', ['edge_id' => 'f:device:bb>firewall', 'fingerprint' => '1234abcd']);
    $got = call($R, 'get');
    check('checks stored with fingerprints', $got['reviews'] === ['f:device:aa>firewall' => 'acc484bb', 'f:device:bb>firewall' => '1234abcd']);
    check('snapshot stored (empty when not sent)', $got['snapshots']['f:device:aa>firewall'] === "tcp 22 \u{2014} anti-lockout rule"
        && $got['snapshots']['f:device:bb>firewall'] === '');
    call($R, 'set', ['edge_id' => 'f:device:aa>firewall', 'fingerprint' => 'ffff0000', 'snapshot' => 'new']);
    $got = call($R, 'get');
    check('re-checking an edge replaces its entry, no duplicate', count(StubModel::$instance->reviews->rows) === 2
        && $got['reviews']['f:device:aa>firewall'] === 'ffff0000' && $got['snapshots']['f:device:aa>firewall'] === 'new');
    call($R, 'set', ['edge_id' => 'f:device:bb>firewall', 'checked' => '0']);
    check('unchecking removes just that edge', array_keys(call($R, 'get')['reviews']) === ['f:device:aa>firewall']);
    check('snapshot is capped', strlen((function () use ($R) {
        call($R, 'set', ['edge_id' => 'x', 'fingerprint' => 'aa', 'snapshot' => str_repeat('a', 10000)]);
        return call($R, 'get')['snapshots']['x'];
    })()) === 4000);
    call($R, 'set', ['edge_id' => 'u', 'fingerprint' => 'aa', 'snapshot' => str_repeat("\u{00e9}", 5000)]);
    $u = call($R, 'get')['snapshots']['u'];
    check('cap counts characters, never splits a UTF-8 character', preg_match('//u', $u) === 1 && strlen($u) === 8000);
    call($R, 'reset');
    check('review reset clears every check', call($R, 'get')['reviews'] === []);
    check('edge_id is required', call($R, 'set', ['fingerprint' => 'aa'])['status'] === 'failed');

    // ---- positions are kept per layout (star / columns)
    call($L, 'reset', ['layout' => 'star']);
    call($L, 'reset', ['layout' => 'columns']);
    call($L, 'set', ['layout' => 'columns', 'positions' => [['node_id' => 'device:aa', 'node_type' => 'device', 'x' => 1, 'y' => 1]]]);
    call($L, 'set', ['layout' => 'star', 'positions' => [['node_id' => 'device:aa', 'node_type' => 'device', 'x' => 9, 'y' => 9]]]);
    $byLayout = function () use ($L) {
        $out = [];
        foreach (call($L, 'get')['positions'] as $p) {
            $out[$p['layout']][$p['node_id']] = $p['x'];
        }
        return $out;
    };
    check('each layout keeps its own positions', $byLayout() === ['columns' => ['device:aa' => 1], 'star' => ['device:aa' => 9]]);
    call($L, 'set', ['layout' => 'star', 'positions' => [['node_id' => 'device:bb', 'node_type' => 'device', 'x' => 5, 'y' => 5]]]);
    check('saving one layout replaces only that layout', $byLayout() === ['columns' => ['device:aa' => 1], 'star' => ['device:bb' => 5]]);
    call($L, 'reset', ['layout' => 'star']);
    check('resetting one layout leaves the other', $byLayout() === ['columns' => ['device:aa' => 1]]);
    // a position saved before layouts existed (no layout field) is a columns one
    $old = StubModel::$instance->positions->add();
    $old->node_id = 'device:old';
    $old->node_type = 'device';
    $old->x = 7;
    $old->y = 7;
    check('positions saved before layouts existed count as columns', ($byLayout()['columns']['device:old'] ?? null) === 7);
    call($L, 'set', ['layout' => 'star', 'positions' => []]);
    check('...and are normalised to columns on the next save', $old->layout === 'columns' && ($byLayout()['columns']['device:old'] ?? null) === 7);
    check('an unknown layout name means columns', call($L, 'set', ['layout' => 'spiral', 'positions' => []])['result'] === 'saved'
        && !isset($byLayout()['columns']));
    call($L, 'reset', ['layout' => 'star']);
    call($L, 'reset', ['layout' => 'columns']);

    // ---- limits: a user granted only this page can't bloat config.xml
    $many = [];
    for ($i = 0; $i < 2001; $i++) {
        $many[] = ['node_id' => 'device:' . $i, 'node_type' => 'device', 'x' => $i, 'y' => 0];
    }
    call($L, 'set', ['positions' => [['node_id' => 'wan', 'node_type' => 'wan', 'x' => 1, 'y' => 2]]]);
    $r = call($L, 'set', ['positions' => $many]);
    check('layout over 2000 positions refused, with the reason', $r['status'] === 'failed' && strpos($r['error_msg'], '2001') !== false);
    check('...and the saved layout is left as it was', array_column(call($L, 'get')['positions'], 'node_id') === ['wan']);
    $r = call($L, 'set', ['positions' => array_slice($many, 0, 2000)]);
    check('2000 positions still save', $r === ['result' => 'saved'] && count(call($L, 'get')['positions']) === 2000);
    $r = call($L, 'set', ['positions' => [
        ['node_id' => 'device:fd00:77::be24:11ff:fe77:302', 'node_type' => 'device', 'x' => 1, 'y' => 1],
        ['node_id' => 'device:192.168.77.20', 'node_type' => 'device', 'x' => 1, 'y' => 1],
        ['node_id' => str_repeat('a', 5000), 'node_type' => 'device', 'x' => 1, 'y' => 1],
        ['node_id' => 'device:<b>x</b>', 'node_type' => 'device', 'x' => 1, 'y' => 1],
    ]]);
    check('MAC, IPv4 and IPv6 node ids save; odd ones are skipped and reported', $r['result'] === 'saved'
        && count(call($L, 'get')['positions']) === 2
        && $r['skipped'] === [str_repeat('a', 60), 'device:<b>x</b>']);
    call($L, 'reset');

    call($R, 'reset');
    check('edge id with unexpected characters refused', call($R, 'set', ['edge_id' => 'f:<b>x</b>>firewall', 'fingerprint' => 'aa'])['status'] === 'failed');
    check('over-long edge id refused', call($R, 'set', ['edge_id' => str_repeat('a', 301), 'fingerprint' => 'aa'])['status'] === 'failed');
    check('real edge ids accepted (directed, same-segment, IPv6)', call($R, 'set', ['edge_id' => 'f:wan>device:bc:24:11:77:03:02', 'fingerprint' => 'aa'])['result'] === 'saved'
        && call($R, 'set', ['edge_id' => 'u:device:192.168.77.41|device:fd00::5', 'fingerprint' => 'aa'])['result'] === 'saved');
    for ($i = count(StubModel::$instance->reviews->rows); $i < 5000; $i++) {
        $row = StubModel::$instance->reviews->add();
        $row->edge_id = 'f:device:' . $i . '>firewall';
        $row->fingerprint = 'aa';
        $row->snapshot = '';
    }
    $unlocks = Config::$unlocks;
    $r = call($R, 'set', ['edge_id' => 'f:device:new>firewall', 'fingerprint' => 'aa']);
    check('a 5001st check is refused, with the reason, and the lock released', $r['status'] === 'failed'
        && strpos($r['error_msg'], '5000') !== false && Config::$unlocks === $unlocks + 1);
    check('re-checking an edge at the limit still works', call($R, 'set', ['edge_id' => 'f:device:7>firewall', 'fingerprint' => 'bb'])['result'] === 'saved');
    check('unchecking at the limit still works', call($R, 'set', ['edge_id' => 'f:device:8>firewall', 'checked' => '0'])['result'] === 'saved');
    call($R, 'reset');

    // ---- history-free saves, lock hygiene, read-only
    check('every save skips the config history (backup=false)', count(Config::$saves) > 0
        && !array_filter(Config::$saves, function ($s) {
            return $s['backup'] !== false;
        }));
    \OPNsense\Base\ApiMutableModelControllerBase::$readOnly = true;
    $threw = false;
    $before = Config::$locks;
    try {
        call($R, 'set', ['edge_id' => 'f:x>y', 'fingerprint' => 'aa']);
    } catch (\Exception $e) {
        $threw = true;
    }
    check('read-only users are refused before the config is locked', $threw && Config::$locks === $before);

    echo "{$passed} passed, {$failures} failed\n";
    exit($failures > 0 ? 1 : 0);
}
