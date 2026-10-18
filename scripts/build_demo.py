#!/usr/bin/env python3
"""
Build the interactive demo page, docs/demo/index.html (served by GitHub
Pages), from docs/demo/template.html, the plugin's own topology.css and
topology.js, and sample data:

- the real testlab captures, evaluated afresh by the current engine (the
  capture tests' CB_DUMP_GRAPH hook), and their pair breakdowns;
- the scenario and example fixtures in tests/fixtures/;
- docs/demo/make_five_vlans.php (a made-up network with a realistic
  ruleset, also evaluated by the engine).

So the demo always shows what the plugin does now.

Usage:
  python3 scripts/build_demo.py          write docs/demo/index.html
  python3 scripts/build_demo.py --check  exit 1 if it's out of date (CI)

Needs php (the same as the tests).
"""

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'docs', 'demo', 'index.html')
DEMO_HOSTNAME = 'firewall.example'


def path(*parts):
    return os.path.join(ROOT, *parts)


def read(*parts):
    with open(path(*parts), encoding='utf-8') as f:
        return f.read()


def fixture(name):
    return json.loads(read('tests', 'fixtures', name))


def captured(test):
    """The graph a capture test builds, via its CB_DUMP_GRAPH hook."""
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, 'graph.json')
        env = dict(os.environ, CB_DUMP_GRAPH=out)
        run = subprocess.run(['php', path('tests', test)], env=env, capture_output=True, text=True)
        if run.returncode != 0:
            sys.exit('%s failed, not building the demo from it:\n%s%s' % (test, run.stdout, run.stderr))
        with open(out, encoding='utf-8') as f:
            return json.load(f)


def php_json(*script):
    run = subprocess.run(['php', path(*script)], capture_output=True, text=True)
    if run.returncode != 0:
        sys.exit('%s failed:\n%s' % (script, run.stderr))
    return json.loads(run.stdout)


def script_json(value):
    """JSON safe to embed in a <script> block."""
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).replace('</', '<\\/')


def build():
    data = {
        'port-forwards': captured('test_testlab_nat.php'),
        'testlab': captured('test_testlab_capture.php'),
        'iot-mistake': fixture('scenario_iot_mistake.json'),
        'iot-naive': fixture('scenario_iot_reorder.json'),
        'iot-fixed': fixture('scenario_iot_fixed.json'),
        'ipv6-bypass': fixture('scenario_ipv6_bypass.json'),
        'three-segments': fixture('example_graph.json'),
        'five-vlans': php_json('docs', 'demo', 'make_five_vlans.php'),
    }
    for graph in data.values():
        # the captures run without a hostname; show what the plugin would
        graph['hostname'] = graph.get('hostname') or DEMO_HOSTNAME
    pairs = {'port-forwards': php_json('tests', 'fixtures', 'make_pairs_nat.php')}

    page = read('docs', 'demo', 'template.html')
    for key, value in (
        ('%%CSS%%', read('src', 'opnsense', 'www', 'css', 'ControlledBurn', 'topology.css')),
        ('%%JS%%', read('src', 'opnsense', 'www', 'js', 'ControlledBurn', 'topology.js')),
        ('%%DATA%%', script_json(data)),
        ('%%PAIRS%%', script_json(pairs)),
    ):
        if page.count(key) != 1:
            sys.exit('template must contain %s exactly once' % key)
        page = page.replace(key, value)
    return page


def main():
    page = build()
    if '--check' in sys.argv[1:]:
        current = open(OUT, encoding='utf-8').read() if os.path.exists(OUT) else ''
        if current != page:
            sys.exit('docs/demo/index.html is out of date: run python3 scripts/build_demo.py')
        print('docs/demo/index.html is up to date')
        return
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write(page)
    print('wrote %s (%d KB)' % (os.path.relpath(OUT, ROOT), len(page.encode('utf-8')) // 1024))


if __name__ == '__main__':
    main()
