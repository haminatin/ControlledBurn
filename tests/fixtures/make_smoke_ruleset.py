"""
Regenerate tests/fixtures/smoke_ruleset.json (the `controlledburn get ruleset`
output used by tests/smoke_topology_controller.php) by running the real
parser over hand-written pf lines. <tables> are marked unresolved.

Run: python3 -I tests/fixtures/make_smoke_ruleset.py > tests/fixtures/smoke_ruleset.json
"""
import os, sys, types, json, importlib.util
sys.modules['ujson'] = types.SimpleNamespace(dumps=json.dumps)
_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'src', 'opnsense', 'scripts', 'OPNsense', 'ControlledBurn', 'get_ruleset.py')
spec = importlib.util.spec_from_file_location('gr', _path); gr = importlib.util.module_from_spec(spec); spec.loader.exec_module(gr)
lines = [
 'pass in quick on vtnet0 inet proto tcp from (vtnet0:network) to (self) port = 443 flags S/SA keep state label "11111111-1111-1111-1111-111111111111"',
 'block drop in quick on vtnet0 inet proto tcp from 192.168.77.191 to 10.0.10.20 port = 22 label "22222222-2222-2222-2222-222222222222"',
 'pass in quick on vtnet0 inet proto tcp from 192.168.77.191 to 10.0.10.20 port = 445 flags S/SA keep state label "33333333-3333-3333-3333-333333333333"',
 'pass out log inet all keep state allow-opts label "44444444444444444444444444444444"',
 'block drop in log quick on vtnet0 inet from <virusprot> to any label "55555555555555555555555555555555"',
]
rules=[]
for l in lines:
    r = gr.parse_line(l, resolve=lambda a: [x if not x.startswith('<') else {'table': x, 'unresolved': True} for x in a])
    r['seq']=len(rules); rules.append(r)
print(json.dumps({'rules': rules, 'unparsed': []}))
