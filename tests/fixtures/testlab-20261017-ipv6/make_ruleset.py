"""
Regenerate ruleset.json from pfctl.txt with the real parser (tables as on
the box: net_rfc1918 the private ranges; lockout lists empty).

Run: python3 -I tests/fixtures/testlab-20261017-ipv6/make_ruleset.py > tests/fixtures/testlab-20261017-ipv6/ruleset.json
"""
import importlib.util
import json
import os
import sys
import types

sys.modules['ujson'] = types.SimpleNamespace(dumps=json.dumps)
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    'get_ruleset', os.path.join(here, '..', '..', '..', 'src', 'opnsense', 'scripts', 'OPNsense', 'ControlledBurn', 'get_ruleset.py'))
gr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gr)
TABLES = {'net_rfc1918': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']}


def resolve(addrs):
    out = []
    for a in addrs:
        if a.startswith('<') and a.endswith('>'):
            out.extend(TABLES.get(a[1:-1], []))
        else:
            out.append(a)
    return out


with open(os.path.join(here, 'pfctl.txt')) as f:
    print(json.dumps(gr.parse_ruleset(f.read(), resolve=resolve,
                                      table_sizes={'net_rfc1918': 3, 'sshlockout': 0, 'virusprot': 0})))
