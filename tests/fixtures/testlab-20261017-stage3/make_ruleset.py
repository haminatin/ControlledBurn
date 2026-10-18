"""
Regenerate ruleset.json from pfctl.txt with the real parser, resolving pf
tables as on the box (see README.md).

Run: python3 -I tests/fixtures/testlab-20261017-stage3/make_ruleset.py > tests/fixtures/testlab-20261017-stage3/ruleset.json
     python3 -I tests/fixtures/testlab-20261017-stage3/make_ruleset.py --corrected > tests/fixtures/testlab-20261017-stage3/ruleset_corrected.json
     python3 -I tests/fixtures/testlab-20261017-stage3/make_ruleset.py --corrected --empty-alias > tests/fixtures/testlab-20261017-stage3/ruleset_empty_alias.json
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


# --empty-alias: the box's real mistake - net_rfc1918 saved but not applied,
# so pf's table was empty when the plugin read it
EMPTY = '--empty-alias' in sys.argv
if EMPTY:
    TABLES['net_rfc1918'] = []

# --corrected: the re-run with the lab matching the spec (block to LAN net)
SOURCE = 'pfctl_corrected.txt' if '--corrected' in sys.argv else 'pfctl.txt'

with open(os.path.join(here, SOURCE)) as f:
    sizes = {'sshlockout': 0, 'virusprot': 0, 'net_rfc1918': len(TABLES['net_rfc1918'])}
    print(json.dumps(gr.parse_ruleset(f.read(), resolve=resolve, table_sizes=sizes)))
