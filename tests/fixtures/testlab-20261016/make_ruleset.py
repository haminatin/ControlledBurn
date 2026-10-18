"""
Regenerate ruleset.json (what `configctl controlledburn get ruleset` would
return) from the captured pfctl.txt, using the real parser. pf tables are
resolved as empty - see README.md.

Run: python3 -I tests/fixtures/testlab-20261016/make_ruleset.py > tests/fixtures/testlab-20261016/ruleset.json
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


def empty_tables(addrs):
    return [a for a in addrs if not (a.startswith('<') and a.endswith('>'))]


with open(os.path.join(here, 'pfctl.txt')) as f:
    print(json.dumps(gr.parse_ruleset(f.read(), resolve=empty_tables,
                                      table_sizes={'sshlockout': 0, 'virusprot': 0})))
