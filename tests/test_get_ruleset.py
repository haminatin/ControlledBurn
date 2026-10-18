"""
Fixture tests for get_ruleset.py's pf rule-line parser, runnable anywhere
with Python 3 (no pfctl, no OPNsense): pfctl calls and ujson are stubbed.

The sample lines are hand-written to pf's `pfctl -sr` syntax, NOT captured
from a live box - replace/extend them with real output from the testlab VM.

Run: python3 -I tests/test_get_ruleset.py
"""

import importlib.util
import json
import os
import sys
import types

sys.modules['ujson'] = types.SimpleNamespace(dumps=json.dumps)
_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', 'src', 'opnsense', 'scripts', 'OPNsense', 'ControlledBurn', 'get_ruleset.py'
)
_spec = importlib.util.spec_from_file_location('get_ruleset', _path)
gr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gr)

failures = 0
passed = 0


def parse(line):
    return gr.parse_line(line, resolve=lambda addrs: addrs)


def check(label, condition):
    global failures, passed
    if condition:
        passed += 1
    else:
        failures += 1
        print('FAIL: ' + label, file=sys.stderr)


r = parse('pass in quick on vtnet0 inet from any to any flags S/SA keep state label "aaa"')
check('plain any/any', r and r['interface'] == 'vtnet0' and r['source'] == ['any'] and r['destination'] == ['any'])

r = parse('pass in quick on vtnet0 inet proto tcp from 192.168.77.191 to 192.168.77.20 port = 445 '
          'flags S/SA keep state label "ccc"')
check('dst port keeps operator and value', r and r['to_port'] == '= 445' and r['destination'] == ['192.168.77.20'])

r = parse('pass in quick on vtnet0 proto udp from any port = 68 to 255.255.255.255 port = 67 keep state label "ddd"')
check('src port does not swallow destination',
      r and r['from_port'] == '= 68' and r['destination'] == ['255.255.255.255'] and r['to_port'] == '= 67')

r = parse('pass in quick on vtnet0 proto tcp from any to any port 1000:2000 label "rng"')
check('colon port range', r and r['to_port'] == '1000:2000')

r = parse('pass in quick on vtnet0 proto tcp from any to any port 1000 >< 2000 label "rng2"')
check('>< port range', r and r['to_port'] == '1000 >< 2000')

r = parse('block drop in quick on vtnet0 inet from ! 192.168.77.0/24 to any label "eee"')
check('negated source', r and r['source'] == ['192.168.77.0/24'] and r['source_not'] and not r['destination_not'])

r = parse('pass in quick inet6 proto ipv6-icmp all icmp6-type echoreq keep state label "fff"')
check('floating rule with no "on" gets interface any', r and r['interface'] == 'any')

r = parse('block drop in log quick on vtnet1 all label "ggg"')
check("'all' keyword", r and r['source'] == ['any'] and r['destination'] == ['any'])

r = parse('block drop in quick on vtnet0 inet from 192.168.77.30 to { 192.168.77.20 192.168.77.191 } label "iii"')
check('space-separated address list', r and r['destination'] == ['192.168.77.20', '192.168.77.191'])

r = parse('block drop in quick on vtnet0 inet from 192.168.77.30 to { 192.168.77.20, 192.168.77.191 } label "iii"')
check('comma-separated address list', r and r['destination'] == ['192.168.77.20', '192.168.77.191'])

r = parse('pass in quick on vtnet0 inet proto tcp from 192.168.77.191 to (self) port = 443 label "hhh"')
check('(self) kept verbatim for the engine to treat conservatively', r and r['destination'] == ['(self)'])

r = parse('pass in quick on ! vtnet0 inet from any to any label "neg"')
check('negated interface parsed as "every interface except"', r and r['interface'] == 'vtnet0' and r['interface_not'] is True)

check('unknown token before "from" is rejected, not read as from-any',
      parse('pass in quick on vtnet0 frobnicate from 10.0.0.1 to any label "unk"') is None)

r = parse('pass in quick on vtnet0 inet from any to any label "fam4"')
check('inet rule keeps family', r and r['ipprotocol'] == 'inet')

r = parse('pass in quick on vtnet0 all label "fam"')
check('rule without inet/inet6 applies to both families', r and r['ipprotocol'] == 'any')

# OPNsense anti-spoofing rules carry no label (real 26.7 output)
r = parse('block drop in log on ! vtnet0 inet from 192.168.77.0/24 to any')
check('unlabelled anti-spoof rule parses', r and r['label'] is None and r['interface_not']
      and r['source'] == ['192.168.77.0/24'] and r['destination'] == ['any'] and not r['quick'])
r = parse('block drop in log inet from 192.168.77.1 to any')
check('unlabelled rule ending in "to any" parses', r and r['destination'] == ['any'] and r['interface'] == 'any')

whole = gr.parse_ruleset('scrub in all fragment reassemble\n'
                         'block drop in log on ! vtnet0 inet from 192.168.77.0/24 to any\n'
                         'pass in quick on vtnet0 inet from any to any label "x"\n',
                         resolve=lambda addrs: addrs)
check('scrub is skipped, not unparsed', whole['unparsed'] == [] and len(whole['rules']) == 2)
check('unlabelled rule gets a synthetic label', whole['rules'][0]['label'] == 'nolabel-0' and whole['rules'][1]['label'] == 'x')
check('rule order preserved', [r['seq'] for r in whole['rules']] == [0, 1])
check('genuinely unreadable filter line is reported', gr.parse_ruleset('pass in quick on vtnet0 frobnicate from 1.2.3.4 to any\n', resolve=lambda a: a)['unparsed'][0]['text'].startswith('pass'))

# table sizes are reported for every table the rules reference
t = gr.parse_ruleset('pass in quick on vtnet2 inet from (vtnet2:network) to ! <net_rfc1918> label "x"\n'
                     'block in quick from <sshlockout> to (self) label "y"\n',
                     resolve=lambda a: [v for v in a if not v.startswith('<')],
                     table_sizes={'net_rfc1918': 0, 'sshlockout': 0, 'unused': 5})
check('referenced tables reported with their sizes', t['tables'] == {'net_rfc1918': 0, 'sshlockout': 0})

# ---- redirects (pfctl -sn), real lines from the 26.7 testlab
sn = gr.parse_redirects('''no nat proto carp all
nat on vtnet1 inet from (vtnet0:network) to any -> (vtnet1:0) port 1024:65535
no rdr proto carp all
no rdr on vtnet0 proto tcp from any to (vtnet0) port = ssh
rdr on vtnet1 inet proto tcp from any to (vtnet1) port = 8443 -> 192.168.77.20 port 443
rdr pass on vtnet1 inet proto tcp from any to (vtnet1) port = 2222 -> 192.168.77.191 port 22
rdr on vtnet1 inet proto tcp from any to (vtnet1) port 8000:8010 -> 192.168.77.30 port 8000 round-robin
rdr on vtnet1 inet proto tcp from any to (vtnet1) port = 9999 -> 192.168.77.31 port 22 frobnicate
''', resolve=lambda a: a)
rd = sn['redirects']
check('nat lines and carp ignored; rdr/no rdr kept in order', [r['no'] for r in rd] == [True, False, False, False])
check('no rdr parsed (anti-lockout exclusion)', rd[0]['interface'] == 'vtnet0' and rd[0]['to_port'] == '= ssh' and rd[0]['target'] == [])
check('manual forward: target and ports', not rd[1]['pass'] and rd[1]['to_port'] == '= 8443'
      and rd[1]['target'] == ['192.168.77.20'] and rd[1]['target_port'] == '443' and rd[1]['destination'] == ['(vtnet1)'])
check('rdr pass flagged', rd[2]['pass'] and rd[2]['target'] == ['192.168.77.191'] and rd[2]['target_port'] == '22')
check('port range with a pool option parses', rd[3]['to_port'] == '8000:8010' and rd[3]['target_port'] == '8000')
check('unknown trailing option goes to unparsed, not guessed', len(sn['unparsed']) == 1 and '9999' in sn['unparsed'][0]['text'])

print('%d passed, %d failed' % (passed, failures))
sys.exit(1 if failures else 0)
