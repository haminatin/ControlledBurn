#!/usr/local/bin/python3

"""
Dump the actual, currently-loaded pf filter ruleset in evaluation order, parsed
into structured fields for ControlledBurn's rule-evaluation engine.

Ground truth is `pfctl -sr` output, not config.xml, per the plan's Strategy B:
the loaded ruleset includes auto-generated rules (anti-lockout, NAT-implied
passes, etc.) that don't map 1:1 to config.xml <filter><rule> entries, and a
security-audit tool must not silently miss those. Every rule line is parsed
directly from pf's own text syntax; config.xml is only consulted PHP-side to
attach a human-readable description via label/hash correlation, per
Util::calcRuleHash().

Rule text token order mirrors OPNsense's own generator
(mvc/app/library/OPNsense/Firewall/FilterRule.php $procorder), confirmed
against that source rather than assumed:
  <action> [direction] [log] [quick] on <if> [route/reply clauses] [inet|inet6]
  [proto <proto>] [from <src> [port <port>]] [to <dst> [port <port>]] ...
  label "<label>"

Lines that don't match this grammar closely enough to extract action/interface
confidently are NOT guessed at - they're excluded from the ordered list and
reported separately in `unparsed`, so the PHP side can surface a warning
rather than silently produce a wrong pass/block verdict.

Not every rule carries a label: OPNsense's anti-spoofing rules, for one, are
printed without one. Those still affect verdicts, so they're parsed and given
a synthetic `nolabel-<seq>` label. Non-filter lines (scrub, anchor, match,
...) never decide pass/block and are skipped rather than counted as unparsed.
"""

import re
import subprocess
import ujson

# pf port specs: "= 80", "!= 80", "< 1024", ">= 1024", "1000:2000",
# "1000 >< 2000", "1000 <> 2000", or a {list}
PORT = r'(?:(?:[!<>]?=|[<>])\s*\S+|\S+\s+(?:><|<>)\s+\S+|\{[^}]*\}|\S+)'
# pf address specs, optionally negated with a leading "!"
ADDR = r'(?:\{[^}]*\}|\S+)'

# each clause ends in whitespace or end of line (unlabelled rules end on
# their last clause, e.g. "... to any")
END = r'(?:\s+|$)'

RULE_RE = re.compile(
    r'^(?P<action>pass|block(?: return| drop)?)\s+'
    r'(?:(?P<direction>in|out)\s+)?'
    r'(?:log\s+)?'
    r'(?P<quick>quick\s+)?'
    # no "on" clause = rule applies on every interface (floating rules);
    # "on ! <if>" = every interface except that one
    r'(?:on\s+(?P<if_not>!\s*)?(?P<interface>[^\s!]\S*?)' + END + r')?(?!on\s)'
    r'(?:route-to\s*\([^)]*\)\s+|reply-to\s*\([^)]*\)\s+|reply-to\s+\S+\s+)*'
    r'(?:(?P<ipproto>inet6?)' + END + r')?'
    r'(?:proto\s+(?P<protocol>\S+)' + END + r')?'
    r'(?:from\s+(?P<from_not>!\s*)?(?P<from>' + ADDR + r')' + END + r')?'
    r'(?:port\s+(?P<from_port>' + PORT + r')' + END + r')?'
    r'(?:to\s+(?P<to_not>!\s*)?(?P<to>' + ADDR + r')' + END + r')?'
    r'(?:port\s+(?P<to_port>' + PORT + r')' + END + r')?'
    r'(?:.*?label\s+"(?P<label>[^"]*)")?'
)

# Every group above is optional and the tail is a lazy ".*?", so a clause the
# regex can't read would otherwise be silently swallowed - e.g. an unexpected
# token before "from" would make the source read as "any". If a keyword is
# present in the line but its group didn't capture, treat the line as unparsed.
REQUIRED_IF_PRESENT = {'on': 'interface', 'proto': 'protocol', 'from': 'from', 'to': 'to'}

TABLE_RE = re.compile(r'^<(?P<name>.+)>$')

# pf redirect (port forward) lines from `pfctl -sn`, e.g.
#   rdr on vtnet1 inet proto tcp from any to (vtnet1) port = 8443 -> 192.168.77.20 port 443
#   rdr pass on vtnet1 inet proto tcp from any to (vtnet1) port = 2222 -> 192.168.77.191 port 22
#   no rdr on vtnet0 proto tcp from any to (vtnet0) port = ssh
# "no rdr" excludes matching traffic from redirection (anti-lockout); the
# first matching rdr/no rdr line wins. "rdr pass" skips filter rules.
RDR_RE = re.compile(
    r'^(?P<no>no\s+)?rdr\s+(?P<pass>pass\s+)?(?:log\s+(?:\([^)]*\)\s+)?)?'
    r'(?:on\s+(?P<if_not>!\s*)?(?P<interface>[^\s!]\S*?)' + END + r')?'
    r'(?:(?P<ipproto>inet6?)' + END + r')?'
    r'(?:proto\s+(?P<protocol>\S+)' + END + r')?'
    r'(?:all' + END + r')?'
    r'(?:from\s+(?P<from_not>!\s*)?(?P<from>' + ADDR + r')' + END + r')?'
    r'(?:port\s+(?P<from_port>' + PORT + r')' + END + r')?'
    r'(?:to\s+(?P<to_not>!\s*)?(?P<to>' + ADDR + r')' + END + r')?'
    r'(?:port\s+(?P<to_port>' + PORT + r')' + END + r')?'
    r'(?:->\s+(?P<target>' + ADDR + r')(?:\s+port\s+(?P<target_port>\S+))?)?'
    r'(?P<rest>.*)$'
)


def split_list(value):
    """pf renders multi-value from/to as {a b c} (or {a, b, c}); split back into a list."""
    if value is None:
        return ['any']
    value = value.strip()
    if value.startswith('{') and value.endswith('}'):
        return [v for v in re.split(r'[\s,]+', value[1:-1]) if v]
    return [value]


# table name -> list of entries, or None when pfctl couldn't read it; shared
# across rules so each table is read once, and reported in the output so the
# UI can flag empty tables (e.g. an alias saved but never applied)
TABLE_CACHE = {}


def resolve_tables(addrs):
    """Expand any <table> reference in addrs via `pfctl -t <table> -T show`."""
    resolved = []
    tables_seen = TABLE_CACHE
    for addr in addrs:
        m = TABLE_RE.match(addr)
        if not m:
            resolved.append(addr)
            continue
        table = m.group('name')
        if table not in tables_seen:
            sp = subprocess.run(
                ['/sbin/pfctl', '-t', table, '-T', 'show'],
                capture_output=True, text=True
            )
            tables_seen[table] = [
                line.strip() for line in sp.stdout.split('\n') if line.strip()
            ] if sp.returncode == 0 else None
        if tables_seen[table] is None:
            # table failed to resolve (not loaded / transient) - do not guess
            resolved.append({'table': table, 'unresolved': True})
        else:
            resolved.extend(tables_seen[table])
    return resolved


def parse_line(line, resolve=resolve_tables):
    """
    Parse one `pfctl -sr` rule line into a rule dict (without 'seq'), or
    return None if it can't be parsed confidently. `resolve` expands <table>
    references; overridable so tests can run without pfctl.
    """
    m = RULE_RE.match(line)
    if not m:
        return None
    head = line.split(' label ')[0]
    for kw, group in REQUIRED_IF_PRESENT.items():
        if re.search(r'\s%s\s' % kw, head) and m.group(group) is None:
            return None

    return {
        'label': m.group('label') or None,
        'action': 'block' if m.group('action').startswith('block') else 'pass',
        'direction': m.group('direction') or 'any',
        'quick': bool(m.group('quick')),
        'interface': m.group('interface') or 'any',
        'interface_not': bool(m.group('if_not')),
        # no inet/inet6 means the rule applies to both families
        'ipprotocol': m.group('ipproto') or 'any',
        'protocol': (m.group('protocol') or 'any').lower(),
        'source': resolve(split_list(m.group('from'))),
        'source_not': bool(m.group('from_not')),
        'destination': resolve(split_list(m.group('to'))),
        'destination_not': bool(m.group('to_not')),
        'from_port': m.group('from_port'),
        'to_port': m.group('to_port'),
        'text': line,
    }


def parse_ruleset(text, resolve=resolve_tables, table_sizes=None):
    """
    Parse full `pfctl -sr` output into {'rules': [...], 'unparsed': [...]}.
    Rules keep pf's evaluation order ('seq'); unlabelled rules get a
    synthetic label. 'tables' maps every pf table the rules reference to its
    entry count (None = couldn't be read); table_sizes overrides the counts
    (for tests with their own resolver), else they come from TABLE_CACHE. Only pass/block lines are filter rules - anything else
    (scrub, anchor, match, ...) is skipped, not reported as unparsed.
    """
    rules = []
    unparsed = []
    for lineno, raw_line in enumerate(text.split('\n')):
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        if line.split()[0] not in ('pass', 'block'):
            continue

        rule = parse_line(line, resolve)
        if rule is None:
            unparsed.append({'line': lineno, 'text': line})
            continue

        rule['seq'] = len(rules)
        if rule['label'] is None:
            rule['label'] = 'nolabel-%d' % rule['seq']
        rules.append(rule)
    sizes = table_sizes if table_sizes is not None else {
        name: (None if entries is None else len(entries)) for name, entries in TABLE_CACHE.items()
    }
    referenced = set()
    for rule in rules:
        referenced.update(re.findall(r'<([^>\s]+)>', rule['text']))
    tables = {name: sizes[name] for name in sorted(referenced) if name in sizes}
    return {'rules': rules, 'unparsed': unparsed, 'tables': tables}


# trailing rdr options that don't change where traffic goes
RDR_POOL_OPTIONS = ('round-robin', 'random', 'source-hash', 'bitmask', 'static-port', 'sticky-address')


def parse_redirects(text, resolve=resolve_tables):
    """
    Parse `pfctl -sn` output into the ordered list of rdr / no rdr rules
    (nat, binat and other lines are ignored). Lines that don't parse are
    reported in 'unparsed' rather than guessed.
    """
    redirects = []
    unparsed = []
    for raw_line in text.split('\n'):
        line = raw_line.strip()
        words = line.split()
        if not words or 'rdr' not in words[:2]:
            continue
        m = RDR_RE.match(line)
        # anything left after the target must be a pool option we can
        # ignore; otherwise the line has something we don't understand
        rest = m.group('rest').strip() if m else None
        if rest is None or (rest and not rest.startswith(RDR_POOL_OPTIONS)):
            unparsed.append({'text': line})
            continue
        if m.group('protocol') == 'carp':
            continue  # CARP is never port-forwarded
        redirects.append({
            'seq': len(redirects),
            'no': bool(m.group('no')),
            'pass': bool(m.group('pass')),
            'interface': m.group('interface') or 'any',
            'interface_not': bool(m.group('if_not')),
            'ipprotocol': m.group('ipproto') or 'any',
            'protocol': (m.group('protocol') or 'any').lower(),
            'source': resolve(split_list(m.group('from'))),
            'source_not': bool(m.group('from_not')),
            'from_port': m.group('from_port'),
            'destination': resolve(split_list(m.group('to'))),
            'destination_not': bool(m.group('to_not')),
            'to_port': m.group('to_port'),
            'target': resolve(split_list(m.group('target'))) if m.group('target') else [],
            'target_port': m.group('target_port'),
            'text': line,
        })
    return {'redirects': redirects, 'unparsed': unparsed}


if __name__ == '__main__':
    sp = subprocess.run(['/sbin/pfctl', '-sr'], capture_output=True, text=True)
    result = parse_ruleset(sp.stdout)
    sn = subprocess.run(['/sbin/pfctl', '-sn'], capture_output=True, text=True)
    nat = parse_redirects(sn.stdout)
    result['redirects'] = nat['redirects']
    result['unparsed'] += nat['unparsed']
    print(ujson.dumps(result))
