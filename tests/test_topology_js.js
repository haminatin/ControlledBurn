/*
 * Tests for the pure parts of the overview graph: labels, model building,
 * layout, orthogonal edge routing and path geometry. Model tests use the
 * graph the controller smoke test produces (tests/fixtures/smoke_graph.json).
 *
 * Run: node tests/test_topology_js.js
 */
'use strict';

const path = require('path');
const cb = require(path.join(__dirname, '..', 'src', 'opnsense', 'www', 'js', 'ControlledBurn', 'topology.js'));
const graph = require(path.join(__dirname, 'fixtures', 'smoke_graph.json'));

let passed = 0;
let failures = 0;
function check(label, condition) {
    if (condition) {
        passed++;
    } else {
        failures++;
        console.error('FAIL: ' + label);
    }
}

// ------------------------------------------------------------ API decoding
// real response from the testlab box: OPNsense HTML-escapes API output
const escaped = { reviews: { 'f:device:bc:24:11:77:03:02&gt;firewall': 'acc484bb' } };
const dec = cb.decodeApi(escaped);
check('decodes &gt; in object keys (stored edge ids)', dec.reviews['f:device:bc:24:11:77:03:02>firewall'] === 'acc484bb');
check('decodes values in nested arrays/objects', JSON.stringify(cb.decodeApi({ a: ['block in from &lt;sshlockout&gt; to any', { d: 'LAN -&gt; NAS &amp; media' }] }))
    === JSON.stringify({ a: ['block in from <sshlockout> to any', { d: 'LAN -> NAS & media' }] }));
check('&amp; decoded last (no double decoding)', cb.decodeApi('&amp;lt;') === '&lt;');
check('non-strings untouched', JSON.stringify(cb.decodeApi({ n: 1, b: true, z: null })) === JSON.stringify({ n: 1, b: true, z: null }));
// end to end: a check saved, then read back escaped, still matches its edge
const g = require(path.join(__dirname, 'fixtures', 'example_graph.json'));
const m1 = cb.buildModel(g);
const target = m1.edges.find((e) => e.id === 'f:device:s3>firewall');
const readBack = cb.decodeApi({ [target.id.replace('>', '&gt;')]: target.fingerprint });
check('check survives the escaped round trip', cb.buildModel(g, { reviews: readBack }).edges.find((e) => e.id === target.id).checked === true);

// ------------------------------------------------------------ labels
check('single port', cb.formatAllowed({ proto: 'tcp', from: 445, to: 445 }) === 'tcp/445');
check('range', cb.formatAllowed({ proto: 'tcp', from: 1000, to: 2000 }) === 'tcp/1000-2000');
check('all ports', cb.formatAllowed({ proto: 'udp', from: 0, to: 65535 }) === 'udp/any');
check('portless protocol', cb.formatAllowed({ proto: 'icmp', from: null, to: null }) === 'icmp');
check('other class', cb.formatAllowed({ proto: 'other', from: null, to: null }) === 'other protocols');
const many = [445, 22, 80, 443, 8080].map((p) => ({ proto: 'tcp', from: p, to: p }));
check('label sorts ports and truncates after 3', cb.edgeLabel(many, false) === 'tcp/22, tcp/80, tcp/443 +2');

// real 26.7 shape: three rules carve up tcp, but the label should say tcp/any
const carved = [
    { proto: 'tcp', from: 1, to: 21, rules: ['lan'] }, { proto: 'tcp', from: 22, to: 22, rules: ['lockout'] },
    { proto: 'tcp', from: 23, to: 65535, rules: ['lan'] }, { proto: 'udp', from: 1, to: 66, rules: ['lan'] },
    { proto: 'udp', from: 67, to: 67, rules: ['dhcp'] }, { proto: 'udp', from: 68, to: 65535, rules: ['lan'] },
    { proto: 'icmp', from: null, to: null, rules: ['lan'] }, { proto: 'other', from: null, to: null, rules: ['lan'] }
];
check('touching ranges from different rules merge in the label', cb.edgeLabel(carved, false) === 'tcp/any, udp/any, icmp +1');
check('formatPorts lists a rule\'s own ranges compactly',
    cb.formatPorts([{ proto: 'tcp', from: 1, to: 21 }, { proto: 'tcp', from: 23, to: 65535 }, { proto: 'icmp', from: null, to: null }]) === 'tcp 1-21, 23-65535; icmp');
const grouped = cb.ruleRows({ rules: { lan: { descr: 'Default allow LAN' }, lockout: { descr: 'anti-lockout' }, dhcp: { descr: 'DHCP' } } }, { allowed: carved }, null);
check('card groups by rule, one row each', grouped.allowed.map((r) => r.name).join('|') === 'Default allow LAN|anti-lockout|DHCP');
check('each rule row shows only its own ports', grouped.allowed[0].ports === 'tcp 1-21, 23-65535; udp 1-66, 68-65535; icmp; other protocols'
    && grouped.allowed[1].ports === 'tcp 22');
check('uncertain-only label', cb.edgeLabel([], true) === '?');
check('uncertain suffix', cb.edgeLabel(many.slice(0, 1), true) === 'tcp/445 ?');

// ------------------------------------------------------------ model + layout
const lab = 'device:bc:24:11:77:03:01';
const nas = 'device:bc:24:11:77:03:02';
const printer = 'device:192.168.77.30';

// the columns layout (segments in a row below the firewall)
const model = cb.layout(cb.buildModel(graph), {}, 'columns');
const node = (id) => model.nodes.find((n) => n.id === id);
const edge = (from, to) => model.edges.find((e) => e.from === from && e.to === to);

check('name and IP split for display', node(lab).name === 'lab-dev01' && node(lab).ip === '192.168.77.191');
check('lab-dev01 -> nas labelled with its port', edge(lab, nas).label === 'tcp/445');
check('same-segment pair drawn once', model.edges.filter((e) => e.kind === 'unfiltered').length === 1);
check('unfiltered edges can be hidden',
    !cb.buildModel(graph, { showUnfiltered: false }).edges.some((e) => e.kind === 'unfiltered'));
check('one segment per interface with devices', model.segments.map((s) => s.id).join(',') === 'vtnet0,vtnet2');
check('same segment shares a column', node(lab).x + node(lab).w / 2 === node(printer).x + node(printer).w / 2);
check('different segments in different columns', node(lab).x !== node(nas).x);
check('firewall above devices', node('firewall').y + node('firewall').h < node(lab).y);

// the star layout (default): firewall in the middle, segments either side,
// WAN above; firewall and WAN are squares
const star = cb.layout(cb.buildModel(graph));
const sNode = (id) => star.nodes.find((n) => n.id === id);
const fwS = sNode('firewall');
check('star is the default layout', JSON.stringify(cb.layout(cb.buildModel(graph), {}, 'star').nodes.map((n) => [n.x, n.y]))
    === JSON.stringify(star.nodes.map((n) => [n.x, n.y])));
check('firewall and WAN are squares', fwS.w === fwS.h && sNode('wan').w === sNode('wan').h);
check('star: two segments sit either side of the firewall', sNode(lab).x + sNode(lab).w < fwS.x && sNode(nas).x > fwS.x + fwS.w);
check('star: WAN above the firewall', sNode('wan').y + sNode('wan').h < fwS.y);
check('star: one segment sits below the firewall', (() => {
    const one = cb.layout(cb.buildModel({ nodes: graph.nodes.filter((n) => n.if !== 'vtnet2'), edges: [], interfaces: graph.interfaces }));
    const f = one.nodes.find((n) => n.id === 'firewall');
    return one.nodes.filter((n) => n.type === 'device').every((n) => n.y > f.y + f.h);
})());
check('firewall is "This Firewall", with the hostname when given', fwS.name === 'This Firewall'
    && cb.buildModel(Object.assign({}, graph, { hostname: 'fw.example' })).nodes.find((n) => n.id === 'firewall').ip === 'fw.example');
check('wan above firewall', node('wan').y + node('wan').h < node('firewall').y);
check('DHCPv6-only entry merged into its owner by MAC (no separate node)', !node('device:fd00::5') && node(lab).ipv6.join() === 'fd00::5');

const boxes = cb.segmentBoxes(model);
const lanBox = boxes.find((b) => b.id === 'vtnet0');
check('segment box encloses its members', [lab, printer].every((id) => {
    const n = node(id);
    return n.x > lanBox.x && n.y > lanBox.y && n.x + n.w < lanBox.x + lanBox.w && n.y + n.h < lanBox.y + lanBox.h;
}));

const pinned = cb.layout(cb.buildModel(graph), { firewall: { x: 500, y: -300 } });
const fw = pinned.nodes.find((n) => n.id === 'firewall');
check('saved positions (centres) override layout', fw.x + fw.w / 2 === 500 && fw.y + fw.h / 2 === -300);

// ------------------------------------------------------------ routing
function orthogonal(pts) {
    return pts.every((p, i) => i === 0 || p.x === pts[i - 1].x || p.y === pts[i - 1].y);
}
function onBorder(p, n) {
    const inX = p.x >= n.x && p.x <= n.x + n.w;
    const inY = p.y >= n.y && p.y <= n.y + n.h;
    return (inX && (p.y === n.y || p.y === n.y + n.h)) || (inY && (p.x === n.x || p.x === n.x + n.w));
}
function crossesNode(pts, n) {
    // sample along each run; a point strictly inside the node is a crossing
    for (let i = 0; i < pts.length - 1; i++) {
        const a = pts[i];
        const b = pts[i + 1];
        const steps = Math.max(1, Math.abs(b.x - a.x) + Math.abs(b.y - a.y));
        for (let s = 0; s <= steps; s++) {
            const x = a.x + ((b.x - a.x) * s) / steps;
            const y = a.y + ((b.y - a.y) * s) / steps;
            if (x > n.x + 1 && x < n.x + n.w - 1 && y > n.y + 1 && y < n.y + n.h - 1) {
                return true;
            }
        }
    }
    return false;
}
const bends = (pts) => pts.length - 2;

const routes = cb.routeAll(model);
const allRouted = model.edges.every((e) => Array.isArray(routes[e.id]) && routes[e.id].length >= 2);
check('every edge in the fixture is routed', allRouted);
check('every route is horizontal/vertical only', model.edges.every((e) => orthogonal(routes[e.id])));
check('routes start on the source border and end on the target border', model.edges.every((e) => {
    const pts = routes[e.id];
    return onBorder(pts[0], node(e.from)) && onBorder(pts[pts.length - 1], node(e.to));
}));
check('no route passes through a node', model.edges.every((e) =>
    model.nodes.every((n) => !crossesNode(routes[e.id], n))));
check('fixture routes use at most 2 bends', model.edges.every((e) => bends(routes[e.id]) <= 2));

// three boxes in a row: the outer pair's edge must detour around the middle
function box(id, x, y) {
    return { id, x, y, w: 150, h: 48 };
}
const row = {
    nodes: [box('a', 0, 0), box('m', 250, 0), box('b', 500, 0)],
    edges: [{ id: 'ab', from: 'a', to: 'b' }],
    segments: []
};
const detour = cb.routeAll(row).ab;
check('detour is orthogonal', orthogonal(detour));
check('detour avoids the middle node', !crossesNode(detour, row.nodes[1]));
check('detour takes the minimum 2 bends, not a staircase', bends(detour) === 2);

// aligned boxes connect with a straight line
const straight = cb.routeAll({
    nodes: [box('a', 0, 0), box('b', 0, 200)],
    edges: [{ id: 'ab', from: 'a', to: 'b' }],
    segments: []
}).ab;
check('vertically aligned nodes get a straight edge', bends(straight) === 0);

// offset boxes need exactly one turn (L-shape) or two (Z-shape), never more
const offset = cb.routeAll({
    nodes: [box('a', 0, 0), box('b', 400, 300)],
    edges: [{ id: 'ab', from: 'a', to: 'b' }],
    segments: []
}).ab;
check('offset nodes route with at most 2 bends', bends(offset) <= 2 && orthogonal(offset));

// two edges between the same pair don't sit on top of each other
const pair = cb.routeAll({
    nodes: [box('a', 0, 0), box('b', 400, 300)],
    edges: [{ id: 'ab', from: 'a', to: 'b' }, { id: 'ba', from: 'b', to: 'a' }],
    segments: []
});
check('opposite-direction edges take separate paths', JSON.stringify(pair.ab) !== JSON.stringify(pair.ba.slice().reverse()));

// two parallel edges share the corridor as separate lanes, not one line
const parallel = cb.routeAll({
    nodes: [box('a', 0, 0), box('b', 0, 400)],
    edges: [{ id: 'e1', from: 'a', to: 'b' }, { id: 'e2', from: 'a', to: 'b' }],
    segments: []
});
const xs1 = new Set(parallel.e1.map((p) => p.x));
const xs2 = new Set(parallel.e2.map((p) => p.x));
const minGap = Math.min(...[...xs1].flatMap((a) => [...xs2].map((b) => Math.abs(a - b))));
check('parallel edges between the same pair run in lanes 8px apart', minGap === 8);

// collinear overlap (px) between different edges' runs: edges drawn on top
// of each other
function overlap(routes) {
    const segs = [];
    for (const [id, pts] of Object.entries(routes)) {
        for (let i = 0; pts && i < pts.length - 1; i++) {
            const a = pts[i];
            const b = pts[i + 1];
            segs.push(a.y === b.y
                ? { id, h: true, at: a.y, lo: Math.min(a.x, b.x), hi: Math.max(a.x, b.x) }
                : { id, h: false, at: a.x, lo: Math.min(a.y, b.y), hi: Math.max(a.y, b.y) });
        }
    }
    let len = 0;
    for (let i = 0; i < segs.length; i++) {
        for (let j = i + 1; j < segs.length; j++) {
            const s = segs[i];
            const t = segs[j];
            if (s.id !== t.id && s.h === t.h && s.at === t.at) {
                len += Math.max(0, Math.min(s.hi, t.hi) - Math.max(s.lo, t.lo));
            }
        }
    }
    return len;
}

// parallel runs of different edges closer than 2px: drawn on top of each
// other (lanes are never closer than 3px)
function clashes(routes) {
    const runs = [];
    for (const [id, pts] of Object.entries(routes)) {
        for (let i = 0; pts && i < pts.length - 1; i++) {
            const a = pts[i];
            const b = pts[i + 1];
            runs.push(a.y === b.y
                ? { id, h: true, at: a.y, lo: Math.min(a.x, b.x), hi: Math.max(a.x, b.x) }
                : { id, h: false, at: a.x, lo: Math.min(a.y, b.y), hi: Math.max(a.y, b.y) });
        }
    }
    let n = 0;
    for (let i = 0; i < runs.length; i++) {
        for (let j = i + 1; j < runs.length; j++) {
            const s = runs[i];
            const t = runs[j];
            if (s.id !== t.id && s.h === t.h && Math.abs(s.at - t.at) < 2 && Math.min(s.hi, t.hi) - Math.max(s.lo, t.lo) > 2) {
                n++;
            }
        }
    }
    return n;
}

// crossing counter: a plus is one crossing, a T or a shared end is none
check('countCrossings: a plus crosses once', cb.countCrossings({
    h: [{ x: 0, y: 50 }, { x: 100, y: 50 }], v: [{ x: 50, y: 0 }, { x: 50, y: 100 }]
}) === 1);
check('countCrossings: a T-junction is not a crossing', cb.countCrossings({
    h: [{ x: 0, y: 50 }, { x: 100, y: 50 }], v: [{ x: 50, y: 50 }, { x: 50, y: 100 }]
}) === 0);
check('countCrossings: one edge never crosses itself', cb.countCrossings({
    a: [{ x: 0, y: 50 }, { x: 100, y: 50 }, { x: 100, y: 0 }, { x: 50, y: 0 }, { x: 50, y: 100 }]
}) === 0);

// a round trip around an obstacle: the pair keeps the same way round
// through every bend instead of swapping sides (which crosses them)
const roundTrip = cb.routeAll({
    nodes: [box('a', 0, 0), box('m', 250, 0), box('b', 500, 0)],
    edges: [{ id: 'ab', from: 'a', to: 'b' }, { id: 'ba', from: 'b', to: 'a' }],
    segments: []
});
check('round trip around an obstacle: lanes never cross', cb.countCrossings(roundTrip) === 0);
check('round trip around an obstacle: lanes never overlap', overlap(roundTrip) === 0);

// three devices stacked in a column, all reaching one node above: they
// join one corridor in lanes ordered so none crosses another
const fanIn = {
    nodes: [box('t', 300, 0), box('d1', 0, 200), box('d2', 0, 300), box('d3', 0, 400)],
    edges: ['d1', 'd2', 'd3'].map((d) => ({ id: d, from: d, to: 't' })),
    segments: []
};
const fanRoutes = cb.routeAll(fanIn);
check('fan-in: three edges join one corridor without crossing', cb.countCrossings(fanRoutes) === 0);
check('fan-in: and without overlapping', overlap(fanRoutes) === 0);
check('fan-in: and stay orthogonal and clear of nodes', fanIn.edges.every((e) =>
    orthogonal(fanRoutes[e.id]) && fanIn.nodes.every((n) => !crossesNode(fanRoutes[e.id], n))));

// a segment past 2 x MAX_ROWS devices wraps into 3+ sub-columns; devices in
// a middle one must still be reachable (they were once boxed in by their
// neighbours, and their edges silently not drawn)
const crowd = {
    nodes: [{ id: 'firewall', type: 'firewall', label: 'Firewall', evaluable: true }],
    edges: [],
    interfaces: { vtnet0: { descr: 'LAN' } }
};
for (let i = 0; i < 20; i++) {
    crowd.nodes.push({ id: 'device:c' + i, type: 'device', label: 'c' + i + '\n10.0.0.' + (i + 10), if: 'vtnet0', aliases: [], evaluable: true });
    crowd.edges.push({ from: 'device:c' + i, to: 'firewall', kind: 'filtered', allowed: [{ proto: 'tcp', from: 443, to: 443, rules: ['r'], intended: true, default: false }], uncertain: false, uncertain_rules: [] });
}
const crowdModel = cb.layout(cb.buildModel(crowd));
const crowdRoutes = cb.routeAll(crowdModel);
check('20 devices in one segment: every edge routed, middle sub-column included',
    crowdModel.edges.length === 20 && crowdModel.edges.every((e) => Array.isArray(crowdRoutes[e.id])));

// ------------------------------------------------------------ busier example
const example = cb.layout(cb.buildModel(require(path.join(__dirname, 'fixtures', 'example_graph.json'))));
const exRoutes = cb.routeAll(example);
const exNode = (id) => example.nodes.find((n) => n.id === id);
check('example: every edge routed', example.edges.every((e) => Array.isArray(exRoutes[e.id])));
check('example: all routes orthogonal', example.edges.every((e) => orthogonal(exRoutes[e.id])));
check('example: no route passes through a node', example.edges.every((e) =>
    example.nodes.every((n) => !crossesNode(exRoutes[e.id], n))));
check('example: routes start and end on node borders', example.edges.every((e) => {
    const pts = exRoutes[e.id];
    return onBorder(pts[0], exNode(e.from)) && onBorder(pts[pts.length - 1], exNode(e.to));
}));

// regression guard on the busy fixture: lanes leave no edge drawn on top of
// another, and crossings stay at or below today's count (the router before
// lanes: 60 crossings with 802px of edges overlapping, in columns)
check('example: no two edges drawn on top of each other', overlap(exRoutes) === 0);
check('example (star): at most 33 crossings', cb.countCrossings(exRoutes) <= 33);
const exCols = cb.layout(cb.buildModel(require(path.join(__dirname, 'fixtures', 'example_graph.json'))), {}, 'columns');
const exColRoutes = cb.routeAll(exCols);
check('example (columns): at most 75 crossings, nothing on top of anything', cb.countCrossings(exColRoutes) <= 75 && clashes(exColRoutes) === 0);

// dragged layouts: edges must never end up drawn on top of each other
// (seen on the box: lanes collapsing beside a node corner, crowded
// corridors spilling into the next, runs meeting end to end)
{
    let seed = 1;
    const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
    let layouts = 0;
    let bad = 0;
    for (const f of ['example_graph.json', 'scenario_iot_mistake.json', 'scenario_ipv6_bypass.json']) {
        const graph = require(path.join(__dirname, 'fixtures', f));
        for (let trial = 0; trial < 40; trial++) {
            const m = cb.layout(cb.buildModel(graph));
            const moves = 1 + Math.floor(rnd() * 3);
            for (let d = 0; d < moves; d++) {
                const n = m.nodes[Math.floor(rnd() * m.nodes.length)];
                n.x += Math.round((rnd() - 0.5) * 500);
                n.y += Math.round((rnd() - 0.5) * 400);
            }
            const apart = m.nodes.every((a, i) => m.nodes.every((b, j) => i >= j
                || a.x >= b.x + b.w + 30 || b.x >= a.x + a.w + 30 || a.y >= b.y + b.h + 30 || b.y >= a.y + a.h + 30));
            if (!apart) {
                continue;
            }
            layouts++;
            if (clashes(cb.routeAll(m))) {
                bad++;
            }
        }
    }
    check('dragged layouts (' + layouts + '): no two edges ever drawn on top of each other', layouts > 40 && bad === 0);
}
check('example: no runs within 2px of another edge', clashes(exRoutes) === 0);

// ------------------------------------------------------------ links to hidden devices
{
    const ex = require(path.join(__dirname, 'fixtures', 'example_graph.json'));
    const segOf = {};
    ex.nodes.forEach((n) => { segOf[n.id] = n.if; });
    const hide = { hiddenSegments: ['vtnet3'], query: '' };
    const plain = cb.buildModel(ex);
    const hidden = cb.buildModel(ex, { filter: hide });
    const ghosts = hidden.nodes.filter((n) => n.type === 'ghost');
    check('no ghosts without a filter', !plain.nodes.some((n) => n.type === 'ghost'));
    check('hiding Servers: a ghost per visible segment that links there', ghosts.map((g) => g.id).sort().join() === 'ghost:vtnet0:vtnet3,ghost:vtnet2:vtnet3');
    check('ghost says which segment and how many are hidden', ghosts.every((g) => g.name === 'Servers' && g.ip === '3 hidden'));
    // every filtered edge between a visible device and a Servers device is
    // in exactly one grouped edge, in its own direction
    const crossing = ex.edges.filter((e) => e.kind !== 'unfiltered' && segOf[e.from] && segOf[e.to]
        && (segOf[e.from] === 'vtnet3') !== (segOf[e.to] === 'vtnet3'));
    const grouped = hidden.edges.filter((e) => e.ghost);
    const memberCount = grouped.reduce((t, e) => t + e.members.length, 0);
    check('every link to or from a hidden device is kept in a grouped edge', crossing.length > 0 && memberCount === crossing.length);
    check('grouped edges keep direction (out to a ghost, in from one)', grouped.some((e) => e.to.startsWith('ghost:')) && grouped.some((e) => e.from.startsWith('ghost:')));
    const concern = { filtered: 4, uncertain: 3, intended: 2, default: 1 };
    const memberColour = (m) => (m.edge.kind === 'uncertain' ? 'uncertain' : m.edge.isDefault ? 'default' : m.edge.intended ? 'intended' : 'filtered');
    check('a grouped edge shows its most concerning member\'s colour', grouped.every((e) =>
        concern[e.colour] === Math.max(...e.members.map((m) => concern[memberColour(m)]))));
    check('grouped edges can\'t be checked', grouped.every((e) => !e.checked && !e.stale));
    check('links to hidden devices can be switched off', !cb.buildModel(ex, { filter: hide, hiddenLinks: false }).nodes.some((n) => n.type === 'ghost'));
    check('same-segment links to hidden devices get no ghost', !cb.buildModel(ex, { filter: { hiddenSegments: [], query: 'desktop' } }).edges
        .some((e) => e.ghost && e.members.some((m) => segOf[m.node.id] === 'vtnet0')));
    for (const mode of ['star', 'columns']) {
        const m = cb.layout(cb.buildModel(ex, { filter: hide }), {}, mode);
        const boxes = cb.segmentBoxes(m);
        const g = m.nodes.filter((n) => n.type === 'ghost');
        check(mode + ': ghosts sit outside every segment box', g.every((n) => boxes.every((b) =>
            n.x >= b.x + b.w || n.x + n.w <= b.x || n.y >= b.y + b.h || n.y + n.h <= b.y)));
        const r = cb.routeAll(m);
        check(mode + ': every grouped edge is routed, nothing on top of anything', m.edges.every((e) => Array.isArray(r[e.id])) && clashes(r) === 0);
        check(mode + ': ghost and grouped-edge tooltips build', g.concat(m.edges.filter((e) => e.ghost)).every((it) => cb.tooltipLines(m, it).length > 1));
    }
}

// every node and edge has a tooltip, without throwing (This Firewall's once
// referred to an undefined variable and threw on hover)
check('tooltips build for every node and edge', (() => {
    const withHost = cb.layout(cb.buildModel(Object.assign({}, require(path.join(__dirname, 'fixtures', 'example_graph.json')), { hostname: 'fw.example' })));
    return withHost.nodes.concat(withHost.edges).every((item) => {
        const lines = cb.tooltipLines(withHost, item);
        return Array.isArray(lines) && lines.length > 0 && lines.every((l) => typeof l === 'string');
    }) && cb.tooltipLines(withHost, withHost.nodes.find((n) => n.id === 'firewall'))[0] === 'This Firewall (fw.example)';
})());

const labels = Object.values(cb.placeLabels(example, exRoutes));
const overlaps = (a, b) => Math.min(a.x + a.w, b.x + b.w) > Math.max(a.x, b.x) && Math.min(a.y + a.h, b.y + b.h) > Math.max(a.y, b.y);
check('example: every labelled edge gets a label', labels.length === example.edges.filter((e) => e.label).length);
check('example: no two labels overlap', labels.every((a, i) => labels.every((b, j) => i >= j || !overlaps(a, b))));
check('example: no label covers a node', labels.every((l) => example.nodes.every((n) => !overlaps(l, n))));

// dots where a label's own line meets its outline
const pill = { x: 0, y: 0, w: 60, h: 16 };
const dotsH = cb.labelDots([{ x: -20, y: 8 }, { x: 100, y: 8 }], pill);
check('line through a pill end to end: dots at both ends', dotsH.length === 2
    && dotsH.some((p) => p.x === 0 && p.y === 8) && dotsH.some((p) => p.x === 60 && p.y === 8));
const dotsV = cb.labelDots([{ x: 30, y: -40 }, { x: 30, y: 40 }], pill);
check('lane crossing a pill: dots on its top and bottom edges', dotsV.length === 2
    && dotsV.some((p) => p.x === 30 && p.y === 0) && dotsV.some((p) => p.x === 30 && p.y === 16));
const dotsTurn = cb.labelDots([{ x: -20, y: 8 }, { x: 30, y: 8 }, { x: 30, y: 60 }], pill);
check('line turning inside a pill: one dot where it enters, one where it leaves', dotsTurn.length === 2
    && dotsTurn.some((p) => p.x === 0 && p.y === 8) && dotsTurn.some((p) => p.x === 30 && p.y === 16));
check('line missing the pill: no dots', cb.labelDots([{ x: -20, y: 40 }, { x: 100, y: 40 }], pill).length === 0);

// labels prefer a horizontal run that holds them over a longer vertical one
const lShape = {
    nodes: [box('a', 0, 0), box('b', 400, 600)],
    edges: [{ id: 'ab', from: 'a', to: 'b', label: 'tcp/443' }]
};
const lRoute = { ab: [{ x: 150, y: 24 }, { x: 475, y: 24 }, { x: 475, y: 600 }] };
const lBox = cb.placeLabels(lShape, lRoute).ab;
check('label sits on the horizontal run, not the longer vertical one', lBox.y + lBox.h / 2 === 24);

// a changed check's pill is sized for its "changed \u00b7" prefix too
const staleBox = cb.placeLabels({ nodes: [], edges: [{ id: 's', label: 'tcp/443', stale: true }] },
    { s: [{ x: 0, y: 0 }, { x: 400, y: 0 }] }).s;
check('changed label pill fits its prefixed text', staleBox.w >= ('changed \u00b7 tcp/443').length * 6);

// ------------------------------------------------------------ rule details
const uuidLink = (label) => (/^[0-9a-f]{8}-[0-9a-f]{4}-/.test(label) ? '/ui/firewall/filter#search=' + label : null);
const exEdge = (from, to) => example.edges.find((e) => e.from === 'device:' + from && e.to === to);
const tvRows = cb.ruleRows(example, exEdge('i1', 'device:s2'), uuidLink);
check('card row names the allowing rule in full', tvRows.allowed.length === 1
    && tvRows.allowed[0].ports === 'tcp 8096'
    && tvRows.allowed[0].name.startsWith('Smart TV to media server (Jellyfin) - added after')
    && tvRows.allowed[0].name.length > 80);
check('uuid-labelled rule gets a link', tvRows.allowed[0].link === '/ui/firewall/filter#search=00000000-0000-4000-8000-000000000006');
check('explicitly targeting rule is marked intended', tvRows.allowed[0].intended === true);
const haFw = cb.ruleRows(example, exEdge('s3', 'firewall'), uuidLink);
check('the HA -> firewall hole is attributed to the HA-to-IoT rule',
    haFw.allowed.some((r) => r.name === 'Home Assistant to IoT devices for local control' && r.intended === false && r.automatic === false));
check('the same edge also lists the automatic DHCP rule as a default', haFw.allowed.some((r) => r.name === 'allow access to DHCP server' && r.automatic === true));
check('servers -> firewall via DHCP only is purple', cb.buildModel(require(path.join(__dirname, 'fixtures', 'example_graph.json'))).edges.find((e) => e.id === 'f:device:s1>firewall').colour === 'default');
check('non-uuid label gets no link', cb.ruleRows({ rules: {} }, { allowed: [{ proto: 'tcp', from: 1, to: 1, rules: ['abc123'] }] }, uuidLink).allowed[0].link === null);
check('rule with no description falls back to a short label',
    cb.ruleRows({ rules: {} }, { allowed: [{ proto: 'tcp', from: 1, to: 1, rules: ['0123456789abcdef'] }] }, null).allowed[0].name === 'rule 01234567');

// ------------------------------------------------------------ audit state
const exGraph = require(path.join(__dirname, 'fixtures', 'example_graph.json'));
const haFwId = 'f:device:s3>firewall';
const haIotId = 'f:device:s3>device:i2';
const plain = cb.buildModel(exGraph);
const colourOf = (m, id) => m.edges.find((e) => e.id === id).colour;
check('explicitly targeted flow is blue (intended)', colourOf(plain, haIotId) === 'intended');
check('HA -> firewall (broad rule) stays orange', colourOf(plain, haFwId) === 'filtered');
const defGraph = {
    interfaces: {}, rules: { sys: { descr: 'anti-lockout rule', automatic: true }, mine: { descr: 'mine', automatic: false } },
    nodes: [{ id: 'a', type: 'device', label: 'a\n1.1.1.1', if: null, evaluable: true }, { id: 'firewall', type: 'firewall', label: 'Firewall', evaluable: true }],
    edges: [{ from: 'a', to: 'firewall', kind: 'filtered', allowed: [{ proto: 'tcp', from: 443, to: 443, rules: ['sys'], intended: true, default: true }], uncertain: false, intended: true, default: true }]
};
check('default-only edge is purple even though intended', cb.buildModel(defGraph).edges[0].colour === 'default');
const defChecked = cb.buildModel(defGraph);
check('checked still wins over default', cb.buildModel(defGraph, { reviews: { [defChecked.edges[0].id]: defChecked.edges[0].fingerprint } }).edges[0].colour === 'checked');
check('card marks the rule as an OPNsense default', cb.ruleRows(cb.buildModel(defGraph), cb.buildModel(defGraph).edges[0], null).allowed[0].automatic === true);
check('same-segment link keeps its own colour', plain.edges.filter((e) => e.kind === 'unfiltered').every((e) => e.colour === 'unfiltered'));

const fp = plain.edges.find((e) => e.id === haFwId).fingerprint;
const reviewed = cb.buildModel(exGraph, { reviews: { [haFwId]: fp } });
check('signed-off edge is green (checked)', colourOf(reviewed, haFwId) === 'checked'
    && reviewed.edges.find((e) => e.id === haFwId).checked === true);

const staleModel = cb.buildModel(exGraph, { reviews: { [haFwId]: 'deadbeef' } });
const stale = staleModel.edges.find((e) => e.id === haFwId);
check('sign-off with an old fingerprint lapses visibly (stale style, not checked, not a silent revert)', stale.stale === true && stale.checked === false && stale.colour === 'stale');
check('stale edges are listed for the Rule check bar', cb.staleChecks(staleModel).map((x) => x.id).join() === haFwId
    && cb.staleChecks(staleModel)[0].highlight.pairs[0].join('>') === 'device:s3>firewall');
check('nothing stale when fingerprints match', cb.staleChecks(reviewed).length === 0);
const snap = cb.snapshotText(plain, plain.edges.find((e) => e.id === haFwId));
check('snapshot lists each allowing rule with its ports', snap.includes('udp 67 \u2014 allow access to DHCP server')
    && snap.includes('tcp 80-443 \u2014 Home Assistant to IoT devices for local control'));

// device filter
const nodeIds = (m) => m.nodes.map((n) => n.id);
const noLan = cb.buildModel(exGraph, { filter: { hiddenSegments: ['vtnet0'] } });
check('hiding a segment hides its devices', !nodeIds(noLan).includes('device:l1') && nodeIds(noLan).includes('device:i1'));
check('firewall and WAN always stay', nodeIds(noLan).includes('firewall') && nodeIds(noLan).includes('wan'));
check('edges to hidden devices are dropped', !noLan.edges.some((e) => e.from === 'device:l1' || e.to === 'device:l1'));
const q = cb.buildModel(exGraph, { filter: { query: 'MEDIA' } });
check('text filter matches names case-insensitively', nodeIds(q).filter((id) => id.startsWith('device:')).join() === 'device:s2');
const qip = cb.buildModel(exGraph, { filter: { query: '192.168.20.' } });
check('text filter matches IPs', nodeIds(qip).filter((id) => id.startsWith('device:')).length === 3);
check('segmentsOf lists segments with device counts', JSON.stringify(cb.segmentsOf(exGraph).map((x) => [x.id, x.count])) === JSON.stringify([['vtnet0', 3], ['vtnet2', 3], ['vtnet3', 3]]));

const e1 = { kind: 'filtered', allowed: [{ proto: 'tcp', from: 445, to: 445, rules: ['a'] }], uncertainRules: [] };
const e2 = { kind: 'filtered', allowed: [{ proto: 'tcp', from: 445, to: 446, rules: ['a'] }], uncertainRules: [] };
const e3 = { kind: 'filtered', allowed: [{ proto: 'tcp', from: 445, to: 445, rules: ['b'] }], uncertainRules: [] };
check('fingerprint changes when ports change', cb.fingerprint(e1) !== cb.fingerprint(e2));
check('fingerprint changes when the allowing rule changes', cb.fingerprint(e1) !== cb.fingerprint(e3));
check('fingerprint is stable', cb.fingerprint(e1) === cb.fingerprint(JSON.parse(JSON.stringify(e1))));

// ------------------------------------------------------------ dead-rule findings
const deadGraph = { dead_rules: [
    { label: 'r1', descr: 'lab-dev to nas', action: 'pass', automatic: false, kind: 'redundant', by: 'ed63d6ed-e427-474e-ae54-17f37c3df05d', by_descr: 'Default allow LAN to any rule', by_action: 'pass' },
    { label: '3ade84fe-da9d-4da5-99b8-e4efb27b8fd7', descr: 'printer no outbound', action: 'block', automatic: false, kind: 'contradicted', by: 'ed63d6ed-e427-474e-ae54-17f37c3df05d', by_descr: 'Default allow LAN to any rule', by_action: 'pass' },
    { label: 'nolabel-0', descr: 'block drop in log on ! vtnet0 ...', action: 'block', automatic: true, kind: 'redundant', by: '02f4bab031b57d1e30553ce08e0ec131', by_descr: 'Default deny', by_action: 'block' }
] };
const fnd = cb.deadRuleFindings(deadGraph, uuidLink);
check('findings: contradicted first', fnd.own[0].name === 'printer no outbound' && fnd.own[0].headline === 'Block never applies');
check('findings: redundant after', fnd.own[1].headline === 'Redundant');
check('findings: automatic rules kept apart', fnd.automatic.length === 1 && fnd.own.length === 2);
check('findings: counts', fnd.contradicted === 1 && fnd.redundant === 1);
check('findings: links for uuid rules, none for synthetic labels', fnd.own[0].link.endsWith('3ade84fe-da9d-4da5-99b8-e4efb27b8fd7') && fnd.automatic[0].link === null);
check('findings: empty graph has nothing', cb.deadRuleFindings({}, null).own.length === 0);
const hlGraph = { dead_rules: [
    { label: 'ssh', descr: 'block ssh to nas', action: 'block', automatic: false, kind: 'contradicted', by: 'lan', by_descr: 'LAN', by_action: 'pass',
      pairs: [['device:a', 'device:nas'], ['device:b', 'device:nas']] },
    { label: 'printer', descr: 'printer no outbound', action: 'block', automatic: false, kind: 'contradicted', by: 'lan', by_descr: 'LAN', by_action: 'pass', pairs: [] }
] };
const hl = cb.deadRuleFindings(hlGraph, null);
const ssh = hl.own.find((x) => x.label === 'ssh').highlight;
check('finding highlight: pairs and their nodes', ssh.key === 'dead:ssh' && ssh.pairs.length === 2
    && ssh.nodes.slice().sort().join(',') === 'device:a,device:b,device:nas');
check('reason for an earlier quick shadow', cb.findingReason({ byPosition: 'earlier', byName: 'LAN', byAction: 'pass' })
    === 'Shadowed by "LAN" (pass), which comes earlier and always decides first.');
check('reason for a later override (non-quick)', cb.findingReason({ byPosition: 'later', byName: 'Default deny', byAction: 'block' })
    === 'Always overridden by the later rule "Default deny" (block): without "quick", the last matching rule wins.');
check('finding that matches nothing has no highlight', hl.own.find((x) => x.label === 'printer').highlight === null);

// ------------------------------------------------------------ port names
check('numbers by default', cb.formatAllowed({ proto: 'tcp', from: 22, to: 22 }) === 'tcp/22');
check('names when asked', cb.formatAllowed({ proto: 'tcp', from: 22, to: 22 }, true) === 'tcp/ssh');
check('unknown port stays a number', cb.formatAllowed({ proto: 'tcp', from: 4242, to: 4242 }, true) === 'tcp/4242');
check('ranges stay numeric', cb.formatAllowed({ proto: 'tcp', from: 1000, to: 2000 }, true) === 'tcp/1000-2000');
cb.setPortNames(true);
check('global switch affects labels', cb.edgeLabel([{ proto: 'tcp', from: 445, to: 445 }], false) === 'tcp/microsoft-ds');
check('card ports follow it', cb.formatPorts([{ proto: 'tcp', from: 22, to: 22 }, { proto: 'tcp', from: 80, to: 80 }]) === 'tcp ssh, http');
const nmModel = cb.buildModel(exGraph);
const nmEdge = nmModel.edges.find((e) => e.id === 'f:device:s3>firewall');
check('snapshot stays numeric with names on', cb.snapshotText(nmModel, nmEdge).includes('udp 67 \u2014'));
const fpNames = nmEdge.fingerprint;
cb.setPortNames(false);
check('fingerprint is independent of the display setting', cb.buildModel(exGraph).edges.find((e) => e.id === 'f:device:s3>firewall').fingerprint === fpNames);

// ------------------------------------------------------------ empty aliases
const emptyReason = cb.emptyTableReason({ name: 'net_rfc1918', negated: true, rules: [{ label: 'x', descr: 'Allow IoT to internet', negated: true }] });
check('empty negated alias explained as matching everything', emptyReason.includes('"! net_rfc1918", which therefore matches everything')
    && emptyReason.includes('Apply'));
check('empty plain alias explained as matching nothing', cb.emptyTableReason({ name: 'bad', negated: false, rules: [{}, {}] }).includes('rules using it match nothing'));

// ------------------------------------------------------------ IPv6
const v4tcp = { proto: 'tcp', from: 1, to: 65535, rules: ['a'] };
const v6tcp = { proto: 'tcp', from: 1, to: 65535, rules: ['b'], family: 'inet6' };
const v6ssh = { proto: 'tcp', from: 22, to: 22, rules: ['b'], family: 'inet6' };
check('same allowance in both families: one label', cb.edgeLabel([v4tcp, v6tcp], false) === 'tcp/any');
check('IPv6-only allowance labelled v6', cb.edgeLabel([v6ssh], false) === 'v6: tcp/22');
check('different families shown separately', cb.edgeLabel([{ proto: 'udp', from: 53, to: 53, rules: ['a'] }, v6ssh], false) === 'udp/53 \u00b7 v6: tcp/22');
check('families never merge into one range', cb.mergeRanges([v4tcp, v6tcp]).length === 2);

// "any" only when the engine says every protocol passes (allows_all)
const everything = [v4tcp, { proto: 'udp', from: 1, to: 65535, rules: ['a'] }, { proto: 'icmp', from: null, to: null, rules: ['a'] }, { proto: 'other', from: null, to: null, rules: ['a'] }];
check('allows_all (v4): label reads any', cb.edgeLabel(everything, false, ['inet']) === 'any');
check('without allows_all the same list is spelled out', cb.edgeLabel(everything, false) === 'tcp/any, udp/any, icmp +1');
check('allows_all in both families: any (v4+v6)', cb.edgeLabel(everything.concat([v6tcp]), false, ['inet', 'inet6']) === 'any (v4+v6)');
check('allows_all in v4 only: v6 still spelled out', cb.edgeLabel(everything.concat([v6ssh]), false, ['inet']) === 'any \u00b7 v6: tcp/22');
check('allows_all v6-only edge', cb.edgeLabel([v6tcp], false, ['inet6']) === 'v6: any');
check('any keeps the uncertain marker', cb.edgeLabel(everything, true, ['inet']) === 'any ?');
check('buildModel passes allows_all through to the label', cb.buildModel({
    nodes: [{ id: 'a', type: 'device', label: 'a', evaluable: true }, { id: 'firewall', type: 'firewall', label: 'F', evaluable: true }],
    edges: [{ from: 'a', to: 'firewall', kind: 'filtered', allowed: everything, allows_all: ['inet'], uncertain: false, uncertain_rules: [] }]
}).edges[0].label === 'any');
check('v6 exceeding v4 is detected (bypass)', cb.v6Exceeds([{ proto: 'udp', from: 53, to: 53 }, v6ssh]) === true);
check('v6 inside v4 is not a bypass', cb.v6Exceeds([v4tcp, v6ssh]) === false);
check('no v6 at all: no bypass', cb.v6Exceeds([v4tcp]) === false);
check('card ports mark IPv6', cb.formatPorts([v6ssh, { proto: 'udp', from: 53, to: 53 }]) === 'v6 tcp 22; udp 53');
const fpEdge = (allowed) => cb.fingerprint({ kind: 'filtered', allowed, uncertainRules: [] });
check('IPv4 fingerprints unchanged by IPv6 support', fpEdge([{ proto: 'tcp', from: 22, to: 22, rules: ['a'] }]) === fpEdge([{ proto: 'tcp', from: 22, to: 22, rules: ['a'] }]));
check('v4 and v6 with the same ports fingerprint differently', fpEdge([{ proto: 'tcp', from: 22, to: 22, rules: ['a'] }]) !== fpEdge([{ proto: 'tcp', from: 22, to: 22, rules: ['a'], family: 'inet6' }]));

// ------------------------------------------------------------ port forwards
check('forward mapping text', cb.forwardMapping({ proto: 'tcp', ext: [2222, 2222], int: [22, 22] }) === 'WAN tcp 2222 \u2192 22');
check('forward range mapping text', cb.forwardMapping({ proto: 'tcp', ext: [8000, 8010], int: [9000, 9010] }) === 'WAN tcp 8000-8010 \u2192 9000-9010');
const fwdModel = cb.buildModel({ interfaces: {}, rules: {}, nodes: [{ id: 'wan', type: 'wan', label: 'WAN', evaluable: true }, { id: 'device:a', type: 'device', label: 'a\n10.0.0.1', evaluable: true }],
    edges: [{ from: 'wan', to: 'device:a', kind: 'filtered', allowed: [{ proto: 'tcp', from: 22, to: 22, rules: ['fwd-1'] }], forwards: [{ label: 'fwd-1', proto: 'tcp', ext: [2222, 2222], int: [22, 22], pass: true, allowed: true }] }] });
check('WAN -> device edge keeps its forwards', fwdModel.edges[0].forwards.length === 1);
check('WAN node says internet', fwdModel.nodes[0].ip === 'internet');

// ------------------------------------------------------------ pair drill-down (real NAT capture)
const pairs = require(path.join(__dirname, 'fixtures', 'pairs_nat.json'));
const LABN = 'device:bc:24:11:00:ef:67';
const NASN = 'device:bc:24:11:77:03:02';
const inLab = cb.breakdownSections(pairs['wan>' + LABN], { ruleLink: uuidLink });
check('breakdown internet -> lab-dev01: one IPv4 section', inLab.length === 1 && inLab[0].title.startsWith('IPv4 \u00b7 192.168.77.191'));
check('...one row: tcp 22 allowed by the Pass forward, decided by the port forward', inLab[0].rows.length === 1
    && inLab[0].rows[0].proto === 'tcp' && inLab[0].rows[0].ports === '22' && inLab[0].rows[0].verdict === 'pass'
    && inLab[0].rows[0].where === 'port forward' && inLab[0].rows[0].rule.name.startsWith('Port forward (Firewall Rule: Pass)'));
const labFw = cb.breakdownSections(pairs[LABN + '>firewall'], { ruleLink: uuidLink });
check('lab-dev01 -> firewall: one section per firewall address, both families (3 IPv4 + 3 IPv6 incl. its own segment\'s link-local)',
    labFw.length === 6 && labFw.filter((sec) => sec.family === 'inet6').length === 3);
const lanRows = labFw.find((sec) => sec.title.includes('192.168.77.1')).rows;
check('...rows ordered tcp, udp, icmp, then the rest; ports ascending', lanRows[0].proto === 'tcp' && lanRows[0].ports === '0'
    && lanRows.findIndex((r) => r.proto === 'udp') > lanRows.findIndex((r) => r.proto === 'tcp'));
check('...port 0 blocked, decided in on LAN', lanRows[0].verdict === 'block' && lanRows[0].where === 'in on LAN');
check('...anti-lockout row marked as an OPNsense default', lanRows.some((r) => r.ports === '22' && r.rule && r.rule.automatic));
check('same segment pair is reported as unfiltered', pairs[LABN + '>' + NASN].kind === 'unfiltered');
const wanSec = labFw.find((sec) => sec.title.includes('10.100.59.2'));
check('firewall address sections say which interface they belong to', wanSec.title.endsWith('(WAN address)')
    && labFw.find((sec) => sec.title.includes('192.168.77.1')).title.endsWith('(LAN address)'));
check('reaching the WAN address from inside gets a hint', /WAN address, reached from inside/.test(wanSec.note || ''));
check('...the LAN address does not', !labFw.find((sec) => sec.title.includes('192.168.77.1')).note);
check('firewall as source is refused with a reason', pairs['firewall>' + LABN].status === 'failed');
cb.setPortNames(true);
check('breakdown ports follow the port-names setting', cb.breakdownSections(pairs['wan>' + LABN])[0].rows[0].ports === 'ssh');
cb.setPortNames(false);

// ------------------------------------------------------------ WAN
const wanGraph = {
    interfaces: { vtnet0: { key: 'lan', descr: 'LAN' } },
    rules: { lan: { descr: 'Default allow LAN to any rule' }, bad: { descr: 'Block bad network' } },
    nodes: [{ id: 'device:a', type: 'device', label: 'a\n192.168.77.5', if: 'vtnet0', evaluable: true },
        { id: 'wan', type: 'wan', label: 'WAN', evaluable: true }],
    edges: [{ from: 'device:a', to: 'wan', kind: 'filtered', allowed: [{ proto: 'tcp', from: 1, to: 65535, rules: ['lan'] }],
        regions: [{ cidr: '198.18.0.0/15', allowed: [] }], uncertain: false, intended: false }]
};
const wm = cb.buildModel(wanGraph);
check('WAN node says it is evaluated', wm.nodes.find((n) => n.id === 'wan').ip === 'internet');
check('WAN edge carries its exceptions', wm.edges[0].regions.length === 1);
check('snapshot records WAN exceptions', cb.snapshotText(wm, wm.edges[0]).includes('198.18.0.0/15: blocked'));
const noRegions = JSON.parse(JSON.stringify(wanGraph));
delete noRegions.edges[0].regions;
const withEmpty = JSON.parse(JSON.stringify(wanGraph));
withEmpty.edges[0].regions = [];
check('edges without exceptions keep their old fingerprint (existing checks stay valid)',
    cb.buildModel(noRegions).edges[0].fingerprint === cb.buildModel(withEmpty).edges[0].fingerprint);
check('a change in exceptions changes the fingerprint (check lapses)', cb.buildModel(withEmpty).edges[0].fingerprint !== wm.edges[0].fingerprint);
check('pending WAN (no WAN interface) says so', cb.buildModel({ interfaces: {}, nodes: [{ id: 'wan', type: 'wan', label: 'WAN', evaluable: false }], edges: [] }).nodes[0].ip === 'not evaluated yet');

// ------------------------------------------------------------ geometry
const d = cb.roundedPath([{ x: 0, y: 0 }, { x: 100, y: 0 }, { x: 100, y: 100 }]);
check('one rounded bend per turn', (d.match(/Q/g) || []).length === 1);
check('bend radius capped by short runs', cb.roundedPath([{ x: 0, y: 0 }, { x: 10, y: 0 }, { x: 10, y: 100 }]).includes('L5,0'));
check('straight path has no curves', !/Q/.test(cb.roundedPath([{ x: 0, y: 0 }, { x: 0, y: 50 }])));
const sq = cb.squirclePath(0, 0, 150, 48, 14);
check('squircle is closed with 4 curved corners', /Z$/.test(sq) && (sq.match(/C/g) || []).length === 4);
check('label sits on the longest run', JSON.stringify(cb.labelPoint([{ x: 0, y: 0 }, { x: 10, y: 0 }, { x: 10, y: 200 }])) === JSON.stringify({ x: 10, y: 100 }));

console.log(`${passed} passed, ${failures} failed`);
process.exit(failures ? 1 : 0);
