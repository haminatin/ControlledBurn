/*
 * ControlledBurn overview graph (layer 1, docs/PLAN.md section 3.3).
 *
 * Self-contained SVG renderer: squircle nodes with the name and IP inside,
 * one column per network segment, and orthogonal edges (horizontal and
 * vertical runs only) with soft rounded bends, routed around nodes with as
 * few turns as possible. Edges are dotted lines whose dots travel from
 * source to destination - the direction the rule allows traffic to start.
 *
 * Deliberately independent of OPNsense: the volt view fetches
 * /api/controlledburn/topology/graph and hands the result to
 * ControlledBurn.render(). Layout, routing and path geometry are pure
 * functions exported for tests (tests/test_topology_js.js).
 *
 * Security note: hostnames come from DHCP clients, i.e. from untrusted
 * devices. Every piece of text reaches the DOM through textContent, never
 * as HTML.
 */
(function (root) {
    'use strict';

    var SVG_NS = 'http://www.w3.org/2000/svg';

    var NODE_H = 48;
    var NODE_MIN_W = 150;
    var NODE_MAX_W = 230;
    var ROW_GAP = 30;
    var COL_GAP = 130;
    var MAX_ROWS = 8;
    var HUB_SIZE = 128;        // the firewall and WAN nodes are squares
    var STAR_GAP = 120;        // star layout: firewall to the boxes around it

    // 24x24 line icons, drawn with the node's text colour
    var ICONS = {
        firewall: ['M12 2.6l7.4 2.9v5.7c0 4.5-3.1 8.5-7.4 10.2-4.3-1.7-7.4-5.7-7.4-10.2V5.5z',
            'M8.6 12.1l2.4 2.4 4.5-4.7'],
        wan: ['M12 2.5a9.5 9.5 0 1 0 0 19a9.5 9.5 0 1 0 0-19z',
            'M12 2.5c-2.6 2.6-4 6-4 9.5s1.4 6.9 4 9.5c2.6-2.6 4-6 4-9.5s-1.4-6.9-4-9.5z',
            'M2.5 12h19', 'M4.2 7h15.6', 'M4.2 17h15.6']
    };
    var SUBCOL_GAP = 64;     // between a segment's sub-columns: a corridor,
                             // or devices in a middle one are boxed in
    var CONTAINER_PAD = 22;
    var CONTAINER_HEAD = 26;

    var GRID = 8;            // routing grid cell size (px)
    var CLEARANCE = 12;      // keep edges this far from nodes
    // routing costs, in half-cells: a cell costs STEP_COST, or SHARE_COST
    // along a line another edge already runs on, so edges gather into
    // shared corridors and are then spread into lanes (assignLanes)
    var STEP_COST = 2;
    var SHARE_COST = 1;
    var BEND_COST = 28;      // high, so routes prefer few turns
    var CROSS_COST = 24;     // per edge passed straight through
    var NEAR_COST = 2;       // running alongside another corridor, not in it
    var NEAR_CELLS = 2;      // ...within this many cells
    var CENTRE_CELLS = 8;    // cells nearer a node than this cost extra,
    var CENTRE_COST = 0.5;   // ...this much per cell short: routes keep to
                             // the middle of gaps, so they share its line
    var CORRIDOR_LINES = 6;  // runs this many grid lines apart share lanes
    var LANE_GAP = 8;        // px between lanes in a corridor (less if tight);
                             // about an arrowhead wide (markerWidth 9)
    var MIN_LANE_GAP = 3;    // ...but never less: lanes must not merge
    var LABEL_H = 16;
    var LABEL_GAP = 4;       // minimum clear space around a label
    var LABEL_STEP = 8;      // label candidates every this many px along a run
    var BEND_RADIUS = 14;
    var MAX_EDGE_LABEL_ITEMS = 3;
    var TIP_RULE_CHARS = 44;  // rule names in hover tooltips; the card shows more

    // ------------------------------------------------------------------
    // API responses
    // ------------------------------------------------------------------

    /**
     * Undo the HTML escaping OPNsense applies to API responses.
     *
     * Core's Response::send() runs every JSON body sent to a browser through
     * htmlspecialchars(..., ENT_NOQUOTES), so '&', '<' and '>' inside any
     * string - and any object key - arrive as &amp; &lt; &gt;. Core's own
     * pages insert those strings as HTML, so it works there; this page uses
     * textContent and compares ids, so it must decode first (e.g. stored
     * edge ids contain '>'). Only those three entities are produced
     * (ENT_NOQUOTES); &amp; is decoded last so "&amp;lt;" stays "&lt;".
     */
    function decodeApi(value) {
        if (typeof value === 'string') {
            return value.indexOf('&') < 0 ? value
                : value.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
        }
        if (Array.isArray(value)) {
            return value.map(decodeApi);
        }
        if (value !== null && typeof value === 'object') {
            var out = {};
            Object.keys(value).forEach(function (k) {
                out[decodeApi(k)] = decodeApi(value[k]);
            });
            return out;
        }
        return value;
    }

    // ------------------------------------------------------------------
    // Labels
    // ------------------------------------------------------------------

    /**
     * Well-known service names for display (the browser has no services
     * database). Names follow the IANA / FreeBSD /etc/services spelling, as
     * pf prints them; a few very common unofficial ones are included.
     */
    var PORT_NAMES = {
        20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain', 67: 'bootps',
        68: 'bootpc', 69: 'tftp', 80: 'http', 88: 'kerberos', 110: 'pop3', 123: 'ntp', 137: 'netbios-ns',
        138: 'netbios-dgm', 139: 'netbios-ssn', 143: 'imap', 161: 'snmp', 162: 'snmptrap', 179: 'bgp',
        389: 'ldap', 443: 'https', 445: 'microsoft-ds', 465: 'submissions', 500: 'isakmp', 514: 'syslog',
        515: 'printer', 546: 'dhcpv6-client', 547: 'dhcpv6-server', 587: 'submission', 631: 'ipp',
        636: 'ldaps', 853: 'domain-s', 873: 'rsync', 993: 'imaps', 995: 'pop3s', 1194: 'openvpn',
        1433: 'ms-sql-s', 1883: 'mqtt', 1900: 'ssdp', 3306: 'mysql', 3389: 'ms-wbt-server', 4500: 'ipsec-nat-t',
        5060: 'sip', 5353: 'mdns', 5432: 'postgresql', 5900: 'vnc', 6379: 'redis', 8080: 'http-alt',
        8443: 'https-alt', 51820: 'wireguard'
    };

    // display preference: port numbers (default) or service names
    var usePortNames = false;
    function setPortNames(on) {
        usePortNames = !!on;
    }

    function portText(port, names) {
        return names && PORT_NAMES[port] ? PORT_NAMES[port] : String(port);
    }

    /**
     * "tcp/445", "tcp/1000-2000", "tcp/any", "icmp", "other protocols".
     * Port 0 isn't usable, so 1-65535 counts as "any". Single ports show
     * their service name ("tcp/ssh") when port names are switched on;
     * pass names=false to force numbers (fingerprints, snapshots).
     */
    function formatAllowed(a, names) {
        names = names === undefined ? usePortNames : names;
        if (a.from === null || a.from === undefined) {
            return a.proto === 'other' ? 'other protocols' : a.proto;
        }
        if (a.from <= 1 && a.to === 65535) {
            return a.proto + '/any';
        }
        return a.proto + '/' + (a.from === a.to ? portText(a.from, names) : a.from + '-' + a.to);
    }

    /**
     * Merge allowed ranges that touch, per protocol, ignoring which rule
     * allows them - so tcp 1-21 + 22 + 23-65535 (three rules) reads as one
     * "tcp/any". Order: protocols as first seen, ranges ascending.
     */
    function mergeRanges(allowed) {
        var byProto = {};
        var order = [];
        // grouped per family and protocol: IPv4 and IPv6 never merge, so an
        // IPv6 path that the IPv4 rules don't allow can't hide
        allowed.forEach(function (a) {
            var k = (a.family === 'inet6' ? '6:' : '4:') + a.proto;
            if (!byProto[k]) {
                byProto[k] = [];
                order.push(k);
            }
            byProto[k].push(a);
        });
        var out = [];
        order.forEach(function (k) {
            var list = byProto[k].slice().sort(function (x, y) { return (x.from || 0) - (y.from || 0); });
            var start = out.length;
            list.forEach(function (a) {
                var last = out.length > start ? out[out.length - 1] : null;
                var entry = { proto: a.proto, from: a.from, to: a.to };
                if (a.family === 'inet6') {
                    entry.family = 'inet6';
                }
                if (last && a.from !== null && last.to !== null && a.from <= last.to + 1) {
                    last.to = Math.max(last.to, a.to);
                } else if (!(last && a.from === null)) {
                    out.push(entry);
                }
            });
        });
        return out;
    }

    /** "tcp 1-21, 23-79, 81-442" for one protocol's ranges */
    function formatPorts(ranges, names) {
        var byProto = {};
        var order = [];
        mergeRanges(ranges).forEach(function (a) {
            var label = formatAllowed(a, names);
            var slash = label.indexOf('/');
            var proto = (a.family === 'inet6' ? 'v6 ' : '') + (slash < 0 ? label : label.slice(0, slash));
            if (!byProto[proto]) {
                byProto[proto] = [];
                order.push(proto);
            }
            if (slash >= 0) {
                byProto[proto].push(label.slice(slash + 1));
            }
        });
        return order.map(function (proto) {
            return byProto[proto].length ? proto + ' ' + byProto[proto].join(', ') : proto;
        }).join('; ');
    }

    /** "a, b, c +2" for a list of allowed entries (one family) */
    function shortList(entries) {
        var items = mergeRanges(entries).map(function (a) { return formatAllowed(a); });
        var label = items.slice(0, MAX_EDGE_LABEL_ITEMS).join(', ');
        if (items.length > MAX_EDGE_LABEL_ITEMS) {
            label += ' +' + (items.length - MAX_EDGE_LABEL_ITEMS);
        }
        return label;
    }

    /** split allowed entries by family */
    function byFamily(allowed) {
        return {
            v4: allowed.filter(function (a) { return a.family !== 'inet6'; }),
            v6: allowed.filter(function (a) { return a.family === 'inet6'; })
        };
    }

    /**
     * True when IPv6 allows something IPv4 doesn't on this edge - the
     * classic "IPv6 bypasses the IPv4 policy" hole.
     */
    function v6Exceeds(allowed) {
        var f = byFamily(allowed);
        if (!f.v6.length) {
            return false;
        }
        if (!f.v4.length) {
            return true;
        }
        // IPv6 exceeds unless every IPv6 range sits inside an IPv4 range
        var v4 = mergeRanges(f.v4);
        return !mergeRanges(f.v6).every(function (a) {
            return v4.some(function (b) {
                return b.proto === a.proto && (a.from === null ? b.from === null
                    : (b.from !== null && b.from <= a.from && a.to <= b.to));
            });
        });
    }

    /**
     * Edge pill text. allowsAll: families ('inet', 'inet6') in which the
     * engine found every protocol allowed on every port (the graph API's
     * allows_all); those read "any" rather than a protocol list.
     */
    function edgeLabel(allowed, uncertain, allowsAll) {
        var f = byFamily(allowed);
        allowsAll = allowsAll || [];
        var v4 = allowsAll.indexOf('inet') >= 0 ? 'any' : shortList(f.v4);
        var v6 = allowsAll.indexOf('inet6') >= 0 ? 'any' : shortList(f.v6);
        var label;
        if (!f.v6.length) {
            label = v4;
        } else if (!f.v4.length) {
            label = 'v6: ' + v6;
        } else if (v4 === 'any' && v6 === 'any') {
            label = 'any (v4+v6)';
        } else if (v4 === v6) {
            label = v4; // same in both families
        } else {
            label = v4 + ' \u00b7 v6: ' + v6;
        }
        if (uncertain) {
            label = label ? label + ' ?' : '?';
        }
        return label;
    }

    function truncate(text, max) {
        return text.length > max ? text.slice(0, max - 1) + '…' : text;
    }

    // ------------------------------------------------------------------
    // Model: graph API response -> nodes/edges with display info
    // ------------------------------------------------------------------

    /**
     * opts.showUnfiltered: include same-segment edges (default true)
     */
    function buildModel(graph, opts) {
        opts = opts || {};
        var showUnfiltered = opts.showUnfiltered !== false;
        var filter = opts.filter || {};
        var reviews = opts.reviews || {};
        var interfaces = graph.interfaces || {};
        var ifOrder = Object.keys(interfaces);

        var nodes = graph.nodes.map(function (n) {
            var parts = n.label.split('\n');
            var node = {
                id: n.id,
                type: n.type,
                name: parts[0],
                ip: parts[1] || '',
                if: n.if || null,
                aliases: n.aliases || [],
                ipv6: n.ipv6 || [],
                ipv6Assumed: !!n.ipv6_assumed,
                evaluable: !!n.evaluable,
                pending: !!n.pending
            };
            if (n.type === 'firewall') {
                // OPNsense's own name for the box's addresses in rules
                // ("This Firewall"); the hostname says which box
                node.name = 'This Firewall';
                node.ip = graph.hostname || '';
            } else if (n.type === 'wan') {
                node.name = 'WAN';
                node.ip = n.evaluable ? 'internet' : 'not evaluated yet';
            }
            node.segment = n.type === 'device' ? (n.if && interfaces[n.if] ? n.if : '__unplaced') : null;
            var chars = Math.max(node.name.length * 7.4, node.ip.length * 7.2);
            node.w = Math.round(Math.min(NODE_MAX_W, Math.max(NODE_MIN_W, chars + 32)));
            node.h = NODE_H;
            node.nameShown = truncate(node.name, Math.floor((NODE_MAX_W - 32) / 7.4));
            if (n.type === 'firewall' || n.type === 'wan') {
                node.w = HUB_SIZE;
                node.h = HUB_SIZE;
                node.nameShown = truncate(node.name, Math.floor((HUB_SIZE - 12) / 7.4));
                node.ip = truncate(node.ip, Math.floor((HUB_SIZE - 12) / 6.6));
            }
            return node;
        }).filter(function (node) {
            return nodeVisible(node, filter);
        });
        var visible = {};
        nodes.forEach(function (n) { visible[n.id] = true; });

        var edges = [];
        var seenUnfiltered = {};
        graph.edges.forEach(function (e) {
            if (!visible[e.from] || !visible[e.to]) {
                return; // an end was filtered out
            }
            if (e.kind === 'unfiltered') {
                if (!showUnfiltered) {
                    return;
                }
                // reported in both directions; same-segment traffic is
                // symmetric, so draw one undirected line per pair
                var key = [e.from, e.to].sort().join('|');
                if (seenUnfiltered[key]) {
                    return;
                }
                seenUnfiltered[key] = true;
                edges.push(withReview({ id: 'u:' + key, from: e.from, to: e.to, kind: 'unfiltered', label: '' }, reviews));
                return;
            }
            var uncertainOnly = !!e.uncertain && !e.allowed.length;
            edges.push(withReview({
                id: 'f:' + e.from + '>' + e.to,
                from: e.from,
                to: e.to,
                kind: uncertainOnly ? 'uncertain' : 'filtered',
                allowed: e.allowed,
                uncertain: !!e.uncertain,
                uncertainRules: e.uncertain_rules || [],
                conditional: !!e.conditional,
                intended: !!e.intended,
                isDefault: !!e['default'],
                regions: e.regions || [],
                forwards: e.forwards || [],
                label: edgeLabel(e.allowed, e.uncertain, e.allows_all)
            }, reviews));
        });

        var segments = ifOrder.filter(function (physical) {
            return nodes.some(function (n) { return n.segment === physical; });
        }).map(function (physical) {
            return { id: physical, label: interfaces[physical].descr + ' (' + physical + ')' };
        });
        if (nodes.some(function (n) { return n.segment === '__unplaced'; })) {
            segments.push({ id: '__unplaced', label: 'Unknown interface' });
        }

        return { nodes: nodes, edges: edges, segments: segments, rules: graph.rules || {} };
    }

    /**
     * Fingerprint of what an edge allows: kind, allowed ranges and the
     * rules behind them, and uncertain rules. Stored with an audit
     * sign-off; if the rules later change what the edge allows, the
     * fingerprint changes and the sign-off lapses. (djb2, hex.)
     */
    function fingerprint(edge) {
        var parts = [
            edge.kind,
            (edge.allowed || []).map(function (a) {
                var entry = [a.proto, a.from, a.to, (a.rules || []).slice().sort()];
                // IPv6 only, so IPv4 fingerprints (saved checks) are unchanged
                if (a.family === 'inet6') {
                    entry.push('inet6');
                }
                return entry;
            }),
            (edge.uncertainRules || []).slice().sort()
        ];
        // WAN exceptions only when present, so edges without any keep the
        // fingerprints their existing checks were saved with
        if (edge.regions && edge.regions.length) {
            parts.push(edge.regions.map(function (r) {
                return [r.cidr, r.allowed.map(function (a) { return [a.proto, a.from, a.to, (a.rules || []).slice().sort()]; })];
            }));
        }
        var basis = JSON.stringify(parts);
        var h = 5381;
        for (var i = 0; i < basis.length; i++) {
            h = ((h << 5) + h + basis.charCodeAt(i)) >>> 0;
        }
        return h.toString(16);
    }

    /**
     * Attach audit state to a model edge:
     *   checked - signed off and still allowing exactly what it did then
     *   stale   - signed off, but what it allows has changed since
     * and the colour it's drawn in: checked (green) beats changed-since-
     * checked (green line, amber "changed" label) beats uncertain (amber)
     * beats OPNsense-default-only (purple) beats intended (blue) beats the
     * plain kind.
     */
    function withReview(edge, reviews) {
        edge.fingerprint = fingerprint(edge);
        var saved = reviews[edge.id];
        edge.checked = saved !== undefined && saved === edge.fingerprint;
        edge.stale = saved !== undefined && saved !== edge.fingerprint;
        edge.colour = edge.checked ? 'checked'
            : edge.stale ? 'stale'
            : edge.kind === 'uncertain' ? 'uncertain'
            : edge.isDefault ? 'default'
            : edge.intended ? 'intended'
            : edge.kind;
        return edge;
    }

    /**
     * Device filter (for busy networks). filter.hiddenSegments: physical
     * interface names whose devices are hidden ('__unplaced' for devices on
     * no known interface); filter.query: case-insensitive text matched
     * against name, IP and aliases. The firewall and WAN are always shown.
     */
    function nodeVisible(node, filter) {
        if (node.type !== 'device') {
            return true;
        }
        if ((filter.hiddenSegments || []).indexOf(node.segment) >= 0) {
            return false;
        }
        var q = (filter.query || '').trim().toLowerCase();
        if (!q) {
            return true;
        }
        return [node.name, node.ip].concat(node.aliases || [], node.ipv6 || []).some(function (v) {
            return String(v).toLowerCase().indexOf(q) >= 0;
        });
    }

    /**
     * Segments that have devices, for building filter controls:
     * [{id, label, count}], in interface order, plus '__unplaced'.
     */
    function segmentsOf(graph) {
        var interfaces = graph.interfaces || {};
        var counts = {};
        (graph.nodes || []).forEach(function (n) {
            if (n.type === 'device') {
                var seg = n.if && interfaces[n.if] ? n.if : '__unplaced';
                counts[seg] = (counts[seg] || 0) + 1;
            }
        });
        var out = Object.keys(interfaces).filter(function (k) { return counts[k]; }).map(function (k) {
            return { id: k, label: interfaces[k].descr, count: counts[k] };
        });
        if (counts.__unplaced) {
            out.push({ id: '__unplaced', label: 'Unknown interface', count: counts.__unplaced });
        }
        return out;
    }

    /**
     * Plain-text summary of what an edge allows and why, stored with a
     * sign-off so a later "changed since checked" card can show what it was.
     */
    function snapshotText(model, edge) {
        if (edge.kind === 'unfiltered') {
            return 'Same network segment (unfiltered).';
        }
        // numbers, not names: snapshots must not depend on the display setting
        var rows = ruleRows(model, edge, null, false);
        var lines = rows.allowed.map(function (r) {
            return r.ports + ' \u2014 ' + r.name;
        });
        if (!lines.length) {
            lines.push('Nothing definitely allowed.');
        }
        rows.uncertain.forEach(function (r) {
            lines.push('Uncertain because of: ' + r.name);
        });
        (edge.regions || []).forEach(function (rg) {
            lines.push(rg.cidr + ': ' + (rg.allowed.length ? formatPorts(rg.allowed, false) : 'blocked'));
        });
        return lines.join('\n');
    }

    /**
     * Checked edges whose allowed set has changed since they were checked
     * (fingerprint mismatch), as highlight-ready items for the Rule check
     * bar: [{id, name: "A -> B", highlight}].
     */
    function staleChecks(model) {
        var byId = {};
        model.nodes.forEach(function (n) { byId[n.id] = n; });
        return model.edges.filter(function (e) { return e.stale; }).map(function (e) {
            return {
                id: e.id,
                name: (byId[e.from] ? byId[e.from].name : e.from) + ' \u2192 ' + (byId[e.to] ? byId[e.to].name : e.to),
                highlight: { key: 'stale:' + e.id, nodes: [e.from, e.to], pairs: [[e.from, e.to]] }
            };
        });
    }

    /** a rule's description, or a short form of its label if it has none */
    function ruleName(model, label) {
        var info = (model.rules || {})[label];
        return info && info.descr ? info.descr : 'rule ' + label.slice(0, 8);
    }

    /**
     * What an edge's detail card lists: one row per rule that allows
     * something, with the ports it allows (merged, e.g. "tcp 1-21, 23-79")
     * and whether it targets the destination explicitly; plus the rules
     * that made the verdict uncertain. ruleLink(label) returns a URL to open
     * the rule, or null when it can't be linked (e.g. auto-generated rules).
     */
    function ruleRows(model, edge, ruleLink, names) {
        var describe = function (label) {
            return { label: label, name: ruleName(model, label), link: ruleLink ? ruleLink(label) : null };
        };
        var byRule = {};
        var order = [];
        (edge.allowed || []).forEach(function (a) {
            (a.rules || []).forEach(function (label) {
                if (!byRule[label]) {
                    byRule[label] = describe(label);
                    byRule[label].ranges = [];
                    byRule[label].intended = true;
                    byRule[label].automatic = !!((model.rules || {})[label] || {}).automatic;
                    order.push(label);
                }
                byRule[label].ranges.push(a);
                byRule[label].intended = byRule[label].intended && !!a.intended;
            });
        });
        return {
            allowed: order.map(function (label) {
                var r = byRule[label];
                r.ports = formatPorts(r.ranges, names);
                delete r.ranges;
                return r;
            }),
            uncertain: (edge.uncertainRules || []).map(describe)
        };
    }

    // ------------------------------------------------------------------
    // Layout
    // ------------------------------------------------------------------

    /**
     * Assign x/y (top-left) to every node: WAN, then firewall, centred on
     * top; below them one column per segment, devices stacked (wrapping
     * into sub-columns past MAX_ROWS). Saved positions override.
     *
     * @param model from buildModel()
     * @param positions {nodeId: {x, y}} centre positions, e.g. a saved layout
     * @param mode 'star' (default: the firewall in the middle, segments
     *        around it) or 'columns' (segments in a row below it)
     */
    function layout(model, positions, mode) {
        positions = positions || {};
        var byId = {};
        model.nodes.forEach(function (n) { byId[n.id] = n; });

        if (mode !== 'columns') {
            starPlace(model, byId);
            model.nodes.forEach(function (n) {
                if (positions[n.id]) {
                    n.x = positions[n.id].x - n.w / 2;
                    n.y = positions[n.id].y - n.h / 2;
                }
            });
            return model;
        }

        var x = 0;
        var wanH = byId.wan ? byId.wan.h : NODE_H;
        var fwH = byId.firewall ? byId.firewall.h : NODE_H;
        var fwY = wanH + 62;
        var top = fwY + fwH + 72;
        model.segments.forEach(function (seg) {
            var members = model.nodes.filter(function (n) { return n.segment === seg.id; });
            var colW = Math.max.apply(null, members.map(function (n) { return n.w; }));
            var subCols = Math.ceil(members.length / MAX_ROWS);
            members.forEach(function (n, i) {
                var sub = Math.floor(i / MAX_ROWS);
                var row = i % MAX_ROWS;
                n.x = x + CONTAINER_PAD + sub * (colW + SUBCOL_GAP) + (colW - n.w) / 2;
                n.y = top + CONTAINER_HEAD + CONTAINER_PAD + row * (NODE_H + ROW_GAP);
            });
            x += subCols * colW + (subCols - 1) * SUBCOL_GAP + 2 * CONTAINER_PAD + COL_GAP;
        });
        var width = Math.max(x - COL_GAP, 400);

        if (byId.firewall) {
            byId.firewall.x = (width - byId.firewall.w) / 2;
            byId.firewall.y = fwY;
        }
        if (byId.wan) {
            byId.wan.x = (width - byId.wan.w) / 2;
            byId.wan.y = 0;
        }

        model.nodes.forEach(function (n) {
            if (positions[n.id]) {
                n.x = positions[n.id].x - n.w / 2;
                n.y = positions[n.id].y - n.h / 2;
            }
        });
        return model;
    }

    /**
     * Star layout: the firewall in the middle, each segment's box on one
     * side of it, and WAN in the middle of the top side, like another
     * segment. A single segment goes below (as in the columns layout);
     * with more, they go left, right, below, above, then round again -
     * of the orders tried, the fewest crossings across the test networks.
     */
    function starPlace(model, byId) {
        var GAP = STAR_GAP;
        var fw = byId.firewall;
        if (fw) {
            fw.x = -fw.w / 2;
            fw.y = -fw.h / 2;
        }
        var fwW = fw ? fw.w : 0;
        var fwH = fw ? fw.h : 0;
        // each segment as a block: its devices in columns, as in the
        // default layout, positioned relative to the block's corner
        var blocks = model.segments.map(function (seg) {
            var members = model.nodes.filter(function (n) { return n.segment === seg.id; });
            var colW = Math.max.apply(null, members.map(function (n) { return n.w; }));
            var subCols = Math.ceil(members.length / MAX_ROWS);
            var rows = Math.min(members.length, MAX_ROWS);
            return {
                members: members,
                place: function (bx, by) {
                    members.forEach(function (n, i) {
                        var sub = Math.floor(i / MAX_ROWS);
                        var row = i % MAX_ROWS;
                        n.x = bx + CONTAINER_PAD + sub * (colW + SUBCOL_GAP) + (colW - n.w) / 2;
                        n.y = by + CONTAINER_HEAD + CONTAINER_PAD + row * (NODE_H + ROW_GAP);
                    });
                },
                w: subCols * colW + (subCols - 1) * SUBCOL_GAP + 2 * CONTAINER_PAD,
                h: CONTAINER_HEAD + 2 * CONTAINER_PAD + rows * (NODE_H + ROW_GAP) - ROW_GAP
            };
        });
        var sides = { top: [], right: [], bottom: [], left: [] };
        var cycle = blocks.length === 1 ? ['bottom'] : ['left', 'right', 'bottom', 'top'];
        blocks.forEach(function (b, i) { sides[cycle[i % 4]].push(b); });
        if (byId.wan) {
            var wan = byId.wan;
            var wanBlock = { w: wan.w, h: wan.h, place: function (bx, by) { wan.x = bx; wan.y = by; } };
            // WAN in the middle of the top side
            sides.top.splice(Math.floor(sides.top.length / 2), 0, wanBlock);
        }
        var rowW = function (list) {
            return list.reduce(function (t, b) { return t + b.w; }, 0) + Math.max(0, list.length - 1) * COL_GAP;
        };
        var colH = function (list) {
            return list.reduce(function (t, b) { return t + b.h; }, 0) + Math.max(0, list.length - 1) * COL_GAP;
        };
        // top and bottom rows run across; the side columns sit outside them
        var reach = Math.max(fwW / 2, rowW(sides.top) / 2, rowW(sides.bottom) / 2);
        var x = -rowW(sides.top) / 2;
        sides.top.forEach(function (b) { b.place(x, -fwH / 2 - GAP - b.h); x += b.w + COL_GAP; });
        x = -rowW(sides.bottom) / 2;
        sides.bottom.forEach(function (b) { b.place(x, fwH / 2 + GAP); x += b.w + COL_GAP; });
        var y = -colH(sides.left) / 2;
        sides.left.forEach(function (b) { b.place(-reach - GAP - b.w, y); y += b.h + COL_GAP; });
        y = -colH(sides.right) / 2;
        sides.right.forEach(function (b) { b.place(reach + GAP, y); y += b.h + COL_GAP; });
    }

    /** container rectangles around each segment's current members */
    function segmentBoxes(model) {
        return model.segments.map(function (seg) {
            var members = model.nodes.filter(function (n) { return n.segment === seg.id; });
            var x1 = Math.min.apply(null, members.map(function (n) { return n.x; }));
            var y1 = Math.min.apply(null, members.map(function (n) { return n.y; }));
            var x2 = Math.max.apply(null, members.map(function (n) { return n.x + n.w; }));
            var y2 = Math.max.apply(null, members.map(function (n) { return n.y + n.h; }));
            return {
                id: seg.id,
                label: seg.label,
                x: x1 - CONTAINER_PAD,
                y: y1 - CONTAINER_PAD - CONTAINER_HEAD,
                w: x2 - x1 + 2 * CONTAINER_PAD,
                h: y2 - y1 + 2 * CONTAINER_PAD + CONTAINER_HEAD
            };
        });
    }

    // ------------------------------------------------------------------
    // Orthogonal routing
    // ------------------------------------------------------------------

    // directions: 0 right, 1 down, 2 left, 3 up
    var DX = [1, 0, -1, 0];
    var DY = [0, 1, 0, -1];

    function Heap() {
        this.items = [];
    }
    Heap.prototype.push = function (item) {
        var a = this.items;
        a.push(item);
        var i = a.length - 1;
        while (i > 0) {
            var p = (i - 1) >> 1;
            if (a[p].f <= a[i].f) {
                break;
            }
            var t = a[p]; a[p] = a[i]; a[i] = t;
            i = p;
        }
    };
    Heap.prototype.pop = function () {
        var a = this.items;
        var top = a[0];
        var last = a.pop();
        if (a.length) {
            a[0] = last;
            var i = 0;
            for (;;) {
                var l = 2 * i + 1;
                var r = l + 1;
                var m = i;
                if (l < a.length && a[l].f < a[m].f) { m = l; }
                if (r < a.length && a[r].f < a[m].f) { m = r; }
                if (m === i) { break; }
                var t = a[m]; a[m] = a[i]; a[i] = t;
                i = m;
            }
        }
        return top;
    };

    /**
     * Routing grid over the drawing, with every node (inflated by
     * CLEARANCE) marked blocked.
     */
    function makeGrid(nodes) {
        var margin = 6 * GRID;
        var x1 = Math.min.apply(null, nodes.map(function (n) { return n.x; })) - margin;
        var y1 = Math.min.apply(null, nodes.map(function (n) { return n.y; })) - margin;
        var x2 = Math.max.apply(null, nodes.map(function (n) { return n.x + n.w; })) + margin;
        var y2 = Math.max.apply(null, nodes.map(function (n) { return n.y + n.h; })) + margin;
        var grid = {
            ox: Math.floor(x1 / GRID) * GRID,
            oy: Math.floor(y1 / GRID) * GRID,
            cols: 0,
            rows: 0,
            blocked: null,
            used: null,
            near: null
        };
        grid.cols = Math.ceil((x2 - grid.ox) / GRID) + 1;
        grid.rows = Math.ceil((y2 - grid.oy) / GRID) + 1;
        grid.blocked = new Uint8Array(grid.cols * grid.rows);
        // per axis (0 horizontal, 1 vertical): edges running along each
        // cell, and cells beside such runs
        grid.used = [new Uint16Array(grid.cols * grid.rows), new Uint16Array(grid.cols * grid.rows)];
        grid.near = [new Uint16Array(grid.cols * grid.rows), new Uint16Array(grid.cols * grid.rows)];
        // [axis][side]: edges along that axis turning off to that side
        // (0 negative, 1 positive) at each cell
        grid.branch = [0, 1].map(function () {
            return [new Uint16Array(grid.cols * grid.rows), new Uint16Array(grid.cols * grid.rows)];
        });
        nodes.forEach(function (n) {
            var r = cellRect(grid, n);
            for (var cy = r.y1; cy <= r.y2; cy++) {
                for (var cx = r.x1; cx <= r.x2; cx++) {
                    grid.blocked[cy * grid.cols + cx] = 1;
                }
            }
        });
        // extra cost by distance (in cells) to the nearest node, capped
        var size = grid.cols * grid.rows;
        var away = new Uint8Array(size).fill(CENTRE_CELLS);
        var queue = [];
        for (var c = 0; c < size; c++) {
            if (grid.blocked[c]) {
                away[c] = 0;
                queue.push(c);
            }
        }
        for (var q = 0; q < queue.length; q++) {
            var cur = queue[q];
            var x = cur % grid.cols;
            var y = (cur - x) / grid.cols;
            for (var d = 0; d < 4; d++) {
                var nx = x + DX[d];
                var ny = y + DY[d];
                var nc = ny * grid.cols + nx;
                if (nx >= 0 && ny >= 0 && nx < grid.cols && ny < grid.rows && away[nc] > away[cur] + 1) {
                    away[nc] = away[cur] + 1;
                    queue.push(nc);
                }
            }
        }
        grid.edgeCost = new Float32Array(size);
        for (c = 0; c < size; c++) {
            grid.edgeCost[c] = (CENTRE_CELLS - away[c]) * CENTRE_COST;
        }
        return grid;
    }

    /** inclusive cell bounds of a node inflated by CLEARANCE */
    function cellRect(grid, n) {
        return {
            x1: Math.max(0, Math.floor((n.x - CLEARANCE - grid.ox) / GRID)),
            y1: Math.max(0, Math.floor((n.y - CLEARANCE - grid.oy) / GRID)),
            x2: Math.min(grid.cols - 1, Math.ceil((n.x + n.w + CLEARANCE - grid.ox) / GRID)),
            y2: Math.min(grid.rows - 1, Math.ceil((n.y + n.h + CLEARANCE - grid.oy) / GRID))
        };
    }

    /**
     * Port cells just outside a node's blocked area, each with the
     * direction pointing away from the node (`dir`) and the point on the
     * node's border it connects to. Corners are skipped so edges meet the
     * node square-on.
     */
    function ports(grid, n) {
        var r = cellRect(grid, n);
        var out = [];
        var cx;
        var cy;
        var px = function (c) { return grid.ox + c * GRID; };
        var py = function (c) { return grid.oy + c * GRID; };
        for (cx = r.x1 + 2; cx <= r.x2 - 2; cx++) {
            if (px(cx) <= n.x + 6 || px(cx) >= n.x + n.w - 6) { continue; }
            if (r.y1 > 0) { out.push({ cx: cx, cy: r.y1 - 1, dir: 3, bx: px(cx), by: n.y }); }
            if (r.y2 < grid.rows - 1) { out.push({ cx: cx, cy: r.y2 + 1, dir: 1, bx: px(cx), by: n.y + n.h }); }
        }
        for (cy = r.y1 + 2; cy <= r.y2 - 2; cy++) {
            if (py(cy) <= n.y + 6 || py(cy) >= n.y + n.h - 6) { continue; }
            if (r.x1 > 0) { out.push({ cx: r.x1 - 1, cy: cy, dir: 2, bx: n.x, by: py(cy) }); }
            if (r.x2 < grid.cols - 1) { out.push({ cx: r.x2 + 1, cy: cy, dir: 0, bx: n.x + n.w, by: py(cy) }); }
        }
        return out;
    }

    /**
     * Route one edge: A* over (cell, heading) with a high cost per turn,
     * so the result uses as few turns as the obstacles allow rather than
     * stair-stepping. Starts leaving the source square-on from any port,
     * must arrive at a target port heading into the target. Running along
     * a line another edge already uses is cheaper (edges gather into
     * corridors); passing straight through another edge, or running just
     * beside a corridor, costs extra.
     *
     * @return array|null polyline points [{x, y}] from source border to
     *         target border, collinear points removed
     */
    function routeEdge(grid, src, dst) {
        var cols = grid.cols;
        var size = cols * grid.rows;
        // search state = (cell * 4 + heading) * 3 + run, where run says
        // whether the route is running along a line other edges use, and
        // if so which side it joined from: 0 not, 1 negative, 2 positive
        var best = new Float64Array(size * 12).fill(Infinity);
        var prev = new Int32Array(size * 12).fill(-1);
        var startPort = {};
        var goal = {};
        var heap = new Heap();
        var side = function (d) { return d < 2 ? 1 : 0; };   // 0 neg, 1 pos

        var targets = ports(grid, dst);
        targets.forEach(function (p) {
            // arrive heading into the target = opposite of the port's outward dir
            goal[(p.cy * cols + p.cx) * 4 + ((p.dir + 2) % 4)] = p;
        });
        var tx1 = Math.min.apply(null, targets.map(function (p) { return p.cx; }));
        var tx2 = Math.max.apply(null, targets.map(function (p) { return p.cx; }));
        var ty1 = Math.min.apply(null, targets.map(function (p) { return p.cy; }));
        var ty2 = Math.max.apply(null, targets.map(function (p) { return p.cy; }));
        var h = function (cx, cy) {
            return Math.max(0, tx1 - cx, cx - tx2) + Math.max(0, ty1 - cy, cy - ty2);
        };

        ports(grid, src).forEach(function (p) {
            var base = (p.cy * cols + p.cx) * 4 + p.dir;
            if (grid.blocked[p.cy * cols + p.cx]) { return; }
            best[base * 3] = 0;
            startPort[base] = p;
            heap.push({ s: base * 3, g: 0, f: h(p.cx, p.cy) });
        });

        var found = -1;
        var expanded = 0;
        while (heap.items.length) {
            var cur = heap.pop();
            if (cur.g > best[cur.s]) { continue; }
            var run = cur.s % 3;
            var base = (cur.s - run) / 3;
            if (goal[base]) { found = cur.s; break; }
            if (++expanded > 300000) { break; }
            var cell = base >> 2;
            var dir = base & 3;
            var cx = cell % cols;
            var cy = (cell - cx) / cols;
            var lineAxis = dir & 1;
            for (var nd = 0; nd < 4; nd++) {
                if (nd === (dir + 2) % 4) { continue; }
                var nx = cx + DX[nd];
                var ny = cy + DY[nd];
                if (nx < 0 || ny < 0 || nx >= cols || ny >= grid.rows) { continue; }
                var ncell = ny * cols + nx;
                if (grid.blocked[ncell]) { continue; }
                var axis = nd & 1;
                var along = grid.used[axis][ncell] > 0;
                var g = cur.g + grid.edgeCost[ncell]
                    + (along ? SHARE_COST : STEP_COST + (grid.near[axis][ncell] ? NEAR_COST : 0));
                var nrun = 0;
                if (nd === dir) {
                    if (!grid.used[axis][cell]) {
                        // straight through a cell other edges run across
                        g += grid.used[1 - axis][cell] * CROSS_COST;
                    } else if (run && !along) {
                        // a shared run ends here: edges branching off it
                        // here towards the side we joined from cross us
                        g += grid.branch[axis][run - 1][cell] * CROSS_COST;
                    }
                    nrun = along ? run : 0;
                } else {
                    g += BEND_COST;
                    if (run && side(nd) !== run - 1) {
                        // joined a shared run on one side, leaving it on
                        // the other: crosses every edge passing straight on
                        var passing = grid.used[lineAxis][cell]
                            - grid.branch[lineAxis][0][cell] - grid.branch[lineAxis][1][cell];
                        g += Math.max(0, passing) * CROSS_COST;
                    }
                    // joining a line: we arrive from the side opposite our heading
                    nrun = along ? 2 - side(dir) : 0;
                }
                var ns = (ncell * 4 + nd) * 3 + nrun;
                if (g < best[ns]) {
                    best[ns] = g;
                    prev[ns] = cur.s;
                    heap.push({ s: ns, g: g, f: g + h(nx, ny) });
                }
            }
        }
        if (found < 0) {
            return null;
        }

        var states = [];
        for (var st = found; st >= 0; st = prev[st]) {
            states.push((st - st % 3) / 3);
        }
        states.reverse();
        occupy(grid, states);

        var sp = startPort[states[0]];
        var gp = goal[states[states.length - 1]];
        var pts = [{ x: sp.bx, y: sp.by }];
        states.forEach(function (b) {
            var c = b >> 2;
            var ccx = c % cols;
            pts.push({ x: grid.ox + ccx * GRID, y: grid.oy + ((c - ccx) / cols) * GRID });
        });
        pts.push({ x: gp.bx, y: gp.by });
        return simplify(pts);
    }

    /**
     * Record a route's search states on the grid for later routes: each
     * cell counts as used along the axis of each move in or out, and
     * the cells beside it, across that axis, as near. At a turn, each of
     * the two lines meeting there gets a branch on the side the other
     * goes off to.
     */
    function occupy(grid, states) {
        var cols = grid.cols;
        var mark = function (c, axis) {
            grid.used[axis][c]++;
            var hx = c % cols;
            var hy = (c - hx) / cols;
            for (var k = -NEAR_CELLS; k <= NEAR_CELLS; k++) {
                var x = axis ? hx + k : hx;
                var y = axis ? hy : hy + k;
                if (k && x >= 0 && y >= 0 && x < cols && y < grid.rows) {
                    grid.near[axis][y * cols + x]++;
                }
            }
        };
        states.forEach(function (st, i) {
            mark(st >> 2, st & 1);
            if (i + 1 < states.length && (states[i + 1] & 1) !== (st & 1)) {
                var c = st >> 2;
                var din = st & 3;
                var dout = states[i + 1] & 3;
                mark(c, dout & 1);
                // the line we leave branches towards where we go; the
                // line we join branches back towards where we came from
                grid.branch[din & 1][dout < 2 ? 1 : 0][c]++;
                grid.branch[dout & 1][din < 2 ? 0 : 1][c]++;
            }
        });
    }

    /** drop points that sit on a straight run */
    function simplify(pts) {
        var out = [pts[0]];
        for (var i = 1; i < pts.length - 1; i++) {
            var a = out[out.length - 1];
            var b = pts[i];
            var c = pts[i + 1];
            var collinear = (a.x === b.x && b.x === c.x) || (a.y === b.y && b.y === c.y);
            if (!collinear) {
                out.push(b);
            }
        }
        out.push(pts[pts.length - 1]);
        return out;
    }

    /** route every edge; returns {edgeId: points} */
    function routeAll(model) {
        var byId = {};
        model.nodes.forEach(function (n) { byId[n.id] = n; });
        var grid = makeGrid(model.nodes);
        var routes = {};
        // firewall-crossing edges first, then same-segment links, which go
        // round whatever is left (routed early, a link between two devices
        // wraps round the ones between them, and everything they reach
        // has to cross it); shorter first within each, having the fewest
        // alternatives
        var order = model.edges.slice().sort(function (a, b) {
            return ((a.kind === 'unfiltered') - (b.kind === 'unfiltered'))
                || dist(byId[a.from], byId[a.to]) - dist(byId[b.from], byId[b.to]);
        });
        order.forEach(function (e) {
            routes[e.id] = routeEdge(grid, byId[e.from], byId[e.to]);
        });
        // runs that only meet end to end can still end up overlapping once
        // the lanes across them spread; lay out, find any, and lay out
        // again from the grid routes with those pairs kept apart too
        var grid0 = JSON.stringify(routes);
        var apart = {};
        for (var pass = 0; pass < 5; pass++) {
            routes = JSON.parse(grid0);
            assignLanes(model, routes, apart);
            var clashes = laneClashes(routes);
            if (!clashes.length) {
                break;
            }
            clashes.forEach(function (k) { apart[k] = true; });
        }
        return routes;
    }

    /** key for a pair of runs (edge id + segment index each) */
    function runPair(a, ai, b, bi) {
        var p = a + '#' + ai;
        var q = b + '#' + bi;
        return p < q ? p + '|' + q : q + '|' + p;
    }

    /** pairs of runs from different edges drawn on top of each other */
    function laneClashes(routes) {
        var runs = [];
        Object.keys(routes).forEach(function (id) {
            var pts = routes[id] || [];
            for (var i = 0; i < pts.length - 1; i++) {
                var a = pts[i];
                var b = pts[i + 1];
                var horiz = a.y === b.y;
                runs.push({
                    id: id,
                    i: i,
                    horiz: horiz,
                    at: horiz ? a.y : a.x,
                    lo: horiz ? Math.min(a.x, b.x) : Math.min(a.y, b.y),
                    hi: horiz ? Math.max(a.x, b.x) : Math.max(a.y, b.y)
                });
            }
        });
        runs.sort(function (a, b) { return a.at - b.at; });
        var out = [];
        for (var a = 0; a < runs.length; a++) {
            for (var b = a + 1; b < runs.length && runs[b].at - runs[a].at < MIN_LANE_GAP - 0.5; b++) {
                var s = runs[a];
                var t = runs[b];
                if (s.id !== t.id && s.horiz === t.horiz && Math.min(s.hi, t.hi) - Math.max(s.lo, t.lo) > 1) {
                    out.push(runPair(s.id, s.i, t.id, t.i));
                }
            }
        }
        return out;
    }

    /** unit step from point a towards b (orthogonal) */
    function heading(a, b) {
        return { x: Math.sign(b.x - a.x), y: Math.sign(b.y - a.y) };
    }

    /**
     * A route as the grid points it visits, one per cell, plus a virtual
     * point one cell into each end node, so walks along it see the turn
     * into the node like any other turn.
     */
    function routeCells(pts) {
        var cells = [];
        for (var i = 0; i < pts.length - 1; i++) {
            var a = pts[i];
            var b = pts[i + 1];
            var horiz = a.y === b.y;
            var from = horiz ? a.x : a.y;
            var to = horiz ? b.x : b.y;
            var step = to > from ? GRID : -GRID;
            var v = step > 0 ? Math.ceil(from / GRID) * GRID : Math.floor(from / GRID) * GRID;
            for (; step > 0 ? v <= to : v >= to; v += step) {
                var c = horiz ? { x: v, y: a.y } : { x: a.x, y: v };
                var last = cells[cells.length - 1];
                if (!last || last.x !== c.x || last.y !== c.y) {
                    cells.push(c);
                }
            }
        }
        if (cells.length) {
            var d0 = heading(pts[0], pts[1]);
            var d1 = heading(pts[pts.length - 2], pts[pts.length - 1]);
            var end = cells[cells.length - 1];
            cells.unshift({ x: cells[0].x - d0.x * GRID, y: cells[0].y - d0.y * GRID });
            cells.push({ x: end.x + d1.x * GRID, y: end.y + d1.y * GRID });
        }
        return cells;
    }

    /**
     * Which side of route q route p ends up on, walking forward together
     * from cell i of p (= cell j of q) until they part: +1 p turns off to
     * the left of q, -1 to the right, 0 they never part (or one ends
     * first, into a node straight ahead).
     */
    function partingSide(p, i, q, j) {
        var h = heading(p[i - 1] || p[i], p[i - 1] ? p[i] : p[i + 1]);
        for (;;) {
            var pn = p[i + 1];
            var qn = q[j + 1];
            if (!pn || !qn) {
                return 0;
            }
            if (pn.x === qn.x && pn.y === qn.y) {
                h = heading(p[i], pn);
                i++;
                j++;
                continue;
            }
            // left of heading h is (h.y, -h.x) in screen coordinates
            var dp = heading(p[i], pn);
            var dq = heading(q[j], qn);
            return Math.sign((dp.x * h.y - dp.y * h.x) - (dq.x * h.y - dq.y * h.x));
        }
    }

    /**
     * Spread edges that share a corridor into parallel lanes. Routes sit
     * on the routing grid, mostly on the middle line of each gap; parallel
     * runs that overlap on the same or a nearby line (CORRIDOR_LINES) form
     * a corridor. Runs on different lines keep their order. Two edges on
     * one line are ordered by which way they part company (ahead or,
     * failing that, behind), so lanes peel off towards their own side
     * without crossing the others. Lanes are LANE_GAP apart, closer where
     * the corridor is tight. Moves route points in place.
     */
    function assignLanes(model, routes, apart) {
        apart = apart || {};
        var byId = {};
        model.nodes.forEach(function (n) { byId[n.id] = n; });
        var cellsOf = {};
        var lines = { h: [], v: [] };
        model.edges.forEach(function (e) {
            var pts = routes[e.id];
            if (!pts) {
                return;
            }
            var cells = routeCells(pts);
            var index = {};
            cells.forEach(function (c, k) { index[c.x + ',' + c.y] = k; });
            cellsOf[e.id] = { cells: cells, index: index };
            for (var i = 0; i < pts.length - 1; i++) {
                var a = pts[i];
                var b = pts[i + 1];
                var horiz = a.y === b.y;
                lines[horiz ? 'h' : 'v'].push({
                    id: e.id,
                    pts: pts,
                    i: i,
                    horiz: horiz,
                    at: horiz ? a.y : a.x,
                    dir: heading(a, b),
                    lo: horiz ? Math.min(a.x, b.x) : Math.min(a.y, b.y),
                    hi: horiz ? Math.max(a.x, b.x) : Math.max(a.y, b.y),
                    ends: [i === 0 ? byId[e.from] : null, i + 1 === pts.length - 1 ? byId[e.to] : null]
                });
            }
        });

        // a corridor: parallel runs that overlap on the same or a nearby
        // line, laid out together so lanes from neighbouring lines don't
        // land on top of each other
        var moves = [];
        ['h', 'v'].forEach(function (o) {
            var segs = lines[o].sort(function (a, b) { return a.at - b.at; });
            var root = segs.map(function (s, k) { return k; });
            var find = function (k) {
                while (root[k] !== k) {
                    k = root[k] = root[root[k]];
                }
                return k;
            };
            for (var a = 0; a < segs.length; a++) {
                for (var b = a + 1; b < segs.length && segs[b].at - segs[a].at <= CORRIDOR_LINES * GRID; b++) {
                    if (touches(segs[a], segs[b])) {
                        root[find(b)] = find(a);
                    }
                }
            }
            // lay out each corridor; where a crowded one spills into a
            // neighbour (runs from both closer than MIN_LANE_GAP), merge
            // the two and lay them out again together
            for (var round = 0; round < 20; round++) {
                var groups = {};
                segs.forEach(function (s, k) {
                    (groups[find(k)] = groups[find(k)] || []).push(k);
                });
                Object.keys(groups).forEach(function (r) {
                    var members = groups[r].map(function (k) { return segs[k]; });
                    var at = members.length > 1 ? laneGroup(members) : [members[0].at];
                    members.forEach(function (m, i) { m.pos = at[i]; });
                });
                var byPos = segs.map(function (s, k) { return k; }).sort(function (a, b) {
                    return segs[a].pos - segs[b].pos;
                });
                var merged = false;
                for (a = 0; a < byPos.length; a++) {
                    for (b = a + 1; b < byPos.length && segs[byPos[b]].pos - segs[byPos[a]].pos < MIN_LANE_GAP; b++) {
                        var p = byPos[a];
                        var q = byPos[b];
                        if (find(p) !== find(q) && segs[p].id !== segs[q].id && touches(segs[p], segs[q])) {
                            root[find(q)] = find(p);
                            merged = true;
                        }
                    }
                }
                if (!merged) {
                    break;
                }
            }
            segs.forEach(function (s) {
                var off = Math.round((s.pos - s.at) * 10) / 10;
                if (off) {
                    moves.push({ s: s, off: off });
                }
            });
        });

        /**
         * Runs that overlap, or meet end to end and were found drawn on
         * top of each other last time (apart).
         */
        function touches(s, t) {
            var lo = Math.max(s.lo, t.lo);
            var hi = Math.min(s.hi, t.hi);
            return hi > lo || (hi === lo && !!apart[runPair(s.id, s.i, t.id, t.i)]);
        }

        // apply after every bundle is decided, from the original coordinates
        moves.forEach(function (m) {
            var a = m.s.pts[m.s.i];
            var b = m.s.pts[m.s.i + 1];
            if (m.s.horiz) {
                a.y += m.off;
                b.y += m.off;
            } else {
                a.x += m.off;
                b.x += m.off;
            }
        });

        /**
         * +1 when segment s should sit on the negative side of t, else -1.
         * When their routes never part, s keeps to the left (relative to
         * its own direction of travel, so the pair stays the same way
         * round through every bend).
         */
        function before(s, t) {
            var leftSign = s.horiz ? -s.dir.x : s.dir.y;
            return partingOrder(s, t) * leftSign < 0 ? 1 : -1;
        }

        /** +1 s parts to the left of t (or they never part), -1 to the right */
        function partingOrder(s, t) {
            var lo = Math.max(s.lo, t.lo);
            var hi = Math.min(s.hi, t.hi);
            // a shared grid point inside the overlap
            var at = Math.ceil(lo / GRID) * GRID;
            if (at > hi) {
                return 1;
            }
            var pt = s.horiz ? { x: at, y: s.pts[s.i].y } : { x: s.pts[s.i].x, y: at };
            var ps = cellsOf[s.id];
            var qs = cellsOf[t.id];
            var i = ps.index[pt.x + ',' + pt.y];
            var j = qs.index[pt.x + ',' + pt.y];
            if (i === undefined || j === undefined) {
                return 1;
            }
            var p = ps.cells;
            var q = qs.cells;
            var same = s.dir.x === t.dir.x && s.dir.y === t.dir.y;
            if (!same) {
                q = q.slice().reverse();
                j = q.length - 1 - j;
            }
            var side = partingSide(p, i, q, j);
            if (!side) {
                // walking backwards, left and right swap
                var pr = p.slice().reverse();
                var qr = q.slice().reverse();
                side = -partingSide(pr, p.length - 1 - i, qr, q.length - 1 - j);
            }
            return side || 1;
        }

        function laneGroup(group) {
            var n = group.length;
            // after[a] = segments that must sit on a's positive side
            var after = group.map(function () { return []; });
            var indeg = group.map(function () { return 0; });
            for (var a = 0; a < n; a++) {
                for (var b = a + 1; b < n; b++) {
                    var s = group[a];
                    var t = group[b];
                    if (s.id === t.id || !touches(s, t)) {
                        continue;
                    }
                    // runs on different lines keep their order; on one line,
                    // ask from the lower id's side so ties break the same
                    // way in every bundle the pair shares
                    var r = s.at !== t.at ? (s.at < t.at ? 1 : -1)
                        : s.id < t.id ? before(s, t) : -before(t, s);
                    if (r > 0) {
                        after[a].push(b);
                        indeg[b]++;
                    } else {
                        after[b].push(a);
                        indeg[a]++;
                    }
                }
            }
            // order to place them in (a cycle means a crossing is
            // unavoidable: take the least-constrained run and carry on)
            var order = [];
            var done = group.map(function () { return false; });
            for (var k = 0; k < n; k++) {
                var pick = -1;
                for (var c = 0; c < n; c++) {
                    if (!done[c] && (pick < 0 || indeg[c] < indeg[pick])) {
                        pick = c;
                    }
                }
                done[pick] = true;
                order.push(pick);
                after[pick].forEach(function (b) { indeg[b]--; });
            }
            var rank = [];
            order.forEach(function (g, i) { rank[g] = i; });
            // a run must keep clear of the nodes beside it, and on the
            // border of any node it ends at
            var lo = [];
            var hi = [];
            group.forEach(function (s, g) {
                lo[g] = -Infinity;
                hi[g] = Infinity;
                model.nodes.forEach(function (nd) {
                    var along = s.horiz ? [nd.x, nd.x + nd.w] : [nd.y, nd.y + nd.h];
                    var across = s.horiz ? [nd.y, nd.y + nd.h] : [nd.x, nd.x + nd.w];
                    if (along[1] <= s.lo || along[0] >= s.hi || s.ends.indexOf(nd) >= 0) {
                        return;
                    }
                    if (across[1] <= s.at) {
                        lo[g] = Math.max(lo[g], across[1] + 4);
                    } else if (across[0] >= s.at) {
                        hi[g] = Math.min(hi[g], across[0] - 4);
                    }
                });
                s.ends.forEach(function (nd) {
                    if (nd) {
                        var side = s.horiz ? [nd.y, nd.y + nd.h] : [nd.x, nd.x + nd.w];
                        lo[g] = Math.max(lo[g], side[0] + 6);
                        hi[g] = Math.min(hi[g], side[1] - 6);
                    }
                });
            });
            // every run a run overlaps must keep a gap from it, on the side
            // the placing order says (in a cycle, one pair is the "wrong"
            // way round: a crossing, but never lanes on top of each other)
            var beside = group.map(function () { return []; });
            after.forEach(function (list, g) {
                list.forEach(function (b) {
                    beside[g].push(b);
                    beside[b].push(g);
                });
            });
            // Each run's feasible band [L, U]: its own limits, pushed in by
            // the runs it must keep a gap from. Then pack the runs towards
            // the positive side starting from where each was routed, and
            // again towards the negative side, both held inside the bands
            // (which keeps every gap); the average centres each bundle on
            // where it was routed. If a band is empty, narrow the gap
            // (never merging lanes).
            var place = function (gap) {
                var L = [];
                var U = [];
                var up = [];
                var down = [];
                var fits = true;
                order.forEach(function (g) {
                    L[g] = lo[g];
                    up[g] = group[g].at;
                    beside[g].forEach(function (t) {
                        if (rank[t] < rank[g]) {
                            L[g] = Math.max(L[g], L[t] + gap);
                            up[g] = Math.max(up[g], up[t] + gap);
                        }
                    });
                });
                order.slice().reverse().forEach(function (g) {
                    U[g] = hi[g];
                    down[g] = group[g].at;
                    beside[g].forEach(function (t) {
                        if (rank[t] > rank[g]) {
                            U[g] = Math.min(U[g], U[t] - gap);
                            down[g] = Math.min(down[g], down[t] - gap);
                        }
                    });
                    fits = fits && L[g] <= U[g];
                });
                return {
                    fits: fits,
                    at: group.map(function (s, g) {
                        var a = Math.min(Math.max(up[g], L[g]), U[g]);
                        var b = Math.min(Math.max(down[g], L[g]), U[g]);
                        return (a + b) / 2;
                    })
                };
            };
            var placed = place(LANE_GAP);
            for (var gap = LANE_GAP - 1; !placed.fits && gap >= MIN_LANE_GAP; gap--) {
                placed = place(gap);
            }
            return placed.at;
        }
    }

    function dist(a, b) {
        return Math.abs(a.x - b.x) + Math.abs(a.y - b.y);
    }

    /**
     * Number of places where two different edges' routes cross: a
     * horizontal run of one passing strictly through a vertical run of
     * the other. Edges meeting at a shared node border don't count.
     */
    function countCrossings(routes) {
        var h = [];
        var v = [];
        Object.keys(routes).forEach(function (id) {
            var pts = routes[id] || [];
            for (var i = 0; i < pts.length - 1; i++) {
                var a = pts[i];
                var b = pts[i + 1];
                if (a.y === b.y && a.x !== b.x) {
                    h.push({ id: id, at: a.y, lo: Math.min(a.x, b.x), hi: Math.max(a.x, b.x) });
                } else if (a.x === b.x && a.y !== b.y) {
                    v.push({ id: id, at: a.x, lo: Math.min(a.y, b.y), hi: Math.max(a.y, b.y) });
                }
            }
        });
        var n = 0;
        h.forEach(function (s) {
            v.forEach(function (t) {
                if (s.id !== t.id && t.at > s.lo && t.at < s.hi && s.at > t.lo && s.at < t.hi) {
                    n++;
                }
            });
        });
        return n;
    }

    // ------------------------------------------------------------------
    // Path geometry
    // ------------------------------------------------------------------

    /** SVG path through orthogonal points, with each bend rounded */
    function roundedPath(pts, radius) {
        if (!pts || pts.length < 2) {
            return '';
        }
        radius = radius === undefined ? BEND_RADIUS : radius;
        var d = 'M' + pts[0].x + ',' + pts[0].y;
        for (var i = 1; i < pts.length - 1; i++) {
            var a = pts[i - 1];
            var b = pts[i];
            var c = pts[i + 1];
            var lin = Math.abs(b.x - a.x) + Math.abs(b.y - a.y);
            var lout = Math.abs(c.x - b.x) + Math.abs(c.y - b.y);
            var r = Math.min(radius, lin / 2, lout / 2);
            var p1 = { x: b.x - Math.sign(b.x - a.x) * r, y: b.y - Math.sign(b.y - a.y) * r };
            var p2 = { x: b.x + Math.sign(c.x - b.x) * r, y: b.y + Math.sign(c.y - b.y) * r };
            d += ' L' + p1.x + ',' + p1.y + ' Q' + b.x + ',' + b.y + ' ' + p2.x + ',' + p2.y;
        }
        var last = pts[pts.length - 1];
        return d + ' L' + last.x + ',' + last.y;
    }

    /**
     * Squircle-style rounded rectangle: corners use cubic curves with
     * control points pulled close to the corner, giving the smoother,
     * continuous-curvature look of a superellipse rather than a circular arc.
     */
    function squirclePath(x, y, w, h, r) {
        r = Math.min(r, w / 2, h / 2);
        var k = 0.1 * r; // smaller = squarer corner, smoother transition
        return 'M' + (x + r) + ',' + y +
            ' H' + (x + w - r) +
            ' C' + (x + w - k) + ',' + y + ' ' + (x + w) + ',' + (y + k) + ' ' + (x + w) + ',' + (y + r) +
            ' V' + (y + h - r) +
            ' C' + (x + w) + ',' + (y + h - k) + ' ' + (x + w - k) + ',' + (y + h) + ' ' + (x + w - r) + ',' + (y + h) +
            ' H' + (x + r) +
            ' C' + (x + k) + ',' + (y + h) + ' ' + x + ',' + (y + h - k) + ' ' + x + ',' + (y + h - r) +
            ' V' + (y + r) +
            ' C' + x + ',' + (y + k) + ' ' + (x + k) + ',' + y + ' ' + (x + r) + ',' + y + ' Z';
    }

    /** text drawn on an edge's pill (a changed check says so) */
    function labelText(e) {
        return e.stale ? 'changed \u00b7 ' + e.label : e.label;
    }

    function labelWidth(label) {
        return label.length * 6 + 12;   // 10px monospace
    }

    function overlapArea(a, b) {
        var w = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
        var h = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
        return w > 0 && h > 0 ? w * h : 0;
    }

    /**
     * Place edge labels so they don't sit on top of each other or on
     * nodes. Labels on the shortest routes are placed first. Each label
     * tries spots every LABEL_STEP px along its own route and takes the
     * first that's clear (with LABEL_GAP to spare); if none is clear, the
     * spot with the least overlap. Runs are tried horizontal ones long
     * enough to hold the label first (its line then runs in one end and
     * out the other), then other horizontal ones, then vertical ones (where
     * a label lies across any neighbouring lanes); longest first within
     * each, nearest the middle first.
     *
     * @return {edgeId: {x, y, w, h}} label boxes (top-left + size)
     */
    function placeLabels(model, routes) {
        var placed = [];
        var obstacles = model.nodes.map(function (n) {
            return { x: n.x, y: n.y, w: n.w, h: n.h };
        });
        var out = {};
        var routeLen = function (pts) {
            var len = 0;
            for (var i = 0; i < pts.length - 1; i++) {
                len += Math.abs(pts[i + 1].x - pts[i].x) + Math.abs(pts[i + 1].y - pts[i].y);
            }
            return len;
        };
        // shortest routes first: they have the fewest places a label can go,
        // so long edges (with room to spare) work around them, not vice versa
        var order = model.edges.filter(function (e) {
            return e.label && routes[e.id];
        }).sort(function (a, b) {
            return routeLen(routes[a.id]) - routeLen(routes[b.id]);
        });
        order.forEach(function (e) {
            var pts = routes[e.id];
            var w = labelWidth(labelText(e));
            var runs = [];
            for (var i = 0; i < pts.length - 1; i++) {
                runs.push({ a: pts[i], b: pts[i + 1], len: Math.abs(pts[i + 1].x - pts[i].x) + Math.abs(pts[i + 1].y - pts[i].y) });
            }
            var rank = function (r) {
                var horiz = r.a.y === r.b.y;
                return horiz ? (r.len >= w ? 0 : 1) : 2;
            };
            runs.sort(function (p, q) { return (rank(p) - rank(q)) || (q.len - p.len); });
            var best = null;
            var bestCost = Infinity;
            runs.some(function (run) {
                var steps = Math.max(1, Math.floor(run.len / LABEL_STEP));
                var spots = [];
                for (var k = 0; k <= steps; k++) {
                    spots.push(k / steps);
                }
                spots.sort(function (p, q) { return Math.abs(p - 0.5) - Math.abs(q - 0.5); });
                return spots.some(function (t) {
                    var cx = run.a.x + (run.b.x - run.a.x) * t;
                    var cy = run.a.y + (run.b.y - run.a.y) * t;
                    var box = { x: cx - w / 2, y: cy - LABEL_H / 2, w: w, h: LABEL_H };
                    var padded = { x: box.x - LABEL_GAP, y: box.y - LABEL_GAP, w: w + 2 * LABEL_GAP, h: LABEL_H + 2 * LABEL_GAP };
                    var cost = 0;
                    placed.concat(obstacles).forEach(function (o) {
                        cost += overlapArea(padded, o);
                    });
                    if (cost < bestCost) {
                        bestCost = cost;
                        best = box;
                    }
                    return cost === 0;
                });
            });
            if (best) {
                placed.push(best);
                out[e.id] = best;
            }
        });
        return out;
    }

    /**
     * Where a route meets a label's outline: dots there tie the label to
     * its own line when it sits on a bundle of lanes.
     *
     * @return [{x, y}]
     */
    function labelDots(pts, box) {
        var out = [];
        var add = function (x, y) {
            if (!out.some(function (p) { return Math.abs(p.x - x) < 1 && Math.abs(p.y - y) < 1; })) {
                out.push({ x: x, y: y });
            }
        };
        for (var i = 0; pts && i < pts.length - 1; i++) {
            var a = pts[i];
            var b = pts[i + 1];
            if (a.y === b.y && a.y > box.y && a.y < box.y + box.h) {
                [box.x, box.x + box.w].forEach(function (x) {
                    if (x >= Math.min(a.x, b.x) && x <= Math.max(a.x, b.x)) {
                        add(x, a.y);
                    }
                });
            } else if (a.x === b.x && a.x > box.x && a.x < box.x + box.w) {
                [box.y, box.y + box.h].forEach(function (y) {
                    if (y >= Math.min(a.y, b.y) && y <= Math.max(a.y, b.y)) {
                        add(a.x, y);
                    }
                });
            }
        }
        return out;
    }

    /** midpoint of the longest run */
    function labelPoint(pts) {
        var bestLen = -1;
        var at = null;
        for (var i = 0; i < pts.length - 1; i++) {
            var len = Math.abs(pts[i + 1].x - pts[i].x) + Math.abs(pts[i + 1].y - pts[i].y);
            if (len > bestLen) {
                bestLen = len;
                at = { x: (pts[i].x + pts[i + 1].x) / 2, y: (pts[i].y + pts[i + 1].y) / 2 };
            }
        }
        return at;
    }

    // ------------------------------------------------------------------
    // Dead-rule findings
    // ------------------------------------------------------------------

    /**
     * Highlight target for a dead rule: the pairs it was written for and
     * the nodes in them, or null when it matches nothing on the graph.
     */
    function findingHighlight(d) {
        var pairs = d.pairs || [];
        if (!pairs.length) {
            return null;
        }
        var nodes = {};
        pairs.forEach(function (p) {
            nodes[p[0]] = true;
            nodes[p[1]] = true;
        });
        return { key: 'dead:' + d.label, nodes: Object.keys(nodes), pairs: pairs };
    }

    /**
     * Shape the graph's dead_rules for display: the user's own rules first
     * (contradicted before redundant), OPNsense's automatic rules apart.
     * Each item gets a plain-language headline.
     */
    function deadRuleFindings(graph, ruleLink) {
        var list = (graph.dead_rules || []).map(function (d) {
            var headline;
            if (d.kind === 'contradicted') {
                headline = d.action === 'block' ? 'Block never applies' : 'Pass never applies';
            } else {
                headline = 'Redundant';
            }
            return {
                label: d.label,
                name: d.descr,
                headline: headline,
                kind: d.kind,
                automatic: !!d.automatic,
                byName: d.by_descr,
                byAction: d.by_action,
                byPosition: d.by_position === 'later' ? 'later' : 'earlier',
                link: ruleLink ? ruleLink(d.label) : null,
                byLink: ruleLink ? ruleLink(d.by) : null,
                highlight: findingHighlight(d)
            };
        });
        var rank = function (f) { return f.kind === 'contradicted' ? 0 : 1; };
        var own = list.filter(function (f) { return !f.automatic; }).sort(function (a, b) { return rank(a) - rank(b); });
        return {
            own: own,
            automatic: list.filter(function (f) { return f.automatic; }),
            contradicted: own.filter(function (f) { return f.kind === 'contradicted'; }).length,
            redundant: own.filter(function (f) { return f.kind === 'redundant'; }).length
        };
    }

    /**
     * Why a rule is dead, in plain words. An earlier quick rule decides
     * before it is reached; for a non-quick rule, a later matching rule
     * overrides it because pf uses the last match unless a rule is quick.
     */
    function findingReason(r) {
        if (r.byPosition === 'later') {
            return 'Always overridden by the later rule "' + r.byName + '" (' + r.byAction + '): '
                + 'without "quick", the last matching rule wins.';
        }
        return 'Shadowed by "' + r.byName + '" (' + r.byAction + '), which comes earlier and always decides first.';
    }

    /** "WAN tcp 2222 -> 22" for a port forward */
    function forwardMapping(f) {
        var range = function (r) {
            return r ? (r[0] === r[1] ? String(r[0]) : r[0] + '-' + r[1]) : 'any';
        };
        return 'WAN ' + f.proto + ' ' + range(f.ext) + ' \u2192 ' + range(f.int);
    }

    /**
     * Why an empty pf table matters, in plain words. In OPNsense an alias
     * only fills pf's table when it's applied.
     */
    function emptyTableReason(t) {
        var n = t.rules.length;
        var uses = n + (n === 1 ? ' rule uses it' : ' rules use it');
        if (t.negated) {
            return 'This alias has no entries in the live firewall, and ' + uses
                + ' as "! ' + t.name + '", which therefore matches everything. '
                + 'If you just edited the alias, it may not have been applied (Firewall \u2192 Aliases \u2192 Apply).';
        }
        return 'This alias has no entries in the live firewall, so the ' + (n === 1 ? 'rule using it matches' : 'rules using it match')
            + ' nothing. If you just edited the alias, it may not have been applied (Firewall \u2192 Aliases \u2192 Apply).';
    }

    /**
     * Render the findings panel into `host` (browser only). Collapsed to a
     * one-line summary; expands to the list. Nothing is rendered when no
     * rule is dead.
     *
     * opts.onHover(target|null) / opts.onSelect(target): hovering / clicking
     * a card whose rule matches something on the graph (target from
     * findingHighlight()). Returns {setPinned(key|null)} so the caller can
     * mark the pinned card when the graph reports a pin change.
     */
    function renderFindings(host, graph, opts) {
        opts = opts || {};
        host.textContent = '';
        var cards = [];
        var controller = {
            setPinned: function (key) {
                cards.forEach(function (c) {
                    c.el.classList.toggle('cb-finding-pinned', key !== null && c.key === key);
                });
            }
        };
        var f = deadRuleFindings(graph, opts.ruleLink);
        var stale = opts.stale || [];
        var empty = graph.empty_tables || [];
        var inert = graph.inert_forwards || [];
        var badForwards = graph.forward_config || [];
        if (!f.own.length && !f.automatic.length && !stale.length && !empty.length && !inert.length && !badForwards.length) {
            return controller;
        }
        var mk = function (tag, cls, parent, textValue) {
            var e = document.createElement(tag);
            if (cls) {
                e.className = cls;
            }
            if (textValue !== undefined) {
                e.textContent = textValue;
            }
            if (parent) {
                parent.appendChild(e);
            }
            return e;
        };
        var dangerousEmpty = empty.filter(function (t) { return t.negated; }).length;
        var box = mk('details', 'cb-findings' + (f.contradicted || stale.length || dangerousEmpty || inert.length || badForwards.length ? ' cb-findings-alert' : ''), host);
        box.setAttribute('data-theme', opts.theme === 'light' ? 'light' : 'dark');
        var parts = [];
        if (inert.length || badForwards.length) {
            var nf = inert.length + badForwards.length;
            parts.push(nf + (nf === 1 ? ' port forward problem' : ' port forward problems'));
        }
        if (empty.length) {
            parts.push(empty.length + (empty.length === 1 ? ' empty alias' : ' empty aliases'));
        }
        if (f.contradicted) {
            parts.push(f.contradicted + (f.contradicted === 1 ? ' rule never takes effect' : ' rules never take effect'));
        }
        if (f.redundant) {
            parts.push(f.redundant + ' redundant');
        }
        if (stale.length) {
            parts.push(stale.length + (stale.length === 1 ? ' checked edge changed' : ' checked edges changed'));
        }
        if (!parts.length) {
            parts.push('No problems with your rules');
        }
        mk('summary', 'cb-findings-summary', box, 'Rule check: ' + parts.join(' \u00b7 '));

        var item = function (parent, r) {
            var row = mk('div', 'cb-finding cb-finding-' + r.kind, parent);
            mk('div', 'cb-finding-head', row, r.headline);
            var name = mk('div', 'cb-finding-name', row, r.name);
            name.title = r.name;
            var why = mk('div', 'cb-finding-why', row);
            why.appendChild(document.createTextNode(findingReason(r)));
            if (r.highlight) {
                row.classList.add('cb-finding-active');
                row.title = 'Hover to highlight the flows this rule was written for; click to keep them highlighted';
                row.addEventListener('mouseenter', function () {
                    if (typeof opts.onHover === 'function') {
                        opts.onHover(r.highlight);
                    }
                });
                row.addEventListener('mouseleave', function () {
                    if (typeof opts.onHover === 'function') {
                        opts.onHover(null);
                    }
                });
                row.addEventListener('click', function (evt) {
                    if (evt.target.closest('a')) {
                        return; // the rule links do their own thing
                    }
                    if (typeof opts.onSelect === 'function') {
                        opts.onSelect(r.highlight);
                    }
                });
                cards.push({ key: r.highlight.key, el: row });
            } else {
                mk('div', 'cb-finding-nomatch', row, 'Matches no device on the graph.');
            }
            var links = mk('div', 'cb-finding-links', row);
            [[r.link, 'Open rule'], [r.byLink, 'Open shadowing rule']].forEach(function (l) {
                if (l[0]) {
                    var a = mk('a', 'cb-card-link', links, l[1] + ' \u2197');
                    a.href = l[0];
                    a.target = '_blank';
                    a.rel = 'noopener noreferrer';
                }
            });
        };
        var listBox = mk('div', 'cb-findings-list', box);
        inert.forEach(function (fw) {
            var row = mk('div', 'cb-finding cb-finding-contradicted cb-finding-active', listBox);
            mk('div', 'cb-finding-head', row, 'Port forward does nothing');
            mk('div', 'cb-finding-name', row, forwardMapping(fw) + ' to ' + fw.device_name + ' (' + fw.target + ')');
            mk('div', 'cb-finding-why', row, 'The traffic is redirected, but no firewall rule allows it (Firewall Rule: Manual), so it is dropped. '
                + 'Add a WAN rule for it, or set the forward\'s Firewall Rule to Pass.');
            var hl = { key: 'fwd:' + fw.label, nodes: ['wan', fw.device], pairs: [['wan', fw.device]] };
            row.addEventListener('mouseenter', function () { if (typeof opts.onHover === 'function') { opts.onHover(hl); } });
            row.addEventListener('mouseleave', function () { if (typeof opts.onHover === 'function') { opts.onHover(null); } });
            row.addEventListener('click', function () { if (typeof opts.onSelect === 'function') { opts.onSelect(hl); } });
            cards.push({ key: hl.key, el: row });
        });
        badForwards.forEach(function (bf) {
            var row = mk('div', 'cb-finding cb-finding-contradicted', listBox);
            mk('div', 'cb-finding-head', row, 'Port forward looks wrong');
            mk('div', 'cb-finding-name', row, bf.descr);
            mk('div', 'cb-finding-why', row, 'Firewall \u2192 NAT \u2192 Destination NAT: ' + bf.problem + '.');
        });
        empty.forEach(function (t) {
            var row = mk('div', 'cb-finding ' + (t.negated ? 'cb-finding-contradicted' : 'cb-finding-redundant'), listBox);
            mk('div', 'cb-finding-head', row, t.negated ? 'Empty alias: matches everything' : 'Empty alias: matches nothing');
            mk('div', 'cb-finding-name', row, t.name);
            mk('div', 'cb-finding-why', row, emptyTableReason(t));
            var links = mk('div', 'cb-finding-links', row);
            t.rules.forEach(function (r) {
                var link = opts.ruleLink ? opts.ruleLink(r.label) : null;
                var a = mk(link ? 'a' : 'span', link ? 'cb-card-link' : 'cb-finding-why', links, (r.negated ? '! ' : '') + r.descr + (link ? ' \u2197' : ''));
                if (link) {
                    a.href = link;
                    a.target = '_blank';
                    a.rel = 'noopener noreferrer';
                }
            });
        });
        stale.forEach(function (st) {
            var row = mk('div', 'cb-finding cb-finding-stale cb-finding-active', listBox);
            mk('div', 'cb-finding-head', row, 'Changed since checked');
            mk('div', 'cb-finding-name', row, st.name);
            mk('div', 'cb-finding-why', row, 'What this edge allows has changed since you checked it. Click the edge on the graph to compare and re-confirm.');
            row.title = 'Hover to highlight this edge; click to keep it highlighted';
            row.addEventListener('mouseenter', function () {
                if (typeof opts.onHover === 'function') {
                    opts.onHover(st.highlight);
                }
            });
            row.addEventListener('mouseleave', function () {
                if (typeof opts.onHover === 'function') {
                    opts.onHover(null);
                }
            });
            row.addEventListener('click', function () {
                if (typeof opts.onSelect === 'function') {
                    opts.onSelect(st.highlight);
                }
            });
            cards.push({ key: st.highlight.key, el: row });
        });
        f.own.forEach(function (r) { item(listBox, r); });
        if (f.automatic.length) {
            var auto = mk('details', 'cb-findings-auto', listBox);
            mk('summary', null, auto, f.automatic.length + ' of OPNsense\'s own default rules are also shadowed (usually expected)');
            f.automatic.forEach(function (r) { item(auto, r); });
        }
        return controller;
    }

    // ------------------------------------------------------------------
    // Pair drill-down (layer 2)
    // ------------------------------------------------------------------

    var PROTO_ORDER = { tcp: 0, udp: 1, icmp: 2 };

    /**
     * Shape a pair response (topology/pair) for display: one section per
     * address family and target address, each row a protocol/port range
     * with its verdict, deciding rule and where it was decided. Pure.
     */
    function breakdownSections(resp, opts) {
        opts = opts || {};
        var rules = resp.rules || {};
        var where = function (stage) {
            var info = stage === 'out' ? resp.out_if : resp.in_if;
            var dir = stage === 'out' ? 'out' : 'in';
            return info ? dir + ' on ' + info.descr : dir;
        };
        return (resp.targets || []).map(function (t) {
            var v6 = t.family === 'inet6';
            var title = (v6 ? 'IPv6' : 'IPv4') + ' · ' + t.ip + (t.region ? ' (' + t.region + ')' : '')
                + (t.if_descr ? ' (' + t.if_descr + ' address)' : '');
            var rows = (t.slices || []).slice().sort(function (a, b) {
                var pa = PROTO_ORDER[a.proto] !== undefined ? PROTO_ORDER[a.proto] : 9;
                var pb = PROTO_ORDER[b.proto] !== undefined ? PROTO_ORDER[b.proto] : 9;
                return pa - pb || (a.from || 0) - (b.from || 0);
            }).map(function (sl) {
                var info = sl.rule ? (rules[sl.rule] || {}) : null;
                return {
                    proto: sl.proto,
                    ports: sl.from === null || sl.from === undefined ? ''
                        : (sl.from <= 1 && sl.to === 65535 ? 'any' : (sl.from === sl.to ? portText(sl.from, usePortNames) : sl.from + '-' + sl.to)),
                    verdict: sl.verdict,
                    rule: sl.rule ? {
                        label: sl.rule,
                        name: info.descr || ('rule ' + sl.rule.slice(0, 8)),
                        automatic: !!info.automatic,
                        link: opts.ruleLink ? opts.ruleLink(sl.rule) : null
                    } : null,
                    where: sl.rule && sl.rule.indexOf('fwd-') === 0 ? 'port forward' : where(sl.stage),
                    uncertain: (sl.uncertain || []).map(function (l) { return (rules[l] || {}).descr || l; }),
                    conditional: !!sl.conditional
                };
            });
            var allowedHere = rows.some(function (r) { return r.verdict === 'pass'; });
            return {
                title: title,
                // reaching the firewall's WAN address from an inside device
                // is correct pf behaviour, but easy to overlook: services
                // listening on WAN (GUI, SSH) are reachable this way
                note: t.on_wan && resp.src !== 'wan' && allowedHere
                    ? 'This is the firewall’s WAN address, reached from inside. Services listening on WAN (e.g. the web GUI or SSH) are reachable this way too.'
                    : null,
                family: v6 ? 'inet6' : 'inet',
                allowed: rows.filter(function (r) { return r.verdict === 'pass'; }).length,
                rows: rows
            };
        });
    }

    /**
     * Render the drill-down panel into `host` (browser only).
     * opts: nodes [{id, name}], nodeName(id), ruleLink, onChange(src, dst),
     * onClose().
     */
    function renderBreakdown(host, resp, opts) {
        opts = opts || {};
        host.textContent = '';
        host.hidden = false;
        var mk = function (tag, cls, parent, textValue) {
            var e = document.createElement(tag);
            if (cls) {
                e.className = cls;
            }
            if (textValue !== undefined) {
                e.textContent = textValue;
            }
            if (parent) {
                parent.appendChild(e);
            }
            return e;
        };
        var name = opts.nodeName || function (id) { return id; };

        var head = mk('div', 'cb-bd-head', host);
        mk('div', 'cb-bd-title', head, 'Full breakdown');
        var close = mk('button', 'cb-card-close', head, '×');
        close.type = 'button';
        close.setAttribute('aria-label', 'Close');
        close.addEventListener('click', function () {
            host.hidden = true;
            if (typeof opts.onClose === 'function') {
                opts.onClose();
            }
        });

        // from / to pickers
        var picks = mk('div', 'cb-bd-picks', host);
        var select = function (value, id) {
            var sel = mk('select', 'cb-bd-select', picks);
            sel.id = id;
            (opts.nodes || []).forEach(function (n) {
                var o = mk('option', null, sel, n.name);
                o.value = n.id;
                o.selected = n.id === value;
            });
            return sel;
        };
        var from = select(resp.src, 'cb-bd-from');
        var swap = mk('button', 'cb-bd-swap', picks, '⇄');
        swap.type = 'button';
        swap.title = 'Swap direction';
        var to = select(resp.dst, 'cb-bd-to');
        var changed = function (s, d) {
            if (typeof opts.onChange === 'function') {
                opts.onChange(s, d);
            }
        };
        from.addEventListener('change', function () { changed(from.value, to.value); });
        to.addEventListener('change', function () { changed(from.value, to.value); });
        swap.addEventListener('click', function () { changed(to.value, from.value); });

        var body = mk('div', 'cb-bd-body', host);
        if (resp.status !== 'ok') {
            mk('div', 'cb-card-note', body, 'Can’t show this pair: ' + (resp.error_msg || 'unknown error') + '.');
            return;
        }
        mk('div', 'cb-bd-pair', body, name(resp.src) + ' → ' + name(resp.dst));
        if (resp.kind === 'unfiltered') {
            mk('div', 'cb-card-note', body, 'Same network segment: this traffic never crosses the firewall, so no rule decides it. Everything is reachable.');
            return;
        }
        if (resp.src === 'wan' && resp.dst !== 'firewall') {
            mk('div', 'cb-card-note', body, 'Only ports reached through a port forward (or a public address) are listed. Anything else from the internet never gets to this device.');
        }
        (resp.forwards || []).forEach(function (f) {
            mk('div', 'cb-bd-forward', body, forwardMapping(f) + (f.pass ? ' · Firewall Rule: Pass' : (f.allowed ? ' · allowed by a rule' : ' · no rule allows it')));
        });
        var sections = breakdownSections(resp, opts);
        if (!sections.length) {
            mk('div', 'cb-card-note', body, 'Nothing to evaluate for this pair (no address in a common family, or no route).');
        }
        sections.forEach(function (sec) {
            mk('div', 'cb-card-section', body, sec.title + ' · ' + (sec.allowed ? sec.allowed + ' allowed' : 'nothing allowed'));
            if (sec.note) {
                mk('div', 'cb-card-note', body, sec.note);
            }
            var table = mk('div', 'cb-bd-table', body);
            sec.rows.forEach(function (r) {
                var row = mk('div', 'cb-bd-row cb-bd-' + (r.verdict === 'pass' ? 'pass' : 'block'), table);
                mk('div', 'cb-bd-ports', row, r.proto + (r.ports ? ' ' + r.ports : ''));
                mk('div', 'cb-bd-verdict', row, r.verdict === 'pass' ? 'allowed' : 'blocked');
                var who = mk('div', 'cb-bd-rule', row);
                if (r.rule) {
                    var n = mk(r.rule.link ? 'a' : 'span', 'cb-bd-rule-name', who, r.rule.name);
                    n.title = r.rule.name;
                    if (r.rule.link) {
                        n.href = r.rule.link;
                        n.target = '_blank';
                        n.rel = 'noopener noreferrer';
                    }
                    if (r.rule.automatic) {
                        mk('span', 'cb-card-badge cb-badge-default', who, 'OPNsense default');
                    }
                } else {
                    mk('span', 'cb-bd-rule-name cb-bd-muted', who, 'No rule matched (default deny)');
                }
                mk('div', 'cb-bd-where', row, r.where);
                if (r.uncertain.length || r.conditional) {
                    mk('div', 'cb-bd-note', row, (r.conditional ? 'Only from particular source ports. ' : '')
                        + (r.uncertain.length ? 'Uncertain because of: ' + r.uncertain.join(', ') : ''));
                }
            });
        });
    }

    // ------------------------------------------------------------------
    // Rendering (browser only)
    // ------------------------------------------------------------------

    function el(tag, attrs, parent) {
        var e = document.createElementNS(SVG_NS, tag);
        Object.keys(attrs || {}).forEach(function (k) {
            e.setAttribute(k, attrs[k]);
        });
        if (parent) {
            parent.appendChild(e);
        }
        return e;
    }

    function text(parent, x, y, value, cls) {
        var t = el('text', { x: x, y: y, 'class': cls }, parent);
        t.textContent = value;
        return t;
    }

    function tooltipLines(model, item) {
        var byId = {};
        model.nodes.forEach(function (n) { byId[n.id] = n; });
        if (item.kind) {
            var a = byId[item.from].name;
            var b = byId[item.to].name;
            if (item.kind === 'unfiltered') {
                return [a + ' ↔ ' + b, 'Same network segment: this traffic never crosses the firewall, so no rule can block it.'];
            }
            var lines = [a + ' → ' + b];
            if (item.allowed.length) {
                ruleRows(model, item, null).allowed.forEach(function (r) {
                    lines.push(truncate(r.name, TIP_RULE_CHARS) + ':  ' + truncate(r.ports, TIP_RULE_CHARS));
                });
            } else {
                lines.push('Nothing definitely allowed.');
            }
            if (item.conditional) {
                lines.push('Some allowed flows only match particular source ports.');
            }
            if (v6Exceeds(item.allowed || [])) {
                lines.push('IPv6 allows more than IPv4 here: check the IPv6 rules.');
            }
            if (item.regions && item.regions.length) {
                lines.push(item.regions.length + ' specific internet network(s) named in rules differ: see the card.');
            }
            if (item.uncertain) {
                lines.push('Uncertain because a rule could not be evaluated.');
            }
            if (item.checked) {
                lines.push('Checked by you.');
            } else if (item.stale) {
                lines.push('Changed since you checked it: click to compare and re-confirm.');
            } else if (item.isDefault) {
                lines.push('Allowed only by OPNsense\'s own default rules.');
            } else if (item.intended) {
                lines.push('Explicitly targeted by its rule(s).');
            } else if (item.allowed.length) {
                lines.push('Allowed by a broad rule (wider network or any): review.');
            }
            lines.push('Click the line for full rule details.');
            return lines;
        }
        if (item.type === 'firewall') {
            return ['This Firewall' + (item.ip ? ' (' + item.ip + ')' : ''), 'Arrows into this node: what devices can reach on the firewall itself (GUI, SSH, DNS, ...).'];
        }
        if (item.type === 'wan') {
            return item.evaluable
                ? ['WAN / Internet', 'Arrows into this node: what each device can reach on the internet.',
                    'Arrows out of it: what the internet can reach (port forwards, rules on WAN).']
                : ['WAN / Internet', 'No WAN interface found, so internet access is not evaluated.'];
        }
        var info = [item.name + (item.ip ? ' · ' + item.ip : '')];
        if (item.aliases && item.aliases.length) {
            info.push('Also known as: ' + item.aliases.join(', '));
        }
        if (item.ipv6 && item.ipv6.length) {
            info.push('IPv6: ' + item.ipv6.join(', ') + (item.ipv6Assumed
                ? ' (assumed from its MAC: not seen in the neighbour table yet)' : ''));
        }
        if (!item.evaluable) {
            info.push(item.if ? 'Not evaluated: IPv6-only (planned: Milestone 10).' : 'Not evaluated: no known interface.');
        }
        return info;
    }

    /**
     * Render into a container element. Returns a handle with destroy()
     * and positions() (current node centres, for saving a layout).
     *
     * opts.showUnfiltered, opts.positions, opts.layout ('star' or
     *   'columns'): see buildModel() / layout()
     * opts.theme: 'dark' (default for now) or 'light'
     * opts.ruleLink: function(label) -> URL to open a rule, or null
     * opts.reviews: {edgeId: fingerprint} saved audit sign-offs
     * opts.onReview: function(edgeId, fingerprint|null, snapshot|null) when
     *                the user checks/unchecks an edge (null = cleared)
     * opts.snapshots: {edgeId: text} what each checked edge allowed then
     * opts.filter: {hiddenSegments: [...], query: '...'} device filter
     * opts.portNames: show service names (tcp/ssh) instead of numbers
     * opts.onBreakdown(from, to): edge card's "Full breakdown" button
     * opts.onPairPick(nodeId): shift-click on a node
     * opts.onPinChange: function(setKey|null) when a pinned set (e.g. a
     *                dead-rule finding) is pinned or cleared
     */
    function render(container, graph, opts) {
        opts = opts || {};
        setPortNames(!!opts.portNames);
        var reviews = opts.reviews || {};
        opts.reviews = reviews; // one shared object: the model and later toggles agree
        var snapshots = opts.snapshots || {};
        opts.snapshots = snapshots;
        var model = layout(buildModel(graph, opts), opts.positions, opts.layout);
        var byId = {};
        model.nodes.forEach(function (n) { byId[n.id] = n; });

        container.innerHTML = '';
        container.classList.add('cb-topology');
        container.setAttribute('data-theme', opts.theme === 'light' ? 'light' : 'dark');
        var svg = el('svg', { 'class': 'cb-svg', width: '100%', height: '100%' }, container);
        var defs = el('defs', {}, svg);
        // sized in user space (not scaled by the line's stroke width) so the
        // heads stay small; a thick stroke on a short chevron keeps them bold
        ['filtered', 'uncertain', 'intended', 'default', 'checked', 'stale'].forEach(function (kind) {
            var m = el('marker', {
                id: 'cb-arrow-' + kind, viewBox: '0 0 10 10', refX: '8', refY: '5',
                markerWidth: '9', markerHeight: '9', markerUnits: 'userSpaceOnUse',
                orient: 'auto-start-reverse'
            }, defs);
            el('path', { d: 'M2,1.5 L8,5 L2,8.5', 'class': 'cb-arrow cb-arrow-' + kind }, m);
        });
        var viewport = el('g', {}, svg);
        var gSegments = el('g', {}, viewport);
        var gEdges = el('g', {}, viewport);
        var gLabels = el('g', {}, viewport);
        var gNodes = el('g', {}, viewport);

        var tip = document.createElement('div');
        tip.className = 'cb-tip';
        tip.hidden = true;
        container.appendChild(tip);

        function showTip(evt, lines) {
            tip.textContent = '';
            lines.forEach(function (line, i) {
                var div = document.createElement('div');
                div.textContent = line;
                if (i === 0) {
                    div.className = 'cb-tip-head';
                }
                tip.appendChild(div);
            });
            var box = container.getBoundingClientRect();
            tip.style.left = (evt.clientX - box.left + 14) + 'px';
            tip.style.top = (evt.clientY - box.top + 14) + 'px';
            tip.hidden = false;
        }
        function hideTip() {
            tip.hidden = true;
        }

        // --- edge detail card (click an edge): full rule names + links
        var edgeById = {};
        model.edges.forEach(function (e) { edgeById[e.id] = e; });
        var card = null;
        var lastCardEvt = null;
        function setChecked(e, checked) {
            var snapshot = checked ? snapshotText(model, e) : null;
            if (checked) {
                reviews[e.id] = e.fingerprint;
                snapshots[e.id] = snapshot;
            } else {
                delete reviews[e.id];
                delete snapshots[e.id];
            }
            withReview(e, reviews);
            drawEdges();
            if (typeof opts.onReview === 'function') {
                opts.onReview(e.id, checked ? e.fingerprint : null, snapshot);
            }
        }
        function closeCard() {
            if (card) {
                card.remove();
                card = null;
            }
        }
        function div(cls, parent, textValue) {
            var d = document.createElement('div');
            d.className = cls;
            if (textValue !== undefined) {
                d.textContent = textValue;
            }
            if (parent) {
                parent.appendChild(d);
            }
            return d;
        }
        function ruleLine(parent, r) {
            var row = div('cb-card-rule', parent);
            var name = div('cb-card-rule-name', row, r.name);
            name.title = r.name;
            if (r.link) {
                var a = document.createElement('a');
                a.className = 'cb-card-link';
                a.href = r.link;
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                a.textContent = 'Open rule ↗';
                row.appendChild(a);
            } else {
                div('cb-card-nolink', row, 'No direct link (auto-generated or legacy rule)');
            }
        }
        function openCard(e, evt) {
            closeCard();
            hideTip();
            card = div('cb-card', container);
            var head = div('cb-card-head', card);
            div('cb-card-title', head, byId[e.from].name + (e.kind === 'unfiltered' ? ' ↔ ' : ' → ') + byId[e.to].name);
            var close = document.createElement('button');
            close.type = 'button';
            close.className = 'cb-card-close';
            close.setAttribute('aria-label', 'Close');
            close.textContent = '×';
            close.addEventListener('click', closeCard);
            head.appendChild(close);

            if (e.kind === 'unfiltered') {
                div('cb-card-note', card, 'Same network segment: this traffic never crosses the firewall, so no rule can block it.');
            } else {
                var rows = ruleRows(model, e, opts.ruleLink);
                if (rows.allowed.length) {
                    div('cb-card-section', card, 'Allowed');
                    rows.allowed.forEach(function (r) {
                        var item = div('cb-card-item', card);
                        var portBox = div('cb-card-portbox', item);
                        div('cb-card-port', portBox, r.ports);
                        if (r.automatic) {
                            div('cb-card-badge cb-badge-default', portBox, 'OPNsense default');
                        } else {
                            div('cb-card-badge ' + (r.intended ? 'cb-badge-intended' : 'cb-badge-broad'), portBox, r.intended ? 'explicit' : 'broad rule');
                        }
                        var rulesBox = div('cb-card-rules', item);
                        ruleLine(rulesBox, r);
                    });
                } else {
                    div('cb-card-note', card, 'Nothing definitely allowed.');
                }
                if (rows.uncertain.length) {
                    div('cb-card-section', card, 'Uncertain because of');
                    var ub = div('cb-card-rules', card);
                    rows.uncertain.forEach(function (r) { ruleLine(ub, r); });
                }
                if (e.conditional) {
                    div('cb-card-note', card, 'Some allowed flows only match particular source ports.');
                }
            }

            if (e.forwards && e.forwards.length) {
                div('cb-card-section', card, 'Port forwards');
                e.forwards.forEach(function (f) {
                    var item = div('cb-card-item', card);
                    var portBox = div('cb-card-portbox', item);
                    div('cb-card-port', portBox, forwardMapping(f));
                    var box = div('cb-card-rules', item);
                    div('cb-card-rule-name', box, f.pass
                        ? 'Firewall Rule: Pass. The forward skips filter rules entirely.'
                        : (f.allowed ? 'Firewall Rule: Manual, allowed by the rules listed above.'
                            : 'Firewall Rule: Manual, but no rule allows it: the traffic is dropped.'));
                });
            }
            if (e.regions && e.regions.length) {
                div('cb-card-section', card, 'Specific internet networks (rules name these)');
                e.regions.forEach(function (rg) {
                    var item = div('cb-card-item', card);
                    var portBox = div('cb-card-portbox', item);
                    div('cb-card-port', portBox, rg.cidr);
                    var box = div('cb-card-rules', item);
                    if (!rg.allowed.length) {
                        div('cb-card-rule-name', box, 'Blocked');
                    } else {
                        ruleRows(model, { allowed: rg.allowed }, opts.ruleLink).allowed.forEach(function (r) {
                            div('cb-card-rule-name', box, r.ports + ' \u2014 ' + r.name);
                        });
                    }
                });
            }
            if (e.stale) {
                div('cb-card-note cb-card-stale', card, 'Changed since you checked it. The list above is what it allows now.');
                if (snapshots[e.id]) {
                    div('cb-card-section', card, 'When you checked it');
                    div('cb-card-snapshot', card, snapshots[e.id]);
                }
            }
            if (typeof opts.onBreakdown === 'function') {
                var bd = document.createElement('button');
                bd.type = 'button';
                bd.className = 'cb-card-check cb-card-secondary';
                bd.textContent = 'Full breakdown (everything allowed and blocked)';
                bd.addEventListener('click', function () {
                    closeCard();
                    opts.onBreakdown(e.from, e.to);
                });
                card.appendChild(bd);
            }
            var button = function (label, cls, onClick) {
                var b = document.createElement('button');
                b.type = 'button';
                b.className = 'cb-card-check' + (cls ? ' ' + cls : '');
                b.textContent = label;
                b.addEventListener('click', onClick);
                card.appendChild(b);
            };
            if (e.stale) {
                button('Re-confirm as checked', '', function () {
                    setChecked(e, true);
                    openCard(e, lastCardEvt);
                });
                button('Clear the old check', 'cb-card-secondary', function () {
                    setChecked(e, false);
                    openCard(e, lastCardEvt);
                });
            } else {
                button(e.checked ? '\u2713 Checked \u00b7 undo' : 'Mark as checked', e.checked ? 'cb-is-checked' : '', function () {
                    setChecked(e, !e.checked);
                    openCard(e, lastCardEvt);
                });
            }
            lastCardEvt = { clientX: evt.clientX, clientY: evt.clientY };

            var box = container.getBoundingClientRect();
            var x = evt.clientX - box.left + 12;
            var y = evt.clientY - box.top + 12;
            card.style.left = Math.max(8, Math.min(x, box.width - card.offsetWidth - 8)) + 'px';
            card.style.top = Math.max(8, Math.min(y, box.height - card.offsetHeight - 8)) + 'px';
        }
        function onKey(evt) {
            if (evt.key === 'Escape') {
                closeCard();
            }
        }
        document.addEventListener('keydown', onKey);

        // --- segments
        function drawSegments() {
            gSegments.textContent = '';
            segmentBoxes(model).forEach(function (b) {
                var box = el('path', { d: squirclePath(b.x, b.y, b.w, b.h, 18), 'class': 'cb-segment' }, gSegments);
                // drag a segment's box to move all its devices together
                box.addEventListener('pointerdown', function (evt) {
                    startDrag(evt, model.nodes.filter(function (n) { return n.segment === b.id; }));
                });
                // long names are cut to the box (11px bold capitals with
                // letter spacing: ~8.5px a character); the full name on hover
                var fits = Math.max(4, Math.floor((b.w - 32) / 8.5));
                var t = text(gSegments, b.x + 16, b.y + 19, truncate(b.label, fits), 'cb-segment-label');
                t.addEventListener('pointerdown', function (evt) {
                    startDrag(evt, model.nodes.filter(function (n) { return n.segment === b.id; }));
                });
                if (b.label.length > fits) {
                    el('title', {}, t).textContent = b.label;
                }
            });
        }

        // --- edges
        var edgeEls = {};
        var routes = {};
        var labelBoxes = {};
        function drawEdges() {
            gEdges.textContent = '';
            gLabels.textContent = '';
            edgeEls = {};
            routes = routeAll(model);
            labelBoxes = placeLabels(model, routes);
            model.edges.forEach(function (e) {
                var pts = routes[e.id];
                if (!pts) {
                    return;
                }
                var g = el('g', { 'class': 'cb-edge cb-edge-' + e.kind + ' cb-c-' + e.colour, 'data-edge': e.id }, gEdges);
                var d = roundedPath(pts);
                el('path', { d: d, 'class': 'cb-edge-hit' }, g);
                var line = el('path', { d: d, 'class': 'cb-edge-line' }, g);
                if (e.kind !== 'unfiltered') {
                    line.setAttribute('marker-end', 'url(#cb-arrow-' + e.colour + ')');
                }
                g.addEventListener('mousemove', function (evt) { showTip(evt, tooltipLines(model, e)); });
                g.addEventListener('mouseleave', hideTip);
                var parts = { g: g, label: null };
                var lb = labelBoxes[e.id];
                if (lb) {
                    var lg = el('g', { 'class': 'cb-label cb-c-' + e.colour, 'data-edge': e.id }, gLabels);
                    el('rect', { x: lb.x, y: lb.y, width: lb.w, height: lb.h, rx: lb.h / 2, 'class': 'cb-label-bg' }, lg);
                    text(lg, lb.x + lb.w / 2, lb.y + lb.h / 2 + 3.5, labelText(e), 'cb-label-text');
                    labelDots(pts, lb).forEach(function (p) {
                        el('circle', { cx: p.x, cy: p.y, r: 2.5, 'class': 'cb-label-dot' }, lg);
                    });
                    lg.addEventListener('mousemove', function (evt) { showTip(evt, tooltipLines(model, e)); });
                    lg.addEventListener('mouseleave', hideTip);
                    parts.label = lg;
                }
                edgeEls[e.id] = parts;
            });
            // redrawn edges (e.g. while dragging) start unhighlighted
            focusNode(focused);
        }

        // --- nodes
        function drawNodes() {
            gNodes.textContent = '';
            model.nodes.forEach(function (n) {
                var cls = 'cb-node cb-node-' + n.type + (n.evaluable || n.type !== 'device' ? '' : ' cb-node-off');
                var g = el('g', { 'class': cls, transform: 'translate(' + n.x + ',' + n.y + ')' }, gNodes);
                el('path', { d: squirclePath(0, 0, n.w, n.h, 14), 'class': 'cb-node-body' }, g);
                if (ICONS[n.type]) {
                    // firewall / WAN: icon above the name, all centred
                    var block = 32 + 10 + (n.ip ? 34 : 16);
                    var ig = el('g', { 'class': 'cb-node-icon', transform: 'translate(' + (n.w / 2 - 16) + ',' + ((n.h - block) / 2) + ') scale(1.3333)' }, g);
                    ICONS[n.type].forEach(function (d) { el('path', { d: d }, ig); });
                    var top = (n.h - block) / 2 + 42;
                    text(g, n.w / 2, top + 13, n.nameShown, 'cb-node-name');
                    if (n.ip) {
                        text(g, n.w / 2, top + 31, n.ip, 'cb-node-ip');
                    }
                } else if (n.ip) {
                    text(g, n.w / 2, 21, n.nameShown, 'cb-node-name');
                    text(g, n.w / 2, 37, n.ip, 'cb-node-ip');
                } else {
                    text(g, n.w / 2, 29, n.nameShown, 'cb-node-name');
                }
                n.el = g;
                g.addEventListener('mousemove', function (evt) { showTip(evt, tooltipLines(model, n)); });
                g.addEventListener('mouseleave', hideTip);
                // hover previews a node's edges; a pinned node (click) wins
                g.addEventListener('mouseenter', function () {
                    if (pinned === null) {
                        focusNode(n.id);
                    }
                });
                g.addEventListener('mouseleave', function () { focusNode(pinned); });
                g.addEventListener('pointerdown', function (evt) { startDrag(evt, n); });
            });
        }

        // Click a node to pin its highlight; click it again, another node,
        // or the background to change or clear it. Drags don't count.
        //
        // A highlight target is either a node id (string: that node's edges)
        // or a set {key, nodes: [ids], pairs: [[from, to], ...]} - e.g. the
        // flows a dead rule was written for. Sets also fade unrelated nodes.
        var pinned = null;
        var focused = null;
        function sameTarget(a, b) {
            if (a === null || b === null) {
                return a === b;
            }
            return typeof a === 'string' ? a === b : (typeof b === 'object' && a.key === b.key);
        }
        function pin(target) {
            pinned = target;
            model.nodes.forEach(function (n) {
                if (n.el) {
                    n.el.classList.toggle('cb-pinned', typeof pinned === 'string' && n.id === pinned);
                }
            });
            focusNode(pinned);
            if (typeof opts.onPinChange === 'function') {
                opts.onPinChange(pinned !== null && typeof pinned === 'object' ? pinned.key : null);
            }
        }

        function focusNode(target) {
            focused = target;
            var isSet = target !== null && typeof target === 'object';
            svg.classList.toggle('cb-focus', target !== null);
            svg.classList.toggle('cb-focus-set', isSet);
            var pairKeys = {};
            var nodeOn = {};
            if (isSet) {
                (target.pairs || []).forEach(function (p) {
                    pairKeys[p[0] + '>' + p[1]] = true;
                });
                (target.nodes || []).forEach(function (id) {
                    nodeOn[id] = true;
                });
            }
            model.edges.forEach(function (e) {
                var parts = edgeEls[e.id];
                if (!parts) {
                    return;
                }
                var on;
                if (isSet) {
                    // same-segment links are drawn once for both directions
                    on = pairKeys[e.from + '>' + e.to] || (e.kind === 'unfiltered' && pairKeys[e.to + '>' + e.from]);
                } else {
                    on = target !== null && (e.from === target || e.to === target);
                }
                parts.g.classList.toggle('cb-on', !!on);
                if (parts.label) {
                    parts.label.classList.toggle('cb-on', !!on);
                }
            });
            model.nodes.forEach(function (n) {
                if (n.el) {
                    n.el.classList.toggle('cb-on', isSet && !!nodeOn[n.id]);
                }
            });
        }

        // clicking anywhere outside the graph and the findings cards drops
        // a pinned set (node pins clear by clicking the graph background)
        function onDocClick(evt) {
            if (pinned === null || typeof pinned !== 'object') {
                return;
            }
            var t = evt.target;
            if (container.contains(t) || (t.closest && t.closest('.cb-finding'))) {
                return;
            }
            pin(null);
        }
        document.addEventListener('click', onDocClick);

        // --- pan / zoom / drag
        var view = { x: 0, y: 0, k: 1 };
        function applyView() {
            viewport.setAttribute('transform', 'translate(' + view.x + ',' + view.y + ') scale(' + view.k + ')');
        }
        function fit() {
            var box = container.getBoundingClientRect();
            var x1 = Infinity, y1 = Infinity, x2 = -Infinity, y2 = -Infinity;
            model.nodes.forEach(function (n) {
                x1 = Math.min(x1, n.x); y1 = Math.min(y1, n.y);
                x2 = Math.max(x2, n.x + n.w); y2 = Math.max(y2, n.y + n.h);
            });
            segmentBoxes(model).forEach(function (b) {
                x1 = Math.min(x1, b.x); y1 = Math.min(y1, b.y);
                x2 = Math.max(x2, b.x + b.w); y2 = Math.max(y2, b.y + b.h);
            });
            // labels and outer lanes can sit outside every node
            Object.keys(labelBoxes).forEach(function (id) {
                var b = labelBoxes[id];
                x1 = Math.min(x1, b.x); y1 = Math.min(y1, b.y);
                x2 = Math.max(x2, b.x + b.w); y2 = Math.max(y2, b.y + b.h);
            });
            Object.keys(routes).forEach(function (id) {
                (routes[id] || []).forEach(function (p) {
                    x1 = Math.min(x1, p.x); y1 = Math.min(y1, p.y);
                    x2 = Math.max(x2, p.x); y2 = Math.max(y2, p.y);
                });
            });
            var pad = 40;
            view.k = Math.min(1.25, (box.width - 2 * pad) / (x2 - x1), (box.height - 2 * pad) / (y2 - y1));
            view.x = (box.width - (x2 - x1) * view.k) / 2 - x1 * view.k;
            view.y = (box.height - (y2 - y1) * view.k) / 2 - y1 * view.k;
            applyView();
        }

        // drag one node, or a list of nodes (a whole segment) together;
        // drag.node is the single node, for clicks
        var drag = null;
        function startDrag(evt, what) {
            evt.stopPropagation();
            var list = Array.isArray(what) ? what : [what];
            drag = {
                node: Array.isArray(what) ? null : what,
                items: list.map(function (n) { return { n: n, ox: n.x, oy: n.y }; }),
                sx: evt.clientX,
                sy: evt.clientY,
                moved: false
            };
            svg.setPointerCapture(evt.pointerId);
        }
        var pan = null;
        svg.addEventListener('pointerdown', function (evt) {
            var hit = evt.target.closest ? evt.target.closest('[data-edge]') : null;
            pan = { sx: evt.clientX, sy: evt.clientY, ox: view.x, oy: view.y, moved: false, edge: hit ? hit.getAttribute('data-edge') : null };
            svg.setPointerCapture(evt.pointerId);
            svg.classList.add('cb-panning');
        });
        var frame = null;
        svg.addEventListener('pointermove', function (evt) {
            // a few pixels of jitter during a click isn't a drag
            var far = function (s) {
                return Math.abs(evt.clientX - s.sx) + Math.abs(evt.clientY - s.sy) > 3;
            };
            if (drag) {
                if (!drag.moved && !far(drag)) {
                    return;
                }
                drag.items.forEach(function (it) {
                    it.n.x = it.ox + (evt.clientX - drag.sx) / view.k;
                    it.n.y = it.oy + (evt.clientY - drag.sy) / view.k;
                    if (it.n.el) {
                        it.n.el.setAttribute('transform', 'translate(' + it.n.x + ',' + it.n.y + ')');
                    }
                });
                drag.moved = true;
                hideTip();
                if (!frame) {
                    frame = requestAnimationFrame(function () {
                        frame = null;
                        drawSegments();
                        drawEdges();
                    });
                }
            } else if (pan) {
                if (!pan.moved && !far(pan)) {
                    return;
                }
                pan.moved = true;
                view.x = pan.ox + evt.clientX - pan.sx;
                view.y = pan.oy + evt.clientY - pan.sy;
                applyView();
            }
        });
        function endPointer(evt) {
            if (drag && drag.moved && typeof opts.onMove === 'function') {
                opts.onMove(positions());
            }
            if (evt.type === 'pointerup') {
                if (drag && !drag.moved && !drag.node) {
                    // a click on a segment's box: like the background
                    pin(null);
                    closeCard();
                } else if (drag && !drag.moved && evt.shiftKey && typeof opts.onPairPick === 'function') {
                    // shift-click: pick nodes for the pair breakdown
                    opts.onPairPick(drag.node.id);
                } else if (drag && !drag.moved) {
                    pin(sameTarget(pinned, drag.node.id) ? null : drag.node.id);
                } else if (pan && !pan.moved && pan.edge) {
                    openCard(edgeById[pan.edge], evt);
                } else if (pan && !pan.moved) {
                    pin(null);
                    closeCard();
                }
            }
            drag = null;
            pan = null;
            svg.classList.remove('cb-panning');
        }
        svg.addEventListener('pointerup', endPointer);
        svg.addEventListener('pointercancel', endPointer);
        svg.addEventListener('wheel', function (evt) {
            evt.preventDefault();
            var box = container.getBoundingClientRect();
            var mx = evt.clientX - box.left;
            var my = evt.clientY - box.top;
            var k = Math.min(3, Math.max(0.2, view.k * (evt.deltaY < 0 ? 1.1 : 1 / 1.1)));
            view.x = mx - (mx - view.x) * (k / view.k);
            view.y = my - (my - view.y) * (k / view.k);
            view.k = k;
            applyView();
        }, { passive: false });

        function positions() {
            var out = {};
            model.nodes.forEach(function (n) {
                out[n.id] = { x: Math.round(n.x + n.w / 2), y: Math.round(n.y + n.h / 2) };
            });
            return out;
        }

        drawSegments();
        drawEdges();
        drawNodes();
        fit();

        return {
            fit: fit,
            positions: positions,
            // checked edges whose allowed set changed (for the Rule check bar)
            staleChecks: function () {
                return staleChecks(model);
            },
            // hover preview of a set; ignored while something is pinned
            preview: function (target) {
                if (pinned === null) {
                    focusNode(target);
                }
            },
            // click on a set: pin it, or unpin if it's already pinned
            togglePin: function (target) {
                pin(sameTarget(pinned, target) ? null : target);
            },
            clearPin: function () {
                pin(null);
            },
            destroy: function () {
                document.removeEventListener('keydown', onKey);
                document.removeEventListener('click', onDocClick);
                container.innerHTML = '';
            }
        };
    }

    var api = {
        decodeApi: decodeApi,
        setPortNames: setPortNames,
        nodeVisible: nodeVisible,
        segmentsOf: segmentsOf,
        snapshotText: snapshotText,
        staleChecks: staleChecks,
        render: render,
        buildModel: buildModel,
        layout: layout,
        segmentBoxes: segmentBoxes,
        routeAll: routeAll,
        countCrossings: countCrossings,
        placeLabels: placeLabels,
        ruleRows: ruleRows,
        deadRuleFindings: deadRuleFindings,
        findingReason: findingReason,
        breakdownSections: breakdownSections,
        renderBreakdown: renderBreakdown,
        forwardMapping: forwardMapping,
        emptyTableReason: emptyTableReason,
        renderFindings: renderFindings,
        mergeRanges: mergeRanges,
        v6Exceeds: v6Exceeds,
        formatPorts: formatPorts,
        fingerprint: fingerprint,
        roundedPath: roundedPath,
        squirclePath: squirclePath,
        labelPoint: labelPoint,
        labelDots: labelDots,
        tooltipLines: tooltipLines,
        formatAllowed: formatAllowed,
        edgeLabel: edgeLabel
    };
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    } else {
        root.ControlledBurn = api;
    }
})(typeof window !== 'undefined' ? window : this);
