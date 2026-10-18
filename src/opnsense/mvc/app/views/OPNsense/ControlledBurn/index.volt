{# versioned by the plugin's own file mtimes (see IndexController), not cache_safe() #}
<link rel="stylesheet" href="/ui/css/ControlledBurn/topology.css?v={{ cbAssetVersion }}">
<script src="/ui/js/ControlledBurn/topology.js?v={{ cbAssetVersion }}"></script>

<style>
    #cb-graph { height: 75vh; border-radius: 10px; }
    .cb-legend { display: flex; flex-wrap: wrap; gap: 0.4em 1.6em; align-items: center; }
    .cb-legend > span { display: inline-flex; align-items: center; gap: 0.5em; white-space: nowrap; }
    .cb-legend svg { overflow: visible; }
    .cb-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5em 1em; margin-top: 0.6em; }
    .cb-filter-text { display: inline-flex; align-items: center; gap: 0.4em; font-weight: normal; margin: 0; }
    .cb-filter-text input { width: 18em; max-width: 60vw; }
    .cb-filter-segments { display: inline-flex; flex-wrap: wrap; gap: 0.3em 1em; }
    .cb-filter-segments label { font-weight: normal; margin: 0; }
    .cb-toolbar-spacer { flex: 1; }
</style>

<div class="content-box" style="padding: 1em;">
    <div class="row">
        <div class="col-sm-8">
            <div class="cb-legend">
                <span><svg width="30" height="6"><line x1="2" y1="3" x2="28" y2="3" stroke="#4f9dff" stroke-width="2" stroke-linecap="round" stroke-dasharray="7 5"/></svg>{{ lang._('Explicitly targeted by its rule') }}</span>
                <span><svg width="30" height="6"><line x1="2" y1="3" x2="28" y2="3" stroke="#3ecf8e" stroke-width="2" stroke-linecap="round" stroke-dasharray="7 5"/></svg>{{ lang._('Checked by you') }}</span>
                <span><svg width="30" height="6"><line x1="2" y1="3" x2="28" y2="3" stroke="#b07cff" stroke-width="2" stroke-linecap="round" stroke-dasharray="7 5"/></svg>{{ lang._('OPNsense default rules only') }}</span>
                <span><svg width="30" height="6"><line x1="2" y1="3" x2="28" y2="3" stroke="#e8710a" stroke-width="2" stroke-linecap="round" stroke-dasharray="7 5"/></svg>{{ lang._('Allowed by a broad rule: review (dashes move in the allowed direction)') }}</span>
                <span><svg width="30" height="6"><line x1="2" y1="3" x2="28" y2="3" stroke="#b89100" stroke-width="2" stroke-linecap="round" stroke-dasharray="7 5"/></svg>{{ lang._('Possibly allowed (uncertain)') }}</span>
                <span><svg width="30" height="6"><line x1="2" y1="3" x2="28" y2="3" stroke="#9aa4ae" stroke-width="2" stroke-linecap="round" stroke-dasharray="3 4"/></svg>{{ lang._('Same segment: unfiltered') }}</span>
            </div>
        </div>
        <div class="col-sm-4 text-right">
            <select id="cb-layout" class="form-control input-sm" style="display: inline-block; width: auto; margin-right: 1em;" title="{{ lang._('Layout') }}">
                <option value="star">{{ lang._('Star layout') }}</option>
                <option value="columns">{{ lang._('Columns layout') }}</option>
            </select>
            <label style="font-weight: normal; margin-right: 1em;">
                <input type="checkbox" id="cb-show-unfiltered" checked> {{ lang._('Show same-segment links') }}
            </label>
            <label style="font-weight: normal; margin-right: 1em;">
                <input type="checkbox" id="cb-port-names"> {{ lang._('Port names') }}
            </label>
            <button class="btn btn-default btn-sm" id="cb-fit"><i class="fa fa-expand fa-fw"></i> {{ lang._('Fit') }}</button>
            <button class="btn btn-default btn-sm" id="cb-reload"><i class="fa fa-refresh fa-fw"></i> {{ lang._('Re-evaluate') }}</button>
        </div>
    </div>
    <div class="cb-toolbar">
        <label class="cb-filter-text">
            <i class="fa fa-search fa-fw"></i>
            <input type="search" id="cb-filter-query" class="form-control input-sm" placeholder="{{ lang._('Filter devices by name, IP or alias') }}">
        </label>
        <span id="cb-filter-segments" class="cb-filter-segments"></span>
        <span class="cb-toolbar-spacer"></span>
        <button class="btn btn-default btn-sm" id="cb-reset-layout"><i class="fa fa-th fa-fw"></i> {{ lang._('Reset layout') }}</button>
        <button class="btn btn-default btn-sm" id="cb-clear-checks"><i class="fa fa-eraser fa-fw"></i> {{ lang._('Clear all checks') }}</button>
    </div>
    <div id="cb-warnings" style="margin-top: 0.5em;"></div>
    <div id="cb-findings"></div>
    <div id="cb-graph-wrap" style="position: relative; margin-top: 0.5em;">
        <div id="cb-graph"></div>
        <div id="cb-breakdown" class="cb-breakdown" data-theme="dark" hidden></div>
        <div id="cb-pick-hint" class="alert alert-info" style="position: absolute; left: 12px; bottom: 12px; margin: 0; padding: 6px 10px;" hidden></div>
    </div>
    <p class="text-muted" style="margin-top: 0.5em;">
        <span class="pull-right" title="{{ lang._('Plugin build') }}">ControlledBurn {{ cbBuild }}</span>
        {{ lang._('Edges show what each device could start a connection to under the current rules, not live traffic. Hover for details, click an edge for its rules and to mark it checked, shift-click two nodes for a full breakdown, click a node to keep its links highlighted, drag nodes to rearrange, drag the background to pan, scroll to zoom.') }}
    </p>
</div>

<script>
    'use strict';

    $(document).ready(function () {
        var graph = null;      // decoded graph API response
        var network = null;    // ControlledBurn.render() handle
        var findings = null;   // ControlledBurn.renderFindings() handle
        var reviews = {};      // edge id -> fingerprint (audit sign-offs)
        var snapshots = {};    // edge id -> what it allowed when checked
        var positions = {};    // node id -> {x, y} saved positions (centres), current layout
        var savedLayouts = { star: {}, columns: {} };   // the same, per layout
        var FILTER_KEY = 'controlledburn.filter';

        // Warnings: a repeated message updates one alert with a counter
        // instead of stacking. Action warnings (opts.transient, e.g. a failed
        // save) fade out after WARN_FADE_MS; load-level ones stay until the
        // next load because they describe the current view.
        var WARN_FADE_MS = 30000;
        var shown = {};
        function warn(text, level, opts) {
            opts = opts || {};
            var key = (level || 'warning') + '|' + text;
            var entry = shown[key];
            if (entry) {
                entry.count++;
                entry.el.find('.cb-warn-count').text(' (\u00d7' + entry.count + ')');
            } else {
                var el = $('<div/>').addClass('alert alert-' + (level || 'warning')).css('margin-bottom', '0.5em');
                el.append($('<span/>').text(text)).append($('<span class="cb-warn-count"/>'));
                $('#cb-warnings').append(el);
                entry = shown[key] = { el: el, count: 1, timer: null };
            }
            if (opts.transient) {
                clearTimeout(entry.timer);
                entry.timer = setTimeout(function () {
                    entry.el.fadeOut(600, function () {
                        entry.el.remove();
                    });
                    delete shown[key];
                }, WARN_FADE_MS);
            }
            return entry.el;
        }
        function clearWarnings() {
            Object.keys(shown).forEach(function (k) {
                clearTimeout(shown[k].timer);
            });
            shown = {};
            $('#cb-warnings').empty();
        }

        // Why a save call failed, from what the API returned: validation
        // messages, an error message, or just the HTTP status.
        function failureReason(data, status) {
            if (data && data.validations) {
                var msgs = [];
                Object.keys(data.validations).forEach(function (field) {
                    [].concat(data.validations[field]).forEach(function (m) {
                        msgs.push(field.split('.').pop() + ': ' + m);
                    });
                });
                return msgs.slice(0, 3).join('; ') + (msgs.length > 3 ? ' (+' + (msgs.length - 3) + ' more)' : '');
            }
            if (data && (data.error_msg || data.errorMessage || data.message)) {
                return data.error_msg || data.errorMessage || data.message;
            }
            if (data && data.status && typeof data.status === 'number') {
                return 'HTTP ' + data.status + (data.statusText ? ' ' + data.statusText : '');
            }
            return status ? String(status) : 'no response';
        }
        function saveFailed(what, data, status) {
            warn(what + ' ' + ControlledBurn.decodeApi(failureReason(data, status)), 'danger', { transient: true });
        }

        // A stale cached topology.js (or any script error) used to leave the
        // page silently empty; say what happened instead.
        function failed(err) {
            if (window.console) {
                console.error(err);
            }
            warn("{{ lang._('The graph could not be drawn. If the plugin was just upgraded, your browser may be using an old copy of its script: reload with Ctrl+Shift+R. Otherwise check the browser console.') }}", 'danger');
        }

        // Newer-model rules are labelled by uuid in pf, and the Firewall ->
        // Rules page accepts #search=<phrase> (core opnsense_ui.js
        // getUrlHash). Legacy and auto-generated rules have md5 labels that
        // the page can't look up, so they get no link.
        function ruleLink(label) {
            return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(label)
                ? '/ui/firewall/filter#search=' + encodeURIComponent(label)
                : null;
        }

        // OPNsense HTML-escapes API responses; maps from PHP arrive as []
        // when empty
        function decodeMap(value) {
            var v = ControlledBurn.decodeApi(value || {});
            return Array.isArray(v) ? {} : v;
        }

        // ---- device filter (per browser, a viewing convenience)
        function loadFilter() {
            try {
                var f = JSON.parse(window.localStorage.getItem(FILTER_KEY) || '{}');
                return { query: f.query || '', hiddenSegments: Array.isArray(f.hiddenSegments) ? f.hiddenSegments : [] };
            } catch (e) {
                return { query: '', hiddenSegments: [] };
            }
        }
        function saveFilter(f) {
            try {
                window.localStorage.setItem(FILTER_KEY, JSON.stringify(f));
            } catch (e) {
                // storage unavailable: the filter just won't be remembered
            }
        }
        var filter = loadFilter();
        $('#cb-filter-query').val(filter.query);

        // port numbers vs service names (22 vs ssh), remembered per browser
        // ---- layout (per browser): star by default
        var LAYOUT_KEY = 'controlledburn.layout';
        function layoutMode() {
            return $('#cb-layout').val() === 'columns' ? 'columns' : 'star';
        }
        try {
            $('#cb-layout').val(window.localStorage.getItem(LAYOUT_KEY) === 'columns' ? 'columns' : 'star');
        } catch (e) {
            $('#cb-layout').val('star');
        }
        $('#cb-layout').change(function () {
            try {
                window.localStorage.setItem(LAYOUT_KEY, layoutMode());
            } catch (e) {
                // a viewing convenience only
            }
            positions = savedLayouts[layoutMode()];
            redraw();
        });

        var PORTNAMES_KEY = 'controlledburn.portNames';
        try {
            $('#cb-port-names').prop('checked', window.localStorage.getItem(PORTNAMES_KEY) === '1');
        } catch (e) {
            // storage unavailable: default to numbers
        }
        $('#cb-port-names').change(function () {
            try {
                window.localStorage.setItem(PORTNAMES_KEY, $(this).is(':checked') ? '1' : '0');
            } catch (e) {
                // not remembered, still applied
            }
            redraw();
        });

        function renderSegmentFilters() {
            var host = $('#cb-filter-segments').empty();
            var segs = ControlledBurn.segmentsOf(graph);
            if (segs.length < 2) {
                return; // nothing to choose between
            }
            segs.forEach(function (seg) {
                var box = $('<input type="checkbox"/>').prop('checked', filter.hiddenSegments.indexOf(seg.id) < 0);
                box.on('change', function () {
                    var hidden = filter.hiddenSegments.filter(function (id) { return id !== seg.id; });
                    if (!box.is(':checked')) {
                        hidden.push(seg.id);
                    }
                    filter.hiddenSegments = hidden;
                    saveFilter(filter);
                    redraw();
                });
                host.append($('<label/>').append(box).append(document.createTextNode(' ' + seg.label + ' (' + seg.count + ')')));
            });
        }

        // ---- saving
        function nodeType(id) {
            return id === 'firewall' || id === 'wan' ? id : 'device';
        }
        function saveLayout(centres) {
            // merge: nodes hidden by the filter keep their saved positions;
            // nodes no longer in the graph (devices gone, randomised MACs)
            // are dropped, so the saved layout doesn't grow forever
            var current = {};
            (graph ? graph.nodes : []).forEach(function (n) { current[n.id] = true; });
            var merged = $.extend({}, positions, centres);
            positions = {};
            Object.keys(merged).forEach(function (id) {
                if (current[id]) {
                    positions[id] = merged[id];
                }
            });
            savedLayouts[layoutMode()] = positions;
            var list = Object.keys(positions).map(function (id) {
                return { node_id: id, node_type: nodeType(id), x: positions[id].x, y: positions[id].y };
            });
            ajaxCall('/api/controlledburn/layout/set', { positions: list, layout: layoutMode() }, function (data, status) {
                if (status !== 'success' || !data || data.result !== 'saved') {
                    saveFailed("{{ lang._('Could not save the layout:') }}", data, status);
                } else if (Array.isArray(data.skipped) && data.skipped.length) {
                    warn("{{ lang._('Some node positions were not saved (unexpected node id; please report this):') }} "
                        + ControlledBurn.decodeApi(data.skipped).join(', '), 'warning', { transient: true });
                }
            });
        }
        function saveReview(edgeId, fingerprint, snapshot) {
            ajaxCall('/api/controlledburn/review/set', {
                edge_id: edgeId,
                fingerprint: fingerprint || '',
                snapshot: snapshot || '',
                checked: fingerprint ? '1' : '0'
            }, function (data, status) {
                if (status !== 'success' || !data || data.result !== 'saved') {
                    saveFailed("{{ lang._('Could not save the checked status (reload to see what was saved):') }}", data, status);
                }
            });
            renderRuleCheck();
        }

        // ---- pair drill-down
        var pickFrom = null;
        function nodeName(id) {
            var n = (graph && graph.nodes || []).find(function (x) { return x.id === id; });
            return n ? n.label.split('\n')[0] : id;
        }
        function openBreakdown(src, dst) {
            $('#cb-pick-hint').prop('hidden', true);
            pickFrom = null;
            ajaxGet('/api/controlledburn/topology/pair', { src: src, dst: dst }, function (data, status) {
                var resp = status === 'success' && data ? ControlledBurn.decodeApi(data)
                    : { status: 'failed', error_msg: failureReason(data, status), src: src, dst: dst };
                resp.src = resp.src || src;
                resp.dst = resp.dst || dst;
                ControlledBurn.renderBreakdown(document.getElementById('cb-breakdown'), resp, {
                    nodes: (graph.nodes || []).map(function (n) { return { id: n.id, name: n.label.split('\n')[0] }; }),
                    nodeName: nodeName,
                    ruleLink: ruleLink,
                    onChange: openBreakdown
                });
            });
        }
        function pickNode(id) {
            if (pickFrom === null || pickFrom === id) {
                pickFrom = id;
                $('#cb-pick-hint').text(nodeName(id) + " \u2192 {{ lang._('shift-click a second node for the full breakdown') }}").prop('hidden', false);
                return;
            }
            openBreakdown(pickFrom, id);
        }

        // ---- drawing
        function renderRuleCheck() {
            findings = ControlledBurn.renderFindings(document.getElementById('cb-findings'), graph, {
                ruleLink: ruleLink,
                stale: network !== null ? network.staleChecks() : [],
                onHover: function (target) {
                    if (network !== null) {
                        network.preview(target);
                    }
                },
                onSelect: function (target) {
                    if (network !== null) {
                        network.togglePin(target);
                    }
                }
            });
        }

        // Routing time grows faster than the edge count (~1.7s for 480
        // edges, ~4.6s for 960, and again on every drag): past AUTO_HIDE the
        // same-segment links are hidden unless the user asked for them;
        // past MAX_DRAW nothing is drawn until the filter narrows it.
        var AUTO_HIDE_EDGES = 400;
        var MAX_DRAW_EDGES = 1000;
        var unfilteredChosen = false;   // the user ticked "show" themselves
        function edgeCount(showUnfiltered) {
            return ControlledBurn.buildModel(graph, { showUnfiltered: showUnfiltered, filter: filter }).edges.length;
        }

        function draw() {
            if (network !== null) {
                network.destroy();
                network = null;
            }
            var box = $('#cb-show-unfiltered');
            if (box.is(':checked') && !unfilteredChosen && edgeCount(true) > AUTO_HIDE_EDGES && edgeCount(false) < edgeCount(true)) {
                box.prop('checked', false);
                warn("{{ lang._('Same-segment links are hidden: with them there are too many edges to draw quickly. Tick “Show same-segment links” to show them anyway, or narrow the view with the filter.') }}", 'info');
            }
            var count = edgeCount(box.is(':checked'));
            if (count > MAX_DRAW_EDGES) {
                $('#cb-graph').empty();
                warn(count + " {{ lang._('edges are too many to draw at once. Narrow the view with the filter or the segment checkboxes. If this network normally has far fewer devices, something may be flooding DHCP with made-up addresses: check the DHCP leases.') }}", 'warning');
                renderRuleCheck();
                return;
            }
            network = ControlledBurn.render(document.getElementById('cb-graph'), graph, {
                showUnfiltered: box.is(':checked'),
                portNames: $('#cb-port-names').is(':checked'),
                filter: filter,
                positions: positions,
                layout: layoutMode(),
                ruleLink: ruleLink,
                reviews: reviews,
                snapshots: snapshots,
                onMove: saveLayout,
                onReview: saveReview,
                onBreakdown: openBreakdown,
                onPairPick: pickNode,
                onPinChange: function (key) {
                    if (findings !== null) {
                        findings.setPinned(key);
                    }
                }
            });
            renderRuleCheck();
        }

        function redraw() {
            if (graph === null) {
                return;
            }
            try {
                draw();
            } catch (err) {
                failed(err);
            }
        }

        // ---- loading: saved state first, then the graph
        function load() {
            clearWarnings();
            $('#cb-reload').prop('disabled', true);
            ajaxGet('/api/controlledburn/review/get', {}, function (rdata, rstatus) {
                if (rstatus === 'success' && rdata) {
                    reviews = decodeMap(rdata.reviews);
                    snapshots = decodeMap(rdata.snapshots);
                } else {
                    reviews = {};
                    snapshots = {};
                    warn("{{ lang._('Could not load checked status; nothing is shown as checked.') }}", 'info');
                }
                ajaxGet('/api/controlledburn/layout/get', {}, function (ldata, lstatus) {
                    savedLayouts = { star: {}, columns: {} };
                    if (lstatus === 'success' && ldata && Array.isArray(ldata.positions)) {
                        ControlledBurn.decodeApi(ldata.positions).forEach(function (p) {
                            savedLayouts[p.layout === 'star' ? 'star' : 'columns'][p.node_id] = { x: p.x, y: p.y };
                        });
                    }
                    positions = savedLayouts[layoutMode()];
                    ajaxGet('/api/controlledburn/topology/graph', {}, loaded);
                });
            });
        }

        function loaded(data, status) {
            $('#cb-reload').prop('disabled', false);
            if (status === 'success' && data && data.too_many_devices) {
                graph = null;
                if (network !== null) {
                    network.destroy();
                    network = null;
                }
                warn(data.too_many_devices + " {{ lang._('devices found, more than ControlledBurn evaluates') }} (" + data.device_limit
                    + "). {{ lang._('If this network normally has far fewer, something may be flooding DHCP with made-up addresses: check the DHCP leases (Services > Dnsmasq DNS & DHCP > Leases).') }}", 'danger');
                return;
            }
            if (status !== 'success' || !data || !data.nodes) {
                warn("{{ lang._('Could not load the topology. Check the system log for errors.') }}", 'danger');
                return;
            }
            data = ControlledBurn.decodeApi(data);
            graph = data;
            if (data.unparsed_count > 0) {
                // list the skipped lines so it's clear which rules are missing
                var details = $('<details/>').css('margin-top', '0.4em');
                details.append($('<summary/>').css('cursor', 'pointer').text("{{ lang._('Show the lines that were skipped') }}"));
                var pre = $('<pre/>').css({ 'margin': '0.4em 0 0', 'white-space': 'pre-wrap', 'font-size': '11px' });
                pre.text((data.unparsed || []).join('\n') + (data.unparsed_count > (data.unparsed || []).length ? '\n...' : ''));
                details.append(pre);
                warn(data.unparsed_count + " {{ lang._('pf rule(s) could not be parsed and are not included. Verdicts may be incomplete.') }}").append(details);
            }
            if (data.edges.some(function (e) { return e.uncertain; })) {
                warn("{{ lang._('Some verdicts are uncertain because a rule could not be fully evaluated (e.g. an unresolved table). These are drawn in amber.') }}", 'info');
            }
            renderSegmentFilters();
            redraw();
        }

        // ---- controls
        $('#cb-reload').click(load);
        $('#cb-fit').click(function () {
            if (network !== null) {
                network.fit();
            }
        });
        $('#cb-show-unfiltered').change(function () {
            unfilteredChosen = $(this).is(':checked');
            redraw();
        });
        var queryTimer = null;
        $('#cb-filter-query').on('input', function () {
            clearTimeout(queryTimer);
            queryTimer = setTimeout(function () {
                filter.query = $('#cb-filter-query').val();
                saveFilter(filter);
                redraw();
            }, 200);
        });

        $('#cb-reset-layout').click(function () {
            stdDialogConfirm(
                "{{ lang._('Reset layout') }}",
                "{{ lang._('Move every node back to its default position in this layout? Your saved arrangement for it will be lost (the other layout keeps its own).') }}",
                "{{ lang._('Reset') }}", "{{ lang._('Cancel') }}",
                function () {
                    var mode = layoutMode();
                    ajaxCall('/api/controlledburn/layout/reset', { layout: mode }, function (data, status) {
                        if (status !== 'success' || !data || data.result !== 'saved') {
                            saveFailed("{{ lang._('Could not reset the layout:') }}", data, status);
                            return;
                        }
                        savedLayouts[mode] = {};
                        positions = savedLayouts[layoutMode()];
                        redraw();
                    });
                }, 'warning');
        });

        $('#cb-clear-checks').click(function () {
            var count = Object.keys(reviews).length;
            stdDialogConfirm(
                "{{ lang._('Clear all checks') }}",
                count + " {{ lang._('checked edge(s) will go back to unchecked. This cannot be undone.') }}",
                "{{ lang._('Clear all') }}", "{{ lang._('Cancel') }}",
                function () {
                    ajaxCall('/api/controlledburn/review/reset', {}, function (data, status) {
                        if (status !== 'success' || !data || data.result !== 'saved') {
                            saveFailed("{{ lang._('Could not clear the checks:') }}", data, status);
                            return;
                        }
                        reviews = {};
                        snapshots = {};
                        redraw();
                    });
                }, 'danger');
        });

        load();
    });
</script>
