(function () {
    "use strict";

    var EVENTS = window.TRACE_EVENTS;
    var SUMMARY = window.TRACE_SUMMARY;

    // --- Helpers ---
    function formatBytes(b) {
        if (b >= 1073741824) return (b / 1073741824).toFixed(1) + " GB";
        if (b >= 1048576) return (b / 1048576).toFixed(1) + " MB";
        if (b >= 1024) return (b / 1024).toFixed(1) + " KB";
        return b + " B";
    }

    function eventType(e) { return e.type; }

    function eventCategory(e) {
        switch (e.type) {
            case "open": return "file";
            case "connect": case "send": case "recv": return "network";
            case "brk": case "mmap": case "fault": case "fault_group": return "memory";
            case "read": case "write": case "copy_file_range": case "sendfile": return "io";
            case "sched_delay": case "block_io": case "block_io_group": return "kernel";
            case "spawn_process": case "spawn_thread": case "exec": case "exit_thread": case "truncated": return "process";
            default: return "file";
        }
    }

    function catColor(cat) {
        switch (cat) {
            case "file": return "#3b82f6";
            case "network": return "#22c55e";
            case "memory": return "#f97316";
            case "io": return "#a855f7";
            case "kernel": return "#06b6d4";
            case "process": return "#ef4444";
            default: return "#64748b";
        }
    }

    function formatNs(ns) {
        if (ns >= 1000000000) return (ns / 1000000000).toFixed(1) + "s";
        if (ns >= 1000000) return (ns / 1000000).toFixed(1) + "ms";
        if (ns >= 1000) return Math.round(ns / 1000) + "us";
        return ns + "ns";
    }

    function formatEventDetail(e) {
        switch (e.type) {
            case "open": return e.path + (e.writable ? " (write)" : " (read)");
            case "connect": return e.sock_type + " → " + e.remote_addr;
            case "brk": return "+" + formatBytes(e.growth_bytes);
            case "mmap": return e.addr + "-" + e.end_addr + " " + e.prot + " " + formatBytes(e.size) + " " + e.map_type;
            case "read": return (e.count > 1 ? e.count + "\u00d7 " : "") + formatBytes(e.bytes) + " from " + e.filename;
            case "write": return (e.count > 1 ? e.count + "\u00d7 " : "") + formatBytes(e.bytes) + " to " + e.filename;
            case "send": return (e.count > 1 ? e.count + "\u00d7 " : "") + formatBytes(e.bytes);
            case "recv": return (e.count > 1 ? e.count + "\u00d7 " : "") + formatBytes(e.bytes);
            case "copy_file_range": return formatBytes(e.bytes) + " " + e.src_name + " → " + e.dst_name;
            case "sendfile": return formatBytes(e.bytes) + " " + e.src_name + " → " + (e.to_network ? "net" : e.dst_name);
            case "spawn_process": return "pid " + e.child_pid;
            case "spawn_thread": return "tid " + e.child_tid;
            case "exec": return e.program;
            case "exit_thread": return "pid " + e.exit_pid + (e.code != null ? " code " + e.code : "") + (e.signal != null ? " signal " + e.signal : "");
            case "fault": return e.addr + " in " + e.region_name + " (" + e.prot + ")";
            case "fault_group": return e.count + " faults in " + e.region_name + " @ " + e.region_start + " (" + e.prot + ")";
            case "sched_delay": return "waited " + formatNs(e.delay_ns);
            case "block_io": return formatNs(e.latency_ns) + " (" + formatBytes(e.bytes) + ")";
            case "block_io_group": return e.count + "\u00d7 " + formatBytes(e.bytes_per_op) + " (" + formatBytes(e.total_bytes) + " total) avg " + formatNs(e.avg_latency_ns) + " / max " + formatNs(e.max_latency_ns);
            case "truncated": return "showing " + e.kept_count + " of " + e.original_count + " events";
            default: return "";
        }
    }

    // --- Summary cards ---
    function renderCards() {
        var container = document.getElementById("cards");
        var cards = [
            { label: "Memory", value: formatBytes(SUMMARY.total_memory), detail: "heap " + formatBytes(SUMMARY.heap_bytes) + " + mmap " + formatBytes(SUMMARY.mmap_bytes) },
            { label: "File I/O", value: formatBytes(SUMMARY.file_bytes_read + SUMMARY.file_bytes_written), detail: "read " + formatBytes(SUMMARY.file_bytes_read) + " / write " + formatBytes(SUMMARY.file_bytes_written) },
            { label: "Network", value: formatBytes(SUMMARY.net_bytes_sent + SUMMARY.net_bytes_received), detail: SUMMARY.connections.length + " connection" + (SUMMARY.connections.length !== 1 ? "s" : "") },
            { label: "Files", value: String(SUMMARY.files_read + SUMMARY.files_written), detail: SUMMARY.files_read + " read / " + SUMMARY.files_written + " written" },
            { label: "Process", value: SUMMARY.exit_status, detail: SUMMARY.duration_display }
        ];
        if (SUMMARY.perf_enabled) {
            cards.push({ label: "Page Faults", value: String(SUMMARY.page_faults), detail: formatBytes(SUMMARY.page_fault_bytes) + " touched" });
        }
        if (SUMMARY.ebpf_enabled && SUMMARY.sched_delays > 0) {
            cards.push({ label: "Sched Latency", value: String(SUMMARY.sched_delays), detail: "avg " + formatNs(SUMMARY.avg_sched_delay_ns) + " / max " + formatNs(SUMMARY.max_sched_delay_ns) });
        }
        if (SUMMARY.ebpf_enabled && SUMMARY.block_io_ops > 0) {
            cards.push({ label: "Block I/O", value: String(SUMMARY.block_io_ops), detail: "avg " + formatNs(SUMMARY.avg_block_io_ns) + " / max " + formatNs(SUMMARY.max_block_io_ns) });
        }
        cards.forEach(function (c) {
            var div = document.createElement("div");
            div.className = "card";
            div.innerHTML = '<div class="label">' + c.label + '</div><div class="value">' + c.value + '</div><div class="detail">' + c.detail + '</div>';
            container.appendChild(div);
        });
    }

    // --- Filters ---
    var activeFilters = { file: true, network: true, memory: true, io: true, kernel: true, process: true };
    var activeTypes = {};
    EVENTS.forEach(function (ev) { activeTypes[ev.kind.type] = true; });

    // PID → program name (from exec events, last exec wins)
    var pidProgram = {};
    EVENTS.forEach(function (ev) {
        if (ev.kind.type === "exec") pidProgram[ev.pid] = ev.kind.program;
    });

    // Parent-child relationships + root PID detection
    var pidParent = {};
    var rootPid = EVENTS.length > 0 ? EVENTS[0].pid : 0;
    var threadTids = {};
    EVENTS.forEach(function (ev) {
        if (ev.kind.type === "spawn_process") pidParent[ev.kind.child_pid] = ev.pid;
        else if (ev.kind.type === "spawn_thread") {
            pidParent[ev.kind.child_tid] = ev.pid;
            threadTids[ev.kind.child_tid] = true;
        }
    });

    // All unique PIDs in event order
    var allPids = [];
    var allPidSet = {};
    EVENTS.forEach(function (ev) {
        if (!allPidSet[ev.pid]) { allPidSet[ev.pid] = true; allPids.push(ev.pid); }
    });

    // Group non-root, non-thread PIDs by program name
    var programGroups = {};  // name → [pid, ...]
    allPids.forEach(function (pid) {
        if (pid === rootPid || threadTids[pid]) return;
        var name = pidProgram[pid] || ("pid " + pid);
        if (!programGroups[name]) programGroups[name] = [];
        programGroups[name].push(pid);
    });

    // Active PID filter state — root + root's threads visible, rest hidden
    var activePids = {};
    allPids.forEach(function (pid) {
        activePids[pid] = (pid === rootPid) ||
            (threadTids[pid] && pidParent[pid] === rootPid);
    });

    function renderFilters() {
        var container = document.getElementById("filters");
        ["file", "network", "memory", "io", "kernel", "process"].forEach(function (cat) {
            var btn = document.createElement("button");
            btn.className = "filter-pill active";
            btn.style.setProperty("--cat-color", catColor(cat));
            btn.innerHTML = '<span class="filter-dot"></span>' + cat.charAt(0).toUpperCase() + cat.slice(1);
            btn.dataset.cat = cat;
            btn.addEventListener("click", function () {
                activeFilters[cat] = !activeFilters[cat];
                btn.className = "filter-pill " + (activeFilters[cat] ? "active" : "inactive");
                applyFilters();
            });
            container.appendChild(btn);
        });
    }

    function applyFilters() {
        renderTimelineSVG();
        renderVisibleRows();
        updateTypeButtonLabel();
        updateProcessButtonLabel();
    }

    var typeFilterBtn;

    function updateTypeButtonLabel() {
        if (!typeFilterBtn) return;
        var types = Object.keys(activeTypes);
        var activeCount = types.filter(function (t) { return activeTypes[t]; }).length;
        typeFilterBtn.textContent = "Types (" + activeCount + "/" + types.length + ") \u25be";
    }

    function renderTypeFilter() {
        var container = document.getElementById("filters");
        var wrap = document.createElement("div");
        wrap.className = "type-filter-wrap";

        typeFilterBtn = document.createElement("button");
        typeFilterBtn.className = "type-filter-btn";
        updateTypeButtonLabel();

        var dropdown = document.createElement("div");
        dropdown.className = "type-dropdown hidden";

        // All / None actions
        var actions = document.createElement("div");
        actions.className = "type-dropdown-actions";
        var allLink = document.createElement("a");
        allLink.href = "#";
        allLink.textContent = "All";
        allLink.addEventListener("click", function (e) {
            e.preventDefault();
            Object.keys(activeTypes).forEach(function (t) { activeTypes[t] = true; });
            dropdown.querySelectorAll('input[type="checkbox"]').forEach(function (cb) { cb.checked = true; });
            applyFilters();
        });
        var noneLink = document.createElement("a");
        noneLink.href = "#";
        noneLink.textContent = "None";
        noneLink.addEventListener("click", function (e) {
            e.preventDefault();
            Object.keys(activeTypes).forEach(function (t) { activeTypes[t] = false; });
            dropdown.querySelectorAll('input[type="checkbox"]').forEach(function (cb) { cb.checked = false; });
            applyFilters();
        });
        actions.appendChild(allLink);
        actions.appendChild(noneLink);
        dropdown.appendChild(actions);

        // Count events per type
        var typeCounts = {};
        EVENTS.forEach(function (ev) {
            var t = ev.kind.type;
            typeCounts[t] = (typeCounts[t] || 0) + 1;
        });

        // Sorted type list
        var types = Object.keys(activeTypes).sort();
        types.forEach(function (t) {
            var label = document.createElement("label");
            var cb = document.createElement("input");
            cb.type = "checkbox";
            cb.checked = true;
            cb.addEventListener("change", function () {
                activeTypes[t] = cb.checked;
                applyFilters();
            });
            var nameSpan = document.createElement("span");
            nameSpan.className = "type-name";
            nameSpan.textContent = t;
            var countSpan = document.createElement("span");
            countSpan.className = "type-count";
            countSpan.textContent = typeCounts[t] || 0;
            label.appendChild(cb);
            label.appendChild(nameSpan);
            label.appendChild(countSpan);
            dropdown.appendChild(label);
        });

        // Toggle dropdown
        typeFilterBtn.addEventListener("click", function (e) {
            e.stopPropagation();
            dropdown.classList.toggle("hidden");
        });

        // Close on outside click
        document.addEventListener("click", function (e) {
            if (!wrap.contains(e.target)) {
                dropdown.classList.add("hidden");
            }
        });

        wrap.appendChild(typeFilterBtn);
        wrap.appendChild(dropdown);
        container.appendChild(wrap);
    }

    // --- Process filter dropdown ---
    var processFilterBtn;

    function updateProcessButtonLabel() {
        if (!processFilterBtn) return;
        var activeCount = 0;
        allPids.forEach(function (pid) { if (activePids[pid]) activeCount++; });
        processFilterBtn.textContent = "Processes (" + activeCount + "/" + allPids.length + ") \u25be";
    }

    function renderProcessFilter() {
        var container = document.getElementById("filters");
        var wrap = document.createElement("div");
        wrap.className = "type-filter-wrap";

        processFilterBtn = document.createElement("button");
        processFilterBtn.className = "type-filter-btn";
        updateProcessButtonLabel();

        var dropdown = document.createElement("div");
        dropdown.className = "type-dropdown hidden";

        // All / None actions
        var actions = document.createElement("div");
        actions.className = "type-dropdown-actions";
        var allLink = document.createElement("a");
        allLink.href = "#";
        allLink.textContent = "All";
        allLink.addEventListener("click", function (e) {
            e.preventDefault();
            allPids.forEach(function (pid) { activePids[pid] = true; });
            dropdown.querySelectorAll('input[type="checkbox"]').forEach(function (cb) { cb.checked = true; });
            applyFilters();
        });
        var noneLink = document.createElement("a");
        noneLink.href = "#";
        noneLink.textContent = "None";
        noneLink.addEventListener("click", function (e) {
            e.preventDefault();
            allPids.forEach(function (pid) { activePids[pid] = false; });
            dropdown.querySelectorAll('input[type="checkbox"]').forEach(function (cb) { cb.checked = false; });
            applyFilters();
        });
        actions.appendChild(allLink);
        actions.appendChild(noneLink);
        dropdown.appendChild(actions);

        // Root process entry
        var rootName = pidProgram[rootPid] || ("pid " + rootPid);
        var rootLabel = document.createElement("label");
        rootLabel.className = "proc-root";
        var rootCb = document.createElement("input");
        rootCb.type = "checkbox";
        rootCb.checked = !!activePids[rootPid];
        rootCb.addEventListener("change", function () {
            activePids[rootPid] = rootCb.checked;
            // Also toggle root's threads
            allPids.forEach(function (pid) {
                if (threadTids[pid] && pidParent[pid] === rootPid) {
                    activePids[pid] = rootCb.checked;
                }
            });
            applyFilters();
        });
        var rootNameSpan = document.createElement("span");
        rootNameSpan.className = "type-name";
        rootNameSpan.textContent = rootName + " (root)";
        var rootCountSpan = document.createElement("span");
        rootCountSpan.className = "type-count";
        rootCountSpan.textContent = "pid " + rootPid;
        rootLabel.appendChild(rootCb);
        rootLabel.appendChild(rootNameSpan);
        rootLabel.appendChild(rootCountSpan);
        dropdown.appendChild(rootLabel);

        // Separator
        var sep = document.createElement("div");
        sep.className = "proc-separator";
        dropdown.appendChild(sep);

        // Sorted program groups
        var groupNames = Object.keys(programGroups).sort();
        groupNames.forEach(function (name) {
            var pids = programGroups[name];
            var label = document.createElement("label");
            var cb = document.createElement("input");
            cb.type = "checkbox";
            cb.checked = pids.some(function (pid) { return activePids[pid]; });
            cb.addEventListener("change", function () {
                pids.forEach(function (pid) {
                    activePids[pid] = cb.checked;
                    // Also toggle threads of these PIDs
                    allPids.forEach(function (tid) {
                        if (threadTids[tid] && pidParent[tid] === pid) {
                            activePids[tid] = cb.checked;
                        }
                    });
                });
                applyFilters();
            });
            var nameSpan = document.createElement("span");
            nameSpan.className = "type-name";
            nameSpan.textContent = name;
            var countSpan = document.createElement("span");
            countSpan.className = "type-count";
            countSpan.textContent = pids.length === 1 ? "pid " + pids[0] : pids.length + " processes";
            label.appendChild(cb);
            label.appendChild(nameSpan);
            label.appendChild(countSpan);
            dropdown.appendChild(label);
        });

        // Toggle dropdown
        processFilterBtn.addEventListener("click", function (e) {
            e.stopPropagation();
            dropdown.classList.toggle("hidden");
        });

        // Close on outside click
        document.addEventListener("click", function (e) {
            if (!wrap.contains(e.target)) {
                dropdown.classList.add("hidden");
            }
        });

        wrap.appendChild(processFilterBtn);
        wrap.appendChild(dropdown);
        container.appendChild(wrap);
    }

    function getFilteredEvents() {
        return EVENTS.filter(function (ev) {
            return activePids[ev.pid] && activeFilters[eventCategory(ev.kind)] && activeTypes[ev.kind.type];
        });
    }

    // --- SVG Timeline ---
    var timelineZoom = 1;
    var timelineContainer;
    var basePlotW = 760;

    function initTimeline() {
        var el = document.getElementById("timeline");
        if (EVENTS.length === 0) {
            el.innerHTML = '<p style="color:#64748b;padding:20px">No events recorded.</p>';
            return;
        }

        timelineContainer = el.parentElement; // .timeline-section

        document.addEventListener("wheel", function (e) {
            if (!e.ctrlKey && !e.metaKey) return;

            var rect = timelineContainer.getBoundingClientRect();
            if (e.clientX < rect.left || e.clientX > rect.right ||
                e.clientY < rect.top || e.clientY > rect.bottom) return;

            e.preventDefault();
            var mouseX = e.clientX - rect.left + timelineContainer.scrollLeft;
            var margin = { left: 120 };
            var currentPlotW = basePlotW * timelineZoom;
            var mouseFrac = (mouseX - margin.left) / currentPlotW;

            if (e.deltaY < 0) {
                timelineZoom *= 1.3;
            } else {
                timelineZoom /= 1.3;
            }
            timelineZoom = Math.max(1, Math.min(50, timelineZoom));

            renderTimelineSVG();

            var newPlotW = basePlotW * timelineZoom;
            var newMouseX = margin.left + mouseFrac * newPlotW;
            timelineContainer.scrollLeft = newMouseX - (e.clientX - rect.left);
        }, { passive: false });

        document.addEventListener("keydown", function (e) {
            if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
            if (e.key === "+" || e.key === "=") {
                timelineZoom = Math.min(50, timelineZoom * 1.3);
                renderTimelineSVG();
            } else if (e.key === "-") {
                timelineZoom = Math.max(1, timelineZoom / 1.3);
                renderTimelineSVG();
            } else if (e.key === "0") {
                timelineZoom = 1;
                renderTimelineSVG();
                timelineContainer.scrollLeft = 0;
            }
        });

        timelineContainer.addEventListener("dblclick", function () {
            timelineZoom = 1;
            renderTimelineSVG();
            timelineContainer.scrollLeft = 0;
        });

        var resizeTimer;
        window.addEventListener("resize", function () {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(renderTimelineSVG, 150);
        });

        renderTimelineSVG();
    }

    function renderTimelineSVG() {
        var container = document.getElementById("timeline");
        container.innerHTML = "";

        var pids = [];
        var pidSet = {};
        EVENTS.forEach(function (ev) {
            if (!pidSet[ev.pid] && activePids[ev.pid]) { pidSet[ev.pid] = true; pids.push(ev.pid); }
        });

        var maxT = SUMMARY.duration_secs || 1;
        var margin = { left: 120, right: 20, top: 30, bottom: 20 };
        var laneH = 28;

        // Compute base plot width from container so timeline fills the box
        var containerW = container.clientWidth || 900;
        basePlotW = Math.max(containerW - margin.left - margin.right, 460);

        var plotW = basePlotW * timelineZoom;
        var totalW = margin.left + plotW + margin.right;
        var h = margin.top + pids.length * laneH + margin.bottom;

        var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("class", "timeline-svg");
        svg.setAttribute("viewBox", "0 0 " + totalW + " " + h);
        svg.setAttribute("preserveAspectRatio", "xMinYMin meet");
        if (timelineZoom > 1) {
            svg.style.width = totalW + "px";
        }

        // Swimlane backgrounds
        pids.forEach(function (pid, i) {
            var rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
            rect.setAttribute("x", margin.left);
            rect.setAttribute("y", margin.top + i * laneH);
            rect.setAttribute("width", plotW);
            rect.setAttribute("height", laneH);
            rect.setAttribute("class", i % 2 === 0 ? "swimlane-bg" : "swimlane-bg-alt");
            svg.appendChild(rect);

            var label = document.createElementNS("http://www.w3.org/2000/svg", "text");
            label.setAttribute("x", margin.left - 8);
            label.setAttribute("y", margin.top + i * laneH + laneH / 2 + 4);
            label.setAttribute("text-anchor", "end");
            if (threadTids[pid]) {
                label.setAttribute("class", "swimlane-label swimlane-label-thread");
                var parentName = pidProgram[pid] || pidProgram[pidParent[pid]];
                label.textContent = "\u21b3 " + (parentName ? parentName + " (" + pid + ")" : String(pid));
            } else {
                label.setAttribute("class", "swimlane-label");
                label.textContent = pidProgram[pid] ? pidProgram[pid] + " (" + pid + ")" : String(pid);
            }
            svg.appendChild(label);
        });

        // Time axis
        var ticks = Math.min(Math.ceil(5 * timelineZoom), 50);
        for (var t = 0; t <= ticks; t++) {
            var x = margin.left + (t / ticks) * plotW;
            var timeVal = (t / ticks) * maxT;
            var line = document.createElementNS("http://www.w3.org/2000/svg", "line");
            line.setAttribute("x1", x); line.setAttribute("y1", margin.top - 5);
            line.setAttribute("x2", x); line.setAttribute("y2", margin.top + pids.length * laneH);
            line.setAttribute("class", "axis-line");
            svg.appendChild(line);

            var txt = document.createElementNS("http://www.w3.org/2000/svg", "text");
            txt.setAttribute("x", x); txt.setAttribute("y", margin.top - 10);
            txt.setAttribute("text-anchor", "middle");
            txt.setAttribute("class", "axis-text");
            txt.textContent = timeVal.toFixed(2) + "s";
            svg.appendChild(txt);
        }

        // Event rectangles
        var pidIndex = {};
        pids.forEach(function (p, i) { pidIndex[p] = i; });

        var evtW = Math.max(2, plotW / Math.max(EVENTS.length, 100));
        EVENTS.forEach(function (ev, idx) {
            if (!activePids[ev.pid]) return;
            var cat = eventCategory(ev.kind);
            var x = margin.left + (ev.timestamp_secs / maxT) * plotW;
            var yIdx = pidIndex[ev.pid] != null ? pidIndex[ev.pid] : 0;
            var y = margin.top + yIdx * laneH + 4;

            var rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
            rect.setAttribute("x", Math.min(x, margin.left + plotW - evtW));
            rect.setAttribute("y", y);
            rect.setAttribute("width", evtW);
            rect.setAttribute("height", laneH - 8);
            rect.setAttribute("rx", "2");
            rect.setAttribute("class", "evt-rect evt-" + cat + " evtt-" + ev.kind.type);
            rect.dataset.cat = cat;
            rect.dataset.type = ev.kind.type;
            rect.dataset.idx = idx;

            var title = document.createElementNS("http://www.w3.org/2000/svg", "title");
            title.textContent = "+" + ev.timestamp_secs.toFixed(3) + "s [" + ev.pid + "] " + eventType(ev.kind) + ": " + formatEventDetail(ev.kind);
            rect.appendChild(title);

            svg.appendChild(rect);
        });

        container.appendChild(svg);

        // Apply current filters to new SVG
        document.querySelectorAll(".timeline-svg .evt-rect").forEach(function (el) {
            el.classList.toggle("hidden", !activeFilters[el.dataset.cat] || !activeTypes[el.dataset.type]);
        });

        // Zoom indicator
        var section = container.parentElement;
        var existing = section.querySelector(".zoom-indicator");
        if (existing) existing.remove();
        if (timelineZoom > 1) {
            var indicator = document.createElement("span");
            indicator.className = "zoom-indicator";
            indicator.textContent = timelineZoom.toFixed(1) + "x zoom \u00b7 0 or double-click to reset";
            section.querySelector("h2").appendChild(indicator);
        }

        // Hover detail panel
        var detail = document.getElementById("hover-detail");
        svg.addEventListener("mouseover", function (e) {
            var tgt = e.target.closest(".evt-rect");
            if (!tgt) return;
            var idx = parseInt(tgt.dataset.idx, 10);
            var ev = EVENTS[idx];
            detail.querySelector(".hd-type").textContent = "+" + ev.timestamp_secs.toFixed(3) + "s [" + ev.pid + "] " + eventType(ev.kind);
            detail.querySelector(".hd-detail").textContent = formatEventDetail(ev.kind);
            detail.style.display = "block";
        });

        svg.addEventListener("mousemove", function (e) {
            if (detail.style.display === "block") {
                detail.style.left = (e.clientX + 12) + "px";
                detail.style.top = (e.clientY + 12) + "px";
            }
        });

        svg.addEventListener("mouseout", function (e) {
            if (!e.target.closest(".evt-rect")) {
                detail.style.display = "none";
            }
        });
    }

    // --- Virtual-scrolled event table ---
    var ROW_H = 28;
    var tableViewport;
    var tableInner;

    function renderTable() {
        tableViewport = document.getElementById("table-viewport");
        tableInner = document.createElement("div");
        tableInner.style.position = "relative";
        tableViewport.appendChild(tableInner);
        tableViewport.addEventListener("scroll", renderVisibleRows);
        renderVisibleRows();
    }

    function renderVisibleRows() {
        var filtered = getFilteredEvents();
        var totalH = filtered.length * ROW_H;
        tableInner.style.height = totalH + "px";

        // Clear existing rows
        while (tableInner.firstChild) tableInner.removeChild(tableInner.firstChild);

        var scrollTop = tableViewport.scrollTop;
        var viewH = tableViewport.clientHeight;
        var startIdx = Math.max(0, Math.floor(scrollTop / ROW_H) - 2);
        var endIdx = Math.min(filtered.length, Math.ceil((scrollTop + viewH) / ROW_H) + 2);

        for (var i = startIdx; i < endIdx; i++) {
            var ev = filtered[i];
            var cat = eventCategory(ev.kind);
            var row = document.createElement("div");
            row.className = "table-row";
            row.style.top = (i * ROW_H) + "px";
            row.style.height = ROW_H + "px";
            row.innerHTML =
                '<span class="col-time">+' + ev.timestamp_secs.toFixed(3) + 's</span>' +
                '<span class="col-pid' + (threadTids[ev.pid] ? ' col-pid-thread' : '') + '">' + (threadTids[ev.pid] ? '\u21b3 ' : '') + ev.pid + '</span>' +
                '<span class="col-cat cat-' + cat + '">' + cat + '</span>' +
                '<span class="col-type typc-' + ev.kind.type + '">' + eventType(ev.kind) + '</span>' +
                '<span class="col-detail">' + escapeHtml(formatEventDetail(ev.kind)) + '</span>';
            tableInner.appendChild(row);
        }
    }

    function escapeHtml(s) {
        return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    // --- Init ---
    document.addEventListener("DOMContentLoaded", function () {
        renderCards();
        if (SUMMARY.truncated) {
            var banner = document.createElement("div");
            banner.className = "truncation-warning";
            banner.textContent = "Report limited to " + SUMMARY.event_count +
                " of " + SUMMARY.original_event_count + " events. Use --max-report-events to adjust.";
            document.querySelector(".container").insertBefore(banner, document.getElementById("cards"));
        }
        renderFilters();
        renderTypeFilter();
        renderProcessFilter();
        initTimeline();
        renderTable();
    });
})();
