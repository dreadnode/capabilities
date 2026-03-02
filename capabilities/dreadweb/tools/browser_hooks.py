#!/usr/bin/env python3
"""Browser runtime instrumentation via JavaScript injection.

Hooks into browser runtime APIs to capture execution events: dialog calls,
console output, errors, DOM mutations, XHR/fetch requests. Useful for detecting
client-side code execution from XSS, postMessage vulnerabilities, etc.

REQUIRES: Playwright MCP integration (not yet available in dreadweb).
This tool is commented out in capability.yaml until Playwright is integrated.

Protocol: reads JSON from stdin, writes JSON to stdout.
"""

import json
import sys

# JavaScript that instruments the browser
RUNTIME_MONITOR_SCRIPT = r"""
(function() {
    if (window.__runtimeMonitor) return;
    window.__runtimeMonitor = {alerts: [], console: [], errors: [], mutations: [], requests: []};

    // Hook dialog functions (alert, confirm, prompt) - suppress modals, capture calls
    ['alert', 'confirm', 'prompt'].forEach(function(m) {
        var orig = window[m];
        window[m] = function(msg) {
            window.__runtimeMonitor.alerts.push({
                type: m, message: String(msg), timestamp: Date.now(),
                stack: new Error().stack
            });
            if (m === 'confirm') return true;
            if (m === 'prompt') return null;
            return undefined;
        };
    });

    // Hook console methods
    ['log', 'info', 'warn', 'error', 'debug'].forEach(function(l) {
        var orig = console[l];
        console[l] = function() {
            var args = Array.prototype.slice.call(arguments);
            window.__runtimeMonitor.console.push({
                level: l, message: args.map(String).join(' '), timestamp: Date.now()
            });
            return orig.apply(this, arguments);
        };
    });

    // Capture JS errors
    window.addEventListener('error', function(e) {
        window.__runtimeMonitor.errors.push({
            message: e.message, filename: e.filename,
            lineno: e.lineno, colno: e.colno,
            stack: e.error ? e.error.stack : null, timestamp: Date.now()
        });
    });

    window.addEventListener('unhandledrejection', function(e) {
        window.__runtimeMonitor.errors.push({
            message: 'Unhandled rejection: ' + e.reason,
            stack: e.reason ? e.reason.stack : null, timestamp: Date.now()
        });
    });

    // Watch for script/iframe injection via DOM mutation
    if (window.MutationObserver) {
        var obs = new MutationObserver(function(muts) {
            muts.forEach(function(mut) {
                if (mut.type === 'childList' && mut.addedNodes.length > 0) {
                    mut.addedNodes.forEach(function(n) {
                        if (n.nodeType === 1 && (n.tagName === 'SCRIPT' || n.tagName === 'IFRAME')) {
                            window.__runtimeMonitor.mutations.push({
                                type: 'injection', tag: n.tagName,
                                src: n.src || null,
                                content: n.textContent ? n.textContent.substring(0, 200) : null,
                                timestamp: Date.now()
                            });
                        }
                    });
                }
            });
        });
        obs.observe(document.documentElement, {childList: true, subtree: true});
    }

    // Hook fetch
    var origFetch = window.fetch;
    window.fetch = function() {
        var url = typeof arguments[0] === 'string' ? arguments[0] : (arguments[0] && arguments[0].url);
        var method = (arguments[1] && arguments[1].method) || 'GET';
        window.__runtimeMonitor.requests.push({type: 'fetch', url: url, method: method, timestamp: Date.now()});
        return origFetch.apply(this, arguments);
    };

    // Hook XMLHttpRequest
    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url) {
        this.__xhrMethod = method;
        this.__xhrUrl = url;
        return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function() {
        if (this.__xhrUrl) {
            window.__runtimeMonitor.requests.push({
                type: 'xhr', url: this.__xhrUrl,
                method: this.__xhrMethod || 'GET', timestamp: Date.now()
            });
        }
        return origSend.apply(this, arguments);
    };
})();
"""

GET_EVENTS_SCRIPT = r"""
(function() {
    if (!window.__runtimeMonitor) return JSON.stringify({error: 'Monitor not installed'});
    var e = {
        alerts: window.__runtimeMonitor.alerts || [],
        console: window.__runtimeMonitor.console || [],
        errors: window.__runtimeMonitor.errors || [],
        mutations: window.__runtimeMonitor.mutations || [],
        requests: window.__runtimeMonitor.requests || []
    };
    // Clear after retrieval
    window.__runtimeMonitor.alerts = [];
    window.__runtimeMonitor.console = [];
    window.__runtimeMonitor.errors = [];
    window.__runtimeMonitor.mutations = [];
    window.__runtimeMonitor.requests = [];
    return JSON.stringify(e);
})();
"""


def inject_runtime_monitor(_params: dict) -> dict:
    """Return the injection script for the agent to execute via browser_evaluate."""
    return {
        "result": "Runtime monitor script ready. Execute this JavaScript in the browser via browser_evaluate:\n\n" + RUNTIME_MONITOR_SCRIPT,
        "script": RUNTIME_MONITOR_SCRIPT,
    }


def get_runtime_events_script(_params: dict) -> dict:
    """Return the event retrieval script for the agent to execute via browser_evaluate."""
    return {
        "result": "Event retrieval script ready. Execute this JavaScript in the browser via browser_evaluate:\n\n" + GET_EVENTS_SCRIPT,
        "script": GET_EVENTS_SCRIPT,
    }


METHODS = {
    "inject_runtime_monitor": inject_runtime_monitor,
    "get_runtime_events_script": get_runtime_events_script,
}


def main():
    raw = sys.stdin.read()
    request = json.loads(raw)
    method = request.get("method", request.get("name", ""))
    params = request.get("parameters", {})

    handler = METHODS.get(method)
    if not handler:
        print(json.dumps({"error": f"Unknown method: {method}"}))
        sys.exit(1)

    try:
        result = handler(params)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
