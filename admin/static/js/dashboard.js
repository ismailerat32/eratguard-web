
(function () {
    "use strict";

    function pad(value) {
        return String(value).padStart(2, "0");
    }

    function updateClock() {
        var target = document.getElementById("eg-clock");

        if (!target) {
            return;
        }

        var now = new Date();

        target.textContent =
            pad(now.getHours()) + ":" +
            pad(now.getMinutes()) + ":" +
            pad(now.getSeconds());
    }

    updateClock();
    window.setInterval(updateClock, 1000);

    document.documentElement.classList.add(
        "eg-command-center-ready"
    );
})();


/* ========================================================================
   ERATGUARD PHASE 8B.7C.3B - COMMAND CORE INTERACTION CONTROLLER
   ======================================================================== */

(function () {
    "use strict";

    var hud = document.querySelector(".eg-signature-hud");
    var core = document.getElementById("eg-command-core");
    var evaInput = document.getElementById("eg-eva-input");
    var evaPanel = evaInput ? evaInput.closest(".eg-eva-chat-panel") : null;

    var nodes = Array.prototype.slice.call(
        document.querySelectorAll(
            ".eg-hud-node[data-eg-action]"
        )
    );

    if (!hud || !core) {
        return;
    }

    function setCoreActive(active) {
        core.classList.toggle("is-command-active", !!active);
        hud.classList.toggle("is-command-mode", !!active);
    }

    function clearNodeFocus() {
        nodes.forEach(function (node) {
            node.classList.remove("is-command-focus");
        });

        core.removeAttribute("data-eg-selected-action");
    }

    function focusNode(node) {
        if (!node) {
            return;
        }

        clearNodeFocus();

        node.classList.add("is-command-focus");

        var action = node.getAttribute("data-eg-action");

        if (action) {
            core.setAttribute(
                "data-eg-selected-action",
                action
            );
        }

        setCoreActive(true);
    }

    nodes.forEach(function (node) {
        node.addEventListener("mouseenter", function () {
            focusNode(node);
        });

        node.addEventListener("focus", function () {
            focusNode(node);
        });

        node.addEventListener("mouseleave", function () {
            clearNodeFocus();

            if (!evaPanel ||
                !evaPanel.classList.contains("is-command-open")) {
                setCoreActive(false);
            }
        });

        node.addEventListener("blur", function () {
            clearNodeFocus();

            if (!evaPanel ||
                !evaPanel.classList.contains("is-command-open")) {
                setCoreActive(false);
            }
        });
    });

    function openEvaCommand() {
        setCoreActive(true);

        if (!evaPanel || !evaInput) {
            return;
        }

        evaPanel.classList.add("is-command-open");
        core.setAttribute("aria-expanded", "true");

        window.setTimeout(function () {
            if (evaPanel.scrollIntoView) {
                evaPanel.scrollIntoView({
                    behavior: "smooth",
                    block: "nearest"
                });
            }

            evaInput.focus();
        }, 80);
    }

    function closeEvaCommand() {
        if (!evaPanel) {
            return;
        }

        evaPanel.classList.remove("is-command-open");
        core.setAttribute("aria-expanded", "false");

        clearNodeFocus();
        setCoreActive(false);

        try {
            core.focus({
                preventScroll:true
            });
        } catch (e) {
            core.focus();
        }
    }

    function toggleEvaCommand(event) {
        /*
         The legacy inline Phase 8B.7C.2 handler also receives the click.
         Stop propagation is unnecessary; this controller owns only the
         visible command-mode state.
        */

        if (!evaPanel) {
            return;
        }

        if (evaPanel.classList.contains("is-command-open")) {
            closeEvaCommand();
        } else {
            openEvaCommand();
        }
    }

    core.setAttribute("aria-expanded", "false");
    core.setAttribute("aria-controls", "eg-eva-input");

    core.addEventListener("click", toggleEvaCommand);

    /*
       Keyboard activation already exists in the Phase 8B.7C.2 inline
       handler. We intentionally do not register a second keydown handler;
       Enter/Space generates the existing activation path without creating
       duplicate keyboard state transitions.
    */

    document.addEventListener("keydown", function (event) {
        if (event.key !== "Escape") {
            return;
        }

        if (evaPanel &&
            evaPanel.classList.contains("is-command-open")) {
            event.preventDefault();
            closeEvaCommand();
        }
    });

    document.documentElement.classList.add(
        "eg-command-interaction-ready"
    );
})();

/* ===== /ERATGUARD PHASE 8B.7C.3B ===== */
/* ========================================================================
   ERATGUARD PHASE 8B.7C.4B - LIVE COMMAND CORE CONTROLLER
   ======================================================================== */

(function () {
    "use strict";

    var core = document.getElementById("eg-command-core");
    var target = document.getElementById("eg-command-target");
    var targetStatus = document.getElementById(
        "eg-command-target-status"
    );
    var selectedModule = document.getElementById(
        "eg-command-selected-module"
    );
    var openModule = document.getElementById(
        "eg-command-open-module"
    );

    var nodes = Array.prototype.slice.call(
        document.querySelectorAll(
            ".eg-hud-node[data-eg-action]"
        )
    );

    if (!core ||
        !target ||
        !selectedModule ||
        !openModule) {
        return;
    }

    var commandMap = {
        "ai-analysis": {
            label: "AI ANALYSIS"
        },

        "network": {
            label: "NETWORK"
        },

        "firewall": {
            label: "FIREWALL"
        },

        "devices": {
            label: "DEVICES"
        },

        "quarantine": {
            label: "QUARANTINE"
        },

        "reports": {
            label: "REPORTS"
        },

        "licenses": {
            label: "LICENSES"
        },

        "sms-shield": {
            label: "SMS SHIELD"
        }
    };

    var selectedAction = "eva-core";
    var selectedHref = "/admin/eva-chat";

    function setDisplay(label, status) {
        target.textContent = label;
        selectedModule.textContent = label;

        if (targetStatus) {
            targetStatus.textContent = status || "READY";
        }
    }

    function clearSelectedNodes() {
        nodes.forEach(function (node) {
            node.classList.remove(
                "is-command-selected"
            );
        });
    }

    function selectCommand(node) {
        if (!node) {
            return;
        }

        var action = node.getAttribute(
            "data-eg-action"
        );

        var config = commandMap[action];

        if (!config) {
            return;
        }

        clearSelectedNodes();

        node.classList.add(
            "is-command-selected"
        );

        selectedAction = action;

        selectedHref =
            node.getAttribute("href") ||
            "#";

        core.setAttribute(
            "data-eg-selected-action",
            selectedAction
        );

        openModule.setAttribute(
            "href",
            selectedHref
        );

        openModule.setAttribute(
            "data-eg-command-href",
            selectedHref
        );

        setDisplay(
            config.label,
            "TARGET LOCKED"
        );
    }

    function resetCommand() {
        clearSelectedNodes();

        selectedAction = "eva-core";
        selectedHref = "/admin/eva-chat";

        core.setAttribute(
            "data-eg-selected-action",
            selectedAction
        );

        openModule.setAttribute(
            "href",
            selectedHref
        );

        openModule.setAttribute(
            "data-eg-command-href",
            selectedHref
        );

        setDisplay(
            "EVA CORE",
            "READY"
        );
    }

    nodes.forEach(function (node) {
        /*
           First click locks the command target instead of
           immediately navigating away from the command center.
        */
        node.addEventListener(
            "click",
            function (event) {
                event.preventDefault();
                selectCommand(node);
            }
        );

        /*
           Double click remains an immediate operator shortcut.
        */
        node.addEventListener(
            "dblclick",
            function (event) {
                event.preventDefault();

                selectCommand(node);

                if (selectedHref &&
                    selectedHref !== "#") {
                    window.location.href =
                        selectedHref;
                }
            }
        );
    });

    openModule.addEventListener(
        "click",
        function (event) {
            var href = openModule.getAttribute(
                "data-eg-command-href"
            );

            if (!href || href === "#") {
                event.preventDefault();
            }
        }
    );

    /*
       Core click owns EVA. If another command was locked,
       pressing EG CORE returns the operator to EVA mode.
    */
    core.addEventListener(
        "click",
        function () {
            if (selectedAction !== "eva-core") {
                resetCommand();
            }
        }
    );

    resetCommand();

    document.documentElement.classList.add(
        "eg-live-command-core-ready"
    );
})();

/* ===== /ERATGUARD PHASE 8B.7C.4B ===== */

/* ========================================================================
   ERATGUARD PHASE 8B.7C.5C - REAL COMMAND API BINDING

   HUD command selection -> canonical /admin/api/command ->
   live Command Core state.

   Navigation remains owned by Phase 8B.7C.4B.
   EVA chat remains owned by /admin/eva-chat.
   ======================================================================== */

(function () {
    "use strict";

    var API = "/admin/api/command";

    var core =
        document.getElementById("eg-command-core");

    var target =
        document.getElementById("eg-command-target");

    var targetStatus =
        document.getElementById(
            "eg-command-target-status"
        );

    var selectedModule =
        document.getElementById(
            "eg-command-selected-module"
        );

    var openModule =
        document.getElementById(
            "eg-command-open-module"
        );

    var nodes = Array.prototype.slice.call(
        document.querySelectorAll(
            ".eg-hud-node[data-eg-action]"
        )
    );

    if (!core || !target || !targetStatus) {
        return;
    }

    var requestSerial = 0;
    var activeController = null;

    function setState(state) {
        core.setAttribute(
            "data-eg-command-state",
            state
        );
    }

    function setStatus(text) {
        targetStatus.textContent =
            text || "READY";
    }

    function setLabel(text) {
        if (!text) {
            return;
        }

        target.textContent = text;

        if (selectedModule) {
            selectedModule.textContent = text;
        }
    }

    function setModuleHref(href) {
        if (!openModule ||
            !href ||
            href === "#") {
            return;
        }

        openModule.setAttribute(
            "href",
            href
        );

        openModule.setAttribute(
            "data-eg-command-href",
            href
        );
    }

    function summarizeSnapshot(snapshot) {
        if (!snapshot ||
            typeof snapshot !== "object") {
            return "LIVE";
        }

        var preferred = [
            "threat_level",
            "network",
            "status",
            "active",
            "blocked",
            "events",
            "used",
            "licenses",
            "logs",
            "uptime"
        ];

        for (var i = 0;
             i < preferred.length;
             i += 1) {

            var key = preferred[i];

            if (snapshot[key] !== undefined &&
                snapshot[key] !== null &&
                snapshot[key] !== "") {

                return (
                    key.replace(
                        /_/g,
                        " "
                    ).toUpperCase() +
                    ": " +
                    String(snapshot[key])
                );
            }
        }

        return "LIVE";
    }

    function applySuccess(data) {
        setState("ready");

        setLabel(
            data.label ||
            data.action ||
            "COMMAND"
        );

        setModuleHref(
            data.href
        );

        setStatus(
            summarizeSnapshot(
                data.snapshot
            )
        );

        core.setAttribute(
            "data-eg-live-action",
            data.action || ""
        );

        core.setAttribute(
            "data-eg-live-module",
            data.module || ""
        );
    }

    function applyFailure(data) {
        setState("error");

        var message =
            data &&
            (
                data.error ||
                data.status
            );

        setStatus(
            message || "COMMAND ERROR"
        );
    }

    function executeCommand(action) {
        if (!action ||
            action === "eva-core") {
            return;
        }

        requestSerial += 1;

        var serial = requestSerial;

        if (activeController &&
            typeof activeController.abort ===
                "function") {
            activeController.abort();
        }

        activeController =
            typeof AbortController !==
                "undefined"
                ? new AbortController()
                : null;

        setState("loading");
        setStatus("QUERYING CORE...");

        var options = {
            method: "POST",
            headers: {
                "Content-Type":
                    "application/json",
                "Accept":
                    "application/json"
            },
            body: JSON.stringify({
                action: action
            })
        };

        if (activeController) {
            options.signal =
                activeController.signal;
        }

        fetch(API, options)
            .then(function (response) {
                return response
                    .json()
                    .catch(function () {
                        return {
                            ok: false,
                            status:
                                "INVALID_RESPONSE",
                            error:
                                "Invalid command response."
                        };
                    })
                    .then(function (data) {
                        return {
                            response: response,
                            data: data
                        };
                    });
            })
            .then(function (result) {
                if (serial !== requestSerial) {
                    return;
                }

                var response =
                    result.response;

                var data =
                    result.data || {};

                if (!response.ok ||
                    !data.ok) {

                    applyFailure(data);
                    return;
                }

                applySuccess(data);
            })
            .catch(function (error) {
                if (serial !== requestSerial) {
                    return;
                }

                if (error &&
                    error.name ===
                        "AbortError") {
                    return;
                }

                applyFailure({
                    error:
                        "COMMAND API OFFLINE"
                });
            });
    }

    nodes.forEach(function (node) {
        node.addEventListener(
            "click",
            function () {
                var action =
                    node.getAttribute(
                        "data-eg-action"
                    );

                /*
                   Phase 8B.7C.4B owns visual
                   selection first.

                   This listener then resolves
                   that target against the real
                   canonical backend.
                */
                window.setTimeout(
                    function () {
                        executeCommand(action);
                    },
                    0
                );
            }
        );
    });

    core.addEventListener(
        "click",
        function () {
            requestSerial += 1;

            if (activeController &&
                typeof activeController.abort ===
                    "function") {
                activeController.abort();
            }

            activeController = null;

            setState("eva");
            setStatus("READY");

            core.removeAttribute(
                "data-eg-live-action"
            );

            core.removeAttribute(
                "data-eg-live-module"
            );
        }
    );

    setState("ready");

    document.documentElement.classList.add(
        "eg-real-command-api-ready"
    );
})();

/* ===== /ERATGUARD PHASE 8B.7C.5C ===== */

/* ========================================================================
   ERATGUARD PHASE 8B.7C.6 - LIVE COMMAND RESPONSE SURFACE
   ======================================================================== */

(function () {
    "use strict";

    var API = "/admin/api/command";

    var surface =
        document.getElementById(
            "eg-command-response"
        );

    var grid =
        document.getElementById(
            "eg-command-response-grid"
        );

    var title =
        document.getElementById(
            "eg-command-response-title"
        );

    var state =
        document.getElementById(
            "eg-command-response-state"
        );

    var source =
        document.getElementById(
            "eg-command-response-source"
        );

    var actionField =
        document.getElementById(
            "eg-command-response-action"
        );

    var code =
        document.getElementById(
            "eg-command-response-code"
        );

    var nodes = Array.prototype.slice.call(
        document.querySelectorAll(
            ".eg-hud-node[data-eg-action]"
        )
    );

    if (!surface ||
        !grid ||
        !title ||
        !state) {
        return;
    }

    var serial = 0;
    var controller = null;

    function text(value) {
        if (value === null ||
            value === undefined) {
            return "—";
        }

        if (typeof value === "boolean") {
            return value ? "YES" : "NO";
        }

        if (typeof value === "object") {
            try {
                return JSON.stringify(value);
            } catch (e) {
                return "[DATA]";
            }
        }

        return String(value);
    }

    function label(key) {
        return String(key)
            .replace(/_/g, " ")
            .replace(/-/g, " ")
            .toUpperCase();
    }

    function clearGrid() {
        while (grid.firstChild) {
            grid.removeChild(
                grid.firstChild
            );
        }
    }

    function empty(message) {
        clearGrid();

        var item =
            document.createElement("div");

        item.className =
            "eg-command-response-empty";

        item.textContent =
            message || "NO LIVE DATA";

        grid.appendChild(item);
    }

    function renderSnapshot(snapshot) {
        clearGrid();

        if (!snapshot ||
            typeof snapshot !== "object") {
            empty("NO SNAPSHOT DATA");
            return;
        }

        var keys =
            Object.keys(snapshot);

        if (!keys.length) {
            empty("EMPTY SNAPSHOT");
            return;
        }

        keys.slice(0, 12).forEach(
            function (key) {

                var item =
                    document.createElement(
                        "div"
                    );

                item.className =
                    "eg-command-response-item";

                var name =
                    document.createElement(
                        "span"
                    );

                var value =
                    document.createElement(
                        "strong"
                    );

                name.textContent =
                    label(key);

                value.textContent =
                    text(snapshot[key]);

                item.appendChild(name);
                item.appendChild(value);

                grid.appendChild(item);
            }
        );
    }

    function setMode(mode) {
        surface.classList.remove(
            "is-live",
            "is-loading",
            "is-error"
        );

        if (mode) {
            surface.classList.add(
                "is-" + mode
            );
        }
    }

    function standby() {
        serial += 1;

        if (controller &&
            typeof controller.abort ===
                "function") {
            controller.abort();
        }

        controller = null;

        setMode(null);

        title.textContent =
            "EVA CORE";

        state.textContent =
            "STANDBY";

        if (source) {
            source.textContent =
                "COMMAND CORE";
        }

        if (actionField) {
            actionField.textContent =
                "EVA-CORE";
        }

        if (code) {
            code.textContent =
                "READY";
        }

        empty(
            "SELECT A COMMAND TARGET"
        );
    }

    function requestCommand(action) {
        if (!action ||
            action === "eva-core") {
            standby();
            return;
        }

        serial += 1;

        var current = serial;

        if (controller &&
            typeof controller.abort ===
                "function") {
            controller.abort();
        }

        controller =
            typeof AbortController !==
                "undefined"
                ? new AbortController()
                : null;

        setMode("loading");

        title.textContent =
            label(action);

        state.textContent =
            "QUERYING";

        if (actionField) {
            actionField.textContent =
                action.toUpperCase();
        }

        if (code) {
            code.textContent =
                "WAIT";
        }

        empty("QUERYING COMMAND CORE...");

        var options = {
            method:"POST",

            headers:{
                "Content-Type":
                    "application/json",
                "Accept":
                    "application/json"
            },

            body:JSON.stringify({
                action:action
            })
        };

        if (controller) {
            options.signal =
                controller.signal;
        }

        fetch(API, options)
            .then(function (response) {
                return response
                    .json()
                    .catch(function () {
                        return {
                            ok:false,
                            error:
                                "INVALID RESPONSE"
                        };
                    })
                    .then(function (data) {
                        return {
                            response:response,
                            data:data
                        };
                    });
            })
            .then(function (result) {
                if (current !== serial) {
                    return;
                }

                var response =
                    result.response;

                var data =
                    result.data || {};

                if (!response.ok ||
                    !data.ok) {

                    setMode("error");

                    state.textContent =
                        "ERROR";

                    if (code) {
                        code.textContent =
                            data.status ||
                            String(
                                response.status
                            );
                    }

                    empty(
                        data.error ||
                        "COMMAND FAILED"
                    );

                    return;
                }

                setMode("live");

                title.textContent =
                    data.label ||
                    label(action);

                state.textContent =
                    "LIVE";

                if (source) {
                    source.textContent =
                        (
                            data.module ||
                            "COMMAND"
                        ).toUpperCase();
                }

                if (actionField) {
                    actionField.textContent =
                        (
                            data.action ||
                            action
                        ).toUpperCase();
                }

                if (code) {
                    code.textContent =
                        data.status ||
                        "OK";
                }

                renderSnapshot(
                    data.snapshot
                );
            })
            .catch(function (error) {
                if (current !== serial) {
                    return;
                }

                if (error &&
                    error.name ===
                        "AbortError") {
                    return;
                }

                setMode("error");

                state.textContent =
                    "OFFLINE";

                if (code) {
                    code.textContent =
                        "FETCH ERROR";
                }

                empty(
                    "COMMAND API OFFLINE"
                );
            });
    }

    nodes.forEach(function (node) {

        node.addEventListener(
            "click",
            function () {

                var action =
                    node.getAttribute(
                        "data-eg-action"
                    );

                /*
                   8B.7C.5C owns the canonical
                   command-state request.

                   8B.7C.6 owns the expanded
                   response presentation.
                */
                requestCommand(action);
            }
        );

    });

    var core =
        document.getElementById(
            "eg-command-core"
        );

    if (core) {
        core.addEventListener(
            "click",
            standby
        );
    }

    standby();

    document.documentElement.classList.add(
        "eg-command-response-ready"
    );

})();

/* ===== /ERATGUARD PHASE 8B.7C.6 ===== */



/* ========================================================================
   ERATGUARD PHASE 8B.7C.9 - COMMAND CAPABILITY INTEGRATION
   ======================================================================== */

(function () {
    "use strict";

    var API = "/admin/api/command/dispatch";

    var surface =
        document.getElementById(
            "eg-command-capability"
        );

    var modeLabel =
        document.getElementById(
            "eg-capability-mode"
        );

    var statusLabel =
        document.getElementById(
            "eg-capability-status"
        );

    var core =
        document.getElementById(
            "eg-command-core"
        );

    var openModule =
        document.getElementById(
            "eg-command-open-module"
        );

    var buttons =
        Array.prototype.slice.call(
            document.querySelectorAll(
                "[data-eg-command-mode]"
            )
        );

    if (!surface ||
        !modeLabel ||
        !statusLabel ||
        !core) {
        return;
    }

    function currentAction() {
        return (
            core.getAttribute(
                "data-eg-live-action"
            ) ||
            core.getAttribute(
                "data-eg-selected-action"
            ) ||
            "eva-core"
        );
    }

    function setSurfaceState(state) {
        surface.setAttribute(
            "data-eg-capability-state",
            state
        );
    }

    function activateButton(mode) {
        buttons.forEach(function (button) {
            button.classList.toggle(
                "is-active",
                button.getAttribute(
                    "data-eg-command-mode"
                ) === mode
            );
        });
    }

    function setMode(mode, text) {
        modeLabel.textContent =
            String(mode || "inspect")
                .toUpperCase();

        statusLabel.textContent =
            text || "READY";

        activateButton(mode);
    }

    function dispatch(mode) {
        var action = currentAction();

        if (mode === "execute") {
            setSurfaceState("locked");

            setMode(
                "execute",
                "CONTROLLED EXECUTION LOCKED"
            );

            return;
        }

        setSurfaceState("loading");

        setMode(
            mode,
            mode === "inspect"
                ? "READING LIVE CORE..."
                : "RESOLVING MODULE..."
        );

        fetch(API, {
            method: "POST",

            headers: {
                "Content-Type":
                    "application/json",

                "Accept":
                    "application/json"
            },

            body: JSON.stringify({
                action: action,
                mode: mode
            })
        })
        .then(function (response) {
            return response
                .json()
                .catch(function () {
                    return {
                        ok: false,
                        status:
                            "INVALID_RESPONSE"
                    };
                })
                .then(function (data) {
                    return {
                        response: response,
                        data: data
                    };
                });
        })
        .then(function (result) {
            var data = result.data || {};

            if (!result.response.ok ||
                !data.ok) {

                setSurfaceState(
                    data.status ===
                    "EXECUTION_LOCKED"
                        ? "locked"
                        : "error"
                );

                setMode(
                    mode,
                    data.error ||
                    data.status ||
                    "COMMAND FAILED"
                );

                return;
            }

            setSurfaceState("ready");

            if (mode === "open") {

                var href =
                    data.href ||
                    (
                        data.capability &&
                        data.capability.href
                    );

                if (href &&
                    href !== "#" &&
                    openModule) {

                    openModule.setAttribute(
                        "href",
                        href
                    );

                    openModule.setAttribute(
                        "data-eg-command-href",
                        href
                    );
                }

                setMode(
                    mode,
                    "MODULE RESOLVED"
                );

                return;
            }

            setMode(
                mode,
                "LIVE CORE INSPECTED"
            );
        })
        .catch(function () {

            setSurfaceState("error");

            setMode(
                mode,
                "COMMAND DISPATCH OFFLINE"
            );
        });
    }

    buttons.forEach(function (button) {

        button.addEventListener(
            "click",
            function () {

                var mode =
                    button.getAttribute(
                        "data-eg-command-mode"
                    );

                if (!mode) {
                    return;
                }

                dispatch(mode);
            }
        );
    });

    setSurfaceState("standby");

    setMode(
        "inspect",
        "READ-ONLY INSPECTION"
    );

    document.documentElement.classList.add(
        "eg-command-capability-ready"
    );

})();

/* ===== /ERATGUARD PHASE 8B.7C.9 ===== */


/* ========================================================================
   ERATGUARD PHASE 8B.7C.10B - OPERATION SURFACE BINDING

   Explicit operation metadata only.

   No operation execution occurs here.
   No arbitrary dispatch.
   No generic executor.
   Controlled writes remain locked.
   ======================================================================== */

(function () {
    "use strict";

    var API =
        "/admin/api/command/operations";

    var core =
        document.getElementById(
            "eg-command-core"
        );

    var surface =
        document.getElementById(
            "eg-command-operation-surface"
        );

    var list =
        document.getElementById(
            "eg-command-operation-list"
        );

    var count =
        document.getElementById(
            "eg-operation-count"
        );

    var policy =
        document.getElementById(
            "eg-operation-policy"
        );

    if (!core ||
        !surface ||
        !list ||
        !count ||
        !policy) {
        return;
    }

    var requestSerial = 0;
    var lastAction = "";

    function currentAction() {
        return (
            core.getAttribute(
                "data-eg-live-action"
            ) ||
            core.getAttribute(
                "data-eg-selected-action"
            ) ||
            "eva-core"
        );
    }

    function setState(state) {
        surface.setAttribute(
            "data-eg-operation-state",
            state
        );
    }

    function clearList(message) {
        list.innerHTML = "";

        var empty =
            document.createElement("div");

        empty.className =
            "eg-command-operation-empty";

        empty.textContent =
            message ||
            "NO OPERATIONS";

        list.appendChild(empty);
    }

    function setPolicy(data) {
        var executionPolicy =
            data &&
            data.execution_policy;

        if (!executionPolicy) {
            policy.textContent =
                "CONTROLLED WRITES LOCKED";
            return;
        }

        if (
            executionPolicy.controlled_writes ===
            false
        ) {
            policy.textContent =
                "CONTROLLED WRITES LOCKED";
            return;
        }

        policy.textContent =
            "EXPLICIT OPERATIONS ONLY";
    }

    function selectOperation(button) {
        var buttons =
            list.querySelectorAll(
                "[data-eg-operation]"
            );

        Array.prototype.forEach.call(
            buttons,
            function (node) {
                node.classList.remove(
                    "is-selected"
                );
            }
        );

        button.classList.add(
            "is-selected"
        );

        surface.setAttribute(
            "data-eg-selected-operation",
            button.getAttribute(
                "data-eg-operation"
            ) || ""
        );
    }

    function renderOperations(data) {
        var operations =
            Array.isArray(data.operations)
                ? data.operations
                : [];

        var defaultOperation =
            data.default_operation || "";

        list.innerHTML = "";

        count.textContent =
            String(operations.length) +
            (
                operations.length === 1
                    ? " OP"
                    : " OPS"
            );

        setPolicy(data);

        if (!operations.length) {
            clearList(
                "NO REGISTERED OPERATIONS"
            );

            return;
        }

        operations.forEach(
            function (operation) {

                var button =
                    document.createElement(
                        "button"
                    );

                var operationId =
                    String(
                        operation.id || ""
                    );

                var enabled =
                    operation.enabled === true;

                button.type = "button";

                button.className =
                    "eg-command-operation";

                button.setAttribute(
                    "data-eg-operation",
                    operationId
                );

                button.setAttribute(
                    "data-eg-operation-kind",
                    operation.kind || "read"
                );

                if (
                    operationId ===
                    defaultOperation
                ) {
                    button.classList.add(
                        "is-default"
                    );
                }

                if (!enabled) {
                    button.classList.add(
                        "is-locked"
                    );

                    button.disabled = true;

                    button.setAttribute(
                        "aria-disabled",
                        "true"
                    );
                }

                var label =
                    document.createElement("b");

                label.textContent =
                    operation.label ||
                    operationId ||
                    "OPERATION";

                var meta =
                    document.createElement(
                        "small"
                    );

                meta.textContent =
                    String(
                        operation.kind ||
                        "read"
                    ).toUpperCase() +
                    " // " +
                    (
                        enabled
                            ? "AVAILABLE"
                            : "LOCKED"
                    );

                button.appendChild(label);
                button.appendChild(meta);

                if (enabled) {
                    button.addEventListener(
                        "click",
                        function () {
                            selectOperation(
                                button
                            );
                        }
                    );
                }

                list.appendChild(button);
            }
        );

        if (defaultOperation) {
            var defaultButton =
                list.querySelector(
                    '[data-eg-operation="' +
                    defaultOperation +
                    '"]'
                );

            if (
                defaultButton &&
                !defaultButton.disabled
            ) {
                selectOperation(
                    defaultButton
                );
            }
        }
    }

    function loadOperations(action) {
        action =
            String(
                action ||
                currentAction()
            )
            .trim()
            .toLowerCase();

        if (!action) {
            return;
        }

        requestSerial += 1;

        var serial = requestSerial;

        lastAction = action;

        setState("loading");

        count.textContent =
            "QUERYING";

        clearList(
            "READING OPERATION REGISTRY..."
        );

        fetch(API, {
            method: "POST",

            headers: {
                "Content-Type":
                    "application/json",

                "Accept":
                    "application/json"
            },

            body: JSON.stringify({
                action: action
            })
        })
        .then(function (response) {
            return response
                .json()
                .catch(function () {
                    return {
                        ok: false,
                        status:
                            "INVALID_RESPONSE"
                    };
                })
                .then(function (data) {
                    return {
                        response: response,
                        data: data
                    };
                });
        })
        .then(function (result) {

            if (serial !== requestSerial) {
                return;
            }

            var data =
                result.data || {};

            if (!result.response.ok ||
                !data.ok) {

                setState("error");

                count.textContent =
                    "ERROR";

                clearList(
                    data.error ||
                    data.status ||
                    "OPERATION REGISTRY ERROR"
                );

                return;
            }

            setState("ready");

            surface.setAttribute(
                "data-eg-operation-action",
                data.action || action
            );

            renderOperations(data);
        })
        .catch(function () {

            if (serial !== requestSerial) {
                return;
            }

            setState("error");

            count.textContent =
                "OFFLINE";

            clearList(
                "OPERATION API OFFLINE"
            );
        });
    }

    /*
       HUD selection is owned by earlier phases.
       Observe the canonical selected/live action instead of
       replacing their event handlers.
    */
    function syncAction() {
        var action = currentAction();

        if (action === lastAction) {
            return;
        }

        loadOperations(action);
    }

    var nodes =
        Array.prototype.slice.call(
            document.querySelectorAll(
                ".eg-hud-node[data-eg-action]"
            )
        );

    nodes.forEach(function (node) {

        node.addEventListener(
            "click",
            function () {
                window.setTimeout(
                    syncAction,
                    0
                );
            }
        );

        node.addEventListener(
            "dblclick",
            function () {
                window.setTimeout(
                    syncAction,
                    0
                );
            }
        );
    });

    core.addEventListener(
        "click",
        function () {
            window.setTimeout(
                syncAction,
                0
            );
        }
    );

    /*
       Phase 8B.7C.5C may update data-eg-live-action
       asynchronously after the real Command API response.
       MutationObserver keeps the operation registry aligned
       with that canonical live state.
    */
    if (
        typeof MutationObserver !==
        "undefined"
    ) {
        var observer =
            new MutationObserver(
                function (mutations) {

                    var changed =
                        mutations.some(
                            function (mutation) {
                                return (
                                    mutation.attributeName ===
                                        "data-eg-live-action" ||
                                    mutation.attributeName ===
                                        "data-eg-selected-action"
                                );
                            }
                        );

                    if (changed) {
                        syncAction();
                    }
                }
            );

        observer.observe(
            core,
            {
                attributes: true,
                attributeFilter: [
                    "data-eg-live-action",
                    "data-eg-selected-action"
                ]
            }
        );
    }

    setState("standby");

    loadOperations(
        currentAction()
    );

    document.documentElement
        .classList.add(
            "eg-command-operation-ready"
        );

})();

/* ===== /ERATGUARD PHASE 8B.7C.10B ===== */

/* ========================================================================
   ERATGUARD PHASE 8B.7C.10C-F-B - CONTROLLED READ OPERATION UI BINDING

   Security contract:
   - Only an operation already rendered as enabled by the canonical
     operation registry may execute.
   - Only kind=read may execute.
   - Refresh operations remain locked.
   - Controlled writes remain locked.
   - Generic executor remains forbidden.
   - Arbitrary dispatch remains forbidden.
   - Existing EXECUTE capability control remains locked.
   ======================================================================== */

(function () {
    "use strict";

    var EXECUTE_API =
        "/admin/api/command/operation/execute";

    var core =
        document.getElementById(
            "eg-command-core"
        );

    var surface =
        document.getElementById(
            "eg-command-operation-surface"
        );

    var list =
        document.getElementById(
            "eg-command-operation-list"
        );

    var responseSurface =
        document.getElementById(
            "eg-command-response"
        );

    var responseGrid =
        document.getElementById(
            "eg-command-response-grid"
        );

    var responseTitle =
        document.getElementById(
            "eg-command-response-title"
        );

    var responseState =
        document.getElementById(
            "eg-command-response-state"
        );

    var responseSource =
        document.getElementById(
            "eg-command-response-source"
        );

    var responseAction =
        document.getElementById(
            "eg-command-response-action"
        );

    var responseCode =
        document.getElementById(
            "eg-command-response-code"
        );

    if (!core || !surface || !list) {
        return;
    }

    var requestSerial = 0;

    function currentAction() {
        return String(
            surface.getAttribute(
                "data-eg-operation-action"
            ) ||
            core.getAttribute(
                "data-eg-live-action"
            ) ||
            core.getAttribute(
                "data-eg-selected-action"
            ) ||
            ""
        )
        .trim()
        .toLowerCase();
    }

    function selectedOperation() {
        return String(
            surface.getAttribute(
                "data-eg-selected-operation"
            ) || ""
        )
        .trim();
    }

    function selectedButton() {
        var operationId =
            selectedOperation();

        if (!operationId) {
            return null;
        }

        var buttons =
            list.querySelectorAll(
                "[data-eg-operation]"
            );

        var found = null;

        Array.prototype.some.call(
            buttons,
            function (button) {
                if (
                    button.getAttribute(
                        "data-eg-operation"
                    ) === operationId
                ) {
                    found = button;
                    return true;
                }

                return false;
            }
        );

        return found;
    }

    function isAllowedReadButton(button) {
        if (!button) {
            return false;
        }

        if (button.disabled) {
            return false;
        }

        if (
            button.getAttribute(
                "aria-disabled"
            ) === "true"
        ) {
            return false;
        }

        if (
            button.classList.contains(
                "is-locked"
            )
        ) {
            return false;
        }

        return (
            String(
                button.getAttribute(
                    "data-eg-operation-kind"
                ) || ""
            )
            .trim()
            .toLowerCase() === "read"
        );
    }

    function clearResponseGrid() {
        if (!responseGrid) {
            return;
        }

        while (responseGrid.firstChild) {
            responseGrid.removeChild(
                responseGrid.firstChild
            );
        }
    }

    function appendResponseItem(key, value) {
        if (!responseGrid) {
            return;
        }

        var item =
            document.createElement("div");

        var name =
            document.createElement("strong");

        var body =
            document.createElement("span");

        item.className =
            "eg-command-response-item";

        name.textContent =
            String(key || "")
                .replace(/_/g, " ")
                .toUpperCase();

        if (
            value !== null &&
            typeof value === "object"
        ) {
            try {
                body.textContent =
                    JSON.stringify(
                        value,
                        null,
                        2
                    );
            } catch (error) {
                body.textContent =
                    String(value);
            }
        } else {
            body.textContent =
                value === null ||
                typeof value === "undefined"
                    ? "-"
                    : String(value);
        }

        item.appendChild(name);
        item.appendChild(body);

        responseGrid.appendChild(item);
    }

    function renderSnapshot(snapshot) {
        clearResponseGrid();

        if (
            !snapshot ||
            typeof snapshot !== "object"
        ) {
            appendResponseItem(
                "result",
                "NO SNAPSHOT"
            );

            return;
        }

        var keys =
            Object.keys(snapshot);

        if (!keys.length) {
            appendResponseItem(
                "result",
                "EMPTY SNAPSHOT"
            );

            return;
        }

        keys.forEach(function (key) {
            appendResponseItem(
                key,
                snapshot[key]
            );
        });
    }

    function setResponseMode(mode) {
        if (!responseSurface) {
            return;
        }

        responseSurface.setAttribute(
            "data-eg-command-response-state",
            mode
        );
    }

    function renderFailure(data, httpStatus) {
        setResponseMode("error");

        if (responseState) {
            responseState.textContent =
                data.status ===
                "OPERATION_LOCKED" ||
                data.status ===
                "WRITE_EXECUTION_LOCKED"
                    ? "LOCKED"
                    : "ERROR";
        }

        if (responseCode) {
            responseCode.textContent =
                data.status ||
                String(httpStatus || "ERROR");
        }

        clearResponseGrid();

        appendResponseItem(
            "status",
            data.status || "REQUEST_FAILED"
        );

        if (data.error) {
            appendResponseItem(
                "error",
                data.error
            );
        }
    }

    function executeSelectedReadOperation() {
        var action =
            currentAction();

        var operationId =
            selectedOperation();

        var button =
            selectedButton();

        /*
           Fail closed locally.

           The server remains authoritative, but the browser must
           never transform a disabled/locked/non-read registry item
           into an execution request.
        */
        if (
            !action ||
            !operationId ||
            !isAllowedReadButton(button)
        ) {
            return;
        }

        requestSerial += 1;

        var serial =
            requestSerial;

        setResponseMode("loading");

        if (responseTitle) {
            responseTitle.textContent =
                operationId
                    .replace(/-/g, " ")
                    .toUpperCase();
        }

        if (responseState) {
            responseState.textContent =
                "QUERYING";
        }

        if (responseSource) {
            responseSource.textContent =
                "READ OPERATION";
        }

        if (responseAction) {
            responseAction.textContent =
                action.toUpperCase();
        }

        if (responseCode) {
            responseCode.textContent =
                "WAIT";
        }

        fetch(
            EXECUTE_API,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json",

                    "Accept":
                        "application/json"
                },

                body: JSON.stringify({
                    action: action,
                    operation_id:
                        operationId
                })
            }
        )
        .then(function (response) {
            return response
                .json()
                .catch(function () {
                    return {
                        ok: false,
                        status:
                            "INVALID_RESPONSE"
                    };
                })
                .then(function (data) {
                    return {
                        response: response,
                        data: data
                    };
                });
        })
        .then(function (result) {
            if (serial !== requestSerial) {
                return;
            }

            var response =
                result.response;

            var data =
                result.data || {};

            if (
                !response.ok ||
                !data.ok
            ) {
                renderFailure(
                    data,
                    response.status
                );

                return;
            }

            setResponseMode("live");

            if (responseTitle) {
                responseTitle.textContent =
                    String(
                        data.operation_id ||
                        operationId
                    )
                    .replace(/-/g, " ")
                    .toUpperCase();
            }

            if (responseState) {
                responseState.textContent =
                    "LIVE";
            }

            if (responseSource) {
                responseSource.textContent =
                    "READ OPERATION";
            }

            if (responseAction) {
                responseAction.textContent =
                    String(
                        data.action ||
                        action
                    ).toUpperCase();
            }

            if (responseCode) {
                responseCode.textContent =
                    data.status ||
                    "OPERATION_COMPLETE";
            }

            renderSnapshot(
                data.snapshot
            );
        })
        .catch(function () {
            if (serial !== requestSerial) {
                return;
            }

            setResponseMode("error");

            if (responseState) {
                responseState.textContent =
                    "OFFLINE";
            }

            if (responseCode) {
                responseCode.textContent =
                    "FETCH ERROR";
            }

            clearResponseGrid();

            appendResponseItem(
                "error",
                "READ OPERATION API OFFLINE"
            );
        });
    }

    /*
       Operation registry itself owns which buttons exist and
       which are enabled.

       Single click keeps Phase 10B selection semantics.

       Double click is the explicit operator intent to run the
       currently selected enabled READ operation.

       No generic command executor is introduced.
    */
    list.addEventListener(
        "dblclick",
        function (event) {
            var target =
                event.target;

            if (!target) {
                return;
            }

            var button =
                target.closest
                    ? target.closest(
                        "[data-eg-operation]"
                    )
                    : null;

            if (
                !button ||
                !list.contains(button)
            ) {
                return;
            }

            if (
                !isAllowedReadButton(button)
            ) {
                return;
            }

            /*
               Phase 10B click handler has already selected the
               button during the dblclick sequence. Reassert the
               canonical selection before resolving execution.
            */
            surface.setAttribute(
                "data-eg-selected-operation",
                button.getAttribute(
                    "data-eg-operation"
                ) || ""
            );

            executeSelectedReadOperation();
        }
    );

    document.documentElement
        .classList.add(
            "eg-command-read-operation-execution-ready"
        );

})();

/* ===== /ERATGUARD PHASE 8B.7C.10C-F-B ===== */

