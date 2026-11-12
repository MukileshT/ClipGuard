// ClipWarden frontend — plain JavaScript, no Node.js required

/*
 * Copyright 2026 Mukilesh
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// ClipWarden frontend — plain JavaScript, no Node.js required
// Communicates with the Rust backend via Tauri's IPC (window.__TAURI__)

/** Maximum number of entries in the live detection log. */
const MAX_EVENTS = 40;

/** The current configuration, cached between refreshes. */
let config = null;

/** Whether the app is locked behind a password. */
let isLocked = false;

/** The current password (held in memory only, never stored). */
let currentPassword = null;

/** The ready-made detection templates. */
let templates = [];

/** How many refreshes failed in a row. */
let failedRefreshes = 0;

/** Returns an element by id. */
function el(id) {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`missing element #${id}`);
  }
  return element;
}

/** Shows a short-lived message. */
function toast(message, isError = false) {
  const existing = document.querySelector(".toast");
  if (existing) existing.remove();
  const node = document.createElement("div");
  node.className = isError ? "toast error" : "toast";
  node.textContent = message;
  document.body.appendChild(node);
  setTimeout(() => node.remove(), 3200);
}

/** Turns snake_case into a readable label. */
function humanize(value) {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

/** Escapes text for safe insertion into the DOM. */
function escape(value) {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character] ?? character);
}

/** Returns the Tauri API namespace, compatible with Tauri 1 and 2. */
function tauriApi() {
  const tauri = window.__TAURI__;
  // Tauri 2 nests the API under `core`; Tauri 1 exposes it directly.
  return tauri?.core ?? tauri;
}

/** Returns the Tauri event namespace. */
function tauriEvent() {
  const tauri = window.__TAURI__;
  return tauri?.event ?? tauri?.core?.event;
}

/** Calls a Tauri command. */
async function invoke(cmd, args = {}) {
  return tauriApi().invoke(cmd, args);
}

/** Renders the detection log. */
function renderEvents() {
  const container = el("event-log");
  // Events are stored on the window object
  const events = window.__clipwarden_events || [];
  if (events.length === 0) {
    container.innerHTML = '<p class="empty">Nothing detected so far.</p>';
    return;
  }
  container.innerHTML = events
    .map((event) => {
      const risk = event.risk ?? "low";
      const kinds = event.kinds.length
        ? event.kinds.map((kind) => humanize(kind)).join(", ")
        : "Paste blocked";
      const app = event.source_app ? ` · ${escape(event.source_app)}` : "";
      const mode = event.modified ? ` · ${escape(humanize(event.mode))}` : "";
      return `<div class="event">
        <span class="event-dot risk-${escape(risk)}"></span>
        <span><strong>${escape(kinds)}</strong><span class="event-meta">${app}${mode}</span></span>
        <span class="event-meta">${escape(humanize(risk))}</span>
      </div>`;
    })
    .join("");
}

/** Renders the statistics. */
function renderStats(stats) {
  el("stat-scans").textContent = String(stats.scans);
  el("stat-detections").textContent = String(stats.detections);
  el("stat-redacted").textContent = String(stats.redacted);
  el("stat-removed").textContent = String(stats.removed);
  el("stat-blocked").textContent = String(stats.blocked);
  el("stat-allowed").textContent = String(stats.allowed);

  const entries = Object.entries(stats.by_kind).sort((a, b) => b[1] - a[1]);
  const container = el("kind-breakdown");
  if (entries.length === 0) {
    container.innerHTML = '<p class="empty">No detections yet.</p>';
    return;
  }
  const maximum = Math.max(...entries.map(([, count]) => count));
  container.innerHTML = entries
    .map(
      ([kind, count]) => `<div class="breakdown-row">
        <span>${escape(humanize(kind))}</span>
        <span class="breakdown-bar"><span class="breakdown-fill" style="width:${(count / maximum) * 100}%"></span></span>
        <span class="breakdown-count">${count}</span>
      </div>`,
    )
    .join("");
}

/** Renders the status area. */
function renderStatus(status) {
  const pill = el("status-pill");
  pill.textContent = status.enabled ? "Protection active" : "Protection paused";
  pill.className = status.enabled ? "pill pill-active" : "pill pill-paused";

  el("status-value").textContent = status.enabled ? "Active" : "Paused";
  el("mode-value").textContent = humanize(status.global_mode);
  el("default-mode-value").textContent = humanize(status.default_mode);
  el("monitoring-value").textContent = status.monitoring ? "Enabled" : "Disabled";
  el("intercept-value").textContent = config.general.intercept_paste ? "Enabled" : "Disabled";
  el("autostart-value").textContent = config.general.start_with_windows ? "Enabled" : "Disabled";
  el("password-value").textContent = status.password_protected ? "Enabled" : "Disabled";

  const buttons = document.querySelectorAll("#mode-switch button");
  buttons.forEach((button) => {
    button.classList.toggle("active", button.dataset.mode === status.global_mode);
  });

  el("mode-hint").textContent =
    status.global_mode === "ghost"
      ? "Ghost mode protects the clipboard the moment you copy, no matter where you paste it."
      : "Satellite mode keeps the original value and applies the policy of the application you paste into.";

  const pauseToggle = el("pause-toggle");
  pauseToggle.checked = !status.enabled;
}

/** Renders the application rules. */
function renderAppRules() {
  if (!config) return;
  const body = el("app-table").querySelector("tbody");
  if (!body) return;
  body.innerHTML = config.apps
    .map(
      (rule) => `<tr>
        <td>${escape(rule.label || rule.pattern)}</td>
        <td><code>${escape(rule.pattern)}</code></td>
        <td>
          <select data-app-mode="${escape(rule.id)}">
            ${["allow", "redact", "remove", "block"]
              .map(
                (mode) =>
                  `<option value="${mode}" ${rule.mode === mode ? "selected" : ""}>${humanize(mode)}</option>`,
              )
              .join("")}
          </select>
        </td>
        <td><input type="checkbox" data-app-trusted="${escape(rule.id)}" ${rule.trusted ? "checked" : ""} /></td>
        <td><input type="checkbox" data-app-enabled="${escape(rule.id)}" ${rule.enabled ? "checked" : ""} /></td>
        <td><button class="icon-button" data-remove-app="${escape(rule.id)}" title="Remove">x</button></td>
      </tr>`,
    )
    .join("");
}

/** Renders the custom rules. */
function renderCustomRules() {
  if (!config) return;
  const body = el("custom-table").querySelector("tbody");
  if (!body) return;
  if (config.rules.length === 0) {
    body.innerHTML = '<tr><td colspan="6"><span class="empty">No custom rules yet.</span></td></tr>';
    return;
  }
  body.innerHTML = config.rules
    .map(
      (rule) => `<tr>
        <td>${escape(rule.name)}</td>
        <td><code>${escape(rule.pattern)}</code></td>
        <td>${escape(humanize(rule.kind))}</td>
        <td>${escape(humanize(rule.risk ?? "high"))}</td>
        <td>${rule.group}</td>
        <td><button class="icon-button" data-remove-rule="${escape(rule.name)}" title="Remove">x</button></td>
      </tr>`,
    )
    .join("");
}

/** Renders the built-in rules. */
function renderBuiltinRules(list) {
  const body = el("builtin-table").querySelector("tbody");
  if (!body) return;
  body.innerHTML = list
    .map(
      (rule) => `<tr>
        <td>${escape(rule.name)}</td>
        <td>${escape(humanize(rule.kind))}</td>
        <td>${escape(humanize(rule.risk))}</td>
        <td><code>${escape(rule.pattern)}</code></td>
      </tr>`,
    )
    .join("");
}

/** Renders the detection settings. */
function renderDetectionSettings() {
  if (!config) return;
  el("detect-personal").checked = config.detection.detect_personal;
  el("entropy-context").checked = config.detection.entropy.require_context;
  el("entropy-threshold").value = String(config.detection.entropy.threshold);
  el("entropy-min-length").value = String(config.detection.entropy.min_length);
}

/** Sets the switch for the older clipboard content in every place it is shown. */
function setExistingChecked(value) {
  for (const id of ["setting-existing", "setting-existing-quick"]) {
    const element = document.getElementById(id);
    if (element) element.checked = value;
  }
}

/** Applies the switch for the older clipboard content right away. */
async function applyExistingSetting(checked) {
  if (!config) return;
  setExistingChecked(checked);
  config.general.protect_existing_clipboard = checked;
  try {
    config = await invoke("set_config", { config, password: passwordArg() });
    toast(checked ? "Older clipboard content is masked as well" : "Only new copies are masked");
    await refresh();
  } catch (error) {
    toast(`Could not change the setting: ${error}`, true);
  }
}

/** Fills the settings form with the current configuration. */
function renderSettings() {
  if (!config) return;
  const general = config.general ?? {};
  const protection = config.protection ?? {};

  el("setting-global-mode").value = general.global_mode ?? "ghost";
  el("setting-failsafe").value = general.fail_safe ?? "redact";
  el("setting-monitor").checked = general.monitor_clipboard !== false;
  el("setting-paste").checked = general.intercept_paste !== false;
  el("setting-restore").checked = general.restore_on_trusted_paste !== false;
  el("setting-notifications").checked = general.notifications !== false;
  setExistingChecked(general.protect_existing_clipboard === true);
  el("setting-autostart").checked = general.start_with_windows === true;

  el("setting-default-mode").value = protection.default_mode ?? "redact";
  el("setting-placeholder").value = protection.placeholder ?? "[REDACTED]";
}

/** Checks whether Windows keeps a clipboard history of its own. */
async function refreshClipboardHistory() {
  try {
    const history = await invoke("get_clipboard_history");
    const card = el("history-card");
    if (history?.history_enabled) {
      card.hidden = false;
    } else {
      card.hidden = true;
    }
  } catch (error) {
    // The service is not reachable; the card stays hidden.
  }
}

/** Turns the Windows clipboard history off. */
async function disableClipboardHistory() {
  try {
    await invoke("set_clipboard_history", { enabled: false });
    el("history-card").hidden = true;
    toast("The Windows clipboard history is off. Delete the old entries once with Win+V → Clear");
  } catch (error) {
    toast(`Could not change the clipboard history: ${error}`, true);
  }
}

/** Renders the list of files and folders ClipWarden uses. */
function renderPaths(paths) {
  if (!paths) return;
  const grid = el("paths-grid");
  const entries = [
    ["Version", paths.version],
    ["Data folder", paths.data_dir],
    ["Configuration", paths.config_path],
    ["Log file", paths.log_path],
  ];
  grid.innerHTML = entries
    .map(
      ([label, value]) =>
        `<div class="kv"><span class="kv-label">${escape(label)}</span><span class="kv-value">${escape(
          String(value ?? "—"),
        )}</span></div>`,
    )
    .join("");
}
/** Saves the settings form into the configuration. */
async function saveSettings() {
  if (!config) return;
  const general = config.general ?? (config.general = {});
  const protection = config.protection ?? (config.protection = {});

  general.global_mode = el("setting-global-mode").value;
  general.fail_safe = el("setting-failsafe").value;
  general.monitor_clipboard = el("setting-monitor").checked;
  general.intercept_paste = el("setting-paste").checked;
  general.restore_on_trusted_paste = el("setting-restore").checked;
  general.notifications = el("setting-notifications").checked;
  general.protect_existing_clipboard = el("setting-existing").checked;
  general.start_with_windows = el("setting-autostart").checked;

  protection.default_mode = el("setting-default-mode").value;
  protection.placeholder = el("setting-placeholder").value || "[REDACTED]";

  config.detection.detect_personal = el("detect-personal").checked;
  config.detection.entropy.require_context = el("entropy-context").checked;
  config.detection.entropy.threshold = Number(el("entropy-threshold").value || "4.2");
  config.detection.entropy.min_length = Number(el("entropy-min-length").value || "24");

  try {
    config = await invoke("set_config", { config, password: passwordArg() });
    // The autostart entry lives in the registry, not in the configuration.
    await invoke("set_autostart", { enabled: general.start_with_windows });
    toast("Settings saved");
    await refresh();
  } catch (error) {
    toast(`Could not save the settings: ${error}`, true);
  }
}

/** Sets or changes the dashboard password. */
async function savePassword() {
  if (!config) return;
  const next = el("password-new").value;
  const repeat = el("password-confirm").value;
  const current = el("password-current").value;

  if (!next) {
    toast("Please enter a new password", true);
    return;
  }
  if (next !== repeat) {
    toast("The two passwords do not match", true);
    return;
  }
  if (next.length < 4) {
    toast("The password is too short (minimum four characters)", true);
    return;
  }

  // If a password is already set, the current one has to be correct.
  const protectedAlready = (config.general?.password_hash ?? "") !== "";
  if (protectedAlready) {
    const provided = current || currentPassword || "";
    const valid = await invoke("verify_password", { password: provided });
    if (!valid) {
      toast("The current password is wrong", true);
      return;
    }
  }

  try {
    const hash = await invoke("hash_password", { password: next });
    config.general.password_hash = hash;
    config = await invoke("set_config", { config, password: passwordArg() });
    el("password-new").value = "";
    el("password-confirm").value = "";
    el("password-current").value = "";
    toast("Password saved");
    await refresh();
  } catch (error) {
    toast(`Could not save the password: ${error}`, true);
  }
}

/** Removes the dashboard password. */
async function removePassword() {
  if (!config) return;
  const current = el("password-current").value;
  const protectedAlready = (config.general?.password_hash ?? "") !== "";
  if (protectedAlready) {
    const provided = current || currentPassword || "";
    const valid = await invoke("verify_password", { password: provided });
    if (!valid) {
      toast("The current password is wrong", true);
      return;
    }
  }
  try {
    config.general.password_hash = "";
    config = await invoke("set_config", { config, password: passwordArg() });
    el("password-current").value = "";
    toast("Password removed");
    await refresh();
  } catch (error) {
    toast(`Could not remove the password: ${error}`, true);
  }
}

/** Renders the template gallery. */
function renderTemplates(templates) {
  const grid = el("template-grid");
  const enabled = new Set((config?.rules ?? []).map((rule) => rule.name));

  grid.innerHTML = templates
    .map((template) => {
      const isOn = enabled.has(template.name);
      return `<div class="template">
        <span class="template-category">${escape(humanize(template.category))}</span>
        <span class="template-name">${escape(template.name)}</span>
        <span class="template-desc">${escape(template.description)}</span>
        <div class="template-actions">
          <button data-add-template="${escape(template.id)}" ${isOn ? "disabled" : ""}>
            ${isOn ? "Enabled" : "Add"}
          </button>
        </div>
      </div>`;
    })
    .join("");
}

/** Renders the app shell (login screen vs dashboard). */
function renderApp() {
  const loginScreen = document.getElementById("login-screen");
  const dashboard = document.querySelector("main");
  if (!loginScreen || !dashboard) return;
  if (isLocked) {
    loginScreen.style.display = "block";
    dashboard.style.display = "none";
  } else {
    loginScreen.style.display = "none";
    dashboard.style.display = "block";
  }
}

/** Refreshes everything from the service. */
async function refresh() {
  try {
    const [status, stats, current] = await Promise.all([
      invoke("get_status"),
      invoke("get_stats"),
      invoke("get_config"),
    ]);
    config = current;
    failedRefreshes = 0;
    isLocked = status.password_protected && currentPassword === null;
    renderStatus(status);
    renderStats(stats);
    renderAppRules();
    renderCustomRules();
    renderDetectionSettings();
    renderSettings();
    el("password-hint").textContent = status.password_protected
      ? "A password is set — the dashboard asks for it before showing anything."
      : "No password is set — the dashboard opens without a prompt.";
    renderApp();
    renderTemplates(templates);
  } catch (error) {
    // A single failed round trip must not declare the service dead: the
    // service may just be busy or restarting. Only after several attempts
    // in a row the dashboard reports that the service is really gone.
    failedRefreshes += 1;
    if (failedRefreshes < 4) {
      el("footer-status").textContent = `Reconnecting to the ClipWarden service… (${error})`;
      el("status-pill").textContent = "Reconnecting…";
      el("status-pill").className = "pill pill-paused";
      return;
    }
    el("status-pill").textContent = "Service unavailable";
    el("status-pill").className = "pill pill-paused";
    el("footer-status").textContent = `Could not reach the ClipWarden service: ${error}`;
  }
}

/** Attempts to unlock the app with a password. */
async function unlock(password) {
  try {
    const valid = await invoke("verify_password", { password });
    if (valid) {
      currentPassword = password;
      isLocked = false;
      renderApp();
      await refresh();
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

/** Locks the app and clears the password from memory. */
function lock() {
  isLocked = true;
  currentPassword = null;
  renderApp();
}

/** Returns the password to send with protected commands, or undefined. */
function passwordArg() {
  // The password has to be sent whenever one is set — the service checks it
  // on every write, not only while the dashboard is locked.
  return currentPassword ?? undefined;
}

/** Wires up the tab navigation. */
function setupTabs() {
  const tabs = document.querySelectorAll(".tab");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((other) => other.classList.remove("active"));
      tab.classList.add("active");
      document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.remove("active"));
      const panel = document.getElementById(`tab-${tab.dataset.tab}`);
      if (panel) panel.classList.add("active");
    });
  });
}

/** Wires up the interactive elements. */
function setupInteractions() {
  el("pause-toggle").addEventListener("change", async (event) => {
    const paused = event.target.checked;
    try {
      await invoke("set_paused", { paused, password: passwordArg() });
      await refresh();
    } catch (error) {
      toast(`Could not change the protection state: ${error}`, true);
    }
  });

  document.querySelectorAll("#mode-switch button").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!config) return;
      config.general.global_mode = button.dataset.mode;
      await invoke("set_config", { config, password: passwordArg() });
    });
  });

  el("app-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const label = el("app-name").value.trim();
    const pattern = el("app-pattern").value.trim();
    const mode = el("app-mode").value;
    const trusted = el("app-trusted").checked;
    if (!label || !pattern) return;
    try {
      config = await invoke("upsert_app_rule", {
        rule: {
          id: pattern.toLowerCase().replace(/[^a-z0-9]+/g, "-"),
          label,
          pattern,
          mode,
          trusted,
          enabled: true,
        },
        password: passwordArg(),
      });
      renderAppRules();
      toast("Application rule added");
    } catch (error) {
      toast(`Could not add the rule: ${error}`, true);
    }
  });

  el("app-table").addEventListener("change", async (event) => {
    const target = event.target;
    if (!config) return;
    const modeId = target.dataset.appMode;
    const trustedId = target.dataset.appTrusted;
    const enabledId = target.dataset.appEnabled;
    const rule = config.apps.find(
      (candidate) =>
        candidate.id === modeId || candidate.id === trustedId || candidate.id === enabledId,
    );
    if (!rule) return;
    if (modeId) rule.mode = target.value;
    if (trustedId) rule.trusted = target.checked;
    if (enabledId) rule.enabled = target.checked;
    await invoke("set_config", { config, password: passwordArg() });
  });

  el("app-table").addEventListener("click", async (event) => {
    const target = event.target;
    const id = target.dataset.removeApp;
    if (!id) return;
    config = await invoke("remove_app_rule", { id, password: passwordArg() });
    renderAppRules();
    toast("Application rule removed");
  });

  el("rule-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = el("rule-name").value.trim();
    const pattern = el("rule-pattern").value.trim();
    const kind = el("rule-kind").value;
    const risk = el("rule-risk").value;
    const group = Number(el("rule-group").value || "0");
    if (!name || !pattern) return;
    const rule = {
      name,
      pattern,
      kind,
      risk,
      group,
      case_insensitive: false,
      dot_all: false,
      multiline: false,
      context: [],
      validators: [],
      enabled: true,
    };
    try {
      config = await invoke("upsert_rule", { rule, password: passwordArg() });
      renderCustomRules();
      toast("Custom rule added");
    } catch (error) {
      toast(`Could not add the rule: ${error}`, true);
    }
  });

  el("custom-table").addEventListener("click", async (event) => {
    const target = event.target;
    const name = target.dataset.removeRule;
    if (!name) return;
    config = await invoke("remove_rule", { name, password: passwordArg() });
    renderCustomRules();
    toast("Custom rule removed");
  });

  el("template-grid").addEventListener("click", async (event) => {
    const target = event.target;
    const id = target.dataset?.addTemplate;
    if (!id) return;
    const template = templates.find((t) => t.id === id);
    if (!template) return;
    try {
      config = await invoke("upsert_rule", { rule: template.rule, password: passwordArg() });
      renderCustomRules();
      renderTemplates(templates);
      toast(`Template "${template.name}" enabled`);
    } catch (error) {
      toast(`Could not add the template: ${error}`, true);
    }
  });

  el("phone-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const number = el("phone-number").value.trim();
    if (!number) return;
    try {
      const template = await invoke("personal_phone_template", { number });
      config = await invoke("upsert_rule", { rule: template.rule, password: passwordArg() });
      el("phone-number").value = "";
      renderCustomRules();
      renderTemplates(templates);
      toast("Your phone number is now protected");
    } catch (error) {
      toast(`Could not add the number: ${error}`, true);
    }
  });

  el("save-settings").addEventListener("click", () => {
    void saveSettings();
  });

  el("history-disable").addEventListener("click", () => {
    void disableClipboardHistory();
  });

  // Both places show the same switch, so they change each other.
  for (const id of ["setting-existing", "setting-existing-quick"]) {
    const element = document.getElementById(id);
    if (!element) continue;
    element.addEventListener("change", (event) => {
      const checked = event.target.checked;
      setExistingChecked(checked);
      void applyExistingSetting(checked);
    });
  }

  el("password-form").addEventListener("submit", (event) => {
    event.preventDefault();
    void savePassword();
  });

  el("password-remove").addEventListener("click", () => {
    void removePassword();
  });

  el("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = el("login-password").value;
    const success = await unlock(password);
    if (!success) {
      el("login-error").textContent = "Incorrect password";
    }
  });
}

/** Starts the dashboard. */
async function main() {
  setupTabs();
  setupInteractions();

  try {
    const kinds = await invoke("list_secret_kinds");
    const kindSelect = el("rule-kind");
    kindSelect.innerHTML = kinds
      .map((kind) => `<option value="${escape(kind.id)}">${escape(kind.label)}</option>`)
      .join("");

    const builtin = await invoke("list_builtin_rules");
    renderBuiltinRules(builtin);

    templates = await invoke("list_templates");
    renderTemplates(templates);

    // The paths never change while the app runs.
    renderPaths(await invoke("get_paths"));

    // Windows keeps its own clipboard history; the user should know about it.
    await refreshClipboardHistory();

    await refresh();
  } catch (error) {
    el("status-pill").textContent = "Service unavailable";
    el("status-pill").className = "pill pill-paused";
    el("footer-status").textContent = `Could not reach the ClipWarden service: ${error}`;
  }

  // Listen for detection events
  tauriEvent().listen("detection", (event) => {
    const events = window.__clipwarden_events || [];
    events.unshift(event.payload);
    if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
    window.__clipwarden_events = events;
    renderEvents();
    void refresh();
  });

  // Poll for status updates
  setInterval(() => {
    void refresh();
  }, 2000);
}

tauriEvent().listen("tauri://error", (event) => {
  console.error("Tauri error:", event.payload);
});

main();
