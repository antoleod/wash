/**
 * ui.js — All DOM mutation and UI feedback logic.
 *
 * Provides: toast notifications, theme management, modal control,
 * stats dashboard rendering, history panel, and pattern list rendering.
 */

import { CONFIG }       from '../config/config.js';
import { storage, timestamp, escapeHtml } from './utils.js';
import { t }            from './i18n.js';
import { labelForBase } from './labels.js';

const prefersReducedMotion = () =>
    window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;

// ============================================================
// THEME
// ============================================================

export function initTheme() {
    const saved = storage.get(CONFIG.STORAGE.THEME) || 'light';
    applyTheme(saved, false);
}

export function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'light';
    const next    = current === 'light' ? 'dark' : 'light';
    applyTheme(next, true);
    return next;
}

function applyTheme(theme, animate) {
    if (!animate) {
        document.body.classList.add('no-transition');
    }

    document.documentElement.setAttribute('data-theme', theme);
    storage.set(CONFIG.STORAGE.THEME, theme);

    // Swap SVG icon (moon ↔ sun) with a brief spin animation
    const iconEl = document.getElementById('themeIcon');
    if (iconEl) {
        const use = iconEl.querySelector('use');
        if (use) {
            use.setAttribute('href', theme === 'dark' ? '#ic-sun' : '#ic-moon');
        }
        if (animate) {
            iconEl.classList.remove('theme-spin');
            void iconEl.offsetWidth; // reflow to restart animation
            iconEl.classList.add('theme-spin');
        }
    }

    if (!animate) {
        requestAnimationFrame(() => {
            requestAnimationFrame(() => document.body.classList.remove('no-transition'));
        });
    }
}

// ============================================================
// MODAL
// ============================================================

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
let _modalId = null;
let _modalReturnFocus = null;

export function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    _modalId = modalId;
    _modalReturnFocus = document.activeElement;   // restore on close (WCAG 2.4.3)
    modal.hidden = false;
    const first = modal.querySelector(FOCUSABLE);
    (first || modal).focus();
    document.addEventListener('keydown', handleModalKey);
}

export function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    modal.hidden = true;
    document.removeEventListener('keydown', handleModalKey);
    _modalId = null;
    if (_modalReturnFocus && document.contains(_modalReturnFocus)) _modalReturnFocus.focus();
    _modalReturnFocus = null;
}

// Esc closes; Tab is trapped inside the dialog (WCAG 2.1.2 — no keyboard trap on
// the page means the modal must contain focus while open).
function handleModalKey(e) {
    if (!_modalId) return;
    if (e.key === 'Escape') { closeModal(_modalId); return; }
    if (e.key !== 'Tab') return;

    const modal = document.getElementById(_modalId);
    if (!modal || modal.hidden) return;
    const f = [...modal.querySelectorAll(FOCUSABLE)].filter(el => el.offsetParent !== null);
    if (!f.length) return;

    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
}

// ============================================================
// TOAST NOTIFICATIONS
// ============================================================

const TOAST_TYPES = {
    success: { icon: '✅', class: 'toast-success' },
    error:   { icon: '❌', class: 'toast-error' },
    info:    { icon: 'ℹ️',  class: 'toast-info' },
    warning: { icon: '⚠️', class: 'toast-warning' },
};

export function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const config  = TOAST_TYPES[type] || TOAST_TYPES.info;
    const toast   = document.createElement('div');
    toast.className = `toast ${config.class}`;
    toast.innerHTML = `<span class="toast-icon" aria-hidden="true">${config.icon}</span><span>${message}</span>`;

    container.appendChild(toast);

    // Remove after animation completes
    setTimeout(() => {
        toast.remove();
    }, CONFIG.TOAST_DURATION_MS + 300);
}

// ============================================================
// STATS DASHBOARD
// ============================================================

// Risk label TEXT is resolved through i18n at render time (so it follows the
// active language); only the CSS modifier is static here.
const RISK_CSS = {
    none:   '',
    low:    'risk-low',
    medium: 'risk-medium',
    high:   'risk-high',
};

const RISK_METER_WIDTHS = { none: 0, low: 22, medium: 58, high: 94 };
const RISK_METER_COLORS = {
    none:   'var(--color-border)',
    low:    'var(--color-success)',
    medium: 'var(--color-warning)',
    high:   'var(--color-danger)',
};

export function renderStats(stats) {
    const dashboard = document.getElementById('statsDashboard');
    if (!dashboard) return;

    dashboard.hidden = false;

    // Animated number counters
    animateNumber(document.getElementById('statTotal'), stats.total);
    animateNumber(document.getElementById('statPii'),   stats.pii);
    animateNumber(document.getElementById('statPci'),   stats.pci);

    const riskKey = stats.riskLevel in RISK_CSS ? stats.riskLevel : 'none';
    const riskEl  = document.getElementById('statRisk');
    if (riskEl) {
        riskEl.textContent = t(`risk_${riskKey}`);
        riskEl.className   = `stat-number ${RISK_CSS[riskKey]}`;
    }

    // Risk meter bar
    const fill = document.getElementById('riskFill');
    const meter = document.getElementById('riskMeter');
    if (fill) {
        fill.style.width      = `${RISK_METER_WIDTHS[stats.riskLevel] ?? 0}%`;
        fill.style.background = RISK_METER_COLORS[stats.riskLevel] || RISK_METER_COLORS.none;
    }
    if (meter) {
        meter.setAttribute('aria-valuenow', String(RISK_METER_WIDTHS[stats.riskLevel] ?? 0));
    }

    // Breakdown chips
    const breakdown = document.getElementById('statsBreakdown');
    if (breakdown) {
        breakdown.innerHTML = '';
        for (const [name, count] of Object.entries(stats.byPattern)) {
            const chip = document.createElement('span');
            chip.className = 'breakdown-item';
            chip.innerHTML = `<span class="bd-count">${count}</span> ${name}`;
            breakdown.appendChild(chip);
        }
    }
}

function animateNumber(el, target, duration = 480) {
    if (!el) return;
    const start = parseInt(el.textContent) || 0;
    if (start === target) return;
    // Respect reduced-motion: snap to the final value, no counting animation.
    if (prefersReducedMotion()) { el.textContent = String(target); return; }
    const diff      = target - start;
    const startTime = performance.now();

    function tick(now) {
        const elapsed  = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const ease     = 1 - Math.pow(1 - progress, 3); // cubic ease-out
        el.textContent = Math.round(start + diff * ease);
        if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
}

export function hideStats() {
    const dashboard = document.getElementById('statsDashboard');
    if (dashboard) dashboard.hidden = true;
}

// ============================================================
// HISTORY PANEL
// ============================================================

export function addHistoryItem(action, description, inputSnapshot, onRestore) {
    renderHistoryList([{ time: timestamp(), action, description, input: inputSnapshot }], item => onRestore(item.input), true);
}

export function renderHistoryList(entries, onRestore, prepend = false) {
    const panel = document.getElementById('historyPanel');
    if (!panel) return;

    panel.hidden = false;

    const list  = document.getElementById('historyList');
    if (!list) return;

    if (!prepend) list.innerHTML = '';
    const items = Array.isArray(entries) ? entries : [];
    if (!items.length) {
        clearHistoryPanel();
        return;
    }

    for (const item of items) {
        const li = document.createElement('li');
        li.className = 'history-item';
        li.setAttribute('role', 'listitem');
        li.title = t('history_restore_hint');

        li.innerHTML = `
            <span class="history-time">${escapeHtml(item.time || '')}</span>
            <span class="history-desc">${escapeHtml(item.description || '')}</span>
            <span class="history-action-tag">${escapeHtml(item.action || '')}</span>
        `;

        li.addEventListener('click', () => onRestore?.(item));
        if (prepend) list.insertBefore(li, list.firstChild);
        else list.appendChild(li);
    }

    // Limit visible history items
    const maxItems = CONFIG.MAX_HISTORY_ITEMS;
    while (list.children.length > maxItems) {
        list.removeChild(list.lastChild);
    }

    // Remove empty state if present
    const empty = list.querySelector('.history-empty');
    if (empty) empty.remove();
}

export function clearHistoryPanel() {
    const list = document.getElementById('historyList');
    if (!list) return;

    list.innerHTML = `<li class="history-empty">${escapeHtml(t('history_empty'))}</li>`;
}

// ============================================================
// PATTERN LIST
// ============================================================

export function renderPatternList(patterns, groups, onToggle, onRemove) {
    const list = document.getElementById('patternsList');
    if (!list) return;

    list.innerHTML = '';

    // Group patterns for organised display
    const byGroup = new Map();
    for (const p of patterns) {
        const key = p.group || 'global';
        if (!byGroup.has(key)) byGroup.set(key, []);
        byGroup.get(key).push(p);
    }

    // Render each group (in the order defined by PATTERN_GROUPS, custom last)
    const orderedGroups = [...(groups || []), { id: 'custom', icon: '✏️', label: t('patterns_custom_group') }];

    for (const group of orderedGroups) {
        const groupPatterns = byGroup.get(group.id);
        if (!groupPatterns || groupPatterns.length === 0) continue;

        // Group header
        const header = document.createElement('div');
        header.className = 'pattern-group-header';
        header.innerHTML = `<span aria-hidden="true">${group.icon || ''}</span><span>${group.label || group.id}</span>`;
        list.appendChild(header);

        for (const pattern of groupPatterns) {
            const item = document.createElement('div');
            item.className = 'pattern-item';
            item.setAttribute('role', 'listitem');

            const name         = pattern.displayName  || pattern.name;
            const badgeClass   = `badge-${pattern.type}`;
            const removeTitle  = pattern.builtin
                ? (pattern.builtinTip || t('pattern_builtin_tip'))
                : (pattern.removeTip  || t('action_delete'));

            item.innerHTML = `
                <input
                    type="checkbox"
                    class="pattern-toggle"
                    id="pt_${pattern.id}"
                    data-id="${pattern.id}"
                    ${pattern.enabled ? 'checked' : ''}
                    aria-label="Activar/desactivar: ${name}"
                >
                <label for="pt_${pattern.id}" class="pattern-name">${name}</label>
                <code class="pattern-regex" title="${pattern.regexStr}">${pattern.regexStr}</code>
                <span class="pattern-type-badge ${badgeClass}">${pattern.type.toUpperCase()}</span>
                <button
                    class="btn-remove-pattern"
                    data-id="${pattern.id}"
                    ${pattern.builtin ? 'disabled' : ''}
                    title="${removeTitle}"
                    aria-label="${removeTitle}: ${name}"
                >
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true">
                        <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                </button>
            `;

            item.querySelector('.pattern-toggle').addEventListener('change', e => {
                onToggle(pattern.id, e.target.checked);
            });

            const removeBtn = item.querySelector('.btn-remove-pattern');
            if (!pattern.builtin) {
                removeBtn.addEventListener('click', () => onRemove(pattern.id));
            }

            list.appendChild(item);
        }
    }

    // Count badge
    const countEl = document.getElementById('patternsCount');
    const active  = patterns.filter(p => p.enabled).length;
    if (countEl) countEl.textContent = `${active} / ${patterns.length}`;
}

// ============================================================
// OUTPUT / RESULT BOX
// ============================================================

export function setResultHtml(html) {
    const box = document.getElementById('resultBox');
    if (!box) return;
    box.classList.remove('loading');
    box.innerHTML = html || getEmptyStateDom();
    // Fallback for browsers without :has() — toggle a class the success badge
    // can also key off, so it shows once a sanitized report is present.
    const panel = box.closest('.output-panel');
    if (panel) panel.classList.toggle('has-clean-report', !!box.querySelector('.report-clean'));
}

/**
 * Updates the bottom "Confianza" card from a real percentage.
 * @param {number|null} percent  mean detection confidence, or null for the neutral state
 */
export function renderConfidence(percent) {
    const valEl  = document.getElementById('confidenceValue');
    const barEl  = document.getElementById('confidenceBar');
    const fillEl = document.getElementById('confidenceFill');
    const has = percent != null && !Number.isNaN(percent);
    const w   = has ? Math.max(0, Math.min(100, Math.round(percent))) : 0;
    if (valEl)  valEl.textContent = has ? `${w}%` : t('conf_empty');
    if (fillEl) fillEl.style.width = `${w}%`;
    if (barEl)  barEl.setAttribute('aria-valuenow', String(w));
}

export function setResultLoading() {
    const box = document.getElementById('resultBox');
    if (!box) return;
    box.classList.add('loading');
    box.innerHTML = `<span class="placeholder">${escapeHtml(t('result_processing'))}</span>`;
}

function getEmptyStateDom() {
    return `<div class="result-empty-state">
        <svg class="icon icon-xl empty-icon" aria-hidden="true"><use href="#ic-shield"/></svg>
        <p>${escapeHtml(t('result_placeholder'))}</p>
    </div>`;
}

export function setOutputButtonsEnabled(enabled) {
    ['copyBtn', 'copyFullBtn', 'exportBtn'].forEach(id => {
        const btn = document.getElementById(id);
        if (btn) btn.disabled = !enabled;
    });
}

export function setUndoEnabled(enabled) {
    const btn = document.getElementById('undoBtn');
    if (btn) btn.disabled = !enabled;
}

// ============================================================
// FINDINGS NAVIGATOR
// ============================================================
// Decoupled from audit/sanitize: scans whatever highlight spans
// the result box currently holds and lets the user step through them.

let _findings   = [];
let _findingIdx = -1;

/**
 * Scans the result box for highlighted findings and (re)builds the navigator.
 * Call AFTER setResultHtml() — it reads the freshly rendered DOM.
 */
export function initFindingsNav() {
    const box = document.getElementById('resultBox');
    const bar = document.getElementById('findingsNav');
    if (!box || !bar) return;

    // Prefer the clean-prompt block so the navigator skips the (duplicate) tokens
    // inside the collapsed audit table.
    const scope = box.querySelector('.report-clean') || box;
    _findings = Array.from(scope.querySelectorAll('.hl-pii, .hl-pci, .hl-token'));

    if (_findings.length === 0) {
        hideFindingsNav();
        return;
    }

    bar.hidden = false;
    _findings.forEach((el, i) => {
        el.classList.add('finding-clickable');
        el.addEventListener('click', () => gotoFinding(i, true));
    });

    // Mark the first finding as active without scrolling (acts as a hint).
    gotoFinding(0, false);
}

export function hideFindingsNav() {
    const bar = document.getElementById('findingsNav');
    if (bar) bar.hidden = true;
    _findings   = [];
    _findingIdx = -1;
}

export function findingsNavPrev() { gotoFinding(_findingIdx - 1, true); }
export function findingsNavNext() { gotoFinding(_findingIdx + 1, true); }

function gotoFinding(i, scroll) {
    if (!_findings.length) return;

    _findingIdx = (i + _findings.length) % _findings.length; // wrap around

    _findings.forEach(el => el.classList.remove('finding-active'));
    const cur = _findings[_findingIdx];
    cur.classList.add('finding-active');

    if (scroll) cur.scrollIntoView({ block: 'nearest', inline: 'nearest' });

    const counter = document.getElementById('findingsCounter');
    if (counter) counter.textContent = `${_findingIdx + 1} / ${_findings.length}`;
}

// ============================================================
// CHAR COUNT
// ============================================================

export function updateCharCount(text) {
    const el = document.getElementById('charCount');
    if (!el) return;
    const len = text.length;
    el.textContent = len === 0 ? '0 chars' : `${len.toLocaleString('es-ES')} chars`;
}

// ============================================================
// TOKEN MAP PANEL (assisted manual correction)
// ============================================================

/**
 * Renders the "Mapa de tokens" table from the projected rows.
 * @param {Array} rows  rows from buildAnonymizationReport (token/type/value/risk/source/confidence)
 * @param {{onEdit:Function, onReplace:Function, onDelete:Function}} handlers
 */
export function renderTokenMap(rows, handlers = {}) {
    const panel = document.getElementById('tokenmapPanel');
    const body  = document.getElementById('tokenmapBody');
    const count = document.getElementById('tokenmapCount');
    if (!panel || !body) return;

    const list = Array.isArray(rows) ? rows : [];
    panel.hidden = false;
    if (count) count.textContent = String(list.length);
    body.innerHTML = '';

    if (!list.length) {
        body.innerHTML = `<tr><td colspan="6" class="tokenmap-empty">${escapeHtml(t('tm_empty'))}</td></tr>`;
        return;
    }

    list.forEach((row, i) => {
        const tr = document.createElement('tr');
        if (row.source === 'Manual') tr.className = 'tm-row-manual';

        const riskKey   = String(row.risk || 'MEDIO').toUpperCase();
        const riskClass = riskKey === 'ALTO' ? 'tm-risk-alto' : riskKey === 'BAJO' ? 'tm-risk-bajo' : 'tm-risk-medio';
        const isManual  = row.source === 'Manual';
        const conf      = isManual ? 'Manual' : `${row.confidence}%`;
        const srcClass  = isManual ? 'tm-source-manual' : 'tm-source-auto';

        tr.innerHTML = `
            <td class="tm-token">${escapeHtml(row.token)}</td>
            <td>${escapeHtml(row.base ? labelForBase(row.base) : row.type)}</td>
            <td class="tm-value">${escapeHtml(row.value)}</td>
            <td><span class="tm-badge ${riskClass}">${escapeHtml(riskKey)}</span></td>
            <td><span class="tm-badge ${srcClass}">${escapeHtml(conf)}</span></td>
            <td><div class="tm-actions">
                <button class="tm-act-btn tm-act-edit" type="button">${escapeHtml(t('action_edit'))}</button>
                <button class="tm-act-btn tm-act-rep" type="button">${escapeHtml(t('action_replace'))}</button>
                <button class="tm-act-btn tm-act-del" type="button">${escapeHtml(t('action_delete'))}</button>
            </div></td>`;

        tr.querySelector('.tm-act-edit').addEventListener('click', () => handlers.onEdit?.(row, i));
        tr.querySelector('.tm-act-rep').addEventListener('click', () => handlers.onReplace?.(row, i));
        tr.querySelector('.tm-act-del').addEventListener('click', () => handlers.onDelete?.(row, i));
        body.appendChild(tr);
    });
}

export function hideTokenMap() {
    const panel = document.getElementById('tokenmapPanel');
    if (panel) panel.hidden = true;
}

/** Renders the manual-correction audit trail (spec point 9). */
export function renderAuditLog(log) {
    const list  = document.getElementById('auditLogList');
    const count = document.getElementById('auditLogCount');
    if (!list) return;

    const items = Array.isArray(log) ? log : [];
    if (count) count.textContent = String(items.length);
    list.innerHTML = '';

    for (const e of [...items].reverse()) {
        const li = document.createElement('li');
        li.className = 'audit-log-item';
        li.innerHTML = `
            <span class="al-time">${escapeHtml(e.time || '')}</span> —
            <strong>${escapeHtml(e.action || '')}</strong>:
            <span class="al-token">${escapeHtml(e.token || '')}</span>
            = ${escapeHtml(e.value || '')}
            <em>(${escapeHtml(e.type || '')}, ${escapeHtml(e.origin || '')})</em>`;
        list.appendChild(li);
    }
}

export function setCorrectionUndoEnabled(enabled) {
    const btn = document.getElementById('corrUndoBtn');
    if (btn) btn.disabled = !enabled;
}

// ============================================================
// TEMPORAL MEMORY PANEL (Token Painter session decisions)
// ============================================================

/**
 * Renders the session decisions table (custom tokens, protected, ignored).
 * @param {Array} entries  display rows prepared by app.js
 * @param {{onEdit,onDelete,onApply,onPermanent,onToggle}} handlers
 */
export function renderMemoryPanel(entries, handlers = {}) {
    const panel = document.getElementById('memoryPanel');
    const body  = document.getElementById('memoryBody');
    const count = document.getElementById('memoryCount');
    if (!panel || !body) return;

    const list = Array.isArray(entries) ? entries : [];
    if (!list.length) { panel.hidden = true; body.innerHTML = ''; return; }

    panel.hidden = false;
    if (count) count.textContent = String(list.length);
    body.innerHTML = '';

    list.forEach(e => {
        const tr = document.createElement('tr');
        if (!e.active) tr.className = 'mem-row-off';
        tr.innerHTML = `
            <td><span class="mem-tag ${e.tipoClass}">${escapeHtml(e.tipo)}</span></td>
            <td class="mem-name">${escapeHtml(e.nombre)}</td>
            <td class="mem-value">${escapeHtml(e.valor)}</td>
            <td>${escapeHtml(e.accion)}</td>
            <td><span class="${e.active ? 'mem-state-on' : 'mem-state-off'}">${escapeHtml(e.estado)}</span></td>
            <td><div class="mem-actions">
                <button class="mem-act-btn mem-act-edit" type="button">${escapeHtml(t('action_edit'))}</button>
                ${e.canGeneralize ? `<button class="mem-act-btn mem-act-gen" type="button" title="${escapeHtml(t('action_generalize_tip'))}">${escapeHtml(t('action_generalize'))}</button>` : ''}
                <button class="mem-act-btn mem-act-toggle" type="button">${escapeHtml(t(e.active ? 'action_deactivate' : 'action_activate'))}</button>
                ${e.permanent ? '' : `<button class="mem-act-btn mem-act-perm" type="button">${escapeHtml(t('action_permanent'))}</button>`}
                <button class="mem-act-btn mem-act-del" type="button">${escapeHtml(t('action_delete'))}</button>
            </div></td>`;
        tr.querySelector('.mem-act-edit').addEventListener('click', () => handlers.onEdit?.(e.id));
        tr.querySelector('.mem-act-gen')?.addEventListener('click', () => handlers.onGeneralize?.(e.id));
        tr.querySelector('.mem-act-toggle').addEventListener('click', () => handlers.onToggle?.(e.id));
        tr.querySelector('.mem-act-perm')?.addEventListener('click', () => handlers.onPermanent?.(e.id));
        tr.querySelector('.mem-act-del').addEventListener('click', () => handlers.onDelete?.(e.id));
        body.appendChild(tr);
    });
}

export function hideMemoryPanel() {
    const panel = document.getElementById('memoryPanel');
    if (panel) panel.hidden = true;
}
