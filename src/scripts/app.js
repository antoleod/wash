/**
 * app.js — Main application controller.
 *
 * Entry point loaded by index.html as type="module".
 * Bootstraps i18n first, then wires up all modules.
 */

import { CONFIG }               from '../config/config.js';
import { DEFAULT_PATTERNS, PATTERN_GROUPS, validateRegexStr, generatePatternId } from '../data/patterns.js';
import { initI18n, setLanguage, t, tPattern, tGroup, getAvailableLanguages, getCurrentLang } from './i18n.js';
import { initEntityScanner } from './entityScanner.js';
import { auditText }            from './audit.js';
import { analyzeStructured, analyzeStructuredBlocks, analyzeJson } from './detector.js';
import { sanitizeText }         from './sanitize.js';
import { buildAnonymizationReport } from './report.js';
import { suggestExpansion, suggestTokenBase, normalizeTokenBase, generalizeToRegex, CORRECTION_ACTIONS } from './corrections.js';
import { MANUAL_TOKEN_OPTIONS, labelForBase, PCI_TOKEN_BASES } from './labels.js';
import { restore, findPlaceholders } from './privacy.js';
import { downloadTextFile, readFileAsText, storage, debounce, timestamp } from './utils.js';
import {
    initTheme, toggleTheme,
    openModal, closeModal,
    showToast,
    renderStats, hideStats,
    addHistoryItem, renderHistoryList, clearHistoryPanel,
    renderPatternList,
    setResultHtml, setResultLoading, setOutputButtonsEnabled, setUndoEnabled,
    updateCharCount, renderConfidence,
    initFindingsNav, hideFindingsNav, findingsNavPrev, findingsNavNext,
    renderTokenMap, hideTokenMap, renderAuditLog, setCorrectionUndoEnabled,
    renderMemoryPanel, hideMemoryPanel,
} from './ui.js';

// Actions that keep the selection verbatim (no token): protect + ignore.
const SUPPRESS = new Set([CORRECTION_ACTIONS.IGNORE, CORRECTION_ACTIONS.PROTECT]);
const isSuppress = (action) => SUPPRESS.has(action);

// ── State ───────────────────────────────────────────────────

const state = {
    patterns:       [],     // full pattern list (builtin + custom)
    lastSanitized:  '',     // plain-text result (for copy/export)
    undoSnapshot:   null,   // input text before last action
    restoreMap:     null,   // token → original, for the gateway restore step
    manualRules:    [],     // learned (persisted) rules — opt-in
    corrections:    [],     // session correction list (the ordered model)
    correctionUndo: [],     // stack of correction snapshots for undo
    auditLog:       [],     // manual-correction audit trail (session)
    tokenRows:      [],     // last projected token-map rows
    cleanText:      '',     // last clean prompt text (for export)
    manualSelection: '',    // value currently being corrected in the popover
    correctionCtx:  null,   // {action, base} context for an edit/replace from the panel
    lastStats:      null,   // last rendered stats — for re-render on language change
    history:        [],     // persisted sanitized conversations
};

let _resizeTextarea = null; // set by initAutoResize, called on programmatic setInput
let _lastAuditHtml  = '';   // last rendered live-audit HTML (skip redundant re-renders)

// Live audit: as the user types/pastes, detect and preview risks automatically
// — no clicks needed. Quiet path (renderAuditPreview), debounced.
const liveAudit = debounce(() => {
    const text = getInput();
    // An input edit invalidates any prior sanitized result + gateway state.
    if (state.lastSanitized) {
        state.lastSanitized = '';
        setOutputButtonsEnabled(false);
        hideGateway();
        hideTokenMap();        // the projected map is stale until the next sanitize
        renderConfidence(null); // confidence belongs to a sanitize result; reset
        _lastAuditHtml = '';   // the box was showing tokens; force a re-render
    }
    renderAuditPreview(text);
}, 400);

// ── Bootstrap ───────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', init);

async function init() {
    // i18n MUST load first — all subsequent renders depend on it
    await initI18n();
    document.title = t('title') + ' — Simulador DLP';
    initEntityScanner().catch(() => {}); // non-blocking; app works without it

    initTheme();
    loadPatterns();
    loadHistory();
    loadManualRules();
    loadPersistedCorrections();   // opt-in: remembered session decisions
    restoreAutoSave();
    bindEvents();
    renderMemory();               // show remembered decisions immediately
    renderHistory();
    renderLanguageSelector();
    renderVersion();
    initMobileTabs();
    initPatternSearch();
    initAutoResize();
    initSidebar();
    setLayout('restore');   // start with Entrada + Salida active, Restaurar in the rail

    // Type immediately, no click to start (desktop only — avoids popping the
    // mobile keyboard on load).
    if (window.innerWidth >= 700) document.getElementById('inputText')?.focus();
}

// ── Patterns ────────────────────────────────────────────────

function loadPatterns() {
    const saved      = storage.getJSON(CONFIG.STORAGE.CUSTOM_PATTERNS);
    const builtinIds = new Set(DEFAULT_PATTERNS.map(p => p.id));

    if (Array.isArray(saved) && saved.length > 0) {
        // Restore enabled/disabled state of builtins; keep custom patterns
        const merged  = DEFAULT_PATTERNS.map(def => {
            const stored = saved.find(s => s.id === def.id);
            return stored ? { ...def, enabled: stored.enabled } : def;
        });
        const customs = saved.filter(p => !builtinIds.has(p.id));
        state.patterns = [...merged, ...customs];
    } else {
        state.patterns = DEFAULT_PATTERNS.map(p => ({ ...p }));
    }

    refreshPatternList();
}

function savePatterns() {
    storage.setJSON(CONFIG.STORAGE.CUSTOM_PATTERNS, state.patterns);
}

function loadManualRules() {
    const saved = storage.getJSON(CONFIG.STORAGE.MANUAL_RULES);
    state.manualRules = Array.isArray(saved)
        ? saved.filter(rule => rule && typeof rule.value === 'string' && typeof rule.tokenBase === 'string')
        : [];
}

function saveManualRules() {
    storage.setJSON(CONFIG.STORAGE.MANUAL_RULES, state.manualRules);
}

function loadHistory() {
    const saved = storage.getJSON(CONFIG.STORAGE.HISTORY);
    state.history = Array.isArray(saved) ? saved.slice(0, CONFIG.MAX_HISTORY_ITEMS) : [];
}

function saveHistory() {
    storage.setJSON(CONFIG.STORAGE.HISTORY, state.history.slice(0, CONFIG.MAX_HISTORY_ITEMS));
}

function rememberConversation(entry) {
    const next = {
        id: `hist_${Date.now()}`,
        time: timestamp(),
        ...entry,
    };
    state.history = [
        next,
        ...state.history.filter(item => item.cleanText !== next.cleanText || item.input !== next.input),
    ].slice(0, CONFIG.MAX_HISTORY_ITEMS);
    saveHistory();
    renderHistory();
}

function renderHistory() {
    renderHistoryList(state.history, restoreHistoryEntry);
}

function refreshPatternList() {
    // Build display names from i18n, falling back to pattern.name
    const enriched = state.patterns.map(p => ({
        ...p,
        displayName:  tPattern(p.id, 'name')  || p.name,
        displayLabel: tPattern(p.id, 'label') || p.label,
    }));

    renderPatternList(
        enriched,
        PATTERN_GROUPS.map(g => ({ ...g, label: tGroup(g.id) })),
        handlePatternToggle,
        handlePatternRemove,
    );
}

function getActivePatterns() {
    return state.patterns
        .filter(p => p.enabled)
        .map(p => ({
            ...p,
            name: tPattern(p.id, 'name') || p.name,
            label: tPattern(p.id, 'label') || p.label,
        }));
}

function handlePatternToggle(id, enabled) {
    const p = state.patterns.find(x => x.id === id);
    if (!p) return;
    p.enabled = enabled;
    savePatterns();
    refreshPatternList();
    const name = tPattern(id, 'name') || p.name;
    showToast(t(enabled ? 'toast_pattern_on' : 'toast_pattern_off', { name }), 'info');
}

function handlePatternRemove(id) {
    const idx = state.patterns.findIndex(p => p.id === id && !p.builtin);
    if (idx === -1) return;
    const name = tPattern(id, 'name') || state.patterns[idx].name;
    state.patterns.splice(idx, 1);
    savePatterns();
    refreshPatternList();
    showToast(t('toast_pattern_removed', { name }), 'warning');
}

// ── Core actions ────────────────────────────────────────────

function getInput()       { return document.getElementById('inputText')?.value || ''; }
function setInput(text)   {
    const el = document.getElementById('inputText');
    if (el) {
        el.value = text;
        updateCharCount(text);
        if (_resizeTextarea) _resizeTextarea();
    }
    _lastAuditHtml = '';   // force a fresh preview on programmatic changes
    liveAudit();           // paste / import / undo also preview risks automatically
}

/**
 * SILENT audit render — used live while typing. Updates only the result
 * highlights, stats and findings navigator. No toasts, history, tab-switch,
 * loading flicker or pulse (those belong to the explicit click path).
 * Skips the DOM re-render when the audit output is unchanged (avoids jitter).
 * @returns {object} stats
 */
function renderAuditPreview(text) {
    if (!text || !text.trim()) {
        _lastAuditHtml = '';
        setResultHtml('');
        hideFindingsNav();
        hideStats();
        state.lastStats = null;
        setWorkflowStep(1);
        return { total: 0, pii: 0, pci: 0, riskLevel: 'none', byPattern: {} };
    }

    // Structured input (JSON, then CSV) anonymizes by key/column; free text uses
    // regex. analyzeStructuredBlocks(text, active) unions all three so mixed
    // blobs (prose + embedded CSV/JSON) get full coverage, not either/or.
    const active = getActivePatterns();
    const structured = analyzeJson(text) || analyzeStructured(text) || analyzeStructuredBlocks(text, active);
    const fallback = auditText(text, active);
    let html, stats;
    if (structured && structured.stats.total >= fallback.stats.total) {
        html  = structured.auditHtml;
        stats = structured.stats;
    } else {
        ({ html, stats } = fallback);
    }

    if (html !== _lastAuditHtml) {
        _lastAuditHtml = html;
        if (!stats.total) {
            setResultHtml(`<span class="placeholder">${t('result_no_findings')}</span>`);
            hideFindingsNav();
        } else {
            setResultHtml(html);
            initFindingsNav();
        }
        state.lastStats = stats;
        renderStats(stats);
        setWorkflowStep(2);
    }
    return stats;
}

function handleAudit() {
    const text = getInput();
    if (!text.trim()) { showToast(t('toast_no_input'), 'warning'); return; }

    liveAudit.cancel?.();
    const stats = renderAuditPreview(text);

    setOutputButtonsEnabled(false);
    state.lastSanitized = '';
    switchToOutputTab();

    if (!stats.total) {
        showToast(t('toast_no_findings'), 'success');
    } else {
        const n = stats.total;
        showToast(t('toast_findings', { n, s: n === 1 ? '' : 's' }), 'warning');
        pulseSanitizeBtn();
    }

    addHistoryItem(
        t('history_action_audit'),
        t('history_desc_audit', { n: stats.total, level: t(`risk_${stats.riskLevel}`) }),
        text,
        restoreInput,
    );
}

function handleSanitize() {
    const text = getInput();
    if (!text.trim()) { showToast(t('toast_no_input'), 'warning'); return; }

    liveAudit.cancel?.();
    state.undoSnapshot = text;
    setUndoEnabled(true);
    setResultLoading();

    const active = getActivePatterns();
    const { sanitized, html, cleanHtml, detailsHtml, replacements, stats, restoreMap, rows, cleanText } =
        buildAnonymizationReport(text, active, activeCorrections());

    const displayHtml = buildResultDisplay(cleanHtml, detailsHtml, html, text);
    setResultHtml(displayHtml);
    initFindingsNav();
    state.lastSanitized = sanitized;
    state.restoreMap    = restoreMap;
    state.tokenRows     = rows || [];
    state.cleanText     = cleanText || '';
    setOutputButtonsEnabled(true);
    showGateway(replacements > 0 ? sanitized : '', replacements > 0);
    renderTokenMapPanel();

    state.lastStats = stats;
    renderStats(stats);
    renderConfidence(meanConfidence(state.tokenRows));
    setWorkflowStep(3);
    switchToOutputTab();

    if (replacements === 0) {
        showToast(t('toast_no_replace'), 'success');
    } else {
        showToast(t('toast_sanitized', { n: replacements, s: replacements === 1 ? '' : 's' }), 'success');
    }

    addHistoryItem(
        t('history_action_sanitize'),
        t('history_desc_sanitize', { n: replacements }),
        text,
        restoreInput,
    );
    rememberConversation({
        action: t('history_action_sanitize'),
        description: t('history_desc_sanitize', { n: replacements }),
        input: text,
        sanitized,
        cleanText: cleanText || '',
        displayHtml,
        restoreMap,
        rows: rows || [],
        stats,
        replacements,
    });
}

function handleClear() {
    const prev = getInput();
    if (prev) { state.undoSnapshot = prev; setUndoEnabled(true); }
    setInput('');
    setResultHtml('');
    hideFindingsNav();
    hideGateway();
    setOutputButtonsEnabled(false);
    hideStats();
    state.lastStats = null;
    state.lastSanitized = '';
    setWorkflowStep(1);
    showToast(t('toast_cleared'), 'info');
}

function handleUndo() {
    if (!state.undoSnapshot) return;
    restoreInput(state.undoSnapshot);
    state.undoSnapshot = null;
    setUndoEnabled(false);
    showToast(t('toast_undo'), 'info');
}

function restoreInput(text) {
    setInput(text);
    setResultHtml('');
    hideFindingsNav();
    hideGateway();
    setOutputButtonsEnabled(false);
    hideStats();
    state.lastStats = null;
    state.lastSanitized = '';
    autoSave(text);
}

function restoreHistoryEntry(entry) {
    if (!entry) return;
    setInput(entry.input || '');
    setResultHtml(entry.displayHtml || escFallback(entry.cleanText || entry.sanitized || ''));
    initFindingsNav();
    state.lastSanitized = entry.sanitized || entry.cleanText || '';
    state.cleanText = entry.cleanText || '';
    state.restoreMap = entry.restoreMap || {};
    state.tokenRows = entry.rows || [];
    state.lastStats = entry.stats || null;
    setOutputButtonsEnabled(!!state.lastSanitized);
    showGateway(state.lastSanitized, !!Object.keys(state.restoreMap).length);
    renderTokenMapPanel();
    if (state.lastStats) renderStats(state.lastStats);
    else hideStats();
    renderConfidence(meanConfidence(state.tokenRows));
    setWorkflowStep(3);
    switchToOutputTab();
    autoSave(entry.input || '');
}

// "Copiar prompt" → just the clean prompt (what you paste into the LLM).
function handleCopy() {
    const text = state.cleanText || state.lastSanitized;
    if (!text) return;
    navigator.clipboard.writeText(text)
        .then(() => showToast(t('toast_copied'), 'success'))
        .catch(() => showToast(t('toast_copy_fail'), 'error'));
}

// "Copiar full" → the whole report (clean prompt + audit + suspicious + tips).
function handleCopyFull() {
    if (!state.lastSanitized) return;
    navigator.clipboard.writeText(state.lastSanitized)
        .then(() => showToast(t('toast_copied'), 'success'))
        .catch(() => showToast(t('toast_copy_fail'), 'error'));
}

function handleExport() {
    if (!state.lastSanitized) return;
    const date     = new Date().toISOString().slice(0, 10);
    const filename = `prompt-sanitizado-${date}.txt`;
    downloadTextFile(filename, state.lastSanitized);
    showToast(t('toast_exported', { filename }), 'success');
}

// ── Privacy Gateway: reverse anonymization ──────────────────

/**
 * Three-body desktop layout: Salida is always active (centre pivot); Entrada
 * and Restaurar trade the second active slot. The inactive one collapses to a
 * rail. `collapsed` ∈ {'restore','input'}.
 */
function setLayout(collapsed) {
    const area = document.querySelector('.sandbox-area');
    if (!area) return;
    area.classList.toggle('collapse-restore', collapsed === 'restore');
    area.classList.toggle('collapse-input',   collapsed === 'input');
    document.getElementById('panelInput')?.classList.toggle('panel-collapsed', collapsed === 'input');
    document.getElementById('panelRestore')?.classList.toggle('panel-collapsed', collapsed === 'restore');
    document.getElementById('railInput')?.setAttribute('aria-expanded', String(collapsed !== 'input'));
    document.getElementById('railRestore')?.setAttribute('aria-expanded', String(collapsed !== 'restore'));
}

function clearGatewayFields() {
    const input  = document.getElementById('restoreInput');
    const output = document.getElementById('restoreOutput');
    const verify = document.getElementById('restoreVerify');
    if (input)  input.value = '';
    if (output) { output.hidden = true; output.textContent = ''; }
    if (verify) { verify.textContent = ''; verify.className = 'restore-verify'; }
}

function showGateway(prefill, activate) {
    const input  = document.getElementById('restoreInput');
    const output = document.getElementById('restoreOutput');
    const verify = document.getElementById('restoreVerify');
    if (input)  input.value = prefill || '';   // seed with the safe text to try the round-trip
    if (output) { output.hidden = true; output.textContent = ''; }
    if (verify) { verify.textContent = ''; verify.className = 'restore-verify'; }
    setLayout(activate ? 'input' : 'restore');
}

function hideGateway() {
    clearGatewayFields();
    setLayout('restore');
    state.restoreMap = null;
}

function handleRestore() {
    const input  = document.getElementById('restoreInput');
    const output = document.getElementById('restoreOutput');
    const verify = document.getElementById('restoreVerify');
    const text   = input?.value || '';

    if (!state.restoreMap || !Object.keys(state.restoreMap).length || !text.trim()) {
        showToast(t('toast_restore_empty'), 'warning');
        return;
    }

    const restored = restore(text, state.restoreMap);
    const orphans  = findPlaceholders(restored);

    // FASE 5 — re-scan the LLM response for RAW sensitive data (leaked or
    // invented). Strip placeholders first so tokens aren't scanned themselves.
    const active    = getActivePatterns();
    const stripped  = text.replace(/\[[A-Z_]+_\d+\]/g, ' ');
    const invented  = Object.values(sanitizeText(stripped, active).restoreMap);

    if (output) {
        output.hidden = false;
        output.textContent = restored;   // textContent: real data is never rendered as HTML
    }
    if (verify) {
        if (invented.length) {
            verify.textContent = t('restore_invented', { list: invented.join(', ') });
            verify.className   = 'restore-verify restore-danger';
        } else if (orphans.length) {
            verify.textContent = t('restore_orphans', { n: orphans.length, list: orphans.join(', ') });
            verify.className   = 'restore-verify restore-warn';
        } else {
            verify.textContent = t('restore_ok');
            verify.className   = 'restore-verify restore-ok';
        }
    }
    showToast(t('toast_restored'), 'success');
}

function handleCopySafe() {
    const safe = state.lastSanitized;
    if (!safe) { showToast(t('toast_restore_empty'), 'warning'); return; }
    navigator.clipboard?.writeText(safe)
        .then(() => showToast(t('toast_copied'), 'success'))
        .catch(() => showToast(t('toast_copy_fail'), 'error'));
}

async function handlePaste() {
    // navigator.clipboard is undefined on insecure/file:// contexts and some
    // mobile browsers — guard before calling to avoid a synchronous TypeError.
    if (!navigator.clipboard?.readText) {
        showToast(t('toast_paste_unsupported'), 'warning');
        return;
    }
    try {
        const text = await navigator.clipboard.readText();
        if (!text) { showToast(t('toast_paste_empty'), 'info'); return; }
        setInput(text);
        autoSave(text);
        showToast(t('toast_pasted'), 'success');
    } catch {
        showToast(t('toast_paste_fail'), 'error');
    }
}

async function handleImport(file) {
    if (!file) return;
    if (!file.type.startsWith('text') && file.type !== '') {
        showToast(t('toast_import_type'), 'error');
        return;
    }
    try {
        const text = await readFileAsText(file);
        setInput(text);
        autoSave(text);
        showToast(t('toast_imported', { name: file.name }), 'success');
    } catch {
        showToast(t('toast_import_error'), 'error');
    }
}

// ── Assisted manual correction ──────────────────────────────
// Corrections are a session-only ORDERED LIST. The token map is a projection of
// (auto-detections ∪ corrections) recomputed on every sanitize. Learning into a
// persistent rule is an explicit opt-in, never automatic.

/** Active session corrections + applicable learned rules, fed to the report engine. */
function activeCorrections() {
    const session = (state.corrections || []).filter(c => c.active !== false);
    const learned = (state.manualRules || [])
        .filter(r => r && r.value && r.tokenBase)
        .map(r => ({ value: r.value, tokenBase: r.tokenBase, action: CORRECTION_ACTIONS.CREATE, source: 'learned' }));
    return [...session, ...learned];
}

// Right-click (or context menu) on a text selection in the input opens the popover.
function handleInputContextMenu(e) {
    const input = e.currentTarget;
    const selected = input.value.slice(input.selectionStart, input.selectionEnd).trim();
    if (!selected) return;
    e.preventDefault();
    openCorrectionMenu({ value: selected, action: CORRECTION_ACTIONS.CREATE, x: e.clientX, y: e.clientY, fromInput: true });
}

// Mouse selection (Token Painter): selecting text opens the floating popover.
function handleInputMouseUp(e) {
    const input = e.currentTarget;
    // Capture the selection NOW — it collapses the moment the popover takes focus.
    const selected = input.value.slice(input.selectionStart, input.selectionEnd).trim();
    if (!selected || selected.length < 2) return;
    state.manualSelection = selected;
    const x = e.clientX, y = e.clientY;
    // Defer opening: a double-click select fires a trailing `click` that would hit
    // handleCorrectionOutsideClick — deferring lets it fire while the menu's hidden.
    setTimeout(() => openCorrectionMenu({ value: selected, action: CORRECTION_ACTIONS.CREATE, x, y, fromInput: true }), 0);
}

// Output ("Sortie") selection: the clean text shows TOKENS, not the original. We
// reconstruct the original by swapping each [TOKEN_N] back to its value, then open
// the painter on that original — so a token CAN be corrected straight from the result.
function handleOutputMouseUp(e) {
    const box = document.getElementById('resultBox');
    const sel = window.getSelection?.();
    if (!box || !sel || sel.rangeCount === 0) return;
    if (!box.contains(sel.anchorNode) || !box.contains(sel.focusNode)) return;

    const raw = String(sel).trim();
    if (!raw || raw.length < 2) return;

    const original = reconstructFromOutput(raw);
    // Only act when the reconstruction maps back to real input text (a selection
    // over report scaffolding like "1. TEXTO_LIMPIO:" won't, and is ignored).
    if (!original || !getInput().includes(original)) return;

    // Derive the base from the first token in the selection (so "extend" keeps the
    // same type); otherwise guess it from the value.
    const tokMatch = raw.match(/\[([A-Z_]+)_\d+\]/);
    const base   = tokMatch ? normalizeTokenBase(tokMatch[1]) : suggestTokenBase(original);
    const action = tokMatch ? CORRECTION_ACTIONS.EXTEND : CORRECTION_ACTIONS.CREATE;

    state.manualSelection = original;
    const x = e.clientX, y = e.clientY;
    setTimeout(() => openCorrectionMenu({ value: original, action, base, x, y }), 0);
}

/** Swaps every [TOKEN_N] in a piece of output text back to its original value. */
function reconstructFromOutput(text) {
    const map = state.restoreMap || {};
    return String(text || '')
        .replace(/\[[A-Z_]+_\d+\]/g, tok => (map[tok] != null ? map[tok] : tok))
        .trim();
}

/**
 * Opens the assisted-correction popover.
 * @param {{value:string, action:string, base?:string, x?:number, y?:number}} opts
 */
function openCorrectionMenu(opts) {
    const menu   = document.getElementById('correctionMenu');
    const valEl  = document.getElementById('corrValue');
    const action = document.getElementById('corrAction');
    const custom = document.getElementById('corrCustom');
    const learn  = document.getElementById('corrLearn');
    if (!menu || !valEl || !action) return;

    const value = String(opts.value || '').trim();
    state.manualSelection = value;
    state.correctionCtx   = { action: opts.action, base: opts.base || null, fromInput: !!opts.fromInput };

    valEl.value = value;
    action.value = opts.action || CORRECTION_ACTIONS.CREATE;
    if (custom) custom.value = '';
    if (learn)  learn.checked = false;

    const suggestedBase = opts.base || suggestTokenBase(value);
    renderCorrectionTypeOptions(suggestedBase);
    const adv = document.getElementById('corrAdvanced');
    if (adv) adv.open = false;   // start collapsed each open
    onCorrectionTypeChange();
    onCorrectionActionChange();
    refreshHint();
    updateCorrectionPreview();

    menu.hidden = false;
    positionMenu(menu, opts.x, opts.y);
    valEl.focus();
    valEl.select?.();
}

// One contextual hint line, by priority: reuse › expansion suggestion › type guess.
function refreshHint() {
    const hint   = document.getElementById('corrHint');
    const textEl = document.getElementById('corrHintText');
    const btn    = document.getElementById('corrHintBtn');
    if (!hint || !textEl || !btn) return;

    const value    = document.getElementById('corrValue')?.value.trim() || '';
    const suppress = isSuppress(currentAction());
    const clear = () => { btn.hidden = true; btn.dataset.kind = ''; btn.dataset.payload = ''; };

    // 1) Reuse — this selection already maps to a token.
    const existing = suppress ? '' : findExistingToken(value);
    if (existing) {
        textEl.textContent = `${t('corr_reuse_pre') || 'Ya existe como'} ${existing}`;
        btn.hidden = false; btn.textContent = t('corr_reuse_btn') || 'Reutilizar';
        btn.dataset.kind = 'reuse'; btn.dataset.payload = existing;
        hint.hidden = false; hint.dataset.tone = 'reuse';
        return;
    }
    // 2) Expansion suggestion — a fuller value nearby (disabled when triggered from input).
    const base = chosenBase();
    const fromInput = state.correctionCtx?.fromInput;
    const suggestion = (suppress || fromInput) ? '' : suggestExpansion(getInput(), value, base === 'DIRECCION' ? 'address' : 'name');
    if (suggestion && suggestion !== value) {
        textEl.textContent = `${t('corr_suggestion') || 'Posible expansión'}: ${suggestion}`;
        btn.hidden = false; btn.textContent = t('corr_accept') || 'Aceptar';
        btn.dataset.kind = 'suggestion'; btn.dataset.payload = suggestion;
        hint.hidden = false; hint.dataset.tone = 'suggestion';
        return;
    }
    // 3) Type guess — informational, never forced.
    const guess = suppress ? '' : suggestTokenBase(value);
    if (value && guess && guess !== 'RIESGO_MANUAL') {
        textEl.textContent = `${t('corr_guess_pre') || 'Parece'} ${labelForBase(guess).toLowerCase()}`;
        clear();
        hint.hidden = false; hint.dataset.tone = 'guess';
        return;
    }
    hint.hidden = true; clear();
}

function handleHintAction() {
    const btn = document.getElementById('corrHintBtn');
    const kind = btn?.dataset.kind;
    const payload = btn?.dataset.payload || '';
    if (kind === 'reuse') {
        showToast(`${t('corr_reuse_btn') || 'Reutilizar'}: ${payload}`, 'info');
        closeCorrectionMenu();
    } else if (kind === 'suggestion') {
        const valEl = document.getElementById('corrValue');
        if (valEl) { valEl.value = payload; state.manualSelection = payload; }
        refreshHint();
        updateCorrectionPreview();
    }
}

/** Looks up a token for `value` across the projected token-map rows. */
function findExistingToken(value) {
    const v = String(value || '').trim().toLowerCase();
    if (!v) return '';
    const row = (state.tokenRows || []).find(r => String(r.value).toLowerCase() === v);
    return row ? row.token : '';
}

function positionMenu(menu, x, y) {
    const w = menu.offsetWidth  || 360;
    const h = menu.offsetHeight || 320;
    const px = Number.isFinite(x) ? x : (window.innerWidth  - w) / 2;
    const py = Number.isFinite(y) ? y : (window.innerHeight - h) / 2;
    menu.style.left = `${Math.max(12, Math.min(px, window.innerWidth  - w - 12))}px`;
    menu.style.top  = `${Math.max(12, Math.min(py, window.innerHeight - h - 12))}px`;
}

function renderCorrectionTypeOptions(suggestedBase) {
    const select = document.getElementById('corrType');
    if (!select) return;
    select.innerHTML = '';
    const ordered = [...MANUAL_TOKEN_OPTIONS].sort((a, b) => {
        if (a.token === suggestedBase) return -1;
        if (b.token === suggestedBase) return 1;
        return labelForBase(a.token).localeCompare(labelForBase(b.token));
    });
    for (const opt of ordered) {
        const el = document.createElement('option');
        el.value = opt.token;
        el.textContent = `${labelForBase(opt.token)} - [${opt.token}_N]`;
        if (opt.token === suggestedBase) el.selected = true;
        select.appendChild(el);
    }
    // "+ Nuevo tipo…" — lets the user invent a type that isn't in the list.
    const newOpt = document.createElement('option');
    newOpt.value = '__new__';
    newOpt.textContent = `＋ ${t('corr_type_new') || 'Nuevo tipo…'}`;
    select.appendChild(newOpt);
}

/** The token base the user picked; "+ Nuevo tipo…" reads the custom name field. */
function chosenBase() {
    const select = document.getElementById('corrType')?.value;
    if (select === '__new__') {
        return normalizeTokenBase(document.getElementById('corrCustom')?.value?.trim() || 'OTRO');
    }
    return normalizeTokenBase(select || 'RIESGO_MANUAL');
}

function currentAction() {
    return document.getElementById('corrAction')?.value || CORRECTION_ACTIONS.CREATE;
}

// Show the custom-name input only when "+ Nuevo tipo…" is picked.
function onCorrectionTypeChange() {
    const isNew  = document.getElementById('corrType')?.value === '__new__';
    const custom = document.getElementById('corrCustom');
    if (custom) {
        custom.hidden = !isNew || isSuppress(currentAction());
        if (isNew && !custom.hidden) custom.focus();
    }
    refreshHint();
    updateCorrectionPreview();
}

// Suppress actions (protect/ignore) keep text verbatim → hide the type controls.
function onCorrectionActionChange() {
    const suppress  = isSuppress(currentAction());
    const typeField = document.getElementById('corrTypeField');
    const custom    = document.getElementById('corrCustom');
    if (typeField) typeField.style.display = suppress ? 'none' : '';
    if (custom)    custom.hidden = suppress || document.getElementById('corrType')?.value !== '__new__';
    refreshHint();
    updateCorrectionPreview();
}

// Live before/after preview (spec point 11) — computed by a real trial run.
function updateCorrectionPreview() {
    const preview = document.getElementById('corrPreview');
    const before  = document.getElementById('corrBefore');
    const after   = document.getElementById('corrAfter');
    if (!preview || !before || !after) return;

    const value  = document.getElementById('corrValue')?.value.trim() || '';
    const action = currentAction();
    if (!value) { preview.hidden = true; return; }

    const trial = isSuppress(action)
        ? { value, action }
        : { value, tokenBase: chosenBase(), action };

    const active = getActivePatterns();
    const baseRun  = buildAnonymizationReport(getInput(), active, activeCorrections());
    const trialRun = buildAnonymizationReport(getInput(), active, [trial, ...activeCorrections()]);

    before.textContent = snippetAround(baseRun.cleanText, value) || baseRun.cleanText.slice(0, 120) || '—';
    after.textContent  = snippetAround(trialRun.cleanText, value, true) || trialRun.cleanText.slice(0, 120) || '—';
    preview.hidden = false;
}

/** A short window of `text` around `needle` (or around its likely token). */
function snippetAround(text, needle, isAfter = false) {
    const safe = String(text || '');
    let idx = safe.indexOf(needle);
    if (idx === -1 && isAfter) {
        const tok = safe.match(/\[[A-Z_]+_\d+\]/);   // after a correction the value becomes a token
        if (tok) idx = tok.index;
    }
    if (idx === -1) return '';
    const start = Math.max(0, idx - 30);
    const end   = Math.min(safe.length, idx + Math.max(needle.length, 12) + 30);
    return (start > 0 ? '…' : '') + safe.slice(start, end) + (end < safe.length ? '…' : '');
}

function handleCorrectionSubmit(e) {
    e.preventDefault();
    const value  = document.getElementById('corrValue')?.value.trim() || '';
    const action = currentAction();
    const learn  = document.getElementById('corrLearn')?.checked || false;

    if (!value) { showToast(t('toast_select_value'), 'warning'); return; }

    // A forced span is located by exact value in the ORIGINAL text. If it's not
    // there (e.g. the user typed a value not present), nothing would apply.
    if (!getInput().includes(value)) {
        showToast(t('toast_value_not_found'), 'warning');
        return;
    }

    const isNew  = document.getElementById('corrType')?.value === '__new__';
    const custom = isNew ? document.getElementById('corrCustom')?.value?.trim() : '';
    const correction = makeCorrection(value, action, isSuppress(action) ? null : chosenBase(), custom);
    addCorrection(correction, { learn });
    closeCorrectionMenu();
}

let _corrSeq = 0;
function nextCorrectionId() { return `c${Date.now().toString(36)}${(_corrSeq++).toString(36)}`; }

/** Builds a correction record with session flags. */
function makeCorrection(value, action, tokenBase, customName) {
    const rec = { id: nextCorrectionId(), value, action, active: true, permanent: false, ts: new Date().toISOString() };
    if (!isSuppress(action)) rec.tokenBase = tokenBase || 'RIESGO_MANUAL';
    if (customName) rec.customName = customName;
    return rec;
}

// One-click painter actions — apply immediately, no detailed form needed.
function quickValue() { return document.getElementById('corrValue')?.value.trim() || ''; }

function quickGuard(value) {
    if (!value) { showToast(t('toast_select_value'), 'warning'); return false; }
    if (!getInput().includes(value)) { showToast(t('toast_value_not_found'), 'warning'); return false; }
    return true;
}

function handleQuickProtect() {
    const value = quickValue();
    if (!quickGuard(value)) return;
    addCorrection(makeCorrection(value, CORRECTION_ACTIONS.PROTECT), {});
    closeCorrectionMenu();
}

function handleQuickIgnore() {
    const value = quickValue();
    if (!quickGuard(value)) return;
    addCorrection(makeCorrection(value, CORRECTION_ACTIONS.IGNORE), {});
    closeCorrectionMenu();
}

/**
 * Applies a correction: snapshot for undo, re-sanitize, log, optional learning.
 * Latest decision on a value wins — drops ANY prior correction on the same value
 * (across all action types) so protect↔tokenize↔ignore never stack on one span.
 */
function addCorrection(correction, { learn = false } = {}) {
    const beforeText = state.cleanText;
    state.correctionUndo.push(JSON.stringify(state.corrections));
    const v = String(correction.value).toLowerCase();
    state.corrections = state.corrections.filter(c => String(c.value).toLowerCase() !== v);
    state.corrections.push(correction);

    if (learn && !isSuppress(correction.action) && correction.tokenBase) {
        correction.permanent = true;
        learnRule(correction.value, correction.tokenBase);
    }

    handleSanitize();                            // re-projects with the new correction
    logCorrection(correction, beforeText);       // logs against the resulting token
    persistCorrectionsIfEnabled();
    setCorrectionUndoEnabled(true);

    const verbKey = {
        [CORRECTION_ACTIONS.CREATE]:  'corr_verb_create',
        [CORRECTION_ACTIONS.EXTEND]:  'corr_verb_extend',
        [CORRECTION_ACTIONS.REPLACE]: 'corr_verb_replace',
        [CORRECTION_ACTIONS.PROTECT]: 'corr_verb_protect',
        [CORRECTION_ACTIONS.IGNORE]:  'corr_verb_ignore',
    }[correction.action] || 'corr_verb_default';
    showToast(t(verbKey), 'success');
}

function undoCorrection() {
    if (!state.correctionUndo.length) return;
    state.corrections = JSON.parse(state.correctionUndo.pop());
    handleSanitize();
    persistCorrectionsIfEnabled();
    state.auditLog.push(auditEntry({ value: '', token: '', type: '', action: t('audit_act_undo') }));
    renderAuditLog(state.auditLog);
    setCorrectionUndoEnabled(state.correctionUndo.length > 0);
    showToast(t('corr_undone'), 'info');
}

function learnRule(value, tokenBase) {
    const key = `${tokenBase}|${value.toLowerCase()}`;
    const exists = state.manualRules.some(r => `${r.tokenBase}|${String(r.value).toLowerCase()}` === key);
    if (!exists) {
        state.manualRules.push({
            value, tokenBase,
            rule: 'capturar_valor_literal',
            origen: 'correccion_manual',
            activo: true,
        });
        saveManualRules();
    }
}

// ── Token-map panel actions (spec points 6–8) ───────────────

function renderTokenMapPanel() {
    renderTokenMap(state.tokenRows, {
        onEdit:    handleEditToken,
        onReplace: handleReplaceToken,
        onDelete:  handleDeleteToken,
    });
    renderAuditLog(state.auditLog);
    renderMemory();
    setCorrectionUndoEnabled(state.correctionUndo.length > 0);
}

// ── Temporal memory panel (Token Painter session decisions) ─

function renderMemory() {
    if (!state.corrections.length) { hideMemoryPanel(); return; }
    renderMemoryPanel(state.corrections.map(memoryEntry), {
        onEdit:       editMemoryEntry,
        onDelete:     deleteMemoryEntry,
        onPermanent:  permanentMemoryEntry,
        onToggle:     toggleMemoryEntry,
        onGeneralize: generalizeMemoryEntry,
    });
}

// Learning: turn a token entry into a reusable detection PATTERN (its format),
// so the system auto-detects values of that shape from now on — no PII stored.
function generalizeMemoryEntry(id) {
    const c = findCorrection(id);
    if (!c || isSuppress(c.action) || !c.value) {
        showToast(t('toast_generalize_only_tokens'), 'warning');
        return;
    }
    const base = normalizeTokenBase(c.tokenBase || 'OTRO');
    const regexStr = generalizeToRegex(c.value);
    if (!regexStr) { showToast(t('toast_generalize_too_variable'), 'warning'); return; }
    addLearnedPattern(base, regexStr);
}

/** Adds a learned (generalised) custom pattern; user can review it in "Patrones". */
function addLearnedPattern(base, regexStr) {
    if (state.patterns.some(p => p.regexStr === regexStr && (p.token || '') === base)) {
        showToast(t('toast_pattern_exists'), 'info');
        return;
    }
    const name = `${labelForBase(base)} (aprendido)`;
    state.patterns.push({
        id:       generatePatternId(name + regexStr),
        name,
        type:     PCI_TOKEN_BASES.has(base) ? 'pci' : 'pii',
        group:    'custom',
        regexStr,
        flags:    'g',                 // case-sensitive: a shape pattern shouldn't broaden via /i
        token:    base,
        label:    labelForBase(base),
        enabled:  true,
        builtin:  false,
        learned:  true,
    });
    savePatterns();
    refreshPatternList();
    showToast(t('toast_learned_format', { regex: regexStr, base }), 'success');
}

/** Projects a correction into a display row for the memoria-temporal table. */
function memoryEntry(c) {
    const suppress = isSuppress(c.action);
    const token = suppress ? '' : findExistingToken(c.value);
    const tipo = c.action === CORRECTION_ACTIONS.PROTECT ? t('mem_tipo_protect')
        : c.action === CORRECTION_ACTIONS.IGNORE ? t('mem_tipo_ignore')
        : c.customName ? t('mem_tipo_free') : t('mem_tipo_token');
    const tipoClass = c.action === CORRECTION_ACTIONS.PROTECT ? 'mem-tag-protect'
        : c.action === CORRECTION_ACTIONS.IGNORE ? 'mem-tag-ignore' : 'mem-tag-token';
    const accion = c.action === CORRECTION_ACTIONS.PROTECT ? t('mem_accion_protect')
        : c.action === CORRECTION_ACTIONS.IGNORE ? t('mem_accion_ignore') : t('mem_accion_replace');
    const estado = `${c.active === false ? t('mem_state_inactive') : t('mem_state_active')} · ${c.permanent ? t('mem_perm') : t('mem_temp')}`;
    return {
        id: c.id,
        tipo, tipoClass,
        nombre: token || (suppress ? t('mem_no_token') : `[${normalizeTokenBase(c.tokenBase)}_N]`),
        valor: c.value,
        accion, estado,
        active: c.active !== false,
        permanent: !!c.permanent,
        canGeneralize: !suppress,
    };
}

function findCorrection(id) { return state.corrections.find(c => c.id === id); }

function editMemoryEntry(id) {
    const c = findCorrection(id);
    if (c) openCorrectionMenu({ value: c.value, action: c.action, base: c.tokenBase || null });
}

function deleteMemoryEntry(id) {
    state.correctionUndo.push(JSON.stringify(state.corrections));
    state.corrections = state.corrections.filter(c => c.id !== id);
    handleSanitize();
    persistCorrectionsIfEnabled();
    setCorrectionUndoEnabled(true);
    showToast(t('toast_entry_deleted'), 'info');
}

function permanentMemoryEntry(id) {
    const c = findCorrection(id);
    if (!c) return;
    if (isSuppress(c.action)) {
        // Persist protected/ignored phrases as session-remembered (no learned rule).
        c.permanent = true;
        persistCorrections(true);
        showToast(t('toast_saved_future'), 'success');
    } else if (c.tokenBase) {
        c.permanent = true;
        learnRule(c.value, c.tokenBase);
        showToast(t('toast_rule_permanent'), 'success');
    }
    renderMemory();
}

function toggleMemoryEntry(id) {
    const c = findCorrection(id);
    if (!c) return;
    c.active = c.active === false;   // flip
    handleSanitize();
    persistCorrectionsIfEnabled();
    showToast(t(c.active ? 'toast_enabled' : 'toast_disabled'), 'info');
}

// ── Persistence (opt-in: "Recordar para próximas sesiones") ─

function persistCorrectionsIfEnabled() {
    if (storage.get(CONFIG.STORAGE.CORRECTIONS_ON) === '1') persistCorrections(true);
}

function persistCorrections(on) {
    if (on) storage.setJSON(CONFIG.STORAGE.CORRECTIONS, state.corrections);
    else    storage.remove?.(CONFIG.STORAGE.CORRECTIONS);
}

function loadPersistedCorrections() {
    const on = storage.get(CONFIG.STORAGE.CORRECTIONS_ON) === '1';
    const toggle = document.getElementById('memoryRemember');
    if (toggle) toggle.checked = on;
    if (!on) return;
    const saved = storage.getJSON(CONFIG.STORAGE.CORRECTIONS);
    if (Array.isArray(saved)) {
        state.corrections = saved.filter(c => c && typeof c.value === 'string' && typeof c.action === 'string');
    }
}

function handleMemoryRememberToggle(e) {
    const on = !!e.target.checked;
    storage.set(CONFIG.STORAGE.CORRECTIONS_ON, on ? '1' : '0');
    persistCorrections(on);
    showToast(t(on ? 'toast_remember_on' : 'toast_remember_off'), 'info');
}

// Edit the original value of a token → extend with the new value (spec point 7).
function handleEditToken(row) {
    openCorrectionMenu({ value: row.value, action: CORRECTION_ACTIONS.EXTEND, base: row.base });
}

// Replace the type of a detected value (spec "Reemplazar token actual").
function handleReplaceToken(row) {
    openCorrectionMenu({ value: row.value, action: CORRECTION_ACTIONS.REPLACE, base: row.base });
}

// Delete: drop a manual correction, or ignore an auto-detection.
function handleDeleteToken(row) {
    const beforeText = state.cleanText;
    state.correctionUndo.push(JSON.stringify(state.corrections));
    if (row.source === 'Manual') {
        const before = state.corrections.length;
        state.corrections = state.corrections.filter(
            c => !(!isSuppress(c.action)
                   && String(c.value).toLowerCase() === String(row.value).toLowerCase()
                   && normalizeTokenBase(c.tokenBase) === row.base)
        );
        if (state.corrections.length === before) state.correctionUndo.pop();   // nothing removed
    } else {
        state.corrections.push(makeCorrection(row.value, CORRECTION_ACTIONS.IGNORE));
    }
    handleSanitize();
    logCorrection({ value: row.value, tokenBase: row.base, action: 'delete' }, beforeText);
    persistCorrectionsIfEnabled();
    setCorrectionUndoEnabled(true);
    showToast(t('toast_token_deleted'), 'info');
}

// ── Audit trail (spec point 9) ──────────────────────────────

function logCorrection(correction, beforeText = '') {
    const suppress = isSuppress(correction.action);
    const base = normalizeTokenBase(correction.tokenBase || 'RIESGO_MANUAL');
    const row  = state.tokenRows.find(
        r => String(r.value).toLowerCase() === String(correction.value).toLowerCase()
    );
    state.auditLog.push(auditEntry({
        value:  correction.value,
        token:  row ? row.token : '',
        type:   suppress ? '—' : labelForBase(base),
        action: auditActionLabel(correction.action),
        before: snippetAround(beforeText, correction.value) || beforeText.slice(0, 80),
        after:  snippetAround(state.cleanText, correction.value, !suppress) || state.cleanText.slice(0, 80),
        estado: correction.permanent ? 'Permanente' : 'Temporal',
    }));
    renderAuditLog(state.auditLog);
}

function auditEntry({ value, token, type, action, before = '', after = '', estado = 'Temporal' }) {
    return {
        value, token, type, action,
        origin:     'Manual asistido',
        confidence: 'Manual',
        before, after, estado,
        time:       timestamp(),
        iso:        new Date().toISOString(),
    };
}

function auditActionLabel(action) {
    return t({
        [CORRECTION_ACTIONS.CREATE]:  'audit_act_create',
        [CORRECTION_ACTIONS.EXTEND]:  'audit_act_extend',
        [CORRECTION_ACTIONS.REPLACE]: 'audit_act_replace',
        [CORRECTION_ACTIONS.PROTECT]: 'audit_act_protect',
        [CORRECTION_ACTIONS.IGNORE]:  'audit_act_ignore',
        delete:                       'audit_act_delete',
    }[action] || 'audit_act_default');
}

// ── Exports (spec point 14) ─────────────────────────────────

function dateStamp() { return new Date().toISOString().slice(0, 10); }

function handleExportClean() {
    const text = state.cleanText || state.lastSanitized;
    if (!text) { showToast(t('toast_no_input'), 'warning'); return; }
    downloadTextFile(`prompt-limpio-${dateStamp()}.txt`, text);
    showToast(t('toast_export_clean'), 'success');
}

function handleExportMap() {
    if (!state.tokenRows.length) { showToast(t('toast_no_tokens_export'), 'warning'); return; }
    const map = state.tokenRows.map(r => ({
        token: r.token, tipo: r.type, valor_original: r.value,
        riesgo: r.risk, confianza: r.source === 'Manual' ? 'Manual' : `${r.confidence}%`, origen: r.source,
    }));
    downloadTextFile(`mapa-tokens-${dateStamp()}.json`, JSON.stringify(map, null, 2));
    showToast(t('toast_export_map'), 'success');
}

function handleExportAuditCsv() {
    if (!state.auditLog.length) { showToast(t('toast_audit_empty'), 'warning'); return; }
    const head = ['fecha', 'valor', 'tipo', 'token', 'accion', 'origen', 'confianza', 'estado', 'antes', 'despues'];
    const rows = state.auditLog.map(e =>
        [e.iso, e.value, e.type, e.token, e.action, e.origin, e.confidence, e.estado, e.before, e.after].map(csvCell).join(','));
    downloadTextFile(`auditoria-${dateStamp()}.csv`, [head.join(','), ...rows].join('\n'));
    showToast(t('toast_export_audit_csv'), 'success');
}

function handleExportAuditJson() {
    if (!state.auditLog.length) { showToast(t('toast_audit_empty'), 'warning'); return; }
    downloadTextFile(`auditoria-${dateStamp()}.json`, JSON.stringify(state.auditLog, null, 2));
    showToast(t('toast_export_audit_json'), 'success');
}

function handleExportRules() {
    if (!state.manualRules.length) { showToast(t('toast_no_rules'), 'warning'); return; }
    downloadTextFile(`reglas-aprendidas-${dateStamp()}.json`, JSON.stringify(state.manualRules, null, 2));
    showToast(t('toast_export_rules'), 'success');
}

function handleExportMemory() {
    if (!state.corrections.length) { showToast(t('toast_memory_empty'), 'warning'); return; }
    downloadTextFile(`memoria-temporal-${dateStamp()}.json`, JSON.stringify(state.corrections, null, 2));
    showToast(t('toast_export_memory'), 'success');
}

function handleExportProtected() {
    const protectedItems = state.corrections.filter(c => c.action === CORRECTION_ACTIONS.PROTECT);
    if (!protectedItems.length) { showToast(t('toast_no_protected'), 'warning'); return; }
    const list = protectedItems.map(c => ({ frase: c.value, regla: 'mantener_tal_cual', estado: c.permanent ? 'permanente' : 'temporal' }));
    downloadTextFile(`frases-protegidas-${dateStamp()}.json`, JSON.stringify(list, null, 2));
    showToast(t('toast_export_protected'), 'success');
}

function csvCell(v) {
    const s = String(v ?? '');
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

// ── Rule packs (shareable, NO personal data — only patterns) ─

function handleExportPack() {
    const custom = state.patterns.filter(p => !p.builtin);
    if (!custom.length) { showToast(t('toast_no_custom_patterns'), 'warning'); return; }
    const pack = {
        kind: 'lavadora-rule-pack',
        version: 1,
        exported: new Date().toISOString(),
        patterns: custom.map(p => ({
            name: p.name, type: p.type, regexStr: p.regexStr, flags: p.flags || 'gi', token: p.token, label: p.label,
        })),
    };
    downloadTextFile(`pack-reglas-${dateStamp()}.json`, JSON.stringify(pack, null, 2));
    showToast(t('toast_pack_exported', { n: custom.length }), 'success');
}

async function handleImportPack(file) {
    if (!file) return;
    try {
        const pack = JSON.parse(await readFileAsText(file));
        const list = Array.isArray(pack) ? pack : (pack.patterns || []);
        let added = 0, skipped = 0;
        for (const raw of list) {
            const regexStr = String(raw?.regexStr || '').trim();
            const name     = String(raw?.name || '').trim();
            if (!regexStr || !name) { skipped++; continue; }
            if (validateRegexStr(regexStr)) { skipped++; continue; }   // truthy = invalid regex
            const dup = state.patterns.some(p =>
                (p.regexStr === regexStr && (p.token || '') === (raw.token || '')) ||
                p.name.toLowerCase() === name.toLowerCase());
            if (dup) { skipped++; continue; }
            state.patterns.push({
                id:       generatePatternId(name + regexStr),
                name,
                type:     raw.type === 'pci' ? 'pci' : 'pii',
                group:    'custom',
                regexStr,
                flags:    raw.flags || 'gi',
                token:    normalizeTokenBase(raw.token || name),
                label:    raw.label || name,
                enabled:  true,
                builtin:  false,
                learned:  true,
            });
            added++;
        }
        savePatterns();
        refreshPatternList();
        showToast(t('toast_pack_imported', { added, skipped }), added ? 'success' : 'info');
    } catch {
        showToast(t('toast_pack_invalid'), 'error');
    }
}

// ── Popover lifecycle ───────────────────────────────────────

function handleCorrectionOutsideClick(e) {
    const menu = document.getElementById('correctionMenu');
    if (!menu || menu.hidden || menu.contains(e.target)) return;
    // Token-map action buttons OPEN the popover; their click bubbles here in the
    // same event, so ignore them or the menu would close the instant it opens.
    if (e.target.closest?.('.tm-act-btn')) return;
    closeCorrectionMenu();
}

function closeCorrectionMenu() {
    const menu = document.getElementById('correctionMenu');
    if (menu) menu.hidden = true;
    state.correctionCtx = null;
}

function handleAddPattern(e) {
    e.preventDefault();

    const nameEl  = document.getElementById('patternName');
    const regexEl = document.getElementById('patternRegex');
    const typeEl  = document.getElementById('patternType');
    const errorEl = document.getElementById('patternError');

    const name     = nameEl?.value.trim();
    const regexStr = regexEl?.value.trim();
    const type     = typeEl?.value || 'pii';

    if (!name) return showPatternError(t('error_pattern_name_empty'));

    const regexError = validateRegexStr(regexStr);
    if (regexError) return showPatternError(regexError);

    if (state.patterns.some(p => p.name.toLowerCase() === name.toLowerCase())) {
        return showPatternError(t('error_pattern_duplicate', { name }));
    }

    const newPattern = {
        id:       generatePatternId(name),
        name,
        type,
        group:    'custom',
        regexStr,
        flags:    'gi',
        token:    name.toUpperCase().replace(/\W+/g, '_'),
        label:    name,
        enabled:  true,
        builtin:  false,
    };

    state.patterns.push(newPattern);
    savePatterns();
    refreshPatternList();

    if (nameEl)  nameEl.value  = '';
    if (regexEl) regexEl.value = '';
    if (errorEl) errorEl.hidden = true;

    showToast(t('toast_pattern_added', { name }), 'success');
}

function showPatternError(msg) {
    const el = document.getElementById('patternError');
    if (!el) return;
    el.textContent = msg;
    el.hidden = false;
    setTimeout(() => { el.hidden = true; }, 4000);
}

// ── Language selector ───────────────────────────────────────

function renderLanguageSelector() {
    const container = document.getElementById('langSelector');
    if (!container) return;

    const langs   = getAvailableLanguages();
    const current = getCurrentLang();

    container.innerHTML = '';

    const label = document.createElement('span');
    label.className   = 'lang-label';
    label.textContent = t('lang_selector_label') + ':';
    container.appendChild(label);

    for (const lang of langs) {
        const btn = document.createElement('button');
        btn.type      = 'button';
        btn.className = `btn-lang${lang.code === current ? ' active' : ''}`;
        btn.setAttribute('data-lang', lang.code);
        btn.setAttribute('title', lang.name);
        btn.setAttribute('aria-label', `${lang.name} (${lang.code})`);
        btn.setAttribute('aria-pressed', String(lang.code === current));
        btn.innerHTML = `<span aria-hidden="true">${lang.flag}</span> <span class="lang-name">${lang.name}</span>`;

        btn.addEventListener('click', async () => {
            if (lang.code === getCurrentLang()) return;
            await setLanguage(lang.code);
            refreshPatternList(); // pattern names need re-render after lang switch
            showToast(t('toast_lang_changed'), 'info');
            renderLanguageSelector(); // update active state
        });

        container.appendChild(btn);
    }
}

// Re-render UI on language change
document.addEventListener('languagechange', () => {
    document.title = t('title') + ' — Simulador DLP';
    const resultEl = document.getElementById('resultBox');
    if (resultEl && (resultEl.querySelector('.placeholder') || resultEl.querySelector('.result-empty-state'))) {
        setResultHtml('');
    }
    // Re-render every dynamically-built panel so JS-injected strings (toasts
    // aside) follow the new language — these are built after applyI18nToDOM().
    refreshPatternList();
    renderHistory();
    renderMemory();
    renderAuditLog(state.auditLog);
    if (state.tokenRows.length) {
        renderTokenMap(state.tokenRows, {
            onEdit: handleEditToken, onReplace: handleReplaceToken, onDelete: handleDeleteToken,
        });
    }
    if (state.lastStats && !document.getElementById('statsDashboard')?.hidden) {
        renderStats(state.lastStats);
    }
    syncSidebarAvailability();
});

// ── Auto-save ───────────────────────────────────────────────

const autoSave = debounce((text) => {
    storage.set(CONFIG.STORAGE.INPUT_TEXT, text);
}, CONFIG.AUTO_SAVE_DEBOUNCE);

function restoreAutoSave() {
    const saved = storage.get(CONFIG.STORAGE.INPUT_TEXT);
    if (saved && saved.trim()) setInput(saved);
}

// ── Event bindings ──────────────────────────────────────────

function bindEvents() {
    on('auditBtn',    'click', handleAudit);
    on('sanitizeBtn', 'click', handleSanitize);
    on('clearBtn',    'click', handleClear);
    on('undoBtn',     'click', handleUndo);
    on('copyBtn',     'click', handleCopy);
    on('copyFullBtn', 'click', handleCopyFull);
    on('exportBtn',   'click', handleExport);

    bindQuickActions();

    // Theme
    on('themeToggle', 'click', () => {
        const next = toggleTheme();
        showToast(t(next === 'dark' ? 'toast_theme_dark' : 'toast_theme_light'), 'info');
    });

    // Modal
    on('shortcutsBtn',  'click', () => openModal('shortcutsModal'));
    on('helpBtn',       'click', () => openModal('shortcutsModal'));
    on('closeModalBtn', 'click', () => closeModal('shortcutsModal'));
    on('modalBackdrop', 'click', () => closeModal('shortcutsModal'));

    // Paste from clipboard
    on('pasteBtn', 'click', handlePaste);

    // Assisted manual correction popover — opens on selection (mouseup) or right-click
    const inputEl = document.getElementById('inputText');
    inputEl?.addEventListener('contextmenu', handleInputContextMenu);
    inputEl?.addEventListener('mouseup', handleInputMouseUp);
    // Selecting in the OUTPUT result also opens the painter (maps tokens → original).
    document.getElementById('resultBox')?.addEventListener('mouseup', handleOutputMouseUp);
    document.getElementById('correctionForm')?.addEventListener('submit', handleCorrectionSubmit);
    on('corrCancel',  'click', closeCorrectionMenu);
    on('correctionClose', 'click', closeCorrectionMenu);
    on('corrAction',  'change', onCorrectionActionChange);
    on('corrType',    'change', onCorrectionTypeChange);
    on('corrValue',   'input',  () => { state.manualSelection = document.getElementById('corrValue').value.trim(); refreshHint(); updateCorrectionPreview(); });
    on('corrCustom',  'input',  () => { refreshHint(); updateCorrectionPreview(); });
    on('corrHintBtn', 'click',  handleHintAction);
    on('corrQuickProtect', 'click', handleQuickProtect);
    on('corrQuickIgnore',  'click', handleQuickIgnore);
    document.addEventListener('click', handleCorrectionOutsideClick);

    // Temporal memory: persistence toggle
    on('memoryRemember', 'change', handleMemoryRememberToggle);

    // Token map: undo + exports
    on('corrUndoBtn',        'click', undoCorrection);
    on('exportCleanBtn',     'click', handleExportClean);
    on('exportMapBtn',       'click', handleExportMap);
    on('exportAuditCsvBtn',  'click', handleExportAuditCsv);
    on('exportAuditJsonBtn', 'click', handleExportAuditJson);
    on('exportRulesBtn',     'click', handleExportRules);
    on('exportMemoryBtn',    'click', handleExportMemory);
    on('exportProtectedBtn', 'click', handleExportProtected);

    // Rule packs (export current patterns / import a shared pack)
    on('exportPackBtn', 'click', handleExportPack);
    on('importPackBtn', 'click', () => document.getElementById('packFileInput')?.click());
    document.getElementById('packFileInput')?.addEventListener('change', e => {
        handleImportPack(e.target.files?.[0]);
        e.target.value = '';
    });

    // Privacy Gateway restore
    on('restoreBtn', 'click', handleRestore);
    on('copySafeBtn', 'click', handleCopySafe);

    // Three-body layout: clicking a collapsed rail expands it (Salida stays).
    on('railInput',   'click', () => setLayout('restore'));
    on('railRestore', 'click', () => setLayout('input'));

    // Findings navigator
    on('findingPrevBtn', 'click', findingsNavPrev);
    on('findingNextBtn', 'click', findingsNavNext);

    // File import
    on('importBtn', 'click', () => document.getElementById('fileInput')?.click());

    document.getElementById('fileInput')?.addEventListener('change', e => {
        handleImport(e.target.files?.[0]);
        e.target.value = '';
    });

    // Drag & drop
    const dropZone = document.getElementById('dropZone');
    if (dropZone) {
        dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
        dropZone.addEventListener('drop', e => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
            const file = e.dataTransfer?.files?.[0];
            if (file) handleImport(file);
        });
    }

    // Input: char count + auto-save
    document.getElementById('inputText')?.addEventListener('input', e => {
        updateCharCount(e.target.value);
        autoSave(e.target.value);
        liveAudit();   // automatic risk preview — no click needed
    });

    // Custom pattern form
    document.getElementById('patternAddForm')?.addEventListener('submit', handleAddPattern);

    // Clear history
    on('clearHistoryBtn', 'click', () => {
        state.history = [];
        storage.remove(CONFIG.STORAGE.HISTORY);
        clearHistoryPanel();
        showToast(t('toast_history_cleared'), 'info');
    });

    // Global keyboard shortcuts
    document.addEventListener('keydown', handleGlobalKeydown);
}

function handleGlobalKeydown(e) {
    const inInput = ['INPUT', 'SELECT', 'TEXTAREA'].includes(e.target.tagName);

    if (e.key === 'Escape') { closeCorrectionMenu(); closeModal('shortcutsModal'); return; }
    if (!e.ctrlKey && !e.metaKey) return;

    switch (true) {
        case e.key === 'Enter' && !e.shiftKey:
            if (!inInput || e.target.id === 'inputText') { e.preventDefault(); handleSanitize(); }
            break;
        case (e.key === 'A' || e.key === 'a') && e.shiftKey:
            e.preventDefault(); handleAudit(); break;
        case (e.key === 'l' || e.key === 'L') && !e.shiftKey:
            if (!inInput) { e.preventDefault(); handleClear(); } break;
        case (e.key === 'z' || e.key === 'Z') && !e.shiftKey:
            if (!inInput) { e.preventDefault(); handleUndo(); } break;
        case (e.key === 'd' || e.key === 'D') && !e.shiftKey:
            if (!inInput) {
                e.preventDefault();
                const next = toggleTheme();
                showToast(t(next === 'dark' ? 'toast_theme_dark' : 'toast_theme_light'), 'info');
            }
            break;
        case (e.key === 'C' || e.key === 'c') && e.shiftKey:
            e.preventDefault(); handleCopy(); break;
        case (e.key === 'E' || e.key === 'e') && e.shiftKey:
            e.preventDefault(); handleExport(); break;
    }
}

// ── Confidence card ──────────────────────────────────────────

/** Mean confidence (%) across AUTO-detected rows; null when none are numeric. */
function meanConfidence(rows) {
    const nums = (rows || [])
        .filter(r => r && r.source !== 'Manual' && typeof r.confidence === 'number' && !Number.isNaN(r.confidence))
        .map(r => r.confidence);
    if (!nums.length) return null;
    return Math.round(nums.reduce((a, b) => a + b, 0) / nums.length);
}

// ── Sidebar (cosmetic nav: availability-sync + scroll-spy) ───
// Does NOT force panels open — it mirrors their real visibility. Nav items
// whose target is [hidden] are greyed/disabled so they never dead-click.
let _navPairs = [];

function initSidebar() {
    const items = Array.from(document.querySelectorAll('.app-sidebar .nav-item'));
    _navPairs = items
        .map(el => ({ el, target: document.getElementById((el.getAttribute('href') || '').replace(/^#/, '')) }))
        .filter(p => p.target);

    for (const { el, target } of _navPairs) {
        el.addEventListener('click', (e) => {
            e.preventDefault();
            if (target.hidden) return;          // unavailable → no-op (also greyed via CSS)
            setActiveNav(el);
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
        // Mirror the target's [hidden] flips (same pattern as bindQuickActions).
        new MutationObserver(syncSidebarAvailability)
            .observe(target, { attributes: true, attributeFilter: ['hidden'] });
    }
    syncSidebarAvailability();

    // Scroll-spy: highlight whichever available section is at the top of the view.
    if ('IntersectionObserver' in window) {
        const spy = new IntersectionObserver((entries) => {
            const top = entries.filter(en => en.isIntersecting)
                .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
            if (!top) return;
            const pair = _navPairs.find(p => p.target === top.target);
            if (pair && !pair.el.classList.contains('nav-disabled')) setActiveNav(pair.el);
        }, { rootMargin: '-140px 0px -55% 0px', threshold: 0 });
        for (const { target } of _navPairs) spy.observe(target);
    }
}

function syncSidebarAvailability() {
    for (const { el, target } of _navPairs) {
        const off = !!target.hidden;
        el.classList.toggle('nav-disabled', off);
        el.setAttribute('aria-disabled', String(off));
        if (off) el.setAttribute('tabindex', '-1');
        else el.removeAttribute('tabindex');
    }
}

function setActiveNav(activeEl) {
    for (const { el } of _navPairs) el.classList.toggle('nav-active', el === activeEl);
}

// ── Mobile tabs ──────────────────────────────────────────────

function initMobileTabs() {
    const pairs = [
        ['tabInput',   'panelInput'],
        ['tabOutput',  'panelOutput'],
        ['tabRestore', 'panelRestore'],
    ];
    const els = pairs
        .map(([t, p]) => ({ tab: document.getElementById(t), panel: document.getElementById(p) }))
        .filter(x => x.tab && x.panel);
    if (!els.length) return;

    function activate(i) {
        els.forEach((x, j) => {
            const on = j === i;
            x.tab.setAttribute('aria-selected', String(on));
            x.tab.classList.toggle('tab-active', on);
            x.panel.classList.toggle('tab-active', on);
        });
    }

    els.forEach((x, i) => x.tab.addEventListener('click', () => activate(i)));
    activate(0);   // Entrada by default
}

function switchToOutputTab() {
    const tabOutput = document.getElementById('tabOutput');
    // Only switch when in mobile tab mode (tab is visible)
    if (tabOutput && getComputedStyle(tabOutput).display !== 'none') {
        tabOutput.click();
    }
}

// ── Pattern search ───────────────────────────────────────────

function initPatternSearch() {
    const input = document.getElementById('patternSearch');
    if (!input) return;

    input.addEventListener('input', () => {
        const query = input.value.toLowerCase().trim();
        const list  = document.getElementById('patternsList');
        if (!list) return;

        const items   = list.querySelectorAll('.pattern-item');
        const headers = list.querySelectorAll('.pattern-group-header');

        items.forEach(item => {
            const name  = item.querySelector('.pattern-name')?.textContent.toLowerCase()  || '';
            const regex = item.querySelector('.pattern-regex')?.textContent.toLowerCase() || '';
            item.style.display = (!query || name.includes(query) || regex.includes(query)) ? '' : 'none';
        });

        // Hide group headers when all their items are hidden
        headers.forEach(header => {
            let sibling   = header.nextElementSibling;
            let hasVisible = false;
            while (sibling && !sibling.classList.contains('pattern-group-header')) {
                if (sibling.style.display !== 'none') hasVisible = true;
                sibling = sibling.nextElementSibling;
            }
            header.style.display = hasVisible ? '' : 'none';
        });
    });
}

// ── Auto-resize textarea ─────────────────────────────────────

function initAutoResize() {
    const ta = document.getElementById('inputText');
    if (!ta) return;

    function resize() {
        ta.style.height = 'auto';
        const min = window.innerWidth >= 700 ? 290 : 240;
        ta.style.height = Math.max(min, ta.scrollHeight) + 'px';
    }

    _resizeTextarea = resize;
    ta.addEventListener('input', resize);
    resize();
}

// ── Workflow steps ───────────────────────────────────────────

function setWorkflowStep(step) {
    for (let i = 1; i <= 3; i++) {
        const el = document.getElementById(`wfStep${i}`);
        if (!el) continue;
        el.classList.remove('wf-active', 'wf-done');
        if (i < step)  el.classList.add('wf-done');
        if (i === step) el.classList.add('wf-active');
    }
}

// ── CTA pulse ────────────────────────────────────────────────

function pulseSanitizeBtn() {
    const btn = document.getElementById('sanitizeBtn');
    if (!btn) return;
    btn.classList.remove('pulse-hint');
    void btn.offsetWidth; // reflow to restart animation
    btn.classList.add('pulse-hint');
    btn.addEventListener('animationend', () => btn.classList.remove('pulse-hint'), { once: true });
}

// ── Utilities ───────────────────────────────────────────────

function renderVersion() {
    const el = document.getElementById('versionTag');
    if (el) el.textContent = `v${CONFIG.VERSION}`;
}

function on(id, event, handler) {
    document.getElementById(id)?.addEventListener(event, handler);
}

function bindQuickActions() {
    const quickButtons = document.querySelectorAll('.quick-action-btn[data-action-target]');
    quickButtons.forEach(btn => {
        const target = document.getElementById(btn.dataset.actionTarget);
        if (!target) return;

        const syncDisabled = () => {
            btn.disabled = target.disabled;
            btn.setAttribute('aria-disabled', String(target.disabled));
        };

        btn.addEventListener('click', () => target.click());
        new MutationObserver(syncDisabled).observe(target, { attributes: true, attributeFilter: ['disabled'] });
        syncDisabled();
    });
}

function escFallback(text) {
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Output display: clean prompt up front, audit/suspicious/suggestions tucked
// behind a "ver más" disclosure so the result reads as just the clean text.
function buildResultDisplay(cleanHtml, detailsHtml, fullHtml, text) {
    const clean = cleanHtml || fullHtml || escFallback(text);
    let out = `<div class="report-clean">${clean}</div>`;
    if (detailsHtml) {
        out += `<details class="report-details">`
             + `<summary>${t('report_more') || 'Ver auditoría y detalles'}</summary>`
             + `<div class="report-details-body">${detailsHtml}</div>`
             + `</details>`;
    }
    return out;
}
