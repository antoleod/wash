/**
 * corrections.js — Assisted manual-correction engine.
 *
 * The persistent state of a correction session is an ORDERED LIST of
 * corrections. The "token map" the UI shows is a *projection* of
 * (auto-detections ∪ corrections), recomputed deterministically on every run —
 * never a parallel data source that could drift from the input.
 *
 * Correction model (one entry):
 *   { id, value, tokenBase, action, source, timestamp, learn }
 *     action ∈ 'create' | 'extend' | 'replace' | 'ignore'
 *
 * The key idea (why the old post-hoc string-replace failed on "extend"):
 * corrections operate on the ORIGINAL text and pre-empt any overlapping
 * auto-match. A forced correction span reserves its range; auto-matches that
 * overlap it are dropped. So selecting the full "Juan Carlos Anthony Dioses
 * Guerrero" wins over the partial "[PERSONA_ES_1] Dioses Guerrero".
 */

import { buildRegex } from '../data/patterns.js';
import { confusableFold, execOnTextAndTwin } from './utils.js';
import { passesValidation } from './validators.js';
import { regexConfidencePct } from './scoring.js';
import { TOKEN_LABELS, PCI_TOKEN_BASES, labelForBase } from './labels.js';
import { scanEntities } from './entityScanner.js';

export const CORRECTION_ACTIONS = Object.freeze({
    CREATE: 'create',
    EXTEND: 'extend',
    REPLACE: 'replace',
    IGNORE: 'ignore',
    PROTECT: 'protect',   // "guardar tal cual" — keep verbatim, no token, never suspicious
});

/** Actions that suppress a span (no token): the text stays verbatim in the clean output. */
export const SUPPRESS_ACTIONS = new Set([CORRECTION_ACTIONS.IGNORE, CORRECTION_ACTIONS.PROTECT]);

// ── Normalisation helpers ───────────────────────────────────

/** Loose value key so "Juan  Pérez" and "juan pérez " collapse to one entity. */
export function normalizeValue(v) {
    return String(v ?? '').trim().toLowerCase().replace(/\s+/g, ' ');
}

/** Turns any user input (`[DNI_3]`, `dni`, `DNI_N`) into a clean token base. */
export function normalizeTokenBase(value) {
    return String(value || '')
        .trim()
        .replace(/^\[/, '')
        .replace(/_N\]?$/i, '')
        .replace(/_\d+\]?$/, '')
        .replace(/\]?$/, '')
        .toUpperCase()
        .replace(/[^A-Z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '') || 'RIESGO_MANUAL';
}

// ── Core: project (auto-detections ∪ corrections) ───────────

/**
 * Re-derives the whole token map from the original text + correction list.
 *
 * @param {string} text            original ("dirty") text
 * @param {Array}  activePatterns  enabled pattern definitions
 * @param {Array}  corrections     ordered correction list
 * @returns {{ cleanText, rows, restoreMap, replacements, stats, spans }}
 */
export function applyCorrections(text, activePatterns, corrections = []) {
    const safeText = String(text || '');
    const list = Array.isArray(corrections) ? corrections : [];

    // 1) Forced + suppress spans, located in the ORIGINAL text by exact value.
    //    Suppress = ignore ∪ protect: both keep the text verbatim (no token).
    const forced    = [];
    const ignores   = [];
    const suppressed = [];   // values kept verbatim → excluded from "suspicious"
    for (const c of list) {
        const value = String(c?.value || '').trim();
        if (!value) continue;
        const positions = allIndexes(safeText, value);
        if (!positions.length) continue;
        if (SUPPRESS_ACTIONS.has(c.action)) {
            for (const start of positions) ignores.push({ start, end: start + value.length });
            suppressed.push(value);
        } else {
            const base = normalizeTokenBase(c.tokenBase || 'RIESGO_MANUAL');
            for (const start of positions) {
                forced.push({ start, end: start + value.length, text: value, base, action: c.action || 'create' });
            }
        }
    }
    // Suppress wins: a protect/ignore range keeps its text verbatim, so drop any
    // forced span overlapping it too (else a learned rule or an earlier tokenize
    // could punch a token INTO a protected phrase — "dividing" it, spec point 7).
    const forcedSpans = dedupeByPriority(forced).filter(s => !ignores.some(r => overlaps(s, r)));

    // 2) Auto-matches over the same ORIGINAL text.
    const auto = collectAutoMatches(safeText, activePatterns);

    // 3) Corrections win: drop any auto-match overlapping a forced/suppress range.
    const reserved = [...forcedSpans, ...ignores];
    const keptAuto = auto.filter(m => !reserved.some(r => overlaps(m, r)));

    // 4) Merge into one ordered, non-overlapping span list.
    const spans = [
        ...forcedSpans.map(s => ({ ...s, manual: true })),
        ...keptAuto.map(s => ({ ...s, manual: false })),
    ].sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));

    // 5) Assign tokens consistently (same entity → same token, shared counters).
    //    Capture each span's BASE first — span.token gets overwritten with the
    //    bracketed token below, so rows must read span.base, not span.token.
    const entityMap  = new Map();
    const counterMap = new Map();
    const restoreMap = {};
    for (const span of spans) {
        const base = span.manual ? span.base : span.token;
        span.base  = base;
        const key  = `${base}|${normalizeValue(span.text)}`;
        if (!entityMap.has(key)) {
            const n = (counterMap.get(base) || 0) + 1;
            counterMap.set(base, n);
            const token = `[${base}_${n}]`;
            entityMap.set(key, token);
            restoreMap[token] = span.text;
        }
        span.token = entityMap.get(key);
    }

    // 6) Build the clean text in one pass + project the rows.
    let cleanText = '';
    let cursor = 0;
    for (const span of spans) {
        cleanText += safeText.slice(cursor, span.start);
        cleanText += span.token;
        cursor = span.end;
    }
    cleanText += safeText.slice(cursor);

    const rows = spans.map(rowFromSpan);
    return {
        cleanText,
        rows,
        restoreMap,
        replacements: spans.length,
        stats: statsFromSpans(spans),
        spans,
        suppressed,   // protected/ignored values kept verbatim (skip in suspicious)
    };
}

function rowFromSpan(span) {
    const base   = span.base;
    const isPci  = span.manual ? PCI_TOKEN_BASES.has(base) : span.type === 'pci';
    return {
        token:      span.token,
        base,
        value:      span.text,
        type:       labelForBase(base),
        risk:       isPci ? 'ALTO' : (span.manual ? 'ALTO' : 'MEDIO'),
        source:     span.manual ? 'Manual' : 'Auto',
        confidence: span.manual ? 100 : regexConfidencePct({ id: span.id, validator: span.validator, text: span.text }),
        reason:     span.manual ? reasonForAction(span.action) : `Patrón activo: ${span.name}`,
    };
}

function reasonForAction(action) {
    switch (action) {
        case CORRECTION_ACTIONS.EXTEND:  return 'Extensión manual de token';
        case CORRECTION_ACTIONS.REPLACE: return 'Reemplazo manual de tipo';
        default:                         return 'Marcado manual como dato sensible';
    }
}

function statsFromSpans(spans) {
    const stats = { total: spans.length, pii: 0, pci: 0, riskLevel: 'none', byPattern: {} };
    for (const span of spans) {
        const base  = span.base;
        const isPci = span.manual ? PCI_TOKEN_BASES.has(base) : span.type === 'pci';
        if (isPci) stats.pci++; else stats.pii++;
        const label = labelForBase(base);
        stats.byPattern[label] = (stats.byPattern[label] || 0) + 1;
    }
    stats.riskLevel = stats.total === 0 ? 'none'
        : stats.total <= 1 ? 'low'
        : stats.total <= 4 ? 'medium' : 'high';
    return stats;
}

// ── Auto-match collection (same semantics as audit/sanitize) ─

function collectAutoMatches(text, patterns) {
    const raw  = [];
    const twin = confusableFold(text);
    for (const pattern of (patterns || [])) {
        if (!pattern.enabled) continue;
        const regex = buildRegex(pattern);
        for (const hit of execOnTextAndTwin(regex, text, twin)) {
            if (!passesValidation(pattern, hit.text)) continue;
            raw.push({
                start: hit.start,
                end:   hit.end,
                text:  hit.text,
                token: pattern.token,
                type:  pattern.type,
                name:  pattern.name,
                label: pattern.label,
                id:    pattern.id,
                validator: pattern.validator,
            });
        }
    }
    for (const hit of scanEntities(text)) {
        raw.push({
            start: hit.start, end: hit.end, text: hit.text,
            token: hit.token, type: hit.type,
            name: hit.name, label: hit.label, id: hit.id,
        });
    }

    raw.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    const out = [];
    let cursor = 0;
    for (const m of raw) {
        if (m.start >= cursor) { out.push(m); cursor = m.end; }
    }
    return out;
}

// ── Geometry helpers ────────────────────────────────────────

function allIndexes(haystack, needle) {
    const out = [];
    if (!needle) return out;
    let i = haystack.indexOf(needle);
    while (i !== -1) {
        out.push(i);
        i = haystack.indexOf(needle, i + needle.length);
    }
    return out;
}

function overlaps(a, b) {
    return a.start < b.end && b.start < a.end;
}

/** Greedy non-overlapping keep, preferring earlier-then-longer spans. */
function dedupeByPriority(spans) {
    const sorted = [...spans].sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    const out = [];
    for (const s of sorted) {
        if (!out.some(o => overlaps(s, o))) out.push(s);
    }
    return out;
}

// ── Smart assistance (spec point 5) ─────────────────────────

const CAP_WORD = '[A-ZÁÉÍÓÚÑÀÂÄÇÈÊËÎÏÔÖÙÛÜ][\\wÁÉÍÓÚÑáéíóúñàâäçèêëîïôöùûü.\'-]*';

/**
 * Suggests a fuller value by looking at the text around a detected fragment.
 * Returns the expanded string (longer than `value`) or null if nothing better.
 *
 *  - 'name'   → absorb contiguous Capitalised words on both sides (up to maxWords)
 *  - 'address'→ absorb trailing comma chunks until a country / postal tail
 */
export function suggestExpansion(text, value, kind = 'name', maxWords = 6) {
    const safeText = String(text || '');
    const target   = String(value || '').trim();
    if (!safeText || !target) return null;
    const at = safeText.indexOf(target);
    if (at === -1) return null;

    if (kind === 'address') return expandAddress(safeText, at, target);
    return expandName(safeText, at, target, maxWords);
}

function expandName(text, at, value, maxWords) {
    let start = at;
    let end   = at + value.length;

    // Walk left over "Word " sequences.
    const leftRe = new RegExp(`(${CAP_WORD}\\s+)$`);
    let guard = maxWords;
    while (guard-- > 0) {
        const before = text.slice(0, start);
        const m = leftRe.exec(before);
        if (!m) break;
        start -= m[1].length;
    }
    // Walk right over " Word" sequences.
    const rightRe = new RegExp(`^(\\s+${CAP_WORD})`);
    guard = maxWords;
    while (guard-- > 0) {
        const after = text.slice(end);
        const m = rightRe.exec(after);
        if (!m) break;
        end += m[1].length;
    }
    const expanded = text.slice(start, end).trim();
    return expanded.length > value.length ? expanded : null;
}

const ADDRESS_TAIL = /^([,\s][^,\n]{1,40})/;

function expandAddress(text, at, value) {
    let end = at + value.length;
    let guard = 6;
    while (guard-- > 0) {
        const after = text.slice(end);
        const m = ADDRESS_TAIL.exec(after);
        if (!m) break;
        end += m[1].length;
        // Stop once we've swallowed a country-ish / closing token.
        if (/\b(belg|france|españa|espagne|spain|nederland|pays-bas|deutschland)\w*\.?\s*$/i.test(text.slice(at, end))) break;
    }
    const expanded = text.slice(at, end).replace(/[.;]\s*$/, '').trim();
    return expanded.length > value.length ? expanded : null;
}

/**
 * Generalises a value into a reusable regex by its SHAPE — the learning step.
 * Stores the format, never the value: `PE7845123` → `\b[A-Z]{2}\d{7}\b`.
 * Returns '' for values too long/variable to usefully generalise.
 */
export function generalizeToRegex(value) {
    const v = String(value || '').trim();
    if (!v || v.length > 60) return '';

    const classify = (c) => {
        if (/[A-Z]/.test(c)) return { cls: '[A-Z]', test: x => /[A-Z]/.test(x) };
        if (/[a-z]/.test(c)) return { cls: '[a-z]', test: x => /[a-z]/.test(x) };
        if (/[0-9]/.test(c)) return { cls: '\\d',   test: x => /[0-9]/.test(x) };
        if (/\s/.test(c))    return { cls: '\\s',   test: x => /\s/.test(x) };
        const lit = c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');   // escape literal separators
        return { cls: lit, test: x => x === c };
    };

    let out = '';
    let i = 0;
    while (i < v.length) {
        const { cls, test } = classify(v[i]);
        let n = 1;
        while (i + n < v.length && test(v[i + n])) n++;
        out += n > 1 ? `${cls}{${n}}` : cls;
        i += n;
    }
    // Word boundaries so the format doesn't match inside larger tokens.
    if (/[A-Za-z0-9]/.test(v[0]))             out = '\\b' + out;
    if (/[A-Za-z0-9]/.test(v[v.length - 1]))  out = out + '\\b';
    return out;
}

/** Heuristic type guess for a free selection (spec point 3 default). */
export function suggestTokenBase(value) {
    const t = String(value || '').trim();
    if (!t) return 'RIESGO_MANUAL';
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(t)) return 'EMAIL';
    if (/^[A-Z]{2}\d{2}[\sA-Z0-9]{8,30}$/i.test(t.replace(/\s+/g, ' '))) return 'IBAN';
    if (/^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/.test(t)) return 'BIC_SWIFT';
    if (/^\+?\d[\d\s().-]{7,}$/.test(t)) return 'TELEFONO';
    if (/^\d{8}[A-Za-z]$/.test(t)) return 'DNI';
    if (/^[A-Z]{1,2}\d{6,9}$/.test(t)) return 'PASAPORTE';
    if (/^\d{2}\.?\d{2}\.?\d{2}-?\d{3}\.?\d{2}$/.test(t)) return 'RRN_BE';
    if (/^\d{3}-?\d{2}-?\d{4}$/.test(t)) return 'SSN_USA';
    if (/^\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}$/.test(t)) return 'FECHA_NACIMIENTO';
    if (/^\d{4,6}$/.test(t)) return 'CODIGO_POSTAL';
    if (/\d/.test(t) && /^[\w\s,.'-]+\d/.test(t) && /\b(calle|avenue|avenida|rue|street|str|laan|straat)\b/i.test(t)) return 'DIRECCION';
    const words = t.split(/\s+/);
    if (words.length >= 2 && words.every(w => /^[A-ZÁÉÍÓÚÑ]/.test(w))) return 'PERSONA_ES';
    if (/^[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+$/.test(t)) return 'APELLIDO';
    return 'RIESGO_MANUAL';
}

export { TOKEN_LABELS };
