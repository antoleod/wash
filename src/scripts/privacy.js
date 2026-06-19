/**
 * privacy.js — Reversible anonymization core ("Privacy Gateway" engine).
 *
 * The sandbox's sanitize.js is one-way: it tokenizes and throws the mapping
 * away. A privacy gateway needs the inverse. This module provides the missing
 * primitive — anonymize → {anonymized, map} → (LLM) → restore — plus the leak
 * checks that make the round-trip safe.
 *
 * Design notes (see docs/privacy-gateway.md):
 *  - Tokens are BRACKETED (`[NOMBRE_1]`). The prompt's `NAME_1` was illustrative;
 *    brackets make restoration collision-safe (`[NOMBRE_1]` can never be a prefix
 *    of `[NOMBRE_11]` because the `]` delimits it) and easier to detect as orphans.
 *  - Risk is asymmetric vs. the highlighter: a false NEGATIVE here is a data leak.
 *    So detection leans toward recall, but never tokenizes generic words that
 *    would garble the text for the LLM.
 *  - Pure module (string in → object out). No DOM, no network. The LLM call is
 *    injected (FASE 2), so the round-trip is fully unit-testable.
 */

// ── Structured detectors (fixed form) ────────────────────────
const DETECTORS = [
    { token: 'EMAIL',    type: 'pii', re: /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g },
    // Permissive intl phone — the sandbox's phone_intl regex misses grouped
    // numbers like "+32 456 12 34 56" (verified). This captures the whole span.
    { token: 'TELEFONO', type: 'pii', re: /\+\d{1,3}(?:[\s.\-]?\d{1,4}){2,6}/g },
    { token: 'IBAN',     type: 'pci', re: /\b[A-Z]{2}\d{2}(?:[\s\-]?[A-Z0-9]{4}){3,7}(?:[\s\-]?[A-Z0-9]{1,4})?\b/g },
    { token: 'TARJETA',  type: 'pci', re: /\b(?:\d{4}[\s\-]?){3}\d{4}\b/g },
    { token: 'URL',      type: 'pii', re: /\bhttps?:\/\/[^\s]+/g },
    { token: 'HORA',     type: 'pii', re: /\b\d{1,2}:\d{2}\b/g },
];

// ── Dictionary detectors (lexical) ───────────────────────────
// Small, illustrative, extendable. In production these load from RuleStore
// and grow via human corrections (FASE 4).
const DICTIONARIES = {
    NOMBRE: ['Pablo', 'Juan', 'María', 'Maria', 'Pedro', 'Ana', 'Luis', 'Carlos',
             'Elena', 'Sofía', 'David', 'Laura', 'Javier', 'Marta', 'Sergio'],
    CIUDAD: ['Bruselas', 'Madrid', 'Barcelona', 'Valencia', 'Sevilla', 'París',
             'Paris', 'Lyon', 'Ámsterdam', 'Amsterdam', 'Roma', 'Berlín', 'Berlin'],
    PAIS:   ['España', 'Francia', 'Italia', 'Alemania', 'Portugal', 'Bélgica',
             'Belgica', 'México', 'Mexico', 'Países Bajos'],
};

function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Build one whole-word, case-insensitive regex per dictionary. */
function buildDictDetectors() {
    return Object.entries(DICTIONARIES).map(([token, terms]) => {
        const alt = terms.slice().sort((a, b) => b.length - a.length).map(escapeRegex).join('|');
        // Unicode-aware-ish boundaries: not preceded/followed by a letter.
        return { token, type: 'pii', re: new RegExp(`(?<![\\p{L}])(?:${alt})(?![\\p{L}])`, 'gu') };
    });
}

function normValue(s) {
    return s.trim().toLowerCase().replace(/\s+/g, ' ');
}

/**
 * Detect sensitive spans and produce reversible anonymization.
 *
 * @param {string} text
 * @returns {{
 *   anonymized: string,
 *   map: Object.<string,string>,   // token → original value (for restore)
 *   entities: Array<{token,type,value,count}>,
 * }}
 */
export function anonymize(text) {
    if (!text) return { anonymized: '', map: {}, entities: [] };

    const detectors = [...DETECTORS, ...buildDictDetectors()];

    // 1. Collect all candidate matches with positions.
    const raw = [];
    for (const d of detectors) {
        const re = new RegExp(d.re.source, d.re.flags.includes('g') ? d.re.flags : d.re.flags + 'g');
        let m;
        while ((m = re.exec(text)) !== null) {
            if (m.index === re.lastIndex) { re.lastIndex++; continue; }
            raw.push({ start: m.index, end: m.index + m[0].length, text: m[0], token: d.token, type: d.type });
        }
    }

    // 2. Sort by start, prefer longer; drop overlaps (first/longest wins).
    raw.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    const matches = [];
    let cursor = 0;
    for (const r of raw) {
        if (r.start >= cursor) { matches.push(r); cursor = r.end; }
    }

    // 3. Assign consistent tokens (base + normalized value → [BASE_n]).
    const valueToToken = new Map();   // 'BASE|normvalue' → '[BASE_n]'
    const counters     = new Map();   // 'BASE' → n
    const map          = {};          // '[BASE_n]' → original value
    const entityCount  = new Map();   // '[BASE_n]' → count

    function tokenFor(base, value, type) {
        const key = base + '|' + normValue(value);
        if (!valueToToken.has(key)) {
            const n = (counters.get(base) || 0) + 1;
            counters.set(base, n);
            const tok = `[${base}_${n}]`;
            valueToToken.set(key, tok);
            map[tok] = value;                 // store first-seen original
            entityCount.set(tok, 0);
        }
        const tok = valueToToken.get(key);
        entityCount.set(tok, entityCount.get(tok) + 1);
        return tok;
    }

    // 4. Build anonymized text in one pass.
    let anonymized = '';
    cursor = 0;
    const typeByToken = new Map();
    for (const mt of matches) {
        anonymized += text.slice(cursor, mt.start);
        const tok = tokenFor(mt.token, mt.text, mt.type);
        typeByToken.set(tok, mt.type);
        anonymized += tok;
        cursor = mt.end;
    }
    anonymized += text.slice(cursor);

    const entities = Object.keys(map).map(tok => ({
        token: tok,
        type:  typeByToken.get(tok) || 'pii',
        value: map[tok],
        count: entityCount.get(tok),
    }));

    return { anonymized, map, entities };
}

/**
 * Restore real values from a (possibly LLM-transformed) anonymized text.
 * Tolerates altered surrounding text — only the placeholders are swapped back.
 */
export function restore(text, map) {
    let out = text;
    // Replace longest tokens first (defensive; brackets already prevent prefix
    // collisions, but order keeps behaviour obvious).
    const tokens = Object.keys(map).sort((a, b) => b.length - a.length);
    for (const tok of tokens) {
        out = out.split(tok).join(map[tok]);
    }
    return out;
}

const PLACEHOLDER_RE = /\[[A-Z_]+_\d+\]/g;

export function findPlaceholders(text) {
    return text ? (text.match(PLACEHOLDER_RE) || []) : [];
}

/**
 * FASE 5 — leak protection.
 * @returns {{
 *   leakBeforeLLM: string[],     // original values still present in anonymized
 *   orphanPlaceholders: string[],// placeholders left unrestored in final text
 *   fullyRestored: boolean,
 *   ok: boolean,
 * }}
 */
export function verify({ anonymized, map, restored }) {
    const leakBeforeLLM = anonymized
        ? Object.values(map).filter(v => v && anonymized.includes(v))
        : [];
    const orphanPlaceholders = findPlaceholders(restored || '');
    const fullyRestored = orphanPlaceholders.length === 0;
    return {
        leakBeforeLLM,
        orphanPlaceholders,
        fullyRestored,
        ok: leakBeforeLLM.length === 0 && fullyRestored,
    };
}

/**
 * Full gateway round-trip (FASE 1 → 2 → 3 → 5).
 * The LLM is injected as `llmFn(anonymizedText) → Promise<string>|string`;
 * tests pass a deterministic stub, production passes the real client.
 */
export async function gatewayProcess(text, llmFn) {
    const { anonymized, map, entities } = anonymize(text);
    const llmOutput = await llmFn(anonymized);
    const restored  = restore(llmOutput, map);
    const report    = verify({ anonymized, map, restored });

    return {
        anonymized,
        map,
        entities,
        llmOutput,
        restored,
        report: {
            ...report,
            entitiesDetected:    entities.length,
            anonymizationRate:   entities.length, // count of distinct tokens
        },
    };
}
