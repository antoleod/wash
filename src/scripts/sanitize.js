/**
 * sanitize.js — Tokenization / sanitization logic.
 *
 * Replaces sensitive data with consistent tokens.
 * The same entity always gets the same token number within one run:
 *   Juan Pérez → [PERSONA_1]
 *   Ana García → [PERSONA_2]
 *   Juan Pérez → [PERSONA_1]  (same token, not _3)
 */

import { buildRegex } from '../data/patterns.js';
import { escapeHtml, confusableFold, execOnTextAndTwin } from './utils.js';
import { passesValidation } from './validators.js';
import { scanEntities } from './entityScanner.js';

/**
 * @typedef {Object} SanitizeResult
 * @property {string} sanitized     — plain text with tokens (for export/copy)
 * @property {string} html          — HTML with highlighted tokens (for display)
 * @property {Map}    entityMap     — originalValue → token (for reference)
 * @property {number} replacements  — total number of replacements made
 */

/**
 * Sanitizes text by replacing sensitive matches with consistent tokens.
 *
 * @param {string} text
 * @param {Array}  activePatterns
 * @returns {SanitizeResult}
 */
export function sanitizeText(text, activePatterns) {
    if (!text || !text.trim()) {
        return { sanitized: '', html: '', entityMap: new Map(), restoreMap: {}, replacements: 0 };
    }

    // Step 1: collect all matches (same de-overlap logic as audit)
    const matches = collectMatches(text, activePatterns);

    if (matches.length === 0) {
        return {
            sanitized:    text,
            html:         escapeHtml(text),
            entityMap:    new Map(),
            restoreMap:   {},
            replacements: 0,
        };
    }

    // Step 2: build token assignments (consistent per entity value)
    const entityMap   = new Map();   // normalized match → token string
    const counterMap  = new Map();   // token base → counter
    const restoreMap  = {};          // token → first-seen original (for reversal)

    for (const match of matches) {
        const key = match.text.trim().toLowerCase();
        if (!entityMap.has(key)) {
            const base  = match.token;
            const count = (counterMap.get(base) || 0) + 1;
            counterMap.set(base, count);
            const token = `[${base}_${count}]`;
            entityMap.set(key, token);
            restoreMap[token] = match.text;   // remember original to restore later
        }
    }

    // Step 3: build sanitized text and HTML in one pass
    let sanitized = '';
    let html      = '';
    let cursor    = 0;

    for (const match of matches) {
        const plain = text.slice(cursor, match.start);
        sanitized += plain;
        html      += escapeHtml(plain);

        const token = entityMap.get(match.text.trim().toLowerCase());
        sanitized += token;
        html      += `<span class="hl-token" aria-label="Token: ${escapeHtml(token)}">${escapeHtml(token)}</span>`;

        cursor = match.end;
    }

    const tail = text.slice(cursor);
    sanitized += tail;
    html      += escapeHtml(tail);

    return { sanitized, html, entityMap, restoreMap, replacements: matches.length };
}

// ----------- private -----------

function collectMatches(text, patterns) {
    const raw = [];
    const twin = confusableFold(text);

    for (const pattern of patterns) {
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
            });
        }
    }

    for (const hit of scanEntities(text)) {
        raw.push({ start: hit.start, end: hit.end, text: hit.text, token: hit.token, type: hit.type });
    }

    raw.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));

    const deduped = [];
    let cursor = 0;
    for (const match of raw) {
        if (match.start >= cursor) {
            deduped.push(match);
            cursor = match.end;
        }
    }

    return deduped;
}
