/**
 * audit.js — Detection and risk analysis logic.
 *
 * Takes plain text + active patterns, returns:
 *  - HTML string with highlights for display
 *  - Statistics object with counts per type and risk level
 */

import { buildRegex } from '../data/patterns.js';
import { escapeHtml, confusableFold, execOnTextAndTwin } from './utils.js';
import { passesValidation } from './validators.js';

/**
 * @typedef {Object} AuditStats
 * @property {number} total
 * @property {number} pii
 * @property {number} pci
 * @property {string} riskLevel  — 'low' | 'medium' | 'high'
 * @property {Object.<string, number>} byPattern  — { patternName: count }
 */

/**
 * Audits text for sensitive data patterns.
 *
 * @param {string} text — raw input text
 * @param {Array}  activePatterns — enabled pattern definitions
 * @returns {{ html: string, stats: AuditStats }}
 */
export function auditText(text, activePatterns) {
    if (!text || !text.trim()) {
        return { html: '', stats: emptyStats() };
    }

    // We need to:
    // 1. Find all matches with their positions and types
    // 2. Sort by start position
    // 3. Build highlighted HTML in one pass (avoids double-wrapping tags)

    const matches = collectMatches(text, activePatterns);

    const html   = buildHighlightedHtml(text, matches);
    const stats  = computeStats(matches, activePatterns);

    return { html, stats };
}

// ----------- private helpers -----------

/**
 * Collects all pattern matches with position info.
 * Overlapping matches from later patterns are skipped.
 */
function collectMatches(text, patterns) {
    const rawMatches = [];
    const twin = confusableFold(text);

    for (const pattern of patterns) {
        if (!pattern.enabled) continue;
        const regex = buildRegex(pattern);
        for (const hit of execOnTextAndTwin(regex, text, twin)) {
            if (!passesValidation(pattern, hit.text)) continue;
            rawMatches.push({
                start: hit.start,
                end:   hit.end,
                text:  hit.text,
                type:  pattern.type,
                label: pattern.label,
                name:  pattern.name,
                token: pattern.token,
            });
        }
    }

    // Sort by start position, then by length desc (prefer longer match)
    rawMatches.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));

    // Remove overlaps (keep first / longest)
    const deduped = [];
    let cursor = 0;
    for (const match of rawMatches) {
        if (match.start >= cursor) {
            deduped.push(match);
            cursor = match.end;
        }
    }

    return deduped;
}

/**
 * Builds the highlighted HTML string from the original text and match list.
 */
function buildHighlightedHtml(text, matches) {
    let html = '';
    let cursor = 0;

    for (const match of matches) {
        // Plain text before this match
        html += escapeHtml(text.slice(cursor, match.start));

        // Highlighted match
        const cssClass = match.type === 'pci' ? 'hl-pci' : 'hl-pii';
        const safeTitle = escapeHtml(match.label);
        html += `<span class="${cssClass}" title="${safeTitle}" aria-label="${safeTitle}: ${escapeHtml(match.text)}">${escapeHtml(match.text)}</span>`;

        cursor = match.end;
    }

    // Remaining text after last match
    html += escapeHtml(text.slice(cursor));

    return html;
}

/**
 * Builds stats from matches.
 */
function computeStats(matches, patterns) {
    const stats = emptyStats();

    for (const m of matches) {
        stats.total++;
        if (m.type === 'pii') stats.pii++;
        if (m.type === 'pci') stats.pci++;
        stats.byPattern[m.name] = (stats.byPattern[m.name] || 0) + 1;
    }

    stats.riskLevel = computeRiskLevel(stats.total);
    return stats;
}

function computeRiskLevel(total) {
    if (total === 0) return 'none';
    if (total <= 1)  return 'low';
    if (total <= 4)  return 'medium';
    return 'high';
}

function emptyStats() {
    return { total: 0, pii: 0, pci: 0, riskLevel: 'none', byPattern: {} };
}
