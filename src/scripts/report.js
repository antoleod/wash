/**
 * report.js - Advanced anonymization report builder.
 *
 * Produces the four mandatory blocks requested by the auditor workflow while
 * keeping token assignment consistent within a run.
 */

import { buildRegex } from '../data/patterns.js';
import { escapeHtml } from './utils.js';
import { passesValidation } from './validators.js';
import { analyzeJson, analyzeStructured, analyzeStructuredBlocks } from './detector.js';
import { sanitizeText } from './sanitize.js';
import { auditText } from './audit.js';
import { confidencePct, regexConfidencePct } from './scoring.js';
import { applyCorrections, normalizeTokenBase, SUPPRESS_ACTIONS } from './corrections.js';
import { MANUAL_TOKEN_OPTIONS, labelForBase } from './labels.js';

// Re-exported for callers that still import the picker from report.js.
export { MANUAL_TOKEN_OPTIONS };

const SUSPICIOUS_RE = /\b(?:[A-Z]{2,}[-_]?\d{3,}|[A-Z0-9]{8,}|[a-z][a-z0-9._-]{2,20})\b/g;
const TOKEN_RE = /\[[A-Z_]+_\d+\]/g;

export function buildAnonymizationReport(text, activePatterns, corrections = []) {
    if (!text || !text.trim()) {
        return {
            sanitized: '',
            html: '',
            restoreMap: {},
            replacements: 0,
            rows: [],
            cleanText: '',
            stats: { total: 0, pii: 0, pci: 0, riskLevel: 'none', byPattern: {} },
        };
    }

    const list = Array.isArray(corrections) ? corrections : [];

    // GENUINE structure (JSON / key:value / headerless CSV) vs the blocks heuristic
    // (which is just regex over prose+embedded). Only genuine structure owns its
    // route; the heuristic ties with fallback on prose, so it must not capture
    // free-text correction cases away from the engine.
    const structuredStrong = analyzeJson(text) || analyzeStructured(text) || analyzeHeaderlessCsv(text);
    const structured = structuredStrong || analyzeStructuredBlocks(text, activePatterns);
    const fallback = fallbackAnalysis(text, activePatterns);

    // With corrections: layer over genuine structure when it wins (CSV/JSON — a
    // correction must never downgrade it); otherwise the free-text engine owns the
    // result so "extend" works. Routing stays independent of correction CONTENT.
    if (list.length) {
        if (structuredStrong && structuredStrong.stats.total >= fallback.stats.total) {
            return structuredWithCorrections(text, structuredStrong, list);
        }
        return buildCorrectedReport(text, activePatterns, list);
    }

    // No corrections: byte-for-byte the historical structured/regex routing.
    const useStructured = structured && structured.stats.total >= fallback.stats.total;
    if (useStructured) {
        const rows = rowsFromStructured(structured);
        return packReport(text, structured.sanitized, rows, structured.restoreMap,
            structured.replacements || rows.length, structured.stats);
    }
    const rows = rowsFromRegex(text, activePatterns, fallback.restoreMap);
    return packReport(text, fallback.sanitized, rows, fallback.restoreMap,
        fallback.replacements || rows.length, fallback.stats || auditText(text, activePatterns).stats);
}

/** Structured base (CSV/JSON) + whole-value corrections layered on top. */
function structuredWithCorrections(text, structured, list) {
    const rows = rowsFromStructured(structured);
    const layered = layerCorrections(text, structured.sanitized, rows, structured.restoreMap || {}, list);
    const replacements = (structured.replacements || rows.length) + layered.applied;
    const stats = layered.applied ? bumpManualStats(structured.stats, layered.applied) : structured.stats;
    // Protected/ignored values stay verbatim → keep them out of "suspicious".
    const suppressed = list.filter(c => SUPPRESS_ACTIONS.has(c?.action)).map(c => String(c.value || '').trim()).filter(Boolean);
    return packReport(text, layered.sanitized, layered.rows, layered.restoreMap, replacements, stats, suppressed);
}

/** Wraps clean text + rows into the four-block report + display HTML. */
function packReport(text, cleanText, rows, restoreMap, replacements, stats, suppressed = []) {
    const suspicious = findSuspiciousFragments(text, cleanText, rows, suppressed);
    const report = formatReport(cleanText, rows, suspicious);
    // Split for the UI: the clean prompt is the headline; the audit / suspicious /
    // suggestions blocks go behind a "ver más" disclosure (cleanHtml + detailsHtml).
    const marker = '\n2. AUDITORIA_DE_RIESGO:';
    const at = report.indexOf(marker);
    const detailsPart = at >= 0 ? report.slice(at + 1) : '';
    return {
        sanitized: report,
        html: htmlFromReport(report),
        cleanHtml: htmlFromReport(cleanText),
        detailsHtml: detailsPart ? htmlFromReport(detailsPart) : '',
        restoreMap: restoreMap || {},
        replacements,
        rows,
        cleanText,
        stats,
    };
}

/** Correction-aware report for FREE TEXT: clean text from the projected spans. */
function buildCorrectedReport(text, activePatterns, corrections) {
    const corr = applyCorrections(text, activePatterns, corrections);
    return packReport(text, corr.cleanText, corr.rows, corr.restoreMap, corr.replacements, corr.stats, corr.suppressed);
}

/**
 * Layers whole-value corrections over an already-sanitised STRUCTURED result.
 * Only replaces values still present in the clean text (not already tokenised),
 * continuing the per-base token numbering. 'ignore' is free-text-only → skipped.
 */
function layerCorrections(original, sanitized, rows, restoreMap, corrections) {
    const valid = corrections
        .filter(c => c && !SUPPRESS_ACTIONS.has(c.action))   // ignore/protect → keep verbatim
        .map(c => ({ value: String(c.value || '').trim(), base: normalizeTokenBase(c.tokenBase || 'RIESGO_MANUAL') }))
        .filter(c => c.value && c.base);
    if (!valid.length) return { sanitized, rows: [...rows], restoreMap: { ...restoreMap }, applied: 0 };

    const counters = countersFromTokens(sanitized, rows);
    const outRows  = [...rows];
    const outMap   = { ...restoreMap };
    const seen     = new Map();
    let clean   = sanitized;
    let applied = 0;

    for (const c of valid) {
        if (!original.includes(c.value)) continue;
        const key = `${c.base}|${normalize(c.value)}`;
        if (!seen.has(key)) {
            const n = (counters.get(c.base) || 0) + 1;
            counters.set(c.base, n);
            seen.set(key, `[${c.base}_${n}]`);
        }
        const token = seen.get(key);
        const next  = clean.split(c.value).join(token);
        if (next !== clean) {
            applied++;
            outMap[token] = c.value;
            outRows.push({
                value: c.value, base: c.base, type: labelForBase(c.base), token,
                risk: 'ALTO', source: 'Manual', confidence: 100,
                reason: 'Marcado manual como dato sensible',
            });
        }
        clean = next;
    }
    return { sanitized: clean, rows: outRows, restoreMap: outMap, applied };
}

function countersFromTokens(sanitized, rows) {
    const counters = new Map();
    const scan = value => {
        TOKEN_RE.lastIndex = 0;
        let m;
        while ((m = TOKEN_RE.exec(String(value || ''))) !== null) {
            const token = m[0].slice(1, -1);
            const idx = token.lastIndexOf('_');
            if (idx === -1) continue;
            const base = token.slice(0, idx);
            const n = Number(token.slice(idx + 1));
            if (Number.isFinite(n)) counters.set(base, Math.max(counters.get(base) || 0, n));
        }
    };
    scan(sanitized);
    rows.forEach(r => scan(r.token));
    return counters;
}

function bumpManualStats(stats, manualCount) {
    const next = {
        ...stats,
        total: stats.total + manualCount,
        pii: stats.pii + manualCount,
        byPattern: { ...stats.byPattern },
    };
    next.byPattern['Manual'] = (next.byPattern['Manual'] || 0) + manualCount;
    next.riskLevel = next.total > 4 ? 'high' : next.total > 1 ? 'medium' : 'low';
    return next;
}

const HEADERLESS_COLUMNS = [
    { token: 'NOMBRE', label: 'Nombre' },
    { token: 'APELLIDO', label: 'Apellido' },
    { token: 'DNI', label: 'DNI / documento' },
    { token: 'FECHA_NACIMIENTO', label: 'Fecha de nacimiento' },
    { token: 'EDAD', label: 'Edad' },
    { token: 'SEXO', label: 'Sexo / genero' },
    { token: 'DIRECCION', label: 'Direccion' },
    { token: 'CODIGO_POSTAL', label: 'Codigo postal' },
    { token: 'CIUDAD', label: 'Ciudad' },
    { token: 'PAIS', label: 'Pais' },
    { token: 'TELEFONO', label: 'Telefono' },
    { token: 'EMAIL', label: 'Email' },
    { token: 'ESTADO_CIVIL', label: 'Estado civil' },
    { token: 'PROFESION', label: 'Profesion' },
    { token: 'NACIONALIDAD', label: 'Nacionalidad' },
];

function analyzeHeaderlessCsv(text) {
    const lines = text.replace(/\r\n/g, '\n').split('\n').filter(line => line.trim() !== '');
    if (!lines.length) return null;
    const rows = lines.map(line => line.split(','));
    if (!rows.every(row => row.length === HEADERLESS_COLUMNS.length)) return null;
    if (looksLikeKnownHeader(rows[0])) return null;

    const counters = new Map();
    const seen = new Map();
    const restoreMap = {};
    const entities = [];
    const sanitizedLines = [];

    for (const row of rows) {
        const out = row.map((raw, index) => {
            const col = HEADERLESS_COLUMNS[index];
            const value = raw.trim();
            if (!value) return raw;
            const key = `${col.token}|${value.toLowerCase()}`;
            if (!seen.has(key)) {
                const n = (counters.get(col.token) || 0) + 1;
                counters.set(col.token, n);
                const token = `[${col.token}_${n}]`;
                seen.set(key, token);
                restoreMap[token] = value;
            }
            const token = seen.get(key);
            entities.push({ type: col.token, token, value, column: col.label, dataType: 'pii' });
            return token;
        });
        sanitizedLines.push(out.join(','));
    }

    const total = entities.length;
    const byPattern = {};
    entities.forEach(entity => {
        const label = labelForBase(entity.type);
        byPattern[label] = (byPattern[label] || 0) + 1;
    });

    const sanitized = sanitizedLines.join('\n');
    return {
        sanitized,
        sanitizedHtml: htmlFromReport(sanitized),
        auditHtml: escapeHtml(text),
        entities,
        restoreMap,
        replacements: total,
        stats: { total, pii: total, pci: 0, riskLevel: total > 4 ? 'high' : 'medium', byPattern },
    };
}

function looksLikeKnownHeader(row) {
    const normalizedHeader = HEADERLESS_COLUMNS.map(col => normalize(col.token));
    const normalizedRow = row.map(cell => normalize(String(cell).replace(/([a-z])([A-Z])/g, '$1 $2')));
    const matches = normalizedRow.filter((cell, index) =>
        cell === normalizedHeader[index] || cell === normalize(HEADERLESS_COLUMNS[index].label)
    );
    return matches.length >= Math.ceil(HEADERLESS_COLUMNS.length * 0.6);
}

function fallbackAnalysis(text, activePatterns) {
    const safe = sanitizeText(text, activePatterns);
    const audit = auditText(text, activePatterns);
    return { ...safe, stats: audit.stats };
}

function rowsFromStructured(result) {
    return result.entities.map(entity => ({
        value: entity.value,
        base: entity.type,
        type: labelForBase(entity.type),
        token: entity.token,
        risk: entity.dataType === 'pci' ? 'ALTO' : 'MEDIO',
        reason: entity.column
            ? `Columna reconocida: ${entity.column}`
            : entity.patternName
                ? `Patron activo: ${entity.patternName}`
                : `Clave JSON reconocida como ${labelForBase(entity.type)}`,
        // Column / JSON key → structure signal; a regex match inside an unmapped
        // cell scores by its own pattern (so it matches the free-text route).
        confidence: entity.patternName
            ? regexConfidencePct({ id: entity.patternId, validator: entity.validator, text: entity.value })
            : confidencePct({ source: 'structure' }),
    }));
}

function rowsFromRegex(text, patterns, restoreMap) {
    const tokenByValue = new Map(
        Object.entries(restoreMap || {}).map(([token, value]) => [normalize(value), token])
    );
    return collectMatches(text, patterns).map(match => ({
        value: match.text,
        base: match.token,
        type: labelForBase(match.token) || match.label || match.name,
        token: tokenByValue.get(normalize(match.text)) || '[RIESGO_POSIBLE_1]',
        risk: match.type === 'pci' ? 'ALTO' : 'MEDIO',
        reason: `Patron activo: ${match.name}`,
        confidence: regexConfidencePct({ id: match.id, validator: match.validator, text: match.text }),
    }));
}

function collectMatches(text, patterns) {
    const raw = [];
    for (const pattern of patterns) {
        if (!pattern.enabled) continue;
        const regex = buildRegex(pattern);
        let m;
        while ((m = regex.exec(text)) !== null) {
            if (m.index === regex.lastIndex) regex.lastIndex++;
            if (!passesValidation(pattern, m[0])) continue;
            raw.push({
                start: m.index,
                end: m.index + m[0].length,
                text: m[0],
                token: pattern.token,
                type: pattern.type,
                label: pattern.label,
                name: pattern.name,
                id: pattern.id,
                validator: pattern.validator,
            });
        }
    }
    raw.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    const out = [];
    let cursor = 0;
    for (const match of raw) {
        if (match.start >= cursor) {
            out.push(match);
            cursor = match.end;
        }
    }
    return out;
}

function findSuspiciousFragments(original, sanitized, auditRows, suppressed = []) {
    const known = new Set(auditRows.map(row => normalize(row.value)));
    const protectedLc = (suppressed || []).map(v => String(v).toLowerCase());
    const suspects = new Set();
    let m;
    while ((m = SUSPICIOUS_RE.exec(original)) !== null) {
        const fragment = m[0];
        if (TOKEN_RE.test(fragment)) continue;
        TOKEN_RE.lastIndex = 0;
        if (known.has(normalize(fragment))) continue;
        if (!sanitized.includes(fragment)) continue;
        // A protected/ignored span stays verbatim — never re-flag a piece of it.
        const fragLc = fragment.toLowerCase();
        if (protectedLc.some(v => v.includes(fragLc))) continue;
        suspects.add(fragment);
    }
    return [...suspects].slice(0, 20);
}

function formatReport(cleanText, rows, suspicious) {
    const auditLines = [
        '| Valor detectado | Tipo de dato | Etiqueta asignada | Nivel de riesgo | Motivo de deteccion | Confianza |',
        '|---|---|---|---|---|---|',
    ];

    if (rows.length === 0) {
        auditLines.push('| Sin hallazgos confirmados | - | - | BAJO | No se detectaron patrones activos | 0% |');
    } else {
        for (const row of rows) {
            auditLines.push(
                `| ${cell(row.value)} | ${cell(row.type)} | ${cell(row.token)} | ${row.risk} | ${cell(row.reason)} | ${row.confidence}% |`
            );
        }
    }

    const suspiciousLines = suspicious.length
        ? suspicious.map(item => `- ${item}`)
        : ['- Ninguno.'];

    const suggestions = [
        '- Anadir diccionarios de nombres, ciudades, profesiones y nacionalidades especificos del dominio.',
        '- Activar patrones opcionales para fechas, codigos postales, matriculas, expedientes y numeros de serie cuando el contexto lo requiera.',
        '- Usar correcciones manuales como nuevas senales de riesgo para elevar futuros casos ambiguos a RIESGO_POSIBLE.',
    ];

    return [
        '1. TEXTO_LIMPIO:',
        cleanText,
        '',
        '2. AUDITORIA_DE_RIESGO:',
        ...auditLines,
        '',
        '3. DATOS_NO_DETECTADOS_PERO_SOSPECHOSOS:',
        ...suspiciousLines,
        '',
        '4. SUGERENCIAS_DE_MEJORA:',
        ...suggestions,
    ].join('\n');
}

function htmlFromReport(report) {
    return escapeHtml(report).replace(TOKEN_RE, token =>
        `<span class="hl-token" aria-label="Token: ${escapeHtml(token)}">${escapeHtml(token)}</span>`
    );
}

function cell(value) {
    return String(value ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function normalize(value) {
    return String(value ?? '').trim().toLowerCase().replace(/\s+/g, ' ');
}
