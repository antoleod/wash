/**
 * detector.js — Structured (CSV / tabular) sensitive-data detector.
 *
 * The regex engine in audit.js / sanitize.js works on FREE TEXT and only
 * catches fixed-form values (email, phone, IBAN…). It cannot catch a name,
 * a city or a nationality, and it misses values split across columns
 * (e.g. "Juan,Perez" — the two-word name regex needs a space, not a comma).
 *
 * For TABULAR input the column header is the strongest possible signal:
 * a value under a "Nacionalidad" column IS a nationality, no dictionary or
 * confidence score required. This module detects that case and anonymizes
 * cell-by-cell, driven by the header row.
 *
 * Pure module: string in → result out. No DOM, no browser APIs — unit-testable
 * in Node. The persistent learning loop (see docs/detector-hibrido.md) is a
 * separate, deferred phase.
 *
 * UNION ROUTING: analyzeStructuredBlocks(text, patterns) interleaves three
 * detectors over one shared token allocator — CSV blocks (header-driven), JSON
 * blocks (key-driven) and the regex engine on the free-text runs in between —
 * so the structured route is a true SUPERSET of the regex route, never an
 * either/or choice. Passing no `patterns` keeps the legacy CSV-only behavior
 * (and byte-identical output) that the existing tests assert.
 */

import { buildRegex } from '../data/patterns.js';
import { confusableFold, execOnTextAndTwin } from './utils.js';
import { passesValidation } from './validators.js';
import { scanEntities } from './entityScanner.js';

// ── Column header → entity type ──────────────────────────────
// Keyed by normalized header (lowercase, no accents, no separators).
// type defaults to 'pii'; 'pci' marked explicitly.
const COLUMN_TYPES = {
    nombre:          { token: 'NOMBRE',           label: 'Nombre' },
    name:            { token: 'NOMBRE',           label: 'Nombre' },
    firstname:       { token: 'NOMBRE',           label: 'Nombre' },
    apellido:        { token: 'APELLIDO',         label: 'Apellido' },
    apellidos:       { token: 'APELLIDO',         label: 'Apellido' },
    lastname:        { token: 'APELLIDO',         label: 'Apellido' },
    surname:         { token: 'APELLIDO',         label: 'Apellido' },
    nombrecompleto:  { token: 'NOMBRE_COMPLETO',  label: 'Nombre completo' },
    fullname:        { token: 'NOMBRE_COMPLETO',  label: 'Nombre completo' },
    dni:             { token: 'DNI',              label: 'DNI' },
    documento:       { token: 'DNI',              label: 'Documento' },
    nie:             { token: 'NIE',              label: 'NIE' },
    pasaporte:       { token: 'PASAPORTE',        label: 'Pasaporte' },
    passport:        { token: 'PASAPORTE',        label: 'Pasaporte' },
    fechanacimiento: { token: 'FECHA_NACIMIENTO', label: 'Fecha de nacimiento' },
    fechanac:        { token: 'FECHA_NACIMIENTO', label: 'Fecha de nacimiento' },
    fechadenacimiento:{ token: 'FECHA_NACIMIENTO',label: 'Fecha de nacimiento' },
    dob:             { token: 'FECHA_NACIMIENTO', label: 'Fecha de nacimiento' },
    edad:            { token: 'EDAD',             label: 'Edad' },
    age:             { token: 'EDAD',             label: 'Edad' },
    sexo:            { token: 'SEXO',             label: 'Sexo' },
    genero:          { token: 'SEXO',             label: 'Género' },
    direccion:       { token: 'DIRECCION',        label: 'Dirección' },
    domicilio:       { token: 'DIRECCION',        label: 'Dirección' },
    calle:           { token: 'DIRECCION',        label: 'Dirección' },
    address:         { token: 'DIRECCION',        label: 'Dirección' },
    codigopostal:    { token: 'CODIGO_POSTAL',    label: 'Código postal' },
    cp:              { token: 'CODIGO_POSTAL',    label: 'Código postal' },
    ciudad:          { token: 'CIUDAD',           label: 'Ciudad' },
    poblacion:       { token: 'CIUDAD',           label: 'Ciudad' },
    localidad:       { token: 'CIUDAD',           label: 'Ciudad' },
    city:            { token: 'CIUDAD',           label: 'Ciudad' },
    pais:            { token: 'PAIS',             label: 'País' },
    country:         { token: 'PAIS',             label: 'País' },
    nacionalidad:    { token: 'NACIONALIDAD',     label: 'Nacionalidad' },
    nationality:     { token: 'NACIONALIDAD',     label: 'Nacionalidad' },
    telefono:        { token: 'TELEFONO',         label: 'Teléfono' },
    tel:             { token: 'TELEFONO',         label: 'Teléfono' },
    movil:           { token: 'TELEFONO',         label: 'Teléfono' },
    celular:         { token: 'TELEFONO',         label: 'Teléfono' },
    phone:           { token: 'TELEFONO',         label: 'Teléfono' },
    email:           { token: 'EMAIL',            label: 'Email' },
    correo:          { token: 'EMAIL',            label: 'Email' },
    mail:            { token: 'EMAIL',            label: 'Email' },
    estadocivil:     { token: 'ESTADO_CIVIL',     label: 'Estado civil' },
    profesion:       { token: 'PROFESION',        label: 'Profesión' },
    ocupacion:       { token: 'PROFESION',        label: 'Profesión' },
    cargo:           { token: 'PROFESION',        label: 'Cargo' },
    empresa:         { token: 'EMPRESA',          label: 'Empresa' },
    usuario:         { token: 'USUARIO',          label: 'Usuario' },
    login:           { token: 'USUARIO',          label: 'Usuario' },
    upn:             { token: 'USUARIO',          label: 'Usuario' },
    numempleado:     { token: 'NUM_EMPLEADO',     label: 'Nº empleado' },
    numerodeempleado:{ token: 'NUM_EMPLEADO',     label: 'Nº empleado' },
    badge:           { token: 'NUM_EMPLEADO',     label: 'Badge' },
    matricula:       { token: 'MATRICULA',        label: 'Matrícula' },
    // ── PCI (financial) ──
    tarjeta:         { token: 'TARJETA_CREDITO',  label: 'Tarjeta', type: 'pci' },
    numerotarjeta:   { token: 'TARJETA_CREDITO',  label: 'Tarjeta', type: 'pci' },
    iban:            { token: 'IBAN',             label: 'IBAN',    type: 'pci' },
    cuenta:          { token: 'CUENTA',           label: 'Cuenta',  type: 'pci' },
    cvv:             { token: 'CVV',              label: 'CVV',     type: 'pci' },
};

/** Normalize a header for lookup: lowercase, strip accents and separators. */
function normKey(s) {
    return (s || '')
        .toLowerCase()
        .normalize('NFD').replace(/[̀-ͯ]/g, '')
        .replace(/[^a-z0-9]/g, '');
}

/** Normalize a cell value for token-consistency keying. */
function normValue(s) {
    return unquote(s).trim().toLowerCase().replace(/\s+/g, ' ');
}

function unquote(s) {
    const t = (s || '').trim();
    if (t.length >= 2 && t[0] === '"' && t[t.length - 1] === '"') {
        return t.slice(1, -1);
    }
    return t;
}

/**
 * Split a CSV line on commas, ignoring commas inside double-quoted fields, so
 * `Juan,"Av. Libertad 245, Madrid",x` stays 3 cells. Each cell keeps its raw
 * text (quotes included) so `cells.join(',')` losslessly rebuilds the line and
 * the restore round-trip holds; `unquote()` strips the quotes for detection.
 * Simple quote toggle — RFC-escaped `""` is uncommon and not specially handled.
 */
function splitLine(line) {
    if (line.indexOf('"') === -1) return line.split(',');   // fast path, no quotes
    const cells = [];
    let cur = '', inQuotes = false;
    for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"') { inQuotes = !inQuotes; cur += ch; }
        else if (ch === ',' && !inQuotes) { cells.push(cur); cur = ''; }
        else { cur += ch; }
    }
    cells.push(cur);
    return cells;
}

/**
 * Shared token allocator. One per analysis run so the SAME value under the same
 * token base always collapses to one token across CSV / JSON / regex segments,
 * and two distinct values never collide on the same token in restoreMap.
 */
function createTokenizer() {
    const tokenMap   = new Map();   // 'BASE|normval' → '[BASE_n]'
    const counters   = new Map();   // base → highest n
    const restoreMap = {};          // token → first-seen original (string)
    function tokenFor(base, value) {
        const sval = String(value);
        const key  = base + '|' + normValue(sval);
        if (!tokenMap.has(key)) {
            const n = (counters.get(base) || 0) + 1;
            counters.set(base, n);
            const token = `[${base}_${n}]`;
            tokenMap.set(key, token);
            restoreMap[token] = sval;
        }
        return tokenMap.get(key);
    }
    return { tokenFor, restoreMap };
}

function resolveColumn(header) {
    return COLUMN_TYPES[normKey(header)] || null;
}

/**
 * Decides whether the text is tabular and worth structured handling.
 * Gated hard to avoid mangling normal comma-containing prose:
 *   - at least a header + 1 data row
 *   - ≥ 2 columns, consistent count across every row
 *   - header has ≥ 2 cells that map to known column types
 *
 * @returns {{ headers, columns, rows }|null}
 */
export function detectStructured(text) {
    if (!text || !text.trim()) return null;

    const lines = text.replace(/\r\n/g, '\n').split('\n');
    // Drop a single trailing empty line (common with text editors).
    while (lines.length && lines[lines.length - 1].trim() === '') lines.pop();
    if (lines.length < 2) return null;

    const headers = splitLine(lines[0]);
    if (headers.length < 2) return null;

    const columns = headers.map(resolveColumn);
    const mappedCount = columns.filter(Boolean).length;
    if (mappedCount < 2) return null;

    const rows = [];
    for (let i = 1; i < lines.length; i++) {
        const cells = splitLine(lines[i]);
        if (cells.length !== headers.length) return null; // inconsistent → not a table
        rows.push(cells);
    }
    if (rows.length === 0) return null;

    return { headers, columns, rows };
}

const PCI_PREFIXES = ['TARJETA', 'IBAN', 'CUENTA', 'CVV'];
function typeOf(col) {
    return col.type || (PCI_PREFIXES.some(p => col.token.startsWith(p)) ? 'pci' : 'pii');
}

function computeRiskLevel(total) {
    if (total === 0) return 'none';
    if (total <= 1)  return 'low';
    if (total <= 4)  return 'medium';
    return 'high';
}

function escapeHtml(text) {
    return String(text)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * Full structured analysis. Returns null if the text is not tabular.
 *
 * @returns {{
 *   sanitized: string,   // plain text, mapped cells → [TOKEN_n]
 *   auditHtml: string,   // original text, mapped cells wrapped in hl-pii/hl-pci
 *   sanitizedHtml: string, // sanitized text, tokens wrapped in hl-token
 *   entities: Array,
 *   stats: { total, pii, pci, riskLevel, byPattern },
 *   replacements: number,
 * }|null}
 */
export function analyzeStructured(text, tokenizer, patterns = null) {
    const parsed = detectStructured(text);
    if (!parsed) return null;

    const { headers, columns, rows } = parsed;

    // Consistent tokens: key = TOKEN + '|' + normalized value (NOT value alone,
    // so the same string under different column types never collapses).
    // A shared tokenizer (when passed) keeps numbering consistent across blocks.
    const tk         = tokenizer || createTokenizer();
    const restoreMap = tk.restoreMap;
    const entities   = [];
    const stats      = { total: 0, pii: 0, pci: 0, riskLevel: 'none', byPattern: {} };

    const tokenFor = (col, value) => tk.tokenFor(col.token, value);

    const sanitizedLines     = [headers.join(',')];      // header row passes through verbatim
    const auditLines         = [escapeHtml(headers.join(','))];
    const sanitizedHtmlLines = [escapeHtml(headers.join(','))];

    for (const cells of rows) {
        const outPlain = [];
        const outAudit = [];
        const outSani  = [];

        cells.forEach((raw, c) => {
            const col = columns[c];
            const value = unquote(raw).trim();

            if (value === '') {
                // Empty cell → preserve verbatim.
                outPlain.push(raw);
                outAudit.push(escapeHtml(raw));
                outSani.push(escapeHtml(raw));
                return;
            }

            if (!col) {
                // Unmapped column: regex-scan the cell (true superset) when
                // patterns are supplied, so e.g. an email under an unrecognized
                // header is still caught. Otherwise preserve verbatim.
                if (patterns) {
                    const r = analyzeFreeTextRun(raw, patterns, tk);
                    if (r.stats.total > 0) {
                        outPlain.push(r.sanitized);
                        outAudit.push(r.auditHtml);
                        outSani.push(r.sanitizedHtml);
                        entities.push(...r.entities);
                        mergeStats(stats, r.stats);
                        return;
                    }
                }
                outPlain.push(raw);
                outAudit.push(escapeHtml(raw));
                outSani.push(escapeHtml(raw));
                return;
            }

            const token = tokenFor(col, raw);
            const type  = typeOf(col);
            const cls   = type === 'pci' ? 'hl-pci' : 'hl-pii';

            outPlain.push(token);
            outAudit.push(
                `<span class="${cls}" title="${escapeHtml(col.label)}" ` +
                `aria-label="${escapeHtml(col.label)}: ${escapeHtml(value)}">${escapeHtml(value)}</span>`
            );
            outSani.push(`<span class="hl-token" aria-label="Token: ${escapeHtml(token)}">${escapeHtml(token)}</span>`);

            entities.push({ type: col.token, token, column: headers[c], value, dataType: type });
            stats.total++;
            if (type === 'pci') stats.pci++; else stats.pii++;
            stats.byPattern[col.label] = (stats.byPattern[col.label] || 0) + 1;
        });

        sanitizedLines.push(outPlain.join(','));
        auditLines.push(outAudit.join(','));
        sanitizedHtmlLines.push(outSani.join(','));
    }

    stats.riskLevel = computeRiskLevel(stats.total);

    return {
        sanitized:     sanitizedLines.join('\n'),
        auditHtml:     auditLines.join('\n'),
        sanitizedHtml: sanitizedHtmlLines.join('\n'),
        entities,
        restoreMap,
        stats,
        replacements:  stats.total,
    };
}

export function analyzeStructuredBlocks(text, patterns = null) {
    if (!text || !text.trim()) return null;

    const lines = text.replace(/\r\n/g, '\n').split('\n');
    const tk = createTokenizer();
    const outSanitized = [];
    const outAudit = [];
    const outSanitizedHtml = [];
    const entities = [];
    const stats = { total: 0, pii: 0, pci: 0, riskLevel: 'none', byPattern: {} };
    let foundBlock = false;
    let freeBuf = [];

    // Flush buffered free-text lines: regex-tokenize them (when patterns given)
    // so values between blocks aren't left exposed; otherwise pass verbatim.
    const flushFree = () => {
        if (!freeBuf.length) return;
        const runText = freeBuf.join('\n');
        freeBuf = [];
        if (patterns) {
            const r = analyzeFreeTextRun(runText, patterns, tk);
            outSanitized.push(r.sanitized);
            outAudit.push(r.auditHtml);
            outSanitizedHtml.push(r.sanitizedHtml);
            entities.push(...r.entities);
            mergeStats(stats, r.stats);
        } else {
            outSanitized.push(runText);
            outAudit.push(escapeHtml(runText));
            outSanitizedHtml.push(escapeHtml(runText));
        }
    };

    const pushBlock = (analyzed) => {
        flushFree();
        foundBlock = true;
        outSanitized.push(analyzed.sanitized);
        outAudit.push(analyzed.auditHtml);
        outSanitizedHtml.push(analyzed.sanitizedHtml);
        entities.push(...analyzed.entities);
        mergeStats(stats, analyzed.stats);
    };

    let i = 0;
    while (i < lines.length) {
        // 1. CSV block (header-driven). Honored in both legacy and union modes.
        const csvEnd = findStructuredBlockEnd(lines, i);
        if (csvEnd !== -1) {
            const analyzed = analyzeStructured(lines.slice(i, csvEnd).join('\n'), tk, patterns);
            if (analyzed) { pushBlock(analyzed); i = csvEnd; continue; }
        }
        // 2. JSON block (key-driven). Union mode only.
        if (patterns) {
            const jsonEnd = findJsonBlockEnd(lines, i);
            if (jsonEnd !== -1) {
                const analyzed = analyzeJson(lines.slice(i, jsonEnd).join('\n'), tk, patterns);
                if (analyzed) { pushBlock(analyzed); i = jsonEnd; continue; }
            }
        }
        // 3. Free text.
        freeBuf.push(lines[i]);
        i++;
    }
    flushFree();

    // Legacy contract: with no patterns, return null unless a CSV block was hit.
    if (!patterns && !foundBlock) return null;
    if (stats.total === 0) return null;
    stats.riskLevel = computeRiskLevel(stats.total);

    return {
        sanitized: outSanitized.join('\n'),
        auditHtml: outAudit.join('\n'),
        sanitizedHtml: outSanitizedHtml.join('\n'),
        entities,
        restoreMap: tk.restoreMap,
        stats,
        replacements: stats.total,
    };
}

/**
 * Regex-tokenize a free-text run using the active patterns and the shared
 * tokenizer. Mirrors audit/sanitize collectMatches (incl. the confusable twin
 * so homoglyphs in prose are caught) and emits the same hl-pii/hl-token markup.
 */
function analyzeFreeTextRun(text, patterns, tk) {
    const twin = confusableFold(text);
    const raw = [];
    for (const p of patterns) {
        if (!p.enabled) continue;
        const re = buildRegex(p);
        for (const h of execOnTextAndTwin(re, text, twin)) {
            if (!passesValidation(p, h.text)) continue;
            raw.push({ start: h.start, end: h.end, text: h.text, token: p.token, type: p.type, label: p.label, name: p.name, id: p.id, validator: p.validator });
        }
    }
    // Dictionary-based entity scan (names, cities, countries, DOB, employee IDs)
    for (const m of scanEntities(text)) raw.push(m);
    raw.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));

    const matches = [];
    let cursor = 0;
    for (const m of raw) { if (m.start >= cursor) { matches.push(m); cursor = m.end; } }

    const entities = [];
    const stats = { total: 0, pii: 0, pci: 0, riskLevel: 'none', byPattern: {} };
    let sanitized = '', auditHtml = '', sanitizedHtml = '';
    cursor = 0;
    for (const m of matches) {
        const pre = text.slice(cursor, m.start);
        sanitized += pre; auditHtml += escapeHtml(pre); sanitizedHtml += escapeHtml(pre);

        const token = tk.tokenFor(m.token, m.text);
        const cls = m.type === 'pci' ? 'hl-pci' : 'hl-pii';
        const label = escapeHtml(m.label || '');
        sanitized     += token;
        auditHtml     += `<span class="${cls}" title="${label}" aria-label="${label}: ${escapeHtml(m.text)}">${escapeHtml(m.text)}</span>`;
        sanitizedHtml += `<span class="hl-token" aria-label="Token: ${escapeHtml(token)}">${escapeHtml(token)}</span>`;

        entities.push({ type: m.token, token, value: m.text, dataType: m.type, patternName: m.name, patternId: m.id, validator: m.validator });
        stats.total++;
        if (m.type === 'pci') stats.pci++; else stats.pii++;
        stats.byPattern[m.name] = (stats.byPattern[m.name] || 0) + 1;
        cursor = m.end;
    }
    const tail = text.slice(cursor);
    sanitized += tail; auditHtml += escapeHtml(tail); sanitizedHtml += escapeHtml(tail);

    return { sanitized, auditHtml, sanitizedHtml, entities, stats };
}

/**
 * Returns the line index just past a balanced JSON object/array starting at
 * `start`, or -1 if `start` isn't a JSON opener / never balances. Naive brace
 * counter (ignores braces inside strings) — if the slice doesn't parse,
 * analyzeJson returns null and the caller falls back to free text.
 */
function findJsonBlockEnd(lines, start) {
    const first = lines[start].trim();
    if (first[0] !== '{' && first[0] !== '[') return -1;
    let depth = 0, opened = false;
    for (let i = start; i < lines.length; i++) {
        for (const ch of lines[i]) {
            if (ch === '{' || ch === '[') { depth++; opened = true; }
            else if (ch === '}' || ch === ']') { depth--; }
        }
        if (opened && depth <= 0) return i + 1;
    }
    return -1;
}

function findStructuredBlockEnd(lines, start) {
    const headers = splitLine(lines[start]);
    if (headers.length < 2) return -1;

    const columns = headers.map(resolveColumn);
    if (columns.filter(Boolean).length < 2) return -1;
    if (start + 1 >= lines.length) return -1;

    let end = start + 1;
    while (end < lines.length) {
        const line = lines[end];
        if (!line.trim()) break;
        if (splitLine(line).length !== headers.length) break;
        end++;
    }

    return end > start + 1 ? end : -1;
}

function mergeStats(target, source) {
    target.total += source.total;
    target.pii += source.pii;
    target.pci += source.pci;
    for (const [name, count] of Object.entries(source.byPattern || {})) {
        target.byPattern[name] = (target.byPattern[name] || 0) + count;
    }
}

const TOKEN_RE = /\[[A-Z_]+_\d+\]/g;

/**
 * Structured analysis for JSON. Anonymizes values by their KEY name (same
 * COLUMN_TYPES map as CSV), walking nested objects/arrays. Returns null if the
 * text isn't JSON or has no recognizable keys.
 *
 * Output JSON is re-serialized (pretty, 2-space). Tokenized values become
 * strings; numbers therefore restore as their string form. Same return shape
 * as analyzeStructured so the app routes both identically.
 */
export function analyzeJson(text, tokenizer, patterns = null) {
    if (!text || !text.trim()) return null;
    const trimmed = text.trim();
    if (trimmed[0] !== '{' && trimmed[0] !== '[') return null;

    let data;
    try { data = JSON.parse(trimmed); } catch { return null; }

    const tk         = tokenizer || createTokenizer();
    const restoreMap = tk.restoreMap;
    const reverse    = {};          // token → { value, type }  (local: audit HTML)
    const entities   = [];
    const stats      = { total: 0, pii: 0, pci: 0, riskLevel: 'none', byPattern: {} };

    function tokenFor(col, value) {
        const token = tk.tokenFor(col.token, value);
        reverse[token] = { value: String(value), type: typeOf(col) };
        return token;
    }

    // Recursive clone, tokenizing primitive values whose KEY maps to a type.
    function walk(node, keyCol) {
        if (Array.isArray(node)) return node.map(el => walk(el, keyCol));
        if (node && typeof node === 'object') {
            const out = {};
            for (const [k, v] of Object.entries(node)) out[k] = walk(v, resolveColumn(k));
            return out;
        }
        if (keyCol && node !== null && node !== '') {
            const token = tokenFor(keyCol, node);
            const type  = typeOf(keyCol);
            entities.push({ type: keyCol.token, token, value: String(node), dataType: type });
            stats.total++;
            if (type === 'pci') stats.pci++; else stats.pii++;
            stats.byPattern[keyCol.label] = (stats.byPattern[keyCol.label] || 0) + 1;
            return token;
        }
        // Unmapped key: regex-scan the value (true superset) when patterns are
        // supplied, so PII under an unrecognized key isn't passed through.
        // Strings always; numbers only when long enough to plausibly be an
        // account/phone (≥7 digits) — short quantities, ages and years are left
        // untouched to avoid false positives. A matched number becomes a string.
        if (!keyCol && patterns && node !== null && node !== '') {
            const isStr    = typeof node === 'string';
            const isBigNum = typeof node === 'number' && Number.isFinite(node) &&
                             String(Math.trunc(Math.abs(node))).length >= 7;
            if (isStr || isBigNum) {
                const r = analyzeFreeTextRun(String(node), patterns, tk);
                if (r.stats.total > 0) {
                    for (const e of r.entities) reverse[e.token] = { value: e.value, type: e.dataType };
                    entities.push(...r.entities);
                    mergeStats(stats, r.stats);
                    return r.sanitized;   // string with inline [TOKEN]s
                }
            }
        }
        return node;
    }

    const tokenTree = walk(data, null);
    if (stats.total === 0) return null;   // valid JSON but nothing recognizable → let regex handle it

    stats.riskLevel = computeRiskLevel(stats.total);

    const sanitized = JSON.stringify(tokenTree, null, 2);
    const escaped   = escapeHtml(sanitized);

    const sanitizedHtml = escaped.replace(TOKEN_RE, tok =>
        `<span class="hl-token" aria-label="Token: ${tok}">${tok}</span>`);

    // Audit view: swap each token back to its highlighted ORIGINAL value.
    const auditHtml = escaped.replace(TOKEN_RE, tok => {
        const info = reverse[tok];
        if (!info) return tok;
        const cls = info.type === 'pci' ? 'hl-pci' : 'hl-pii';
        const val = escapeHtml(info.value);
        return `<span class="${cls}" title="${val}" aria-label="${val}">${val}</span>`;
    });

    return { sanitized, auditHtml, sanitizedHtml, entities, restoreMap, stats, replacements: stats.total };
}
