/**
 * entityScanner.js — Dictionary-based PII detection.
 *
 * Complements the regex engine (patterns.js) with fast Set lookups against
 * src/data/entities.json. Adding a new name, city or term requires only
 * editing the JSON — no regex knowledge needed.
 *
 * Detection layers:
 *   1. Word scan   — given names, cities, countries (Set, O(1))
 *   2. Bigram      — name + next Cap word → full name
 *   3. Honorific   — "Sr. García" → last name in context
 *   4. DOB prose   — "Nací el 14 de septiembre de 1985" (regex from months)
 *   5. Employee ID — "EMP-45821" (regex from prefix list)
 *   6. Job title   — "soy médico" / "je suis infirmier" (context + title Set)
 *   7. Medical     — "padezco diabetes" / "I have cancer" (context + term Set)
 */

const BASE_PATH = 'src/data/entities.json';

// ── Module state ─────────────────────────────────────────────────────────────

let _ready      = false;
let _nameSet    = new Set();
let _citySet    = new Set();
let _countrySet = new Set();
let _lastNameSet = new Set();
let _honorificSet = new Set();
let _jobSet     = new Set();
let _medSet     = new Set();
let _dobRe      = null;
let _empRe      = null;
let _jobRe      = null;
let _medRe      = null;

// ── Bootstrap ─────────────────────────────────────────────────────────────────

export async function initEntityScanner(basePath = BASE_PATH) {
    if (_ready) return;
    try {
        let e;
        if (typeof window === 'undefined') {
            // Node.js (tests) — fetch doesn't resolve relative paths, use fs
            const { readFile } = await import('node:fs/promises');
            const { resolve } = await import('node:path');
            e = JSON.parse(await readFile(resolve(basePath), 'utf-8'));
        } else {
            const res = await fetch(basePath);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            e = await res.json();
        }

        // ── Given names ───────────────────────────────────────────────────────
        for (const names of Object.values(e.given_names || {})) {
            for (const n of names) _nameSet.add(n.toLowerCase());
        }

        // ── Last names ────────────────────────────────────────────────────────
        for (const names of Object.values(e.last_names || {})) {
            for (const n of names) {
                // Multi-word surnames (De Jong) stored as first word only for
                // the honorific trigger; the bigram extension handles the rest.
                _lastNameSet.add(n.split(' ')[0].toLowerCase());
            }
        }

        // ── Cities ────────────────────────────────────────────────────────────
        for (const cities of Object.values(e.cities || {})) {
            for (const c of cities) {
                if (!c.includes(' ')) _citySet.add(c.toLowerCase());
            }
        }

        // ── Countries (single-word only) ──────────────────────────────────────
        for (const countries of Object.values(e.countries || {})) {
            for (const c of countries) {
                if (!c.includes(' ')) _countrySet.add(c.toLowerCase());
            }
        }

        // ── Honorifics ────────────────────────────────────────────────────────
        for (const h of Object.values(e.honorifics || {}).flat()) {
            _honorificSet.add(h.toLowerCase().replace(/\.$/, ''));
        }

        // ── Job titles ────────────────────────────────────────────────────────
        for (const titles of Object.values(e.job_titles || {})) {
            for (const t of titles) _jobSet.add(t.toLowerCase());
        }

        // ── Medical terms ─────────────────────────────────────────────────────
        for (const terms of Object.values(e.medical_terms || {})) {
            for (const t of terms) {
                if (!t.includes(' ')) _medSet.add(t.toLowerCase());
            }
        }

        // ── DOB regex (built from months lists) ───────────────────────────────
        const allMonths = [...new Set(Object.values(e.months || {}).flat())].join('|');
        if (allMonths) {
            _dobRe = new RegExp(
                `\\b(?:nac[íi](?:do|da)?|née?|born(?:\\s+on)?)` +
                `(?:\\s+(?:el|le|on))?\\s+` +
                `(\\d{1,2})` +
                `(?:\\s+(?:de|van|of))?\\s+` +
                `(${allMonths})` +
                `(?:\\s+(?:de|van|of))?\\s+` +
                `(\\d{4})\\b`,
                'gi'
            );
        }

        // ── Employee ID regex (built from prefix list) ────────────────────────
        const prefixAlt = (e.employee_id_prefixes || []).join('|');
        if (prefixAlt) {
            _empRe = new RegExp(
                `(?:n[uú]mero|num\\.?|n[°º]\\.?|id|badge|empleado|employee|employe|werknemer)` +
                `(?:\\s+(?:de\\s+)?(?:empleado|employee|employe|werknemer|mitarbeiter))?` +
                `\\s*:?\\s*([A-Z0-9][A-Z0-9\\-_]{2,15})` +
                `|\\b(?:${prefixAlt})[\\-_]\\d{3,8}\\b`,
                'gi'
            );
        }

        // ── Job title context regex ───────────────────────────────────────────
        // "soy médico" / "trabajo como enfermera" / "je suis avocat"
        // / "I am a doctor" / "ik ben verpleegkundige"
        if (_jobSet.size) {
            const jobAlt = [..._jobSet].join('|');
            _jobRe = new RegExp(
                `\\b(?:soy|trabajo(?:\\s+como)?|ejer[zc]o\\s+(?:de|como)|` +
                `je\\s+suis|travaille\\s+(?:comme|en\\s+tant\\s+que)|` +
                `ik\\s+ben|werk\\s+als|` +
                `I\\s+(?:am|work\\s+as)\\s+a?n?)\\s+` +
                `(${jobAlt})\\b`,
                'gi'
            );
        }

        // ── Medical context regex ─────────────────────────────────────────────
        // "padezco diabetes" / "I have cancer" / "je souffre de dépression"
        if (_medSet.size) {
            const medAlt = [..._medSet].join('|');
            _medRe = new RegExp(
                `\\b(?:padezco(?:\\s+de)?|tengo|sufro(?:\\s+de)?|` +
                `diagnosticado(?:\\s+(?:con|de))?|` +
                `I\\s+(?:have|suffer\\s+from|was\\s+diagnosed\\s+with)|` +
                `je\\s+souffre\\s+de|atteint(?:e)?\\s+de|diagnostiqu[eé](?:e)?\\s+(?:avec|de)|` +
                `ik\\s+heb|lijd\\s+aan|gediagnosticeerd\\s+met)\\s+` +
                `(${medAlt})\\b`,
                'gi'
            );
        }

        _ready = true;
    } catch (err) {
        console.warn('[entityScanner] failed to load entities.json:', err.message);
    }
}

export function isEntityScannerReady() { return _ready; }

// ── Main scan ─────────────────────────────────────────────────────────────────

/**
 * Scan free text for named entities using dictionary Sets and dynamic regexes.
 * Returns matches in the same shape as the regex engine for seamless merging.
 *
 * @param {string} text
 * @returns {Array<{start,end,text,token,type,label,name,id}>}
 */
export function scanEntities(text) {
    if (!_ready || !text) return [];

    const out = [];

    // ── 1. Word-by-word scan (names, cities, countries) + bigram extension ────
    //
    // Collect all capitalized word positions first (single pass), then classify.
    // For a name hit, extend to the next adjacent Cap word (likely a last name).

    const capWordRe = /[A-ZÁÉÍÓÚÜÑÀÂÇÈÊÎÔÙÛÆŒÄÖÜÀ-ÖØ-Þ][a-záéíóúüñàâçèêîôùûæœäöüà-öø-þ''-]{1,}/g;
    const words = [];
    let wm;
    while ((wm = capWordRe.exec(text)) !== null) {
        words.push({ w: wm[0], s: wm.index, e: wm.index + wm[0].length });
    }

    for (let i = 0; i < words.length; i++) {
        const { w, s, e } = words[i];
        const lc = w.toLowerCase();

        if (_nameSet.has(lc)) {
            // Extend with next adjacent Cap word (likely last name)
            const nxt = words[i + 1];
            if (nxt && nxt.s - e <= 2) {
                out.push(hit(s, nxt.e, text.slice(s, nxt.e), 'NOMBRE', 'pii',
                    'Nombre completo (diccionario)', 'entity_name'));
                i++;
            } else {
                out.push(hit(s, e, w, 'NOMBRE', 'pii',
                    'Nombre (diccionario)', 'entity_name'));
            }
        } else if (_citySet.has(lc)) {
            out.push(hit(s, e, w, 'CIUDAD', 'pii', 'Ciudad (diccionario)', 'entity_city'));
        } else if (_countrySet.has(lc)) {
            out.push(hit(s, e, w, 'PAIS', 'pii', 'País (diccionario)', 'entity_country'));
        }
    }

    // ── 2. Honorific + last name  ("Sr. García", "Dr. Smith") ─────────────────
    //
    // Look for HONORIFIC followed within 3 chars by a capitalized word.
    // The word must be in lastNameSet OR simply be capitalized (unknown surname).
    const honorRe = /\b([A-Za-zÀ-ÖØ-öø-ÿ]{2,5})\.?\s{0,3}([A-ZÁÉÍÓÚÜÑÀÂÇÈÊÎÔÙÛÆŒÄÖÜÀ-ÖØ-Þ][a-záéíóúüñàâçèêîôùûæœäöüà-öø-þ''-]+(?:\s[A-ZÁÉÍÓÚÜÑÀÂÇÈÊÎÔÙÛÆŒÄÖÜÀ-ÖØ-Þ][a-záéíóúüñàâçèêîôùûæœäöüà-öø-þ''-]+)?)/g;
    let hm;
    while ((hm = honorRe.exec(text)) !== null) {
        const prefix = hm[1].toLowerCase();
        if (_honorificSet.has(prefix)) {
            out.push(hit(hm.index, hm.index + hm[0].length, hm[0],
                'APELLIDO', 'pii', 'Apellido con honorífico (diccionario)', 'entity_lastname'));
        }
    }

    // ── 3. DOB in prose ───────────────────────────────────────────────────────
    if (_dobRe) {
        _dobRe.lastIndex = 0;
        let dm;
        while ((dm = _dobRe.exec(text)) !== null) {
            out.push(hit(dm.index, dm.index + dm[0].length, dm[0],
                'FECHA_NACIMIENTO', 'pii', 'Fecha de nacimiento (prosa)', 'entity_dob'));
        }
    }

    // ── 4. Employee ID ────────────────────────────────────────────────────────
    if (_empRe) {
        _empRe.lastIndex = 0;
        let em;
        while ((em = _empRe.exec(text)) !== null) {
            out.push(hit(em.index, em.index + em[0].length, em[0],
                'NUM_EMPLEADO', 'pii', 'Nº de empleado (diccionario)', 'entity_emp_id'));
        }
    }

    // ── 5. Job title in context ───────────────────────────────────────────────
    if (_jobRe) {
        _jobRe.lastIndex = 0;
        let jm;
        while ((jm = _jobRe.exec(text)) !== null) {
            out.push(hit(jm.index, jm.index + jm[0].length, jm[0],
                'PROFESION', 'pii', 'Profesión (contexto)', 'entity_job'));
        }
    }

    // ── 6. Medical term in context ────────────────────────────────────────────
    if (_medRe) {
        _medRe.lastIndex = 0;
        let mm;
        while ((mm = _medRe.exec(text)) !== null) {
            out.push(hit(mm.index, mm.index + mm[0].length, mm[0],
                'DATO_SALUD', 'pii', 'Dato de salud (contexto)', 'entity_medical'));
        }
    }

    return out;
}

// ── Helper ────────────────────────────────────────────────────────────────────

function hit(start, end, text, token, type, label, id) {
    return { start, end, text, token, type, label, name: id, id };
}

// In Node.js (test runner) app.js never runs, so auto-init here via top-level await.
// In the browser this branch is skipped; app.js calls initEntityScanner() explicitly.
if (typeof window === 'undefined') {
    await initEntityScanner();
}
