/**
 * validators.js — Deterministic checksum validators.
 *
 * These confirm that a shape-matched candidate is actually well-formed (a real
 * card / IBAN / national id), turning a loose regex match into a high-confidence
 * signal. Pure functions, string in → boolean out, unit-testable in Node.
 *
 * Used as a detection signal: a pattern may declare `validator: '<name>'`; when
 * present, a candidate that FAILS validation is dropped. Patterns get a
 * validator only when the shape alone is too loose to be meaningful (e.g. any
 * 16-digit run "looks like" a card), so failing the checksum is strong evidence
 * it is NOT that data type.
 */

/** Luhn (mod-10) — credit/debit card numbers. */
export function luhn(value) {
    const digits = String(value).replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0, double = false;
    for (let i = digits.length - 1; i >= 0; i--) {
        let n = digits.charCodeAt(i) - 48;
        if (double) { n *= 2; if (n > 9) n -= 9; }
        sum += n;
        double = !double;
    }
    return sum % 10 === 0;
}

/** IBAN mod-97 (ISO 13616 / 7064). */
export function ibanValid(value) {
    const s = String(value).replace(/[\s\-]/g, '').toUpperCase();
    if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(s)) return false;
    // Move the 4 leading chars to the end, expand letters to numbers (A=10..Z=35).
    const rearranged = s.slice(4) + s.slice(0, 4);
    let expanded = '';
    for (let i = 0; i < rearranged.length; i++) {
        const c = rearranged.charCodeAt(i);
        expanded += (c >= 65 && c <= 90) ? String(c - 55) : rearranged[i];
    }
    // mod-97 over the (very large) number, processed in chunks.
    let remainder = 0;
    for (let i = 0; i < expanded.length; i += 7) {
        remainder = Number(String(remainder) + expanded.slice(i, i + 7)) % 97;
    }
    return remainder === 1;
}

/** Shannon entropy of a string, in bits per character. */
export function shannonEntropy(value) {
    const s = String(value);
    if (!s) return 0;
    const freq = new Map();
    for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
    let h = 0;
    for (const n of freq.values()) { const p = n / s.length; h -= p * Math.log2(p); }
    return h;
}

// ── High-entropy secret heuristic ────────────────────────────
// Flags BARE, unanchored secrets (API keys, access tokens, base64/hex blobs)
// that no keyword-anchored pattern catches. Recall is the easy part; the work
// is PRECISION — plenty of harmless strings also look random and would garble a
// prompt if tokenized: hashes, UUIDs, file paths, URL slugs, code identifiers.
// We layer shape exclusions + charset richness so those don't trip the entropy
// gate. Keyword-anchored secrets (`password: …`, `Authorization: Bearer …`) are
// handled by the password_text / API_KEY patterns, so context is not needed here.

const UUID_RE       = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// MD5 (32) / SHA-1 (40) / SHA-256 (64) hex digests — single-case by convention.
const HEX_DIGEST_RE = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9A-F]{32}|[0-9A-F]{40}|[0-9A-F]{64})$/;

/** Distinct character classes present (0–4): lower, upper, digit, symbol. */
function charsetClasses(s) {
    let c = 0;
    if (/[a-z]/.test(s))    c++;
    if (/[A-Z]/.test(s))    c++;
    if (/\d/.test(s))       c++;
    if (/[+/=_\-]/.test(s)) c++;
    return c;
}

/** A standalone span that itself looks secret-like (mixed, long, random). */
function isSecretPart(p) {
    return p.length >= 16 && charsetClasses(p) >= 3 && shannonEntropy(p) >= 3.5;
}

/**
 * True for paths / slugs / identifiers: a string delimited by `/ _ -` into
 * mostly lowercase-word or short-number segments (src/scripts/foo,
 * blog-post-slug-2024, user_profile_default). Guarded so a prefixed secret
 * like `sk_live_<random>` or `ghp_<random>` is NOT mistaken for words — if any
 * single segment is itself secret-like, the whole string stays in play.
 */
function looksLikeDelimitedWords(s) {
    const parts = s.split(/[\/_\-]+/).filter(Boolean);
    if (parts.length < 2) return false;
    if (parts.some(isSecretPart)) return false;
    const wordish = parts.filter(p => /^[a-z]{2,}$/.test(p) || /^\d{1,4}$/.test(p)).length;
    return wordish / parts.length >= 0.6;
}

/**
 * High-entropy secret heuristic. A candidate is a secret only if it survives
 * every non-secret shape filter AND carries both a rich alphabet and high
 * entropy. Tuned against a corpus of real keys (keep) vs. hashes / UUIDs /
 * paths / slugs / identifiers (drop) — see validators.test.js.
 */
export function highEntropy(value) {
    const s = String(value);
    if (s.length < 20) return false;

    // Mix of letters with digits/symbols — rules out prose and word-blobs.
    if (!/[A-Za-z]/.test(s)) return false;
    if (!/\d/.test(s) && !/[+/=_\-]/.test(s)) return false;

    // Shape exclusions: formats that clear the entropy bar but are not secrets.
    if (UUID_RE.test(s)) return false;
    if (HEX_DIGEST_RE.test(s)) return false;                          // MD5/SHA-1/SHA-256
    if (/^[0-9a-f]{20,}$/.test(s) || /^[0-9A-F]{20,}$/.test(s)) return false; // single-case hex → hash/id
    if (looksLikeDelimitedWords(s)) return false;                    // paths, slugs, snake_case

    // Real secrets pack high entropy AND a rich alphabet — ≥3 of {lower, upper,
    // digit, symbol}. A 2-class string (uppercase+digit base32 like a ULID or
    // serial, single-case hex) is indistinguishable from an identifier by
    // entropy alone, so it is left to explicit prefix patterns (e.g. AWS AKIA…)
    // rather than guessed at here — guessing only adds false positives.
    if (charsetClasses(s) < 3) return false;
    return shannonEntropy(s) >= 3.5;
}

const DNI_LETTERS = 'TRWAGMYFPDXBNJZSQVHLCKE';

/** Spanish DNI / NIE control letter. */
export function dniNieValid(value) {
    const m = String(value).toUpperCase().match(/([XYZ]?)(\d{7,8})\s*-?\s*([A-Z])/);
    if (!m) return false;
    const [, prefix, rawDigits, letter] = m;
    let digits = rawDigits;
    if (prefix) digits = { X: '0', Y: '1', Z: '2' }[prefix] + digits;   // NIE
    if (digits.length !== 8) return false;
    return DNI_LETTERS[Number(digits) % 23] === letter;
}

// Registry: pattern.validator string → function.
const VALIDATORS = {
    luhn,
    iban:        ibanValid,
    dniNie:      dniNieValid,
    highEntropy,
};

/**
 * Returns true if the candidate passes its pattern's validator (or has none).
 * Never throws — an unknown validator name is treated as "no validator".
 */
export function passesValidation(pattern, text) {
    const name = pattern && pattern.validator;
    if (!name) return true;
    const fn = VALIDATORS[name];
    if (!fn) return true;
    try { return fn(text); } catch { return true; }
}
