/**
 * utils.js — Pure utility functions with no side effects.
 */

/**
 * Escapes HTML special characters to prevent XSS in innerHTML assignments.
 */
export function escapeHtml(str) {
    return String(str)
        .replace(/&/g,  '&amp;')
        .replace(/</g,  '&lt;')
        .replace(/>/g,  '&gt;')
        .replace(/"/g,  '&quot;')
        .replace(/'/g,  '&#039;');
}

/**
 * Confusable (homoglyph) fold — maps Unicode look-alike letters to their plain
 * ASCII twin so patterns written in ASCII still match "Mаdrid" (Cyrillic а),
 * "Pеrez" (Cyrillic е), "Jᴜan" (small-cap U), etc.
 *
 * CRITICAL: the fold is length-preserving (1 codepoint → 1 codepoint). Callers
 * run the SAME regex on the original text and on this twin, then report matches
 * using ORIGINAL offsets — which is only valid because positions are identical.
 * Do NOT use NFKC here: it changes string length and would break offset mapping.
 */
const CONFUSABLES = {
    // Cyrillic → Latin
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
    'к': 'k', 'м': 'm', 'н': 'h', 'т': 't', 'в': 'b', 'і': 'i', 'ј': 'j',
    'ѕ': 's', 'А': 'A', 'Е': 'E', 'О': 'O', 'Р': 'P', 'С': 'C', 'Х': 'X',
    'У': 'Y', 'К': 'K', 'М': 'M', 'Н': 'H', 'Т': 'T', 'В': 'B', 'Ј': 'J',
    // Greek → Latin
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M',
    'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
    // Latin small-caps / modifier letters
    'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ɢ': 'g', 'ʜ': 'h',
    'ɪ': 'i', 'ᴊ': 'j', 'ᴋ': 'k', 'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o',
    'ᴘ': 'p', 'ʀ': 'r', 'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ʏ': 'y', 'ᴢ': 'z',
    // Fullwidth ASCII letters
    'ａ': 'a', 'ｅ': 'e', 'ｉ': 'i', 'ｏ': 'o', 'ｕ': 'u',
};

const CONFUSABLE_RE = new RegExp('[' + Object.keys(CONFUSABLES).join('') + ']', 'gu');

/**
 * Returns a length-preserving ASCII-folded twin of `text`, or the same string
 * reference when no confusable characters are present (cheap fast-path).
 */
export function confusableFold(text) {
    if (!CONFUSABLE_RE.test(text)) { CONFUSABLE_RE.lastIndex = 0; return text; }
    CONFUSABLE_RE.lastIndex = 0;
    return text.replace(CONFUSABLE_RE, ch => CONFUSABLES[ch] || ch);
}

/**
 * Runs `regex` over both the original text and its confusable twin, returning
 * raw match ranges as {start, end, text}. `text` is the ORIGINAL slice in every
 * result (even for twin-only hits) so downstream display/tokenization keeps the
 * user's real characters. Offsets are shared because the twin is length-equal.
 * Duplicate (same-position) hits are harmless — the caller's positional dedup
 * collapses them.
 */
export function execOnTextAndTwin(regex, text, twin) {
    const out = [];
    scan(text);
    if (twin !== text) scan(twin);
    return out;

    function scan(str) {
        regex.lastIndex = 0;
        let m;
        while ((m = regex.exec(str)) !== null) {
            if (m.index === regex.lastIndex) { regex.lastIndex++; continue; }
            const start = m.index, end = m.index + m[0].length;
            out.push({ start, end, text: text.slice(start, end) });
        }
    }
}

/**
 * Debounce: returns a function that delays invoking `fn` until after
 * `wait` ms have elapsed since the last call.
 */
export function debounce(fn, wait) {
    let timer;
    function debounced(...args) {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), wait);
    }
    debounced.cancel = () => clearTimeout(timer);
    return debounced;
}

/**
 * Returns a formatted HH:MM:SS timestamp string for the current time.
 */
export function timestamp() {
    return new Date().toLocaleTimeString('es-ES', { hour12: false });
}

/**
 * Triggers a browser download of `content` as a text file named `filename`.
 */
export function downloadTextFile(filename, content) {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement('a'), {
        href:     url,
        download: filename,
    });
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Reads the first file from a FileList as plain text.
 * Returns a Promise<string>.
 */
export function readFileAsText(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload  = e => resolve(e.target.result);
        reader.onerror = () => reject(new Error('No se pudo leer el archivo.'));
        reader.readAsText(file, 'UTF-8');
    });
}

/**
 * Safe localStorage wrapper — returns null on quota/private-mode errors.
 */
export const storage = {
    get(key) {
        try { return localStorage.getItem(key); } catch { return null; }
    },
    set(key, value) {
        try { localStorage.setItem(key, value); return true; } catch { return false; }
    },
    remove(key) {
        try { localStorage.removeItem(key); } catch { /* noop */ }
    },
    getJSON(key) {
        try { return JSON.parse(localStorage.getItem(key)); } catch { return null; }
    },
    setJSON(key, value) {
        return this.set(key, JSON.stringify(value));
    },
};

/**
 * Clamps a number between min and max.
 */
export function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
}
