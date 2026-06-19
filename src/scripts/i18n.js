/**
 * i18n.js — Internationalization module.
 *
 * Loads JSON translation files and provides:
 *   t(key, vars?)        — translate a UI string
 *   tPattern(id, field)  — get translated pattern name/label
 *   initI18n()           — bootstrap: detect/load language
 *   setLanguage(code)    — switch language at runtime
 *   getCurrentLang()     — returns current language code
 *   getAvailableLanguages() — list of available languages
 *   applyI18nToDOM()     — update all [data-i18n] elements
 */

import { CONFIG } from '../config/config.js';
import { storage } from './utils.js';

// ── Constants ───────────────────────────────────────────────

const SUPPORTED = ['es', 'en', 'nl', 'fr'];
const FALLBACK  = 'es';
const BASE_PATH = 'src/data/i18n';

export const LANGUAGES = [
    { code: 'es', name: 'Español',    flag: '🇪🇸' },
    { code: 'en', name: 'English',    flag: '🇬🇧' },
    { code: 'nl', name: 'Nederlands', flag: '🇳🇱' },
    { code: 'fr', name: 'Français',   flag: '🇫🇷' },
];

// ── State ───────────────────────────────────────────────────

let _translations = {};
let _currentLang  = FALLBACK;

// ── Public API ──────────────────────────────────────────────

/**
 * Bootstrap: detect saved/browser language and load translations.
 */
export async function initI18n() {
    const saved   = storage.get(CONFIG.STORAGE.LANGUAGE);
    const browser = detectBrowserLang();
    const lang    = saved || browser;
    await setLanguage(lang, false);
}

/**
 * Load and apply a language. Persists to localStorage.
 * @param {string} code  — ISO 639-1 language code
 * @param {boolean} notify — whether to dispatch a DOM event
 */
export async function setLanguage(code, notify = true) {
    const target = SUPPORTED.includes(code) ? code : FALLBACK;

    try {
        const res = await fetch(`${BASE_PATH}/${target}.json`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        _translations = await res.json();
        _currentLang  = target;
        storage.set(CONFIG.STORAGE.LANGUAGE, target);
        document.documentElement.setAttribute('lang', target);
        document.documentElement.setAttribute('dir', _translations.dir || 'ltr');
        applyI18nToDOM();
        if (notify) {
            document.dispatchEvent(new CustomEvent('languagechange', { detail: { lang: target } }));
        }
    } catch (err) {
        console.warn(`[i18n] Failed to load "${target}", falling back to "${FALLBACK}".`, err);
        if (target !== FALLBACK) await setLanguage(FALLBACK, notify);
    }
}

/**
 * Translate a UI string key. Supports simple {placeholder} interpolation.
 * @param {string} key
 * @param {Object} [vars] — e.g. { n: 3, name: 'IBAN' }
 * @returns {string}
 */
export function t(key, vars = {}) {
    const raw = _translations?.ui?.[key];
    if (raw === undefined) return key; // missing key — return key as fallback

    let result = String(raw);

    // Replace {var} placeholders
    for (const [k, v] of Object.entries(vars)) {
        result = result.replace(new RegExp(`\\{${k}\\}`, 'g'), String(v));
    }

    // Pluralisation shorthand: {s} → '' when n===1, 's' otherwise
    if ('n' in vars) {
        result = result.replace(/\{s\}/g, vars.n === 1 ? '' : 's');
    }

    return result;
}

/**
 * Get a translated field for a pattern ('name' or 'label').
 * Falls back to the pattern's own built-in name/label field.
 */
export function tPattern(patternId, field, fallback = '') {
    return _translations?.patterns?.[patternId]?.[field] ?? fallback;
}

/**
 * Get a translated group label.
 */
export function tGroup(groupId) {
    return t(`group_${groupId}`) || groupId;
}

export function getCurrentLang() { return _currentLang; }

export function getAvailableLanguages() { return LANGUAGES; }

export function getCurrentTranslations() { return _translations; }

// ── DOM integration ─────────────────────────────────────────

/**
 * Updates all elements with data-i18n attributes.
 *
 * Supported attributes:
 *   data-i18n             → sets textContent
 *   data-i18n-html        → sets innerHTML (trusted keys only)
 *   data-i18n-placeholder → sets placeholder
 *   data-i18n-title       → sets title
 *   data-i18n-aria-label  → sets aria-label
 */
export function applyI18nToDOM() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (key) el.textContent = t(key);
    });

    document.querySelectorAll('[data-i18n-html]').forEach(el => {
        const key = el.getAttribute('data-i18n-html');
        if (key) el.innerHTML = t(key);
    });

    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (key) el.setAttribute('placeholder', t(key));
    });

    document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.getAttribute('data-i18n-title');
        if (key) el.setAttribute('title', t(key));
    });

    document.querySelectorAll('[data-i18n-aria]').forEach(el => {
        const key = el.getAttribute('data-i18n-aria');
        if (key) el.setAttribute('aria-label', t(key));
    });
}

// ── Private ─────────────────────────────────────────────────

function detectBrowserLang() {
    const raw = navigator.language || navigator.languages?.[0] || FALLBACK;
    const code = raw.slice(0, 2).toLowerCase();
    return SUPPORTED.includes(code) ? code : FALLBACK;
}
