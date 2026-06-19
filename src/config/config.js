/**
 * Application configuration constants.
 * All keys and limits are defined here to avoid magic strings/numbers.
 */
export const CONFIG = Object.freeze({
    VERSION: '2.1.0',

    // localStorage keys
    STORAGE: {
        THEME:           'dlp_theme',
        INPUT_TEXT:      'dlp_autosave_input',
        CUSTOM_PATTERNS: 'dlp_custom_patterns',
        MANUAL_RULES:    'dlp_manual_rules',
        CORRECTIONS:     'dlp_corrections',      // opt-in: remember session decisions
        CORRECTIONS_ON:  'dlp_corrections_persist',
        HISTORY:         'dlp_history',
        LANGUAGE:        'dlp_language',
    },

    // History
    MAX_HISTORY_ITEMS: 12,

    // Toast
    TOAST_DURATION_MS: 3000,

    // Auto-save debounce (ms)
    AUTO_SAVE_DEBOUNCE: 600,

    // Risk thresholds (total sensitive items found)
    RISK: {
        LOW_THRESHOLD:    1,
        MEDIUM_THRESHOLD: 4,
    },
});
