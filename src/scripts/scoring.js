/**
 * scoring.js — deterministic multi-signal confidence scoring.
 *
 * Turns binary "matched / didn't" detection into a calibrated confidence in
 * [0,1] by combining independent signals with a NOISY-OR: score = 1 − ∏(1−sᵢ).
 * Signals are commutative and bounded, so order never matters and the result
 * never exceeds 1; each extra corroborating signal only pushes confidence up.
 * Pure module (no DOM, no network) — unit-testable in Node.
 *
 * NOT a filter (recall-first): every detected candidate still gets through. The
 * score drives the reported `confidence` column, not whether a finding is kept
 * or how rows are ordered. The checksum/entropy gates in the match collectors
 * remain HARD gates; soft-gating via SCORE_THRESHOLD is a deliberate future step
 * and is inert here (threshold 0 drops nothing). See detection-scoring-roadmap.
 */

import { shannonEntropy } from './validators.js';

// Per-pattern base confidence that the SHAPE alone implies sensitivity. Only
// patterns whose shape deviates from the default need an entry: loose shapes
// start low and lean on corroborating signals (checksum / entropy / prefix),
// specific shapes start high. Custom user patterns have no entry → DEFAULT_SHAPE
// (an intentional, conservative default, not an oversight).
export const SHAPE_CONFIDENCE = {
    email: 0.90, email_obfuscated: 0.85, jwt: 0.90,
    phone_es: 0.80, phone_intl: 0.75, phone_words_es: 0.80,
    ip: 0.70, ipv6: 0.70, passport: 0.70,
    creditCard: 0.45,    // 16 digits alone is weak — needs Luhn
    iban: 0.50,          // shape alone weak — needs mod-97
    dni: 0.55, nie: 0.55,// need the control letter
    cvv: 0.60, card_expiry: 0.50,
    secret_entropy: 0.50,// needs the entropy signal to lift it
    password_text: 0.85, // keyword-anchored ("password: …")
    api_key: 0.85,       // keyword-anchored ("api_key=…")
    // Context/format-anchored locale patterns (number/keyword-anchored → precise).
    address_fr_context: 0.85, address_nl_context: 0.85, address_en_context: 0.85,
    postal_code_be: 0.85, postal_code_nl: 0.85,
    rrn_be: 0.85, nationality_intl_context: 0.85,
};
export const DEFAULT_SHAPE = 0.70;   // unknown / custom user patterns

// Standalone strength of each corroborating signal.
export const SIGNAL = {
    checksum:    0.92,   // Luhn / IBAN mod-97 / DNI control letter passed
    knownPrefix: 0.95,   // vendor prefix (AKIA, ghp_, sk_live_, AIza…)
    structure:   0.95,   // CSV column header / JSON key match
    context:     0.55,   // a type keyword adjacent to the match (deferred wiring)
};

/** Pattern ids whose vendor prefix is itself the signal (see patterns.js). */
export const KNOWN_PREFIX_PATTERNS = new Set([
    'aws_access_key', 'github_token', 'google_api_key',
    'stripe_key', 'slack_token', 'openai_key',
]);

/** Validators that are checksums (math corroboration), vs. heuristics. */
export const CHECKSUM_VALIDATORS = new Set(['luhn', 'iban', 'dniNie']);

/** Map Shannon bits (≈3.5 floor … 5 ceil) to an entropy signal in [0.5, 0.9]. */
export function entropySignal(bits) {
    const lo = 3.5, hi = 5.0;
    const t = Math.max(0, Math.min(1, (bits - lo) / (hi - lo)));
    return 0.5 + t * 0.4;
}

/** Noisy-OR over independent signal strengths in [0,1]. */
export function combine(signals) {
    let inv = 1;
    for (const s of signals) {
        if (s <= 0) continue;
        if (s >= 1) return 1;
        inv *= (1 - s);
    }
    return 1 - inv;
}

/**
 * Confidence in [0,1] from the signals known about a finding.
 *
 * @param {object}  f
 * @param {'regex'|'structure'|'manual'} f.source
 * @param {string}  [f.patternId]    shape-base lookup key (regex source)
 * @param {boolean} [f.checksum]     a checksum validator passed
 * @param {number}  [f.entropyBits]  Shannon bits, when entropy was the signal
 * @param {boolean} [f.knownPrefix]  vendor-prefix credential
 * @param {boolean} [f.context]      a type keyword sits next to the match
 */
export function scoreFinding(f = {}) {
    if (f.source === 'manual') return 1;

    const signals = [];
    if (f.source === 'structure') {
        signals.push(SIGNAL.structure);
    } else {
        signals.push(
            Object.prototype.hasOwnProperty.call(SHAPE_CONFIDENCE, f.patternId)
                ? SHAPE_CONFIDENCE[f.patternId]
                : DEFAULT_SHAPE
        );
    }
    if (f.checksum)    signals.push(SIGNAL.checksum);
    if (f.knownPrefix) signals.push(SIGNAL.knownPrefix);
    if (typeof f.entropyBits === 'number') signals.push(entropySignal(f.entropyBits));
    if (f.context)     signals.push(SIGNAL.context);

    return combine(signals);
}

/** Confidence as an integer percentage 0–100 (for the report display). */
export function confidencePct(f) {
    return Math.round(scoreFinding(f) * 100);
}

/**
 * Confidence for a regex finding — derives the checksum / entropy / prefix
 * signals from the pattern's id + validator so both regex routes (free-text and
 * structured-cell) score a given pattern identically.
 */
export function regexConfidencePct({ id, validator, text, context } = {}) {
    return confidencePct({
        source:      'regex',
        patternId:   id,
        checksum:    CHECKSUM_VALIDATORS.has(validator),
        knownPrefix: KNOWN_PREFIX_PATTERNS.has(id),
        entropyBits: validator === 'highEntropy' ? shannonEntropy(String(text ?? '')) : undefined,
        context,
    });
}

// Recall-first: inert today (drops nothing). Lowering findings below this score
// is the future soft-gating step that replaces the hard validator gates.
export const SCORE_THRESHOLD = 0;
