/**
 * patterns.js — Detection pattern definitions.
 *
 * Each pattern has:
 *  id        — unique key (also used as i18n lookup key)
 *  type      — 'pii' | 'pci'
 *  group     — category: 'global' | 'financial' | 'es' | 'us' | 'nl' | 'fr' | 'uk' | 'mx' | 'tech'
 *  regexStr  — regex source string (no flags, no slashes) — safe for JSON serialization
 *  flags     — regex flags (default 'g')
 *  token     — replacement token base (e.g. 'EMAIL' → [EMAIL_1])
 *  enabled   — active by default
 *  builtin   — built-in patterns cannot be deleted by the user
 *
 * Names and labels are stored in src/data/i18n/*.json and resolved at runtime.
 * Fallback name/label fields are kept for offline/fallback rendering.
 */

export const DEFAULT_PATTERNS = [

    // ── GLOBAL — Universal patterns ──────────────────────────────────────────

    {
        id: 'email', type: 'pii', group: 'global', enabled: true, builtin: true,
        regexStr: '[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}',
        flags: 'gi', token: 'EMAIL',
        name: 'Email', label: 'Email detectado',
    },
    {
        id: 'email_obfuscated', type: 'pii', group: 'global', enabled: true, builtin: true,
        regexStr: "[A-Za-z0-9._%+\\-]+[ \\t]*(?:\\[punto\\]|\\(dot\\)|\\sdot\\s)[ \\t]*[A-Za-z0-9._%+\\-]+[ \\t]*(?:\\[arroba\\]|\\(at\\)|\\sat\\s)[ \\t]*[A-Za-z0-9._%+\\-]+[ \\t]*(?:\\[punto\\]|\\(dot\\)|\\sdot\\s|\\.)[ \\t]*[A-Za-z]{2,}|[A-Za-z0-9._%+\\-]+[ \\t]*(?:\\[arroba\\]|\\(at\\)|\\sat\\s)[ \\t]*[A-Za-z0-9._%+\\-]+[ \\t]*(?:\\[punto\\]|\\(dot\\)|\\sdot\\s|\\.)[ \\t]*[A-Za-z]{2,}",
        flags: 'gi', token: 'EMAIL',
        name: 'Email ofuscado', label: 'Email ofuscado con arroba/punto',
    },
    {
        id: 'phone_es', type: 'pii', group: 'global', enabled: true, builtin: true,
        regexStr: "(?<!\\d)(?:\\+34|0034)?[ \\t\\-]?[6789][ \\t\\-]?(?:\\d[ \\t\\-]?){8}(?!\\d)",
        flags: 'g', token: 'TELEFONO',
        name: 'Teléfono ES', label: 'Número de teléfono español',
    },
    {
        id: 'phone_intl', type: 'pii', group: 'global', enabled: true, builtin: true,
        // Permissive grouping: trailing groups can be 2 digits (e.g. Belgian
        // "+32 471 12 34 56"), which the old fixed `[0-9]{3,4}` tail missed.
        // `[ \t.\-]` (not `\s`) so it never chains across a newline.
        regexStr: '\\(?\\+\\d{1,3}\\)?(?:[ \\t.\\-]?\\d{1,4}){2,6}',
        flags: 'g', token: 'TELEFONO_INTL',
        name: 'Teléfono Internacional', label: 'Número de teléfono internacional',
    },
    {
        id: 'phone_words_es', type: 'pii', group: 'global', enabled: true, builtin: true,
        regexStr: "(?:tel[e\\u00e9]fono|tel|m[o\\u00f3]vil|alternativo)[ \\t]*:[ \\t]*(?:cero|uno|dos|tres|cuatro|cinco|seis|siete|ocho|nueve)(?:[ \\t]+(?:cero|uno|dos|tres|cuatro|cinco|seis|siete|ocho|nueve)){5,12}",
        flags: 'gi', token: 'TELEFONO',
        name: 'Telefono escrito', label: 'Telefono escrito con palabras',
    },
    {
        id: 'phone_be_national', type: 'pii', group: 'global', enabled: true, builtin: true,
        regexStr: '\\b(?:phone|tel(?:ephone|[e\\u00e9]fono)?|t[\\u00e9e]l(?:[\\u00e9e]phone)?|gsm|mobile|mobiel)[ \\t]*(?:number|nummer|num[\\u00e9e]ro)?[ \\t]*(?:is|est|:)?[ \\t]*(?:0[1-9](?:[ \\t.\\-]?\\d){7,9})\\b',
        flags: 'gi', token: 'TELEFONO',
        name: 'Telefono BE por contexto', label: 'Numero de telefono belga con etiqueta',
    },
    {
        id: 'ip', type: 'pii', group: 'global', enabled: true, builtin: true,
        regexStr: '\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b',
        flags: 'g', token: 'DIRECCION_IPV4',
        name: 'Dirección IPv4', label: 'Dirección IP versión 4',
    },
    {
        id: 'ipv6', type: 'pii', group: 'global', enabled: false, builtin: true,
        regexStr: '(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}',
        flags: 'gi', token: 'DIRECCION_IPV6',
        name: 'Dirección IPv6', label: 'Dirección IP versión 6',
    },
    {
        id: 'mac', type: 'pii', group: 'global', enabled: true, builtin: true,
        regexStr: '(?:[0-9A-Fa-f]{2}[:\\-]){5}[0-9A-Fa-f]{2}',
        flags: 'gi', token: 'MAC_ADDRESS',
        name: 'Dirección MAC', label: 'Dirección MAC de red',
    },
    {
        id: 'gps_coords', type: 'pii', group: 'global', enabled: false, builtin: true,
        regexStr: '-?\\d{1,2}\\.\\d{4,}[,\\s]+-?\\d{1,3}\\.\\d{4,}',
        flags: 'g', token: 'COORDENADAS_GPS',
        name: 'Coordenadas GPS', label: 'Coordenadas de geolocalización',
    },
    {
        id: 'dob', type: 'pii', group: 'global', enabled: false, builtin: true,
        regexStr: '(?:nac(?:imiento)?|fecha[\\s]nac|d[ée]e?[\\s]naissance|birth|geboort)[\\s:de]*(?:\\d{1,2}[/\\-.]\\d{1,2}[/\\-.][12]\\d{3}|[12]\\d{3}[/\\-.])\\d{1,2}[/\\-.]\\d{1,2}',
        flags: 'gi', token: 'FECHA_NACIMIENTO',
        name: 'Fecha de Nacimiento', label: 'Fecha de nacimiento',
    },
    {
        id: 'dob_labeled_es', type: 'pii', group: 'global', enabled: true, builtin: true,
        regexStr: "(?:fecha\\s*nac\\.?|f\\.\\s*nacimiento|nacimiento|nac\\.?)\\s*:?\\s*\\d{1,2}[/\\-.]\\d{1,2}[/\\-.](?:\\d{4}|\\d{2})",
        flags: 'gi', token: 'FECHA_NACIMIENTO',
        name: 'Fecha nacimiento por etiqueta', label: 'Fecha de nacimiento precedida por etiqueta',
    },
    {
        id: 'age_labeled_es', type: 'pii', group: 'global', enabled: true, builtin: true,
        regexStr: "(?:edad(?:\\s*actual)?|age)\\s*:?\\s*\\d{1,3}\\s*(?:a(?:\\u00f1|n)os?)?",
        flags: 'gi', token: 'EDAD',
        name: 'Edad por etiqueta', label: 'Edad precedida por etiqueta',
    },
    {
        id: 'sex_labeled_es', type: 'pii', group: 'global', enabled: true, builtin: true,
        regexStr: "(?:sexo|g[e\\u00e9]nero|sex|gender)\\s*:?\\s*(?:M|F|H|Mujer|Hombre|Masculino|Femenino|No\\s*binario)\\b",
        flags: 'gi', token: 'SEXO',
        name: 'Sexo por etiqueta', label: 'Sexo o genero precedido por etiqueta',
    },
    {
        id: 'passport', type: 'pii', group: 'global', enabled: true, builtin: true,
        regexStr: '(?:passport|pasaporte|passeport|paspoort|reisepass)[\\s:nr.]*[A-Z0-9]{6,9}',
        flags: 'gi', token: 'PASAPORTE',
        name: 'Pasaporte', label: 'Número de pasaporte',
    },

    // ── TECH — Credentials & tokens ──────────────────────────────────────────

    {
        id: 'jwt', type: 'pii', group: 'tech', enabled: true, builtin: true,
        regexStr: 'eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+',
        flags: 'g', token: 'TOKEN_JWT',
        name: 'Token JWT', label: 'JSON Web Token detectado',
    },

    // Known-prefix credentials — the vendor prefix IS the signal, so these are
    // high-precision (no entropy/checksum needed). Listed BEFORE secret_entropy
    // so the specific provider wins de-dup over the generic entropy catch, and
    // so 2-class tokens like AWS AKIA… (which entropy cannot flag without also
    // catching ULIDs) are still caught.
    {
        id: 'aws_access_key', type: 'pii', group: 'tech', enabled: true, builtin: true,
        regexStr: '\\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\\b',
        flags: 'g', token: 'SECRETO',
        name: 'AWS Access Key ID', label: 'Clave de acceso de AWS',
    },
    {
        id: 'github_token', type: 'pii', group: 'tech', enabled: true, builtin: true,
        regexStr: '\\bgh[pousr]_[A-Za-z0-9]{36,}\\b',
        flags: 'g', token: 'SECRETO',
        name: 'GitHub Token', label: 'Token de acceso de GitHub',
    },
    {
        id: 'google_api_key', type: 'pii', group: 'tech', enabled: true, builtin: true,
        regexStr: '\\bAIza[0-9A-Za-z_\\-]{35}\\b',
        flags: 'g', token: 'SECRETO',
        name: 'Google API Key', label: 'Clave de API de Google',
    },
    {
        id: 'stripe_key', type: 'pii', group: 'tech', enabled: true, builtin: true,
        regexStr: '\\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\\b',
        flags: 'g', token: 'SECRETO',
        name: 'Stripe API Key', label: 'Clave de API de Stripe',
    },
    {
        id: 'slack_token', type: 'pii', group: 'tech', enabled: true, builtin: true,
        regexStr: '\\bxox[baprs]-[A-Za-z0-9\\-]{10,}\\b',
        flags: 'g', token: 'SECRETO',
        name: 'Slack Token', label: 'Token de acceso de Slack',
    },
    {
        id: 'openai_key', type: 'pii', group: 'tech', enabled: true, builtin: true,
        regexStr: '\\bsk-(?:proj-)?[A-Za-z0-9_\\-]{20,}\\b',
        flags: 'g', token: 'SECRETO',
        name: 'OpenAI API Key', label: 'Clave de API de OpenAI',
    },
    {
        id: 'sendgrid_key', type: 'pii', group: 'tech', enabled: true, builtin: true,
        regexStr: '\\bSG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43}\\b',
        flags: 'g', token: 'SECRETO',
        name: 'SendGrid API Key', label: 'Clave de API de SendGrid',
    },
    {
        id: 'gitlab_token', type: 'pii', group: 'tech', enabled: true, builtin: true,
        regexStr: '\\bglpat-[A-Za-z0-9_\\-]{20}\\b',
        flags: 'g', token: 'SECRETO',
        name: 'GitLab Token', label: 'Token de acceso personal de GitLab',
    },
    {
        id: 'npm_token', type: 'pii', group: 'tech', enabled: true, builtin: true,
        regexStr: '\\bnpm_[A-Za-z0-9]{36}\\b',
        flags: 'g', token: 'SECRETO',
        name: 'npm Token', label: 'Token de acceso de npm',
    },
    {
        id: 'twilio_sid', type: 'pii', group: 'tech', enabled: true, builtin: true,
        regexStr: '\\bAC[0-9a-fA-F]{32}\\b',
        flags: 'g', token: 'SECRETO',
        name: 'Twilio Account SID', label: 'Identificador de cuenta de Twilio',
    },
    {
        id: 'mailgun_key', type: 'pii', group: 'tech', enabled: true, builtin: true,
        regexStr: '\\bkey-[0-9a-f]{32}\\b',
        flags: 'g', token: 'SECRETO',
        name: 'Mailgun API Key', label: 'Clave de API de Mailgun',
    },
    {
        id: 'private_key_pem', type: 'pii', group: 'tech', enabled: true, builtin: true,
        regexStr: '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\\s\\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----',
        flags: 'g', token: 'SECRETO',
        name: 'Clave privada (PEM)', label: 'Bloque de clave privada PEM (RSA/EC/GCP service-account)',
    },
    {
        id: 'api_key', type: 'pii', group: 'tech', enabled: false, builtin: true,
        regexStr: '(?:api[_\\-]?key|token|secret|bearer)[\\s:=]+[A-Za-z0-9_\\-]{20,}',
        flags: 'gi', token: 'API_KEY',
        name: 'API Key / Token', label: 'Clave de API o token de acceso',
    },
    {
        id: 'secret_entropy', type: 'pii', group: 'tech', enabled: true, builtin: true,
        // `=` is intentionally NOT in the char class: in base64 it only appears
        // as trailing padding, so dropping it barely affects recall but stops a
        // run from swallowing a leading `LABEL=` (e.g. STRIPE_KEY=sk_live_…),
        // which would mis-attribute the find and mask the variable name too.
        regexStr: '(?<![A-Za-z0-9+/_\\-])[A-Za-z0-9+/_\\-]{20,}(?![A-Za-z0-9+/_\\-])',
        flags: 'g', token: 'SECRETO', validator: 'highEntropy',
        name: 'Secreto (entropía)', label: 'Cadena de alta entropía (posible clave/secreto/token)',
    },
    {
        id: 'password_text', type: 'pii', group: 'tech', enabled: true, builtin: true,
        regexStr: '(?:password|contraseña|passwd|clave[\\s]?secreta|wachtwoord|mot[\\s]de[\\s]passe|kennwort)[\\s:=]+\\S{4,}',
        flags: 'gi', token: 'CREDENCIAL',
        name: 'Contraseña en texto', label: 'Contraseña en texto plano detectada',
    },

    // ── FINANCIAL — PCI data ──────────────────────────────────────────────────

    {
        id: 'creditCard', type: 'pci', group: 'financial', enabled: true, builtin: true,
        regexStr: '(?:\\d{4}[\\s\\-]?){3}\\d{4}',
        flags: 'g', token: 'TARJETA_CREDITO', validator: 'luhn',
        name: 'Tarjeta de Crédito', label: 'Dato financiero (PCI) — número de tarjeta',
    },
    {
        id: 'cvv', type: 'pci', group: 'financial', enabled: false, builtin: true,
        regexStr: '\\b(?:cvv|cvc|cvv2|csc)[\\s:=]+\\d{3,4}\\b',
        flags: 'gi', token: 'CVV',
        name: 'CVV / CVC', label: 'Código de seguridad de tarjeta',
    },
    {
        id: 'card_expiry', type: 'pci', group: 'financial', enabled: false, builtin: true,
        regexStr: '\\b(?:0[1-9]|1[0-2])[/\\-](?:2[0-9]|[3-9]\\d)\\b',
        flags: 'g', token: 'CADUCIDAD_TARJETA',
        name: 'Caducidad Tarjeta', label: 'Fecha de caducidad de tarjeta de crédito',
    },
    {
        id: 'iban', type: 'pci', group: 'financial', enabled: true, builtin: true,
        regexStr: '\\b[A-Z]{2}\\d{2}[ \\t\\-]?(?:[A-Z0-9]{4}[ \\t\\-]?){2,7}[A-Z0-9]{1,4}\\b',
        flags: 'g', token: 'IBAN', validator: 'iban',
        name: 'IBAN', label: 'IBAN / Cuenta bancaria internacional',
    },
    {
        id: 'bic', type: 'pci', group: 'financial', enabled: true, builtin: true,
        regexStr: '\\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\\b',
        flags: 'g', token: 'BIC_SWIFT',
        name: 'BIC / SWIFT', label: 'Código BIC/SWIFT bancario',
    },
    {
        id: 'bitcoin', type: 'pci', group: 'financial', enabled: false, builtin: true,
        regexStr: '\\b(?:bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,62}\\b',
        flags: 'g', token: 'CRIPTO_WALLET',
        name: 'Cripto Wallet', label: 'Dirección de criptomoneda (Bitcoin/Bech32)',
    },
    {
        id: 'ethereum', type: 'pci', group: 'financial', enabled: false, builtin: true,
        regexStr: '0x[0-9a-fA-F]{40}',
        flags: 'g', token: 'ETH_WALLET',
        name: 'Wallet Ethereum', label: 'Dirección de wallet Ethereum',
    },

    // ── ESPAÑA — Spanish identifiers ─────────────────────────────────────────

    {
        id: 'dni', type: 'pii', group: 'es', enabled: true, builtin: true,
        regexStr: '\\b\\d{8}[A-Za-z]\\b',
        flags: 'g', token: 'DNI_ES', validator: 'dniNie',
        name: 'DNI (España)', label: 'Documento Nacional de Identidad español',
    },
    {
        id: 'dni_labeled_es', type: 'pii', group: 'es', enabled: true, builtin: true,
        regexStr: "(?:dni|documento|id\\s*cliente|referencia|ref)\\s*:?\\s*(?:[A-Za-z]{2,4}[- ]?)?(?:\\d{2}\\.\\d{3}\\.\\d{3}|\\d{8})(?:[A-Za-z])?",
        flags: 'gi', token: 'DNI_ES',
        name: 'DNI por etiqueta', label: 'Documento espanol flexible por etiqueta',
    },
    {
        id: 'case_reference_es', type: 'pii', group: 'es', enabled: true, builtin: true,
        regexStr: "(?:expediente|ticket|referencia)\\s*:?\\s*[A-Z]{2,5}[- ]?\\d{4,6}[- ]?\\d{6,10}",
        flags: 'gi', token: 'EXPEDIENTE',
        name: 'Expediente', label: 'Numero de expediente o referencia compuesto',
    },
    {
        id: 'nie', type: 'pii', group: 'es', enabled: true, builtin: true,
        regexStr: '\\b[XYZxyz]\\d{7}[A-Za-z]\\b',
        flags: 'g', token: 'NIE_ES', validator: 'dniNie',
        name: 'NIE (España)', label: 'Número de Identidad de Extranjero (España)',
    },
    {
        id: 'nif_empresa', type: 'pii', group: 'es', enabled: false, builtin: true,
        regexStr: '\\b[ABCDEFGHJKLMNPQRSUVW]\\d{7}[0-9A-Z]\\b',
        flags: 'g', token: 'NIF_EMPRESA_ES',
        name: 'NIF Empresa (España)', label: 'NIF de persona jurídica española',
    },
    {
        id: 'ss_es', type: 'pii', group: 'es', enabled: false, builtin: true,
        regexStr: '\\b\\d{2}[\\s/]\\d{8}[\\s/]\\d{2}\\b',
        flags: 'g', token: 'SS_ES',
        name: 'Seg. Social (España)', label: 'Número de Seguridad Social española',
    },
    {
        id: 'licencePlate_es', type: 'pii', group: 'es', enabled: false, builtin: true,
        regexStr: '\\b\\d{4}[BCDFGHJKLMNPRSTUVWXYZ]{3}\\b',
        flags: 'g', token: 'MATRICULA_ES',
        name: 'Matrícula (España)', label: 'Matrícula de vehículo española',
    },
    // Nombres ES — replaced by entityScanner.js (entities.json dict + bigram extension)

    // ── USA — United States ───────────────────────────────────────────────────

    {
        id: 'full_name_es', type: 'pii', group: 'es', enabled: true, builtin: true,
        regexStr: "(?:[Cc]liente|[Nn]ombre[ \\t]*[Cc]ompleto)[ \\t]*:?[ \\t]*[A-Z\\u00c1\\u00c9\\u00cd\\u00d3\\u00da\\u00dc\\u00d1][a-z\\u00e1\\u00e9\\u00ed\\u00f3\\u00fa\\u00fc\\u00f1]+(?:[ \\t]+[A-Z\\u00c1\\u00c9\\u00cd\\u00d3\\u00da\\u00dc\\u00d1][a-z\\u00e1\\u00e9\\u00ed\\u00f3\\u00fa\\u00fc\\u00f1]+){1,4}",
        flags: 'g', token: 'PERSONA_ES',
        name: 'Nombre completo por etiqueta', label: 'Nombre completo precedido por etiqueta',
    },
    {
        id: 'ssn', type: 'pii', group: 'us', enabled: true, builtin: true,
        regexStr: '(?!000|666|9\\d\\d)\\d{3}[\\s\\-](?!00)\\d{2}[\\s\\-](?!0000)\\d{4}',
        flags: 'g', token: 'SSN_USA',
        name: 'SSN (USA)', label: 'Social Security Number (Estados Unidos)',
    },
    {
        id: 'ein', type: 'pii', group: 'us', enabled: false, builtin: true,
        regexStr: '\\b(?:EIN|FEIN|Tax[\\s]?ID)[:\\s]*\\d{2}[\\-]\\d{7}\\b',
        flags: 'gi', token: 'EIN_USA',
        name: 'EIN (USA)', label: 'Employer Identification Number (USA)',
    },
    {
        id: 'zip_us', type: 'pii', group: 'us', enabled: false, builtin: true,
        regexStr: '\\b\\d{5}(?:[\\-]\\d{4})?\\b',
        flags: 'g', token: 'ZIP_USA',
        name: 'ZIP Code (USA)', label: 'Código postal de Estados Unidos',
    },

    // ── NETHERLANDS — Países Bajos ────────────────────────────────────────────

    {
        id: 'bsn', type: 'pii', group: 'nl', enabled: true, builtin: true,
        regexStr: '(?:BSN|bsn|burgerservicenummer)[:\\s]+\\d{8,9}|\\b[0-9]{9}\\b(?=[^0-9]|$)',
        flags: 'g', token: 'BSN_NL',
        name: 'BSN (Nederland)', label: 'Burgerservicenummer (Países Bajos)',
    },
    // names_nl — replaced by entityScanner.js
    {
        id: 'address_nl_context', type: 'pii', group: 'nl', enabled: true, builtin: true,
        regexStr: '\\b[A-ZÀ-Ý][A-Za-zà-ÿ]+(?:straat|laan|weg|plein|kade|dijk|gracht)[ \\t]+\\d{1,4}\\b',
        flags: 'g', token: 'DIRECCION',
        name: 'Dirección NL', label: 'Dirección postal neerlandesa (calle + número)',
    },
    {
        id: 'postal_code_nl', type: 'pii', group: 'nl', enabled: true, builtin: true,
        regexStr: '\\b[1-9]\\d{3}[ \\t]?[A-Z]{2}[ \\t]+(?:Amsterdam|Rotterdam|Den[ \\t]Haag|Utrecht|Eindhoven|Groningen|Tilburg|Almere|Breda|Nijmegen|Haarlem)\\b',
        flags: 'g', token: 'CODIGO_POSTAL',
        name: 'Código postal NL', label: 'Código postal neerlandés (1234 AB) con ciudad',
    },

    // ── FRANCE — Francia ──────────────────────────────────────────────────────

    {
        id: 'insee', type: 'pii', group: 'fr', enabled: true, builtin: true,
        regexStr: '\\b[12]\\s?\\d{2}\\s?(?:0[1-9]|1[0-2]|20)\\s?(?:0[1-9]|[1-9]\\d|2[AB])\\s?\\d{3}\\s?\\d{3}\\s?\\d{2}\\b',
        flags: 'g', token: 'INSEE_FR',
        name: 'NIR / INSEE (France)', label: 'Numéro de Sécurité Sociale / INSEE (France)',
    },
    {
        id: 'siret', type: 'pii', group: 'fr', enabled: false, builtin: true,
        regexStr: '\\b\\d{3}[\\s\\-]?\\d{3}[\\s\\-]?\\d{3}[\\s\\-]?\\d{5}\\b',
        flags: 'g', token: 'SIRET_FR',
        name: 'SIRET (France)', label: 'Numéro SIRET d\'entreprise (France)',
    },
    // names_fr — replaced by entityScanner.js
    {
        id: 'address_fr_context', type: 'pii', group: 'fr', enabled: true, builtin: true,
        // French/Belgian street, both orders: "125 Avenue Louise" and "Rue des
        // Tilleuls 45". Street keyword is case-sensitive + number-anchored on one
        // side, so prose ("Place your order") cannot trip it.
        regexStr: '(?:\\d{1,4}[ \\t]+\\b(?:Rue|Avenue|Av\\.?|Boulevard|Bd|All[ée]e|Impasse|Place|Chemin|Quai)[ \\t]+[A-ZÀ-Ý][A-Za-zÀ-ÿ.-]+(?:[ \\t]+[A-Za-zÀ-ÿ.-]+){0,2}|\\b(?:Rue|Avenue|Av\\.?|Boulevard|Bd|All[ée]e|Impasse|Place|Chemin|Quai)[ \\t]+(?:des?[ \\t]+|du[ \\t]+|de[ \\t]+la[ \\t]+)?[A-ZÀ-Ý][A-Za-zÀ-ÿ.-]+(?:[ \\t]+[A-Za-zÀ-ÿ.-]+){0,2}[ \\t]+\\d{1,4})',
        flags: 'g', token: 'DIRECCION',
        name: 'Dirección FR/BE', label: 'Dirección postal francesa o belga (calle + número)',
    },
    {
        id: 'postal_code_be', type: 'pii', group: 'fr', enabled: true, builtin: true,
        regexStr: '\\b[1-9]\\d{3}[ \\t]+(?:Bruxelles|Brussel|Schaerbeek|Anvers|Antwerpen|Li[èe]ge|Gand|Gent|Bruges|Namur|Mons|Louvain|Leuven|Charleroi)\\b',
        flags: 'g', token: 'CODIGO_POSTAL',
        name: 'Código postal BE', label: 'Código postal belga con ciudad',
    },
    {
        id: 'rrn_be', type: 'pii', group: 'fr', enabled: true, builtin: true,
        regexStr: '\\b\\d{2}\\.\\d{2}\\.\\d{2}-\\d{3}\\.\\d{2}\\b',
        flags: 'g', token: 'RRN_BE',
        name: 'Registro Nacional (BE)', label: 'Número de Registro Nacional belga (Rijksregisternummer)',
    },

    // ── UK — United Kingdom ───────────────────────────────────────────────────

    {
        id: 'nino', type: 'pii', group: 'uk', enabled: true, builtin: true,
        regexStr: '\\b[A-CEGHJ-PR-TW-Z]{2}\\d{6}[A-D]\\b',
        flags: 'gi', token: 'NINO_UK',
        name: 'NINO (UK)', label: 'National Insurance Number (United Kingdom)',
    },
    {
        id: 'nhs', type: 'pii', group: 'uk', enabled: false, builtin: true,
        regexStr: '\\b(?:NHS|nhs)[:\\s#]+\\d{3}[\\s\\-]?\\d{3}[\\s\\-]?\\d{4}\\b',
        flags: 'gi', token: 'NHS_UK',
        name: 'NHS Number (UK)', label: 'NHS Number (Reino Unido)',
    },
    {
        id: 'uk_postcode', type: 'pii', group: 'uk', enabled: false, builtin: true,
        regexStr: '\\b[A-Z]{1,2}\\d[A-Z\\d]?[\\s]\\d[A-Z]{2}\\b',
        flags: 'gi', token: 'POSTCODE_UK',
        name: 'Postcode (UK)', label: 'Código postal del Reino Unido',
    },
    {
        id: 'address_en_context', type: 'pii', group: 'uk', enabled: true, builtin: true,
        // Street types are limited to the unambiguous ones. `Court/Way/Square/
        // Terrace` are dropped on purpose: they double as common nouns and the
        // `<number> <Capitalized> <type>` shape would mask prose like "2024
        // Supreme Court" or "1 Times Square".
        regexStr: '\\b\\d{1,5}[ \\t]+[A-Z][A-Za-z]+(?:[ \\t]+[A-Z][A-Za-z]+){0,2}[ \\t]+(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd)\\b',
        flags: 'g', token: 'DIRECCION',
        name: 'Dirección EN', label: 'Dirección postal en inglés (número + calle)',
    },
    // names_en — replaced by entityScanner.js
    {
        id: 'address_be_street_context', type: 'pii', group: 'uk', enabled: true, builtin: true,
        regexStr: '\\b(?:address|adress|adresse|adres|direccion|direcci[\\u00f3o]n)[ \\t]*(?:is|est|:)?[ \\t]*[A-Z][A-Za-z\\u00c0-\\u00ff.-]+(?:[ \\t]+[A-Za-z\\u00c0-\\u00ff.-]+){0,3}[ \\t]+(?:street|straat|strart|str\\.?|rue|laan|avenue|ave\\.?)\\s+\\d{1,5}\\b',
        flags: 'gi', token: 'DIRECCION',
        name: 'Direccion BE/NL/EN por etiqueta', label: 'Direccion postal con etiqueta',
    },

    // ── MEXICO ────────────────────────────────────────────────────────────────

    {
        id: 'curp', type: 'pii', group: 'mx', enabled: true, builtin: true,
        regexStr: '[A-Z]{4}\\d{6}[HM][A-Z]{5}[A-Z0-9]\\d',
        flags: 'g', token: 'CURP_MX',
        name: 'CURP (México)', label: 'Clave Única de Registro de Población (México)',
    },
    {
        id: 'rfc', type: 'pii', group: 'mx', enabled: false, builtin: true,
        regexStr: '[A-Z&Ñ]{3,4}\\d{6}[A-Z0-9]{3}',
        flags: 'g', token: 'RFC_MX',
        name: 'RFC (México)', label: 'Registro Federal de Contribuyentes (México)',
    },

    // ── PERSONAL — Léxico (texto libre) ──────────────────────────────────────
    // Whole-word, Unicode-aware (\p{L} lookarounds, 'gu' flags). Catch single
    // tokens that the structured/two-word patterns miss in prose. Recall-first
    // for a privacy gateway; all toggleable.

    // given_name — replaced by entityScanner.js (entities.json dict, Set lookup)
    {
        id: 'greeting_name_context', type: 'pii', group: 'personal', enabled: true, builtin: true,
        regexStr: "(?<=\\b(?:Dear|Hello|Hi|Hola|Bonjour|Bonsoir|Salut|Hallo|Beste|Geachte)[ \\t,]+)(?!Team\\b|There\\b|All\\b|Everyone\\b|World\\b|Sir\\b|Madam\\b|Monsieur\\b|Madame\\b)[A-Z\\u00c0-\\u00d6\\u00d8-\\u00de][A-Za-z\\u00c0-\\u00ff'.-]{1,40}(?:[ \\t]+[A-Z\\u00c0-\\u00d6\\u00d8-\\u00de][A-Za-z\\u00c0-\\u00ff'.-]{1,40}){0,2}",
        flags: 'gu', token: 'NOMBRE',
        name: 'Nombre tras saludo', label: 'Nombre propio detectado tras un saludo',
    },
    // city_name / country_name — replaced by entityScanner.js (entities.json dict, Set lookup)
    {
        id: 'postal_code_es_context', type: 'pii', group: 'personal', enabled: true, builtin: true,
        regexStr: "(?<=c[o\\u00f3]digo\\s*postal\\s*:?\\s*)\\b(?:0[1-9]|[1-4]\\d|5[0-2])\\d{3}\\b|\\b(?:0[1-9]|[1-4]\\d|5[0-2])\\d{3}\\b(?=\\s+(?:Madrid|Barcelona|Valencia|Sevilla|Bilbao|M[a\\u00e1]laga|Zaragoza|Murcia|Granada)|[^\\n]*(?:expediente|c[o\\u00f3]digo\\s*postal))",
        flags: 'gi', token: 'CODIGO_POSTAL',
        name: 'Codigo postal ES', label: 'Codigo postal espanol con contexto',
    },
    {
        id: 'address_es_context', type: 'pii', group: 'personal', enabled: true, builtin: true,
        regexStr: "\\b(?:Av\\.?|Avenida|Calle|C/|Plaza|Paseo|Pza\\.)\\s+[A-Z\\u00c1\\u00c9\\u00cd\\u00d3\\u00da\\u00dc\\u00d1][A-Za-z\\u00c1\\u00c9\\u00cd\\u00d3\\u00da\\u00dc\\u00d1\\u00e1\\u00e9\\u00ed\\u00f3\\u00fa\\u00fc\\u00f1 .-]+\\s+\\d{1,5}\\b",
        flags: 'g', token: 'DIRECCION',
        name: 'Direccion ES', label: 'Direccion postal espanola',
    },
    {
        id: 'nationality_es', type: 'pii', group: 'personal', enabled: true, builtin: true,
        regexStr: "(?<![\\p{L}])(?:Espa(?:\\u00f1|n)ola|ESP|ES)(?![\\p{L}])",
        flags: 'giu', token: 'NACIONALIDAD',
        name: 'Nacionalidad ES', label: 'Nacionalidad espanola o codigo pais',
    },
    {
        id: 'nationality_intl_context', type: 'pii', group: 'personal', enabled: true, builtin: true,
        // Label-anchored, so only an explicit "nationalité: belge" form fires —
        // safe to keep on by default across languages.
        regexStr: '\\b(?:nationalit[ée]|nationaliteit|nationality)[ \\t]*:?[ \\t]*(?:fran[çc]aise?|belge|n[ée]erlandaise?|dutch|belgian|french|espagnole?|spanish)\\b',
        flags: 'gi', token: 'NACIONALIDAD',
        name: 'Nacionalidad (multi-idioma)', label: 'Nacionalidad por etiqueta (fr/nl/en)',
    },
    // cities_eu / countries_intl — replaced by entityScanner.js (entities.json dict)
    {
        id: 'username_context', type: 'pii', group: 'personal', enabled: true, builtin: true,
        regexStr: "(?:usuario|login|user)[ \\t]*:[ \\t]*[A-Za-z][A-Za-z0-9._-]{2,30}|(?<![\\p{L}@])(?:j\\.?perez|jperez\\d{0,4}|juan\\.perez)(?![\\p{L}@])",
        flags: 'giu', token: 'USUARIO',
        name: 'Usuario/login', label: 'Usuario o login detectable por contexto',
    },
    {
        id: 'homoglyph_known_es', type: 'pii', group: 'personal', enabled: true, builtin: true,
        regexStr: "(?:J\\u1d1can|P\\u0435rez|M\\u0430drid)",
        flags: 'gu', token: 'RIESGO_POSIBLE',
        name: 'Homoglifo sospechoso', label: 'Variante Unicode sospechosa de dato personal',
    },
    {
        id: 'spaced_letters', type: 'pii', group: 'personal', enabled: true, builtin: true,
        // Bounded by non-letters and ≥5 letters: catches "M a d r i d" evasion on
        // its own token, but not spaced acronyms ("I B M y la") inside prose.
        regexStr: '(?<![\\p{L}])(?:[\\p{L}][ \\t]){4,}[\\p{L}](?![\\p{L}])',
        flags: 'gu', token: 'RIESGO_POSIBLE',
        name: 'Texto espaciado', label: 'Posible dato ofuscado con espacios entre letras',
    },
    {
        id: 'time_of_day', type: 'pii', group: 'personal', enabled: false, builtin: true,
        regexStr: '\\b\\d{1,2}:\\d{2}\\b',
        flags: 'g', token: 'HORA',
        name: 'Hora', label: 'Hora del día (HH:MM)',
    },
];

// ── Pattern groups metadata (for UI display) ────────────────────────────────

export const PATTERN_GROUPS = [
    { id: 'global',    icon: '🌐', labelKey: 'group_global' },
    { id: 'personal',  icon: '🧑', labelKey: 'group_personal' },
    { id: 'financial', icon: '💳', labelKey: 'group_financial' },
    { id: 'tech',      icon: '🔐', labelKey: 'group_tech' },
    { id: 'es',        icon: '🇪🇸', labelKey: 'group_es' },
    { id: 'us',        icon: '🇺🇸', labelKey: 'group_us' },
    { id: 'nl',        icon: '🇳🇱', labelKey: 'group_nl' },
    { id: 'fr',        icon: '🇫🇷', labelKey: 'group_fr' },
    { id: 'uk',        icon: '🇬🇧', labelKey: 'group_uk' },
    { id: 'mx',        icon: '🇲🇽', labelKey: 'group_mx' },
];

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Returns a fresh RegExp instance (avoids stateful lastIndex with /g flag).
 */
export function buildRegex(pattern) {
    return new RegExp(pattern.regexStr, pattern.flags || 'g');
}

/**
 * Validates a user-supplied regex string.
 * Returns null if valid, or an error message string if invalid.
 */
export function validateRegexStr(regexStr) {
    if (!regexStr || !regexStr.trim()) return 'La expresión regular no puede estar vacía.';
    try {
        new RegExp(regexStr, 'g');
        return null;
    } catch (e) {
        return `Regex inválida: ${e.message}`;
    }
}

/**
 * Generates a collision-resistant ID for a new custom pattern.
 */
export function generatePatternId(name) {
    return `custom_${name.toLowerCase().replace(/\W+/g, '_')}_${Date.now()}`;
}
