/**
 * labels.js — Shared token-base metadata.
 *
 * Lives in its own module so both report.js (the formatter) and corrections.js
 * (the manual-correction engine) can read it without an import cycle.
 *
 *  - TOKEN_LABELS        token base → human label shown in the audit / token map
 *  - MANUAL_TOKEN_OPTIONS the type picker offered in the manual-correction menu
 *  - PCI_TOKEN_BASES     bases that count as financial (PCI) for risk colouring
 */

import { getCurrentTranslations } from './i18n.js';

export const TOKEN_LABELS = {
    NOMBRE: 'Nombre',
    APELLIDO: 'Apellido',
    NOMBRE_COMPLETO: 'Nombre completo',
    PERSONA_ES: 'Nombre completo',
    PERSONA_FR: 'Nombre completo',
    DNI: 'DNI / documento',
    DNI_ES: 'DNI / documento',
    NIE: 'NIE / documento',
    NIE_ES: 'NIE / documento',
    PASAPORTE: 'Pasaporte',
    SSN_USA: 'SSN (EE. UU.)',
    RRN_BE: 'Registro Nacional (BE)',
    FECHA_NACIMIENTO: 'Fecha de nacimiento',
    EDAD: 'Edad',
    SEXO: 'Sexo / género',
    DIRECCION: 'Dirección',
    CODIGO_POSTAL: 'Código postal',
    CIUDAD: 'Ciudad',
    PROVINCIA: 'Provincia / región',
    PAIS: 'País',
    TELEFONO: 'Teléfono',
    TELEFONO_INTL: 'Teléfono',
    EMAIL: 'Email',
    ESTADO_CIVIL: 'Estado civil',
    PROFESION: 'Profesión',
    NACIONALIDAD: 'Nacionalidad',
    EMPRESA: 'Empresa',
    USUARIO: 'Usuario / login',
    MATRICULA: 'Matrícula',
    EXPEDIENTE: 'Expediente',
    IBAN: 'IBAN / cuenta bancaria',
    BIC_SWIFT: 'BIC / SWIFT',
    CUENTA: 'Cuenta bancaria',
    TARJETA_CREDITO: 'Tarjeta bancaria',
    DIRECCION_IPV4: 'IP',
    DIRECCION_IPV6: 'IP',
    MAC_ADDRESS: 'MAC address',
    TOKEN_JWT: 'Token técnico',
    API_KEY: 'Clave técnica',
    SECRETO: 'Secreto / credencial',
    CREDENCIAL: 'Credencial',
    PERSONNE_FR: 'Nombre completo',
    PERSOON_NL: 'Nombre completo',
    PERSON_EN: 'Nombre completo',
    RIESGO_MANUAL: 'Riesgo manual',
    OTRO: 'Otro',
};

/** Token bases offered in the manual-correction type picker (spec point 3). */
export const MANUAL_TOKEN_OPTIONS = [
    { key: 'persona_es', token: 'PERSONA_ES', label: 'Persona (ES)' },
    { key: 'persona_fr', token: 'PERSONA_FR', label: 'Persona (FR)' },
    { key: 'nombre', token: 'NOMBRE', label: 'Nombre' },
    { key: 'apellido', token: 'APELLIDO', label: 'Apellido' },
    { key: 'direccion', token: 'DIRECCION', label: 'Dirección' },
    { key: 'codigo_postal', token: 'CODIGO_POSTAL', label: 'Código postal' },
    { key: 'ciudad', token: 'CIUDAD', label: 'Ciudad' },
    { key: 'pais', token: 'PAIS', label: 'País' },
    { key: 'telefono', token: 'TELEFONO', label: 'Teléfono' },
    { key: 'email', token: 'EMAIL', label: 'Email' },
    { key: 'iban', token: 'IBAN', label: 'IBAN' },
    { key: 'bic_swift', token: 'BIC_SWIFT', label: 'BIC / SWIFT' },
    { key: 'pasaporte', token: 'PASAPORTE', label: 'Pasaporte' },
    { key: 'rrn_be', token: 'RRN_BE', label: 'Registro Nacional (BE)' },
    { key: 'ssn_usa', token: 'SSN_USA', label: 'SSN (EE. UU.)' },
    { key: 'dni', token: 'DNI', label: 'DNI' },
    { key: 'fecha_nacimiento', token: 'FECHA_NACIMIENTO', label: 'Fecha de nacimiento' },
    { key: 'empresa', token: 'EMPRESA', label: 'Empresa' },
    { key: 'matricula', token: 'MATRICULA', label: 'Matrícula' },
    { key: 'expediente', token: 'EXPEDIENTE', label: 'Expediente' },
    { key: 'otro', token: 'OTRO', label: 'Otro' },
];

/** Token bases treated as financial data (PCI) — drives risk = ALTO colouring. */
export const PCI_TOKEN_BASES = new Set([
    'IBAN', 'BIC_SWIFT', 'CUENTA', 'TARJETA_CREDITO',
]);

/** @returns {string} human label for a token base, falling back to the base. */
export function labelForBase(base) {
    return getCurrentTranslations()?.tokenLabels?.[base] || TOKEN_LABELS[base] || base;
}
