// Versleutelen en ontsleutelen in de browser. De server ziet enkel ciphertext.
//
// Twee onafhankelijke sleutels:
//   1. een lijn uit het codeboek, voor de one time pad (modulo 37). Eenmalig te gebruiken.
//   2. een aparte HMAC-sleutel, voor de integriteit. Die mag je wel hergebruiken.
//
// Niets uit dit bestand schrijft naar localStorage, de URL of de console: sleutels
// blijven enkel als variabele bestaan, zolang de functie die ze gebruikt loopt.

// A=0..Z=25, 0=26..9=35, _=36. Dezelfde volgorde als in de theorie.
export const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
export const MODULUS = ALPHABET.length; // 37

// Kleine letters worden hoofdletters, een spatie wordt _. De rest laten we staan,
// zodat findInvalidChars kan tonen wat er precies niet door de controle komt.
export function normalize(text) {
    return String(text).toUpperCase().replaceAll(' ', '_');
}

// De tekens die na normalize nog altijd buiten het alfabet vallen, elk één keer.
// Accenten en leestekens horen hierbij: die weigeren we bewust in plaats van ze
// stilletjes om te zetten, want dan verandert het bericht zonder dat je het ziet.
export function findInvalidChars(text) {
    const invalid = [...String(text)].filter(char => !ALPHABET.includes(char));
    return [...new Set(invalid)];
}

export function isValidKey(key) {
    return typeof key === 'string' && key.length > 0 && findInvalidChars(key).length === 0;
}

// Controleert tekst en sleutel, en geeft de posities in het alfabet terug.
function toValues(text, key, what) {
    const badText = findInvalidChars(text);
    if (badText.length > 0) {
        throw new Error(`${what} bevat tekens die niet in het alfabet zitten: ${badText.join(' ')}`);
    }
    if (!isValidKey(key)) {
        throw new Error('De sleutel mag enkel A-Z, 0-9 en _ bevatten.');
    }
    // De kern van de one time pad: een sleutel die korter is dan het bericht zou
    // betekenen dat je een stuk sleutel hergebruikt, en dan valt de beveiliging weg.
    if (text.length > key.length) {
        throw new Error(`Het bericht is ${text.length} tekens, de sleutel maar ${key.length}. Neem een langer bericht of een langere sleutel.`);
    }

    return {
        textValues: [...text].map(char => ALPHABET.indexOf(char)),
        keyValues: [...key].map(char => ALPHABET.indexOf(char)),
    };
}

// c[i] = (m[i] + k[i]) mod 37
export function encrypt(plaintext, key) {
    const { textValues, keyValues } = toValues(plaintext, key, 'Het bericht');

    return textValues
        .map((value, i) => ALPHABET[(value + keyValues[i]) % MODULUS])
        .join('');
}

// m[i] = (c[i] - k[i] + 37) mod 37
// De + MODULUS is nodig omdat % in JavaScript het teken van het linkerlid houdt:
// -3 % 37 is -3 en niet 34, en dan zou ALPHABET[-3] undefined teruggeven.
export function decrypt(ciphertext, key) {
    const { textValues, keyValues } = toValues(ciphertext, key, 'De ciphertext');

    return textValues
        .map((value, i) => ALPHABET[(value - keyValues[i] + MODULUS) % MODULUS])
        .join('');
}

// ----------------------------------------------------------------- integriteit

// Web Crypto is er enkel op HTTPS of op localhost. Zonder deze controle krijg je
// verderop een onduidelijke "cannot read property importKey of undefined".
function subtle() {
    if (!globalThis.crypto || !globalThis.crypto.subtle) {
        throw new Error('Web Crypto is niet beschikbaar. Dit werkt enkel via HTTPS of op localhost.');
    }
    return globalThis.crypto.subtle;
}

// De MAC dekt de ciphertext én het lijnnummer, zodat niemand ongemerkt kan doen
// alsof een bericht met een andere codeboeklijn versleuteld is. De velden kunnen
// zelf geen | bevatten (een getal, en ciphertext uit A-Z0-9_), dus deze samenvoeging
// is ondubbelzinnig. v1 houdt de deur open om het formaat later te wijzigen.
export function buildMacInput(keyLineNr, ciphertext) {
    return `v1|${keyLineNr}|${ciphertext}`;
}

function importHmacKey(hmacKey) {
    if (typeof hmacKey !== 'string' || hmacKey.length === 0) {
        throw new Error('Geef een HMAC-sleutel in.');
    }

    return subtle().importKey(
        'raw',
        new TextEncoder().encode(hmacKey),
        { name: 'HMAC', hash: 'SHA-256' },
        false,          // niet exporteerbaar: de sleutel kan er niet meer uit
        ['sign', 'verify']
    );
}

function toHex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

function fromHex(hex) {
    if (!/^[0-9a-f]{64}$/.test(hex)) {
        throw new Error('De MAC heeft niet de vorm van 64 hexadecimale tekens.');
    }
    return Uint8Array.from(hex.match(/../g), byte => parseInt(byte, 16));
}

// Encrypt-then-MAC: we tekenen de ciphertext, niet het bericht zelf.
export async function signMac(hmacKey, macInput) {
    const key = await importHmacKey(hmacKey);
    const signature = await subtle().sign('HMAC', key, new TextEncoder().encode(macInput));
    return toHex(signature);
}

// We laten crypto.subtle.verify vergelijken en doen dat niet zelf met ===.
// Een gewone stringvergelijking stopt bij het eerste verschillende teken, en hoe
// lang dat duurt verraadt hoeveel tekens al juist waren. Zo kan een aanvaller een
// geldige MAC byte per byte opbouwen. verify is daarop voorzien.
export async function verifyMac(hmacKey, macInput, macHex) {
    const key = await importHmacKey(hmacKey);
    return subtle().verify(
        'HMAC',
        key,
        fromHex(macHex),
        new TextEncoder().encode(macInput)
    );
}
