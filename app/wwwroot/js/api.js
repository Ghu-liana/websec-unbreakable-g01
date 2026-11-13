// Praat met de API. Alles wat de SPA weet, komt van hier.
//
// Inloggen gebeurt bij Keycloak, met OIDC: authorization code flow + PKCE (S256).
// Het access token blijft enkel in het geheugen (niet in localStorage) en gaat bij
// elke call mee in de header Authorization. De API haalt daar zelf uit wie je bent.

import Keycloak from '../lib/keycloak-js/dist/keycloak.js';

const keycloak = new Keycloak({
    url: location.origin + '/auth',
    realm: 'unbreakable',
    clientId: 'unbreakable-spa',
});

export async function initAuth() {
    await keycloak.init({
        onLoad: 'login-required',
        pkceMethod: 'S256',
        // De SPA navigeert zelf met #/..., dus de code van Keycloak komt in de query.
        responseMode: 'query',
        checkLoginIframe: false,
        redirectUri: location.origin + '/',
    });
}

// Enkel om te tonen. De API vertrouwt hier niet op: die leest het token zelf.
export function currentUser() {
    return keycloak.tokenParsed?.preferred_username;
}

export function logout() {
    return keycloak.logout({ redirectUri: location.origin + '/' });
}

async function call(method, path, body) {
    // Token bijna verlopen (minder dan 30 seconden)? Eerst vernieuwen.
    try {
        await keycloak.updateToken(30);
    } catch {
        await keycloak.login();
        throw new Error('Je sessie is verlopen. Je wordt opnieuw aangemeld.');
    }

    const headers = { 'Authorization': 'Bearer ' + keycloak.token };
    const options = { method, headers };

    if (body !== undefined) {
        headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(body);
    }

    const response = await fetch('/api' + path, options);
    if (!response.ok) {
        throw new Error(`${method} ${path} gaf ${response.status}`);
    }

    const type = response.headers.get('Content-Type') || '';
    return type.includes('application/json') ? response.json() : response.text();
}

export const api = {
    users: () => call('GET', '/users'),
    inbox: (from) => call('GET', '/messages' + (from ? '?from=' + encodeURIComponent(from) : '')),
    message: (id) => call('GET', '/messages/' + id),
    // message bevat { recipient, subject, ciphertext, keyLineNr, mac }.
    // Geen afzender: die haalt de API uit het token.
    // Het bericht zelf en de twee sleutels komen hier nooit voorbij.
    send: (message) => call('POST', '/messages', message),
    remove: (id) => call('DELETE', '/messages/' + id),
    exportJson: () => call('GET', '/messages/export'),
};
