// De schermen van Unbreakable. Navigeren gebeurt met het deel na # in de URL.

import { api, currentUser, initAuth, logout } from './api.js';
import { normalize, findInvalidChars, isValidKey, encrypt, decrypt, buildMacInput, signMac, verifyMac } from './crypto.js';

const app = document.getElementById('app');

function escapeHtml(text) {
    return String(text)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

function formatDate(value) {
    return new Date(value).toLocaleString('nl-BE', {
        day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit'
    });
}

function showWho() {
    const user = currentUser();
    const who = document.getElementById('who');
    who.innerHTML = user
        ? `Je bent <strong>${escapeHtml(user)}</strong> (<a href="#" id="logout">afmelden</a>)`
        : '';

    const logoutLink = document.getElementById('logout');
    if (logoutLink) {
        logoutLink.addEventListener('click', (event) => {
            event.preventDefault();
            logout();
        });
    }
}

// ------------------------------------------------------------------ startscherm

// Inloggen zelf gebeurt bij Keycloak, nog voor dit scherm getoond wordt.
function renderLogin() {
    const user = currentUser();
    app.innerHTML = `
        <div class="text-center mb-5">
            <h1 class="display-4">Unbreakable</h1>
            <p class="lead">Berichten die niemand anders kan lezen. Dat is toch de bedoeling.</p>
        </div>
        <div class="row justify-content-center">
            <div class="col-md-5">
                <p>Je bent ingelogd als <strong>${escapeHtml(user)}</strong>.
                   <a href="#/inbox">Naar je inbox</a></p>
            </div>
        </div>`;
}

// ------------------------------------------------------------------ inbox

async function renderInbox(params) {
    const user = currentUser();
    const from = params.get('from') || '';

    const all = await api.inbox();
    const senders = [...new Set(all.map(m => m.sender))].sort();
    const messages = all.filter(m => !from || m.sender === from);

    app.innerHTML = `
        <h1>Inbox van ${escapeHtml(user)}</h1>
        <p>
            <a href="#/nieuw" class="btn btn-primary">Nieuw bericht</a>
            <button id="export" class="btn btn-outline-secondary">Exporteer als JSON</button>
        </p>
        <form id="filter" class="mb-3">
            <div class="form-row align-items-end">
                <div class="col-auto">
                    <label for="from">Van</label>
                    <select id="from" class="form-control">
                        <option value="">Iedereen</option>
                        ${senders.map(s => `<option value="${escapeHtml(s)}" ${s === from ? 'selected' : ''}>${escapeHtml(s)}</option>`).join('')}
                    </select>
                </div>
                <div class="col-auto">
                    <button type="submit" class="btn btn-secondary">Filter</button>
                </div>
            </div>
        </form>
        <p class="text-muted">
            Zoeken in de inhoud kan niet meer: de server bewaart enkel versleutelde tekst
            en kan die niet lezen.
        </p>
        <div id="list"></div>`;

    const rows = messages.map(m => `
        <tr>
            <td>${escapeHtml(m.sender)}</td>
            <td><a href="#/bericht/${m.id}">${escapeHtml(m.subject)}</a></td>
            <td>${m.keyLineNr}</td>
            <td>${formatDate(m.sentAt)}</td>
        </tr>`).join('');

    document.getElementById('list').innerHTML = messages.length
        ? `<table class="table">
               <thead><tr><th>Van</th><th>Onderwerp</th><th>Lijn</th><th>Verzonden</th></tr></thead>
               <tbody>${rows}</tbody>
           </table>`
        : '<p class="text-muted">Geen berichten.</p>';

    document.getElementById('filter').addEventListener('submit', (event) => {
        event.preventDefault();
        const next = new URLSearchParams();
        const newFrom = document.getElementById('from').value;
        if (newFrom) next.set('from', newFrom);
        location.hash = '#/inbox' + (next.toString() ? '?' + next.toString() : '');
    });

    document.getElementById('export').addEventListener('click', async () => {
        const data = await api.exportJson();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = 'inbox.json';
        link.click();
        URL.revokeObjectURL(link.href);
    });
}

// ------------------------------------------------------------------ bericht lezen

async function renderMessage(id) {
    const m = await api.message(id);

    app.innerHTML = `
        <h1>${escapeHtml(m.subject)}</h1>
        <dl class="row">
            <dt class="col-sm-3">Van</dt><dd class="col-sm-9">${escapeHtml(m.sender)}</dd>
            <dt class="col-sm-3">Aan</dt><dd class="col-sm-9">${escapeHtml(m.recipient)}</dd>
            <dt class="col-sm-3">Verzonden</dt><dd class="col-sm-9">${formatDate(m.sentAt)}</dd>
            <dt class="col-sm-3">Lijn uit het codeboek</dt><dd class="col-sm-9">${m.keyLineNr}</dd>
        </dl>

        <p class="text-muted mb-1">Zo staat het bericht in de databank:</p>
        <div class="card mb-3"><div class="card-body message-body" id="ciphertext"></div></div>

        <form id="unlock" class="mb-3" autocomplete="off">
            <div class="form-group">
                <label for="key">Sleutel: lijn ${m.keyLineNr} uit je codeboek</label>
                <input id="key" type="password" class="form-control" required autocomplete="off" />
            </div>
            <div class="form-group">
                <label for="hmac-key">HMAC-sleutel</label>
                <input id="hmac-key" type="password" class="form-control" required autocomplete="off" />
            </div>
            <button type="submit" class="btn btn-primary">Controleren en ontsleutelen</button>
        </form>

        <div id="result"></div>

        <p>
            <button id="delete" class="btn btn-outline-danger">Verwijderen</button>
            <a href="#/inbox" class="btn btn-link">Terug naar je inbox</a>
        </p>`;

    document.getElementById('ciphertext').textContent = m.ciphertext;

    const result = document.getElementById('result');

    document.getElementById('unlock').addEventListener('submit', async (event) => {
        event.preventDefault();
        result.innerHTML = '';

        const keyField = document.getElementById('key');
        const hmacField = document.getElementById('hmac-key');
        const key = normalize(keyField.value.trim());
        const hmacKey = hmacField.value;

        try {
            // Eerst de MAC, dan pas ontsleutelen. Klopt de MAC niet, dan is het bericht
            // onderweg of in de databank gewijzigd en heeft ontsleutelen geen zin: je zou
            // tekst te zien krijgen die iemand anders heeft bepaald.
            const macInput = buildMacInput(m.keyLineNr, m.ciphertext);
            const macIsValid = await verifyMac(hmacKey, macInput, m.mac);

            if (!macIsValid) {
                result.innerHTML = `
                    <div class="alert alert-danger">
                        <strong>Bericht is gewijzigd of sleutel klopt niet.</strong>
                        De MAC komt niet overeen, dus het bericht wordt niet ontsleuteld.
                    </div>`;
                return;
            }

            const plaintext = decrypt(m.ciphertext, key);

            result.innerHTML = `
                <div class="alert alert-success">MAC is geldig: dit bericht is niet gewijzigd.</div>
                <div class="card mb-3"><div class="card-body message-body" id="plaintext"></div></div>
                <p class="text-muted">
                    Let op: met een verkeerde codeboeklijn krijg je gewoon onleesbare tekst te zien
                    en geen foutmelding. Een one time pad kan niet zeggen of de sleutel juist is.
                </p>`;
            document.getElementById('plaintext').textContent = plaintext;
        } catch (error) {
            result.innerHTML = `<div class="alert alert-danger">${escapeHtml(error.message)}</div>`;
        } finally {
            // De sleutels blijven niet rondslingeren in het formulier.
            keyField.value = '';
            hmacField.value = '';
        }
    });

    document.getElementById('delete').addEventListener('click', async () => {
        if (confirm('Ben je zeker dat je dit bericht wil verwijderen?')) {
            await api.remove(id);
            location.hash = '#/inbox';
        }
    });
}

// ------------------------------------------------------------------ bericht versturen

async function renderNew() {
    const users = await api.users();

    app.innerHTML = `
        <h1>Nieuw bericht</h1>
        <p class="text-muted">Van: ${escapeHtml(currentUser())}</p>
        <div class="row">
            <div class="col-md-8">
                <form id="compose" autocomplete="off">
                    <div class="form-group">
                        <label for="recipient">Aan</label>
                        <input id="recipient" class="form-control" list="known-users" autocomplete="off"
                               required minlength="2" maxlength="40" />
                        <datalist id="known-users">
                            ${users.map(u => `<option value="${escapeHtml(u)}"></option>`).join('')}
                        </datalist>
                    </div>
                    <div class="form-group">
                        <label for="subject">Onderwerp</label>
                        <input id="subject" class="form-control" required maxlength="100" />
                        <small class="form-text text-muted">
                            Het onderwerp wordt niet versleuteld: de beheerder van de server kan dit lezen.
                        </small>
                    </div>
                    <div class="form-group">
                        <label for="text">Bericht</label>
                        <textarea id="text" class="form-control" rows="6" required maxlength="2000"></textarea>
                        <small class="form-text text-muted" id="preview"></small>
                    </div>

                    <hr />
                    <p class="text-muted">
                        De twee sleutels blijven in je browser. Ze worden niet verstuurd en niet bewaard.
                    </p>
                    <div class="form-group">
                        <label for="line-nr">Lijn uit het codeboek</label>
                        <input id="line-nr" type="number" class="form-control" required min="1" max="10000" />
                        <small class="form-text text-muted">Gebruik elke lijn maar één keer.</small>
                    </div>
                    <div class="form-group">
                        <label for="key">Sleutel: de inhoud van die lijn</label>
                        <input id="key" type="password" class="form-control" required autocomplete="off" />
                    </div>
                    <div class="form-group">
                        <label for="hmac-key">HMAC-sleutel (apart van het codeboek)</label>
                        <input id="hmac-key" type="password" class="form-control" required autocomplete="off" />
                    </div>

                    <div id="error"></div>
                    <button type="submit" class="btn btn-primary">Versleutelen en versturen</button>
                    <a href="#/inbox" class="btn btn-link">Annuleren</a>
                </form>
            </div>
        </div>`;

    const textField = document.getElementById('text');
    const preview = document.getElementById('preview');
    const error = document.getElementById('error');

    // Tonen wat er van het bericht gemaakt wordt, zodat het bij het versturen
    // geen verrassing is. Enkel het genormaliseerde bericht, nooit een sleutel.
    function showPreview() {
        const normalized = normalize(textField.value);
        const invalid = findInvalidChars(normalized);

        preview.textContent = normalized
            ? `Wordt versleuteld als: ${normalized} (${normalized.length} tekens)`
            : '';
        preview.className = invalid.length
            ? 'form-text text-danger'
            : 'form-text text-muted';

        if (invalid.length) {
            preview.textContent += ` — niet toegelaten: ${invalid.join(' ')}`;
        }
    }

    textField.addEventListener('input', showPreview);

    document.getElementById('compose').addEventListener('submit', async (event) => {
        event.preventDefault();
        error.innerHTML = '';

        const keyField = document.getElementById('key');
        const hmacField = document.getElementById('hmac-key');

        // De sleutels bestaan enkel hier, als lokale variabele. Ze gaan niet naar
        // localStorage, niet in de URL en niet naar de console.
        const key = normalize(keyField.value.trim());
        const hmacKey = hmacField.value;
        const keyLineNr = Number(document.getElementById('line-nr').value);
        const plaintext = normalize(textField.value);

        try {
            if (!isValidKey(key)) {
                throw new Error('De sleutel mag enkel A-Z, 0-9 en _ bevatten.');
            }

            // encrypt controleert zelf op verboden tekens en op een te korte sleutel,
            // maar de foutmelding is duidelijker als we de tekens hier opsommen.
            const invalid = findInvalidChars(plaintext);
            if (invalid.length) {
                throw new Error(`Het bericht bevat tekens die niet versleuteld kunnen worden: ${invalid.join(' ')}. Gebruik enkel letters, cijfers en spaties.`);
            }

            const ciphertext = encrypt(plaintext, key);
            const mac = await signMac(hmacKey, buildMacInput(keyLineNr, ciphertext));

            await api.send({
                recipient: document.getElementById('recipient').value.trim(),
                subject: document.getElementById('subject').value,
                ciphertext,
                keyLineNr,
                mac,
            });

            location.hash = '#/inbox';
        } catch (err) {
            error.innerHTML = `<div class="alert alert-danger">${escapeHtml(err.message)}</div>`;
        } finally {
            keyField.value = '';
            hmacField.value = '';
        }
    });
}

// ------------------------------------------------------------------ over

function renderAbout() {
    app.innerHTML = `
        <h1>Over Unbreakable</h1>
        <p>Unbreakable is een berichtenapp. Je stuurt een bericht naar iemand, en enkel die persoon kan het lezen.
           Dat is tenminste het doel.</p>
        <p>Deze versie is de starter app van het vak Cyber Security Advanced aan AP Hogeschool.
           Ze werkt, maar is nog helemaal niet veilig. Doorheen het semester maken jullie ze beter.</p>
        <p>De app bestaat uit twee delen: deze single page app in je browser, en een API op de server.
           Bekijk de developer tools van je browser om te zien wat er over en weer gaat.</p>
        <p class="text-danger">Gebruik deze app enkel in je eigen labomgeving en nooit met echte gegevens.</p>`;
}

// ------------------------------------------------------------------ navigatie

async function route() {
    showWho();

    const [path, query] = (location.hash || '#/').slice(1).split('?');
    const params = new URLSearchParams(query || '');

    try {
        if (path === '/' || path === '') {
            return renderLogin();
        }
        if (path === '/over') {
            return renderAbout();
        }
        if (!currentUser()) {
            location.hash = '#/';
            return;
        }
        if (path === '/inbox') {
            return await renderInbox(params);
        }
        if (path === '/nieuw') {
            return await renderNew();
        }
        const match = path.match(/^\/bericht\/(\d+)$/);
        if (match) {
            return await renderMessage(match[1]);
        }
        app.innerHTML = '<p>Deze pagina bestaat niet.</p>';
    } catch (error) {
        app.innerHTML = `<div class="alert alert-danger">Er liep iets mis: ${escapeHtml(error.message)}</div>`;
    }
}

// Eerst inloggen bij Keycloak (of terugkomen van de login), pas dan de schermen.
try {
    await initAuth();
    window.addEventListener('hashchange', route);
    route();
} catch (error) {
    app.innerHTML = `<div class="alert alert-danger">Inloggen mislukt: ${escapeHtml(error?.message || error)}</div>`;
}
