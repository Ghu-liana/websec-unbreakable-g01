using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Unbreakable.Authorization;
using Unbreakable.Data;
using Unbreakable.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<UnbreakableContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("Unbreakable")));

builder.Services.AddCors(options =>
    options.AddDefaultPolicy(policy => policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

// Inloggen gebeurt in de browser, bij Keycloak (OIDC, authorization code flow + PKCE).
// De API ziet nooit een wachtwoord: hij krijgt enkel een access token en controleert dat zelf.
//   Authority       = de issuer zoals hij in het token staat (de publieke URL)
//   MetadataAddress = waar de API de configuratie en de publieke sleutels (JWKS) ophaalt:
//                     rechtstreeks bij Keycloak over het interne Docker-netwerk
//   Audience        = voor wie het token bedoeld moet zijn
var authority = builder.Configuration["Auth:Authority"]
    ?? throw new InvalidOperationException("Auth:Authority ontbreekt in de configuratie.");
var metadataAddress = builder.Configuration["Auth:MetadataAddress"]
    ?? $"{authority}/.well-known/openid-configuration";
var audience = builder.Configuration["Auth:Audience"]
    ?? throw new InvalidOperationException("Auth:Audience ontbreekt in de configuratie.");

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.MetadataAddress = metadataAddress;
        // De metadata komt over http, maar enkel binnen het Docker-netwerk (app -> keycloak).
        // Van buitenaf loopt alles over HTTPS via BunkerWeb.
        options.RequireHttpsMetadata = metadataAddress.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        // Claims houden hun naam uit het token: "sub" blijft "sub".
        options.MapInboundClaims = false;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            // Handtekening: enkel met de sleutels van Keycloak, en enkel RS256.
            // Zo wordt een token zonder handtekening ("alg": "none") of met een ander
            // algoritme altijd geweigerd.
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },

            // Uitgegeven door onze realm, en niet door een andere.
            ValidateIssuer = true,
            ValidIssuer = authority,

            // Bedoeld voor deze API. Een ID token (aud = de SPA) wordt zo ook geweigerd.
            ValidateAudience = true,
            ValidAudience = audience,

            // Niet verlopen, en niet "nog niet geldig".
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.FromSeconds(30),

            NameClaimType = "preferred_username",
        };
    });

builder.Services.AddAuthorization();

// De PDP: OpenFGA beslist wie welk bericht mag lezen of verwijderen.
// De regels zelf staan in openfga/model.fga, niet in deze code.
builder.Services.AddSingleton<FgaAuthorizer>();

var app = builder.Build();

// Databank aanmaken. Er worden geen voorbeeldberichten meer gezet: de app bewaart
// enkel ciphertext, en daar zou een sleutel voor nodig zijn die niet in deze repo hoort.
// De databank kan iets later opstarten dan de app, dus we proberen een paar keer.
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<UnbreakableContext>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

    for (var attempt = 1; attempt <= 30; attempt++)
    {
        try
        {
            context.Database.EnsureCreated();
            break;
        }
        catch (Exception ex) when (attempt < 30)
        {
            logger.LogWarning("Databank nog niet bereikbaar ({Error}), poging {Attempt}", ex.Message, attempt);
            Thread.Sleep(2000);
        }
    }
}

// OpenFGA klaarzetten op de achtergrond. Is het nog niet klaar, dan start de app toch
// (zodat /health en inloggen werken); de bericht-endpoints antwoorden dan 503.
var fgaAuthorizer = app.Services.GetRequiredService<FgaAuthorizer>();
_ = Task.Run(() => fgaAuthorizer.WarmUpAsync(app.Lifetime.ApplicationStopping));

app.UseDeveloperExceptionPage();
app.UseCors();

// De SPA: index.html, JavaScript en CSS uit wwwroot.
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => "ok");

// De API. Elk verzoek moet een geldig access token van Keycloak hebben.
// Wie je bent, komt uit dat token (claim "sub"), niet meer uit een header.
var api = app.MapGroup("/api").RequireAuthorization();

// Elke gebruiker die met een geldig token langskomt, wordt (bij)gewerkt in de lijst
// sub <-> gebruikersnaam. Beide waarden komen uit het gevalideerde token.
api.AddEndpointFilter(async (context, next) =>
{
    var principal = context.HttpContext.User;
    var sub = principal.FindFirstValue("sub");
    var username = principal.FindFirstValue("preferred_username");
    if (string.IsNullOrEmpty(sub) || string.IsNullOrEmpty(username))
    {
        return Results.Unauthorized();
    }

    var db = context.HttpContext.RequestServices.GetRequiredService<UnbreakableContext>();
    await RememberUser(db, sub, username);

    return await next(context);
});

// Kan de PDP niet antwoorden, dan weigert de API (fail closed): niemand krijgt toegang
// zolang OpenFGA niet beslist heeft.
api.AddEndpointFilter(async (context, next) =>
{
    try
    {
        return await next(context);
    }
    catch (FgaUnavailableException ex)
    {
        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex.InnerException, "OpenFGA niet beschikbaar");
        return Results.Problem("De autorisatieservice is tijdelijk niet beschikbaar.", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});

api.MapGet("/users", async (UnbreakableContext db) =>
{
    return Results.Ok(await db.Users
        .OrderBy(u => u.Username)
        .Select(u => u.Username)
        .ToListAsync());
});

// Inbox: welke berichten je mag lezen, beslist OpenFGA (ListObjects op "can_read").
// De API zoekt enkel die berichten op in de databank.
api.MapGet("/messages", async (HttpRequest request, ClaimsPrincipal principal, UnbreakableContext db, FgaAuthorizer fga) =>
{
    var allowed = await fga.ListAsync(CurrentUserId(principal), "can_read");

    var inbox = db.Messages.Where(m => allowed.Contains(m.Id));

    // ?from= is een zoekfilter, geen recht: het werkt enkel binnen wat OpenFGA toeliet.
    var from = request.Query["from"].ToString();
    if (!string.IsNullOrEmpty(from))
    {
        var fromId = await UserIdFor(db, from);
        inbox = inbox.Where(m => m.Sender == fromId);
    }

    var messages = await inbox.OrderByDescending(m => m.SentAt).ToListAsync();
    return Results.Ok(await ToViews(db, messages));
});

// Verzonden: de berichten die je mag verwijderen (ListObjects op "can_delete").
// Enkel id, ontvanger en datum: onderwerp en inhoud lezen mag enkel de ontvanger.
api.MapGet("/messages/sent", async (ClaimsPrincipal principal, UnbreakableContext db, FgaAuthorizer fga) =>
{
    var allowed = await fga.ListAsync(CurrentUserId(principal), "can_delete");

    var messages = await db.Messages
        .Where(m => allowed.Contains(m.Id))
        .OrderByDescending(m => m.SentAt)
        .ToListAsync();

    var views = await ToViews(db, messages);
    return Results.Ok(views.Select(v => new SentView(v.Id, v.Recipient, v.SentAt)));
});

// GET /messages/search is verdwenen. De server doorzocht daar de inhoud van de berichten,
// en die heeft hij niet meer: hij ziet enkel ciphertext. Zoeken op de server kan dus niet
// meer zonder de versleuteling ongedaan te maken. Dat is de prijs van end to end encryptie.
// (Die query plakte trouwens ook de zoekterm en de header X-User rechtstreeks in SQL.)
//
// GET /messages/export is ook verdwenen: het gaf niets wat de inbox niet al toont, en
// elk endpoint minder is een endpoint minder om aan te vallen.

// Eén bericht lezen: OpenFGA beslist (Check op "can_read"). Mag het niet, dan antwoorden
// we 404, net als voor een bericht dat niet bestaat: zo verraden we niet welke id's bestaan.
api.MapGet("/messages/{id:int}", async (int id, ClaimsPrincipal principal, UnbreakableContext db, FgaAuthorizer fga) =>
{
    if (!await fga.CanAsync(CurrentUserId(principal), "can_read", id))
    {
        return Results.NotFound();
    }

    var message = await db.Messages.FindAsync(id);
    return message == null ? Results.NotFound() : Results.Ok((await ToViews(db, new[] { message }))[0]);
});

api.MapPost("/messages", async (Message message, ClaimsPrincipal principal, UnbreakableContext db, FgaAuthorizer fga) =>
{
    // De attributen op het model controleren niets uit zichzelf: een minimal API draait
    // DataAnnotations niet automatisch. Daarom controleren we hier expliciet wat binnenkomt.
    // De server kan de inhoud niet beoordelen (hij heeft de sleutel niet), maar wel de vorm.
    if (message.Ciphertext == null || !Regex.IsMatch(message.Ciphertext, "^[A-Z0-9_]{1,2000}$"))
    {
        return Results.BadRequest("Ciphertext mag enkel A-Z, 0-9 en _ bevatten, hoogstens 2000 tekens.");
    }

    if (message.Mac == null || !Regex.IsMatch(message.Mac, "^[0-9a-f]{64}$"))
    {
        return Results.BadRequest("MAC moet 64 hexadecimale tekens zijn.");
    }

    if (message.KeyLineNr < 1 || message.KeyLineNr > 10000)
    {
        return Results.BadRequest("Het lijnnummer uit het codeboek ligt buiten het bereik.");
    }

    // De ontvanger kies je op naam; bewaard wordt zijn sub.
    var recipientId = string.IsNullOrWhiteSpace(message.Recipient)
        ? null
        : await UserIdFor(db, message.Recipient.Trim());
    if (recipientId == null)
    {
        return Results.BadRequest("Onbekende ontvanger. Een ontvanger moet minstens één keer ingelogd hebben.");
    }

    // De afzender komt ALTIJD uit het gevalideerde token. Wat de client eventueel
    // als "sender" meestuurt, wordt overschreven en dus genegeerd.
    message.Sender = CurrentUserId(principal);
    message.Recipient = recipientId;
    message.Id = 0;
    message.SentAt = DateTime.UtcNow;

    db.Messages.Add(message);
    await db.SaveChangesAsync();

    // De feiten naar de PDP: wie is de afzender, wie de ontvanger. Lukt dat niet, dan
    // halen we het bericht terug weg: een bericht zonder feiten kan niemand lezen.
    try
    {
        await fga.WriteMessageAsync(message.Id, message.Sender, message.Recipient);
    }
    catch (FgaUnavailableException)
    {
        db.Messages.Remove(message);
        await db.SaveChangesAsync();
        throw;
    }

    // Enkel het id terug: de inhoud lezen mag enkel de ontvanger.
    return Results.Created($"/api/messages/{message.Id}", new { id = message.Id });
});

// Verwijderen: OpenFGA beslist (Check op "can_delete"). Mag het niet, dan 404 (zie hierboven).
api.MapDelete("/messages/{id:int}", async (int id, ClaimsPrincipal principal, UnbreakableContext db, FgaAuthorizer fga) =>
{
    if (!await fga.CanAsync(CurrentUserId(principal), "can_delete", id))
    {
        return Results.NotFound();
    }

    var message = await db.Messages.FindAsync(id);
    if (message == null)
    {
        return Results.NotFound();
    }

    db.Messages.Remove(message);
    await db.SaveChangesAsync();

    // De feiten over dit bericht mogen nu ook weg. Lukt dat niet, dan is dat geen
    // veiligheidsprobleem: het bericht bestaat niet meer, en bij de volgende start
    // ruimt de API verouderde feiten op.
    try
    {
        await fga.DeleteMessageAsync(message.Id, message.Sender, message.Recipient);
    }
    catch (FgaUnavailableException ex)
    {
        app.Logger.LogWarning(ex.InnerException, "Feiten over bericht {Id} niet gewist in OpenFGA", id);
    }

    return Results.NoContent();
});

app.Run();

// Wie je bent: de claim "sub" uit het access token dat de API net gevalideerd heeft.
static string CurrentUserId(ClaimsPrincipal principal)
{
    return principal.FindFirstValue("sub");
}

static async Task<string> UserIdFor(UnbreakableContext db, string username)
{
    return await db.Users
        .Where(u => u.Username == username)
        .Select(u => u.Id)
        .FirstOrDefaultAsync();
}

static async Task RememberUser(UnbreakableContext db, string sub, string username)
{
    var user = await db.Users.FindAsync(sub);
    if (user != null && user.Username == username)
    {
        return;
    }

    // Een oude gebruiker met dezelfde naam maar een andere sub (bv. verwijderd en opnieuw
    // aangemaakt in Keycloak) mag de naam niet blijven claimen.
    var stale = await db.Users.Where(u => u.Username == username && u.Id != sub).ToListAsync();
    db.Users.RemoveRange(stale);

    if (user == null)
    {
        db.Users.Add(new AppUser { Id = sub, Username = username });
    }
    else
    {
        user.Username = username;
    }

    try
    {
        await db.SaveChangesAsync();
    }
    catch (DbUpdateException)
    {
        // Twee gelijktijdige eerste verzoeken van dezelfde gebruiker: de andere was sneller.
        db.ChangeTracker.Clear();
    }
}

// Berichten bevatten subs. Naar de SPA sturen we de gebruikersnamen.
static async Task<List<MessageView>> ToViews(UnbreakableContext db, IEnumerable<Message> messages)
{
    var list = messages.ToList();
    var ids = list.SelectMany(m => new[] { m.Sender, m.Recipient }).Distinct().ToList();
    var names = await db.Users
        .Where(u => ids.Contains(u.Id))
        .ToDictionaryAsync(u => u.Id, u => u.Username);

    string NameOf(string id) => id != null && names.TryGetValue(id, out var name) ? name : id;

    return list.Select(m => new MessageView(
        m.Id, NameOf(m.Sender), NameOf(m.Recipient), m.Subject,
        m.Ciphertext, m.KeyLineNr, m.Mac, m.SentAt)).ToList();
}

record MessageView(
    int Id, string Sender, string Recipient, string Subject,
    string Ciphertext, int KeyLineNr, string Mac, DateTime SentAt);

record SentView(int Id, string Recipient, DateTime SentAt);
