using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
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

api.MapGet("/users", async (UnbreakableContext db) =>
{
    return Results.Ok(await db.Users
        .OrderBy(u => u.Username)
        .Select(u => u.Username)
        .ToListAsync());
});

api.MapGet("/messages", async (HttpRequest request, ClaimsPrincipal principal, UnbreakableContext db) =>
{
    var user = CurrentUserId(principal);

    var inbox = db.Messages.Where(m => m.Recipient == user);

    var from = request.Query["from"].ToString();
    if (!string.IsNullOrEmpty(from))
    {
        var fromId = await UserIdFor(db, from);
        inbox = inbox.Where(m => m.Sender == fromId);
    }

    var messages = await inbox.OrderByDescending(m => m.SentAt).ToListAsync();
    return Results.Ok(await ToViews(db, messages));
});

// GET /messages/search is verdwenen. De server doorzocht daar de inhoud van de berichten,
// en die heeft hij niet meer: hij ziet enkel ciphertext. Zoeken op de server kan dus niet
// meer zonder de versleuteling ongedaan te maken. Dat is de prijs van end to end encryptie.
// (Die query plakte trouwens ook de zoekterm en de header X-User rechtstreeks in SQL.)

api.MapGet("/messages/export", async (ClaimsPrincipal principal, UnbreakableContext db) =>
{
    var user = CurrentUserId(principal);

    var messages = await db.Messages
        .Where(m => m.Recipient == user)
        .OrderBy(m => m.SentAt)
        .ToListAsync();

    var views = await ToViews(db, messages);
    return Results.Text(JsonConvert.SerializeObject(views, Formatting.Indented), "application/json");
});

api.MapGet("/messages/{id:int}", async (int id, UnbreakableContext db) =>
{
    var message = await db.Messages.FindAsync(id);
    return message == null ? Results.NotFound() : Results.Ok((await ToViews(db, new[] { message }))[0]);
});

api.MapPost("/messages", async (Message message, ClaimsPrincipal principal, UnbreakableContext db) =>
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

    return Results.Created($"/api/messages/{message.Id}", (await ToViews(db, new[] { message }))[0]);
});

api.MapDelete("/messages/{id:int}", async (int id, UnbreakableContext db) =>
{
    var message = await db.Messages.FindAsync(id);
    if (message == null)
    {
        return Results.NotFound();
    }

    db.Messages.Remove(message);
    await db.SaveChangesAsync();
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
