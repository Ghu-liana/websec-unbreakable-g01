using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using Unbreakable.Data;
using Unbreakable.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<UnbreakableContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("Unbreakable")));

builder.Services.AddCors(options =>
    options.AddDefaultPolicy(policy => policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

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

app.MapGet("/health", () => "ok");

// De API. Wie je bent, staat voorlopig in de header X-User.
var api = app.MapGroup("/api");

api.MapGet("/users", async (UnbreakableContext db) =>
{
    var senders = await db.Messages.Select(m => m.Sender).Distinct().ToListAsync();
    var recipients = await db.Messages.Select(m => m.Recipient).Distinct().ToListAsync();

    // De vaste namen erbij, anders is de lijst leeg zolang er nog geen bericht verstuurd is.
    return Results.Ok(senders
        .Union(recipients)
        .Union(SeedData.DemoUsers)
        .OrderBy(name => name)
        .ToList());
});

api.MapGet("/messages", async (HttpRequest request, UnbreakableContext db) =>
{
    var user = CurrentUser(request);
    if (string.IsNullOrEmpty(user))
    {
        return Results.Unauthorized();
    }

    var inbox = db.Messages.Where(m => m.Recipient == user);

    var from = request.Query["from"].ToString();
    if (!string.IsNullOrEmpty(from))
    {
        inbox = inbox.Where(m => m.Sender == from);
    }

    return Results.Ok(await inbox.OrderByDescending(m => m.SentAt).ToListAsync());
});

// GET /messages/search is verdwenen. De server doorzocht daar de inhoud van de berichten,
// en die heeft hij niet meer: hij ziet enkel ciphertext. Zoeken op de server kan dus niet
// meer zonder de versleuteling ongedaan te maken. Dat is de prijs van end to end encryptie.
// (Die query plakte trouwens ook de zoekterm en de header X-User rechtstreeks in SQL.)

api.MapGet("/messages/export", async (HttpRequest request, UnbreakableContext db) =>
{
    var user = CurrentUser(request);
    if (string.IsNullOrEmpty(user))
    {
        return Results.Unauthorized();
    }

    var messages = await db.Messages
        .Where(m => m.Recipient == user)
        .OrderBy(m => m.SentAt)
        .ToListAsync();

    return Results.Text(JsonConvert.SerializeObject(messages, Formatting.Indented), "application/json");
});

api.MapGet("/messages/{id:int}", async (int id, UnbreakableContext db) =>
{
    var message = await db.Messages.FindAsync(id);
    return message == null ? Results.NotFound() : Results.Ok(message);
});

api.MapPost("/messages", async (Message message, HttpRequest request, UnbreakableContext db) =>
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

    // Geen afzender meegegeven? Dan nemen we wie je bent.
    if (string.IsNullOrEmpty(message.Sender))
    {
        message.Sender = CurrentUser(request);
    }

    message.Id = 0;
    message.SentAt = DateTime.UtcNow;

    db.Messages.Add(message);
    await db.SaveChangesAsync();

    return Results.Created($"/api/messages/{message.Id}", message);
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

static string CurrentUser(HttpRequest request)
{
    return request.Headers["X-User"].ToString();
}
