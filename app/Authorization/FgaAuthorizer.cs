using Microsoft.EntityFrameworkCore;
using OpenFga.Sdk.Client;
using OpenFga.Sdk.Client.Model;
using OpenFga.Sdk.Configuration;
using Unbreakable.Data;

namespace Unbreakable.Authorization;

// OpenFGA kan niet antwoorden. De API weigert dan (fail closed): bij twijfel geen toegang.
public class FgaUnavailableException : Exception
{
    public FgaUnavailableException(string message, Exception inner) : base(message, inner) { }
}

// Dun laagje rond de OpenFGA-SDK. Hier staan GEEN autorisatieregels: die staan enkel in
// het model (openfga/model.fga). Deze klasse schrijft feiten weg (wie is afzender, wie is
// ontvanger) en stelt vragen ("mag deze gebruiker dit?"). Het antwoord komt van OpenFGA.
public class FgaAuthorizer
{
    private const string MessageType = "message";

    private readonly OpenFgaClient _client;
    private readonly string _storeName;
    private readonly string _modelFile;
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<FgaAuthorizer> _logger;
    private readonly SemaphoreSlim _initLock = new(1, 1);
    private volatile bool _ready;

    public FgaAuthorizer(IConfiguration configuration, IServiceScopeFactory scopes, ILogger<FgaAuthorizer> logger)
    {
        var apiUrl = configuration["Fga:ApiUrl"]
            ?? throw new InvalidOperationException("Fga:ApiUrl ontbreekt in de configuratie.");
        var apiToken = configuration["Fga:ApiToken"]
            ?? throw new InvalidOperationException("Fga:ApiToken ontbreekt in de configuratie.");

        _storeName = configuration["Fga:StoreName"] ?? "unbreakable";
        _modelFile = configuration["Fga:ModelFile"] ?? Path.Combine(AppContext.BaseDirectory, "openfga", "model.json");
        _scopes = scopes;
        _logger = logger;

        // OpenFGA vraagt ook intern een sleutel (preshared key).
        _client = new OpenFgaClient(new ClientConfiguration
        {
            ApiUrl = apiUrl,
            Credentials = new Credentials
            {
                Method = CredentialsMethod.ApiToken,
                Config = new CredentialsConfig { ApiToken = apiToken },
            },
        });
    }

    // Bij het opstarten: blijven proberen tot OpenFGA klaar is, zonder de app te laten crashen.
    public async Task WarmUpAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 1; attempt <= 30 && !cancellationToken.IsCancellationRequested; attempt++)
        {
            try
            {
                await EnsureReadyAsync();
                return;
            }
            catch (FgaUnavailableException ex)
            {
                _logger.LogWarning("OpenFGA nog niet klaar ({Error}), poging {Attempt}", ex.InnerException?.Message, attempt);
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
            }
        }
    }

    // Store zoeken of aanmaken, en het model opladen. Lukt dat niet bij het opstarten,
    // dan probeert elk verzoek het opnieuw.
    private async Task EnsureReadyAsync()
    {
        if (_ready)
        {
            return;
        }

        await _initLock.WaitAsync();
        try
        {
            if (_ready)
            {
                return;
            }

            await Guard(async () =>
            {
                _client.StoreId = await FindOrCreateStoreAsync();

                // Het model staat in een bestand, niet in de code. Bij elke start wordt het
                // opnieuw opgeladen: OpenFGA bewaart elke versie, en we gebruiken de nieuwste.
                var modelJson = await File.ReadAllTextAsync(_modelFile);
                var model = await _client.WriteAuthorizationModel(ClientWriteAuthorizationModelRequest.FromJson(modelJson));
                _client.AuthorizationModelId = model.AuthorizationModelId;

                await ReconcileAsync();
            });

            _ready = true;
            _logger.LogInformation("OpenFGA klaar: store {StoreId}, model {ModelId}", _client.StoreId, _client.AuthorizationModelId);
        }
        finally
        {
            _initLock.Release();
        }
    }

    private async Task<string> FindOrCreateStoreAsync()
    {
        string continuationToken = null;
        do
        {
            var page = await _client.ListStores(null, new ClientListStoresOptions { ContinuationToken = continuationToken });
            var existing = page.Stores.FirstOrDefault(s => s.Name == _storeName);
            if (existing != null)
            {
                return existing.Id;
            }
            continuationToken = page.ContinuationToken;
        } while (!string.IsNullOrEmpty(continuationToken));

        var created = await _client.CreateStore(new ClientCreateStoreRequest { Name = _storeName });
        _logger.LogInformation("OpenFGA-store {StoreName} aangemaakt", _storeName);
        return created.Id;
    }

    // Bij het opstarten trekken we de feiten in OpenFGA gelijk met de berichten in de databank:
    //  - ontbrekende feiten bijschrijven (bv. de allereerste keer, voor berichten die er al
    //    waren), anders ziet niemand die berichten nog;
    //  - feiten over berichten die niet (meer) bestaan wissen. Wordt de databank ooit gewist,
    //    dan beginnen de id's opnieuw bij 1, en mag een oud feit over message:1 geen toegang
    //    geven tot een NIEUW bericht met dat id.
    // Eerst OpenFGA lezen, dan de databank: een bericht dat tussendoor aangemaakt wordt,
    // staat zo zeker in de databank-lijst, en zijn feiten worden dus nooit gewist.
    private async Task ReconcileAsync()
    {
        var actual = new HashSet<(string User, string Relation, string Object)>();
        string continuationToken = null;
        do
        {
            var page = await _client.Read(new ClientReadRequest(), new ClientReadOptions { PageSize = 100, ContinuationToken = continuationToken });
            foreach (var tuple in page.Tuples)
            {
                actual.Add((tuple.Key.User, tuple.Key.Relation, tuple.Key.Object));
            }
            continuationToken = page.ContinuationToken;
        } while (!string.IsNullOrEmpty(continuationToken));

        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<UnbreakableContext>();
        var messages = await db.Messages
            .Select(m => new { m.Id, m.Sender, m.Recipient })
            .ToListAsync();

        var desired = messages
            .SelectMany(m => Facts(m.Id, m.Sender, m.Recipient))
            .Select(t => (t.User, t.Relation, t.Object))
            .ToHashSet();

        var toDelete = actual.Except(desired).ToList();
        var toWrite = desired.Except(actual).ToList();

        // OpenFGA aanvaardt hoogstens 100 tuples per aanvraag.
        foreach (var chunk in toDelete.Chunk(100))
        {
            await _client.DeleteTuples(chunk
                .Select(t => new ClientTupleKeyWithoutCondition { User = t.User, Relation = t.Relation, Object = t.Object })
                .ToList());
        }
        foreach (var chunk in toWrite.Chunk(100))
        {
            await _client.WriteTuples(chunk
                .Select(t => new ClientTupleKey { User = t.User, Relation = t.Relation, Object = t.Object })
                .ToList());
        }

        if (toDelete.Count > 0 || toWrite.Count > 0)
        {
            _logger.LogInformation("OpenFGA gelijkgetrokken: {Written} feiten bijgeschreven, {Deleted} verouderde feiten gewist",
                toWrite.Count, toDelete.Count);
        }
    }

    // ------------------------------------------------------------------ vragen

    // Check: mag deze gebruiker deze relatie hebben met dit bericht?
    public async Task<bool> CanAsync(string userId, string relation, int messageId)
    {
        await EnsureReadyAsync();
        return await Guard(async () =>
        {
            var response = await _client.Check(new ClientCheckRequest
            {
                User = UserObject(userId),
                Relation = relation,
                Object = MessageObject(messageId),
            });
            return response.Allowed == true;
        });
    }

    // ListObjects: op welke berichten heeft deze gebruiker deze relatie?
    public async Task<List<int>> ListAsync(string userId, string relation)
    {
        await EnsureReadyAsync();
        return await Guard(async () =>
        {
            var response = await _client.ListObjects(new ClientListObjectsRequest
            {
                User = UserObject(userId),
                Relation = relation,
                Type = MessageType,
            });

            return response.Objects
                .Select(o => o.StartsWith(MessageType + ":") && int.TryParse(o[(MessageType.Length + 1)..], out var id) ? id : (int?)null)
                .Where(id => id.HasValue)
                .Select(id => id.Value)
                .ToList();
        });
    }

    // ------------------------------------------------------------------ feiten

    // Bij een nieuw bericht: wie is de afzender, wie is de ontvanger.
    public async Task WriteMessageAsync(int messageId, string senderId, string recipientId)
    {
        await EnsureReadyAsync();
        await Guard(() => _client.WriteTuples(Facts(messageId, senderId, recipientId)));
    }

    // Bij het verwijderen van een bericht: de feiten erover mogen ook weg.
    public async Task DeleteMessageAsync(int messageId, string senderId, string recipientId)
    {
        await EnsureReadyAsync();
        await Guard(() => _client.DeleteTuples(Facts(messageId, senderId, recipientId)
            .Select(t => new ClientTupleKeyWithoutCondition { User = t.User, Relation = t.Relation, Object = t.Object })
            .ToList()));
    }

    // ------------------------------------------------------------------ hulp

    private static List<ClientTupleKey> Facts(int messageId, string senderId, string recipientId) => new()
    {
        new ClientTupleKey { User = UserObject(senderId), Relation = "sender", Object = MessageObject(messageId) },
        new ClientTupleKey { User = UserObject(recipientId), Relation = "recipient", Object = MessageObject(messageId) },
    };

    private static string UserObject(string userId) => $"user:{userId}";

    private static string MessageObject(int messageId) => $"{MessageType}:{messageId}";

    // Elke fout van of naar OpenFGA wordt een FgaUnavailableException: de API weigert dan.
    private static async Task Guard(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (Exception ex) when (ex is not FgaUnavailableException)
        {
            throw new FgaUnavailableException("OpenFGA gaf geen geldig antwoord.", ex);
        }
    }

    private static async Task<T> Guard<T>(Func<Task<T>> action)
    {
        try
        {
            return await action();
        }
        catch (Exception ex) when (ex is not FgaUnavailableException)
        {
            throw new FgaUnavailableException("OpenFGA gaf geen geldig antwoord.", ex);
        }
    }
}
