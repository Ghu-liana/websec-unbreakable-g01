using System.ComponentModel.DataAnnotations;

namespace Unbreakable.Models;

// Een gebruiker zoals de identity provider (Keycloak) hem kent.
// Id is de claim "sub": uniek en onveranderlijk, en dus wat we in een bericht bewaren.
// Username is de claim "preferred_username": enkel om te tonen en om een ontvanger
// op naam te kunnen kiezen. Beide komen uit een gevalideerd token, nooit van de client.
public class AppUser
{
    [Key]
    [StringLength(64)]
    public string Id { get; set; }

    [Required]
    [StringLength(255)]
    public string Username { get; set; }
}
