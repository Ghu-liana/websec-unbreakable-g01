using System.ComponentModel.DataAnnotations;

namespace Unbreakable.Models;

// Let op: de kolom met het bericht zelf bestaat niet meer. De browser versleutelt,
// en wat hier binnenkomt en bewaard wordt, is enkel nog ciphertext.
public class Message
{
    public int Id { get; set; }

    [Required]
    [StringLength(40, MinimumLength = 2)]
    [Display(Name = "Van")]
    public string Sender { get; set; }

    [Required]
    [StringLength(40, MinimumLength = 2)]
    [Display(Name = "Aan")]
    public string Recipient { get; set; }

    // Het onderwerp blijft bewust leesbaar: het is metadata die de app nodig heeft om
    // een inbox te tonen. De beheerder van de server ziet dit dus nog, en dat staat zo
    // in het threat model.
    [Required]
    [StringLength(100)]
    [Display(Name = "Onderwerp")]
    public string Subject { get; set; }

    // Het versleutelde bericht: enkel tekens uit het alfabet van modulo 37.
    [Required]
    [StringLength(2000)]
    [RegularExpression("^[A-Z0-9_]+$")]
    [Display(Name = "Ciphertext")]
    public string Ciphertext { get; set; }

    // Welke lijn uit het codeboek de verzender gebruikte. De sleutel zelf staat hier
    // nergens: zonder het codeboek zegt dit nummer niets.
    [Range(1, 10000)]
    [Display(Name = "Lijn uit het codeboek")]
    public int KeyLineNr { get; set; }

    // HMAC-SHA256 over de ciphertext en het lijnnummer, als 64 hexadecimale tekens.
    [Required]
    [RegularExpression("^[0-9a-f]{64}$")]
    [Display(Name = "MAC")]
    public string Mac { get; set; }

    [Display(Name = "Verzonden")]
    public DateTime SentAt { get; set; }
}
