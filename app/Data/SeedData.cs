namespace Unbreakable.Data;

public static class SeedData
{
    // Vroeger stonden hier vijf voorbeeldberichten in plaintext, waaronder een met een
    // wachtwoord erin. Die zijn weg: de app kan geen leesbare berichten meer bewaren,
    // en een voorbeeldbericht met ciphertext zou een sleutel in deze repo vereisen.
    //
    // Wat blijft, zijn de namen. De lijst met gekende gebruikers kwam uit de berichten,
    // dus zonder deze lijst zou de app geen enkele naam meer kunnen voorstellen.
    public static readonly string[] DemoUsers = { "Anna", "Bram", "Chris" };
}
