using Microsoft.EntityFrameworkCore;
using Unbreakable.Models;

namespace Unbreakable.Data;

public class UnbreakableContext : DbContext
{
    public UnbreakableContext(DbContextOptions<UnbreakableContext> options)
        : base(options)
    {
    }

    public DbSet<Message> Messages { get; set; }

    public DbSet<AppUser> Users { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Een gebruikersnaam hoort bij precies één sub.
        modelBuilder.Entity<AppUser>().HasIndex(u => u.Username).IsUnique();
    }
}
