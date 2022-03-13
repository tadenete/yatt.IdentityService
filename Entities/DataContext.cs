namespace IdentityService.Entities;
using Microsoft.EntityFrameworkCore;

public class DataContext : DbContext
{
    private readonly IConfiguration _configuration;
    public DbSet<User> Users { get; set; }
    public DbSet<Organization> Organizations { get; set; }
    public DbSet<UserOrganization> UserOrganizations { get; set; }

    public DataContext(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        options.UseSqlServer(_configuration.GetConnectionString("IdentityServiceDatabase"));
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        //configure primary key for link entity.
        modelBuilder.Entity<UserOrganization>().HasKey(x => new { x.UserId, x.OrganizationId });


        //configure many-to-many relations
        modelBuilder.Entity<UserOrganization>()
            .HasOne<User>(x => x.User)
            .WithMany(y => y.UserOrganizations)
            .HasForeignKey(x => x.UserId);

        modelBuilder.Entity<UserOrganization>()
            .HasOne<Organization>(x => x.Organization)
            .WithMany(y => y.IdentityOrganizations)
            .HasForeignKey(x => x.OrganizationId);
    }
}