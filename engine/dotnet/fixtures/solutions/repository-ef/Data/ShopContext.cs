using Microsoft.EntityFrameworkCore;

namespace Catalog.Data;

public class Product
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string Category { get; set; }
}

public class ShopContext : DbContext
{
    public ShopContext(DbContextOptions<ShopContext> options) : base(options) { }

    public DbSet<Product> Products { get; set; }
}
