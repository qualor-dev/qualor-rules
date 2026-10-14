using Microsoft.EntityFrameworkCore;

namespace Catalog.Data;

public interface IProductRepository
{
    List<Product> SearchByName(string name);
    List<Product> ByCategory(string category);
    List<Product> Newest(string unused);
}

public class ProductRepository : IProductRepository
{
    private readonly ShopContext _context;

    public ProductRepository(ShopContext context) => _context = context;

    public List<Product> SearchByName(string name)
    {
        // ruleid: csharp.sql-injection
        return _context.Products.FromSqlRaw("SELECT * FROM Products WHERE Name LIKE '%" + name + "%'").ToList();
    }

    public List<Product> ByCategory(string category)
    {
        // ok: csharp.sql-injection
        return _context.Products.FromSqlRaw("SELECT * FROM Products WHERE Category = {0}", category).ToList();
    }

    public List<Product> Newest(string unused)
    {
        // ok: csharp.sql-injection
        return _context.Products.FromSqlRaw("SELECT TOP 10 * FROM Products ORDER BY Id DESC").ToList();
    }
}
