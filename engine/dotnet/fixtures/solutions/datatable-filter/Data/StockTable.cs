using System.Data;

namespace Warehouse.Data;

// Stock levels cached in memory as a DataTable and searched with DataColumn filter expressions
// (learn.microsoft.com: DataTable.Select, DataView.RowFilter, DataColumn.Expression).
public sealed class StockTable
{
    private readonly DataTable _stock = new("Stock");

    public StockTable()
    {
        _stock.Columns.Add("Sku", typeof(string));
        _stock.Columns.Add("Site", typeof(string));
        _stock.Columns.Add("Quantity", typeof(int));
    }

    public int Available(string site, string skuPrefix)
    {
        var filter = $"Site = '{site}' AND Sku LIKE '{skuPrefix}*' AND Quantity > 0";
        // ruleid: csharp.sql-injection
        return _stock.Select(filter, "Sku ASC").Length;
    }

    public DataView ForSite(string site)
    {
        var view = _stock.DefaultView;
        // ruleid: csharp.sql-injection
        view.RowFilter = "Site = '" + site + "'";
        return view;
    }

    public int Empty(string orderBy)
    {
        // ok: csharp.sql-injection
        return _stock.Select("Quantity = 0", orderBy).Length;
    }

    public object Total(string bin)
    {
        // ok: csharp.sql-injection
        return _stock.Compute("Sum(Quantity)", "Bin = " + int.Parse(bin));
    }
}
