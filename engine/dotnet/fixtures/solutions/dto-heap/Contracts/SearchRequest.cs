namespace Library.Contracts;

public class SearchRequest
{
    public string Title { get; set; }
    public string Author { get; set; }
    public int PageSize { get; set; }
}
