namespace Shop.Domain;

public interface IOrderService
{
    int CountByCustomer(string customer);
    int CountByStatus(string status);
    int CountAll(string note);
}
