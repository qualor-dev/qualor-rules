namespace RazorXss.Models;

/// The view model of a user's profile page: the controller fills it and the Razor view renders it.
public class UserProfile
{
    public string Name { get; set; }

    public string Bio { get; set; }
}
