namespace AuthenticationNoIdenNoDatabase.Service
{
    public interface IAuthService
    {
        Task<List<User>> GetUsers();
        Task<User> RegisterAsync(RegisterDto request);
        Task<string> LoginAsync(LoginDto request);
        Task<Object> GetTokenDetail();
    }
}
