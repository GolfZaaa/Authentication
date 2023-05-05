namespace AuthenticationNoIdenNoDatabase.Models
{
    public class RegisterDto : LoginDto
    {
        public required int RoleId { get; set; }

    }
}
