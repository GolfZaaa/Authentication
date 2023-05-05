using AuthenticationNoIdenNoDatabase.Data;
using AuthenticationNoIdenNoDatabase.Models;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationNoIdenNoDatabase.Service
{
    public class AuthService : IAuthService
    {
        private readonly IHttpContextAccessor httpContextAccessor;
        private readonly DataContext dataContext;
        private readonly IConfiguration configuration;

        public AuthService(IHttpContextAccessor httpContextAccessor,DataContext dataContext,IConfiguration configuration)
        {
            this.httpContextAccessor = httpContextAccessor;
            this.dataContext = dataContext;
            this.configuration = configuration;
        }

        public async Task<object> GetTokenDetail()
        {
            var user = string.Empty;
            var role = string.Empty;
            if(httpContextAccessor.HttpContext != null)
            {
                user = httpContextAccessor.HttpContext.User.Identity.Name;
                role = httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Role);
            }

            return (new { user, role });
        }

        public async Task<List<User>> GetUsers()
        {
              return await dataContext.Users.OrderByDescending(x=>x.Id).ToListAsync();
        }

        public async Task<string> LoginAsync(LoginDto request)
        {

            var user = await dataContext.Users.Include(x=>x.Role).FirstOrDefaultAsync(x => x.Username.Equals(request.Username));

            if (user == null) { return "UserName Wrong"; }

            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash )) { return "Password Wrong"; }

            string token = CreateToken(user);

            return token;

        }

        public async Task<User> RegisterAsync(RegisterDto request)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            var result = await dataContext.Users.FirstOrDefaultAsync(x => x.Username.Equals(request.Username));

            if (result != null) return null;

            var user = new User()
            {
                Username = request.Username,
                PasswordHash = passwordHash,
                RoleId = request.RoleId
            };

            try
            {
                await dataContext.Users.AddAsync(user);

                await dataContext.SaveChangesAsync();
            }
            catch(Exception ex)
            {
                return null;
            }
            
            return user;
        }


        private string CreateToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["AppSettings:Token"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512Signature);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name,user.Username),
                new Claim(ClaimTypes.Role,user.Role.Name),
            };

            var token = new JwtSecurityToken(
                issuer: configuration["JWT:Issuer"],
                audience: configuration["JWT:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: credentials);


            return new JwtSecurityTokenHandler().WriteToken(token);

        }


    }
}
