﻿using AuthenticationNoIdenNoDatabase.Service;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationNoIdenNoDatabase.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        private readonly IAuthService _authService;


        public AuthController(IAuthService authService,IConfiguration configuration)
        {
            _authService = authService;
            _configuration = configuration;
        }

        [HttpPost("[action]")]
        public async Task <IActionResult> Register(RegisterDto request)
        {
            var user = await _authService.RegisterAsync(request);

            if (user == null) return BadRequest("UserName has already");

            return Ok(await _authService.GetUsers());
        }

        [HttpPost("[action]")]
        public async Task <IActionResult> Login(LoginDto request)
        {
            var token = await _authService.LoginAsync(request);

           return Ok(token);
        }


        [HttpGet("[action]"),Authorize(Roles = "Admin")]
        public IActionResult test()
        {
            return Ok("คุณมีสิทธื์การเข้าใช้สู่ระบบ");
        }

        [HttpGet("[action]"), Authorize]
        public IActionResult GetTokenDetail()
        {
            var user = User.FindFirstValue(ClaimTypes.Name);

            var role = User.FindFirstValue(ClaimTypes.Role);

            return Ok(new { user, role });
        }


        [HttpGet("[action]"), Authorize]

        public async Task <IActionResult> GetToken()
        {
            var token = _authService.GetTokenDetail();

            return Ok(token);
        }

        [HttpGet("[action]"), Authorize]
        public async Task<IActionResult> GetTokenClaim()
        {
            var accessToken = await HttpContext.GetTokenAsync("access_token");
            return Ok(accessToken);
        }


    }

}
