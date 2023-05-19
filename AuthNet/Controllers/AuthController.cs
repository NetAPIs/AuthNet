using AuthNet.Data;
using AuthNet.Models;
using AuthNet.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();

        private readonly IConfiguration _configuration;
        private readonly DataContext _context;
        private readonly IAuthService _service;

        public IAuthService Service { get; }

        public AuthController(IConfiguration configuration, DataContext context, IAuthService service) 
        {
            _configuration = configuration;
            _context = context;
            _service = service;
        }

        [HttpGet, Authorize]
        public ActionResult<string> GetMyName()
        {
            var userName = User?.Identity?.Name;
            var role = User?.FindFirstValue(ClaimTypes.Role);
            return Ok(new { userName, role });
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            return await _service.Register(request);
        }


        [HttpPost("login")]
        public async Task<ActionResult<User>> Login(UserDto request)
        {
            return await _service.Login(request);
        }


        private string CreateToken(User user)
        {
            return _service.CreateToken(user);
        }
    }
}
