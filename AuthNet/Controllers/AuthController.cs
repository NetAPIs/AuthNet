using AuthNet.Data;
using AuthNet.Models;
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

        public AuthController(IConfiguration configuration, DataContext context) 
        {
            _configuration = configuration;
            _context = context;
        }

        [HttpGet, Authorize]
        public ActionResult<string> GetMyName()
        {
            var userName = User?.Identity?.Name;
            var role = User?.FindFirstValue(ClaimTypes.Role);
            return Ok(new { userName, role });
        }

        [HttpPost("register")]
        public ActionResult<User> Register(UserDto request)
        {
            try
            {
                string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

                var user = new User
                {
                    UserName = request.UserName,
                    PasswordHash = passwordHash
                };

                var existingUser = _context.Users.FirstOrDefault(u => u.UserName == user.UserName);

                if (existingUser != null)
                {
                    return BadRequest("Username already exists!");
                }

                _context.Users.Add(user);
                _context.SaveChanges();

                return Ok(user);
            }
            catch (Exception)
            {                
                return StatusCode(500, "An error occurred during registration");
            }
        }


        [HttpPost("login")]
        public ActionResult<User> Login(UserDto request)
        {
            try
            {
                var user = _context.Users.SingleOrDefault(u => u.UserName == request.UserName);

                if (user == null)
                {
                    return BadRequest("User does not exist!");
                }

                var isUsernameCorrect = user.UserName == request.UserName;
                var isPasswordCorrect = BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash);

                if (!isUsernameCorrect || !isPasswordCorrect)
                {
                    return BadRequest("Invalid username or password!");
                }

                string token = CreateToken(user);

                return Ok(token);
            }
            catch (Exception)
            {                
                return StatusCode(500, "An error occurred during login.");
            }
        }


        private string CreateToken(User user)
        {
            Console.WriteLine($"User object: {user}");
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim(ClaimTypes.Role, "User")
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value!));

            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddDays(1),
                    signingCredentials: cred
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}
