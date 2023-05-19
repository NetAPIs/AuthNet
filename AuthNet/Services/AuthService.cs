using AuthNet.Data;
using AuthNet.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthNet.Services
{
    public class AuthService : IAuthService
    {
        private readonly DataContext _context;
        private readonly IConfiguration _configuration;

        public AuthService(DataContext context, IConfiguration configuration) 
        {
            _context = context;
            _configuration = configuration;
        }

        public string CreateToken(User user)
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

        public async Task<ActionResult<User>> Login(UserDto request)
        {
            try
            {
                var user = _context.Users.SingleOrDefault(u => u.UserName == request.UserName);

                if (user == null)
                {
                    return new BadRequestObjectResult("User does not exist!");
                }

                var isUsernameCorrect = user.UserName == request.UserName;
                var isPasswordCorrect = BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash);

                if (!isUsernameCorrect || !isPasswordCorrect)
                {
                    return new BadRequestObjectResult("Invalid username or password!");
                }

                string token = CreateToken(user);

                return new ObjectResult(token);
            }
            catch (Exception)
            {
                return new StatusCodeResult(500);
            }
        }

        public async Task<ActionResult<User>> Register(UserDto request)
        {
            try
            {
                string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

                var user = new User
                {
                    UserName = request.UserName,
                    PasswordHash = passwordHash
                };

                var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.UserName == user.UserName);

                if (existingUser != null)
                {
                    return new BadRequestObjectResult("Username already exists!");
                }

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                return new OkObjectResult(user);
            }
            catch (Exception)
            {                
                return new StatusCodeResult(500);
            }
        }
    }
}
