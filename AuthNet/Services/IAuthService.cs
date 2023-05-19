using AuthNet.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthNet.Services
{
    public interface IAuthService
    {
        Task<ActionResult<User>> Register(UserDto request);
        Task<ActionResult<User>> Login(UserDto request);
        string CreateToken(User user);
    }
}
