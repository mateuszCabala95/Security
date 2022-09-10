using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Security.Api.DTOs;
using Security.Api.Models;

namespace Security.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController: ControllerBase
{
    private static List<User> users = new();
    private readonly IConfiguration _configuration;
    public AuthController(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    [HttpPost("register")]
    public async Task<IActionResult> Reqister([FromBody]UserDto userDto)
    {
        if (users.Any(x => x.UserName == userDto.Username)) return BadRequest("User already exist");
        
        CreatePasswordHash(userDto.Password, out var passwordHash, out var passwordSalt);

        var newUser = new Models.User
        {
            UserName = userDto.Username,
            PasswordHash = passwordHash,
            PasswordSalt = passwordSalt
        };
        users.Add(newUser);
        
        return Ok(newUser);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] UserDto userDto)
    {
        var user = users.SingleOrDefault(x => x.UserName == userDto.Username);
        if (user is null) return BadRequest("User not exist");

        if (!VerifyPasswordHash(userDto.Password, user.PasswordHash, user.PasswordSalt))
        {
            return BadRequest("Wrong Password");
        }
        return Ok(CreateToken(user));
    }

    [HttpGet("isvalid/{userName}")]
    public async Task<IActionResult> IsValidToken([FromQuery] string userName, [FromBody] string jwt)
    {
        return Ok(true);
    }

    private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
    {
        using var hmac = new HMACSHA512();
        passwordSalt = hmac.Key;
        passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
    }

    private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
    {
        using var hmac = new HMACSHA512(passwordSalt);
        var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

        return computedHash.SequenceEqual(passwordHash);
    }

    private string CreateToken(User user)
    {
        List<Claim> claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName),
        };

        var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("Jwt:SecretKey").Value));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: creds);

        var jwt = new JwtSecurityTokenHandler().WriteToken(token);

        return jwt;
    }
}