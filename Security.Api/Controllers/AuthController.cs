using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Security.Api.DTOs;

namespace Security.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController: ControllerBase
{

    private static List<Models.User> users = new(); 
    [HttpPost("egister")]
    public async Task<IActionResult> Reqister([FromBody]UserDto userDto)
    {
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
        return Ok("My crazy token");
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
}