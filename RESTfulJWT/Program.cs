using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;


public class Program
{
    public static void Main(string[] args)
    {
        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();
            });
}
public class User
{
    public User()
    {
        // Initialize properties in the constructor
        Username = string.Empty;
        Password = string.Empty;
    }

    public string Username { get; set; }
    public string Password { get; set; }
}

public class UserService
{
    private List<User> _users;

    public UserService()
    {
        _users = new List<User>
        {
            new User { Username = "user1", Password = "password1" },
            new User { Username = "user2", Password = "password2" }
        };   
    }

    public User GetUserByUsername(string username)
    {
        //return _users.FirstOrDefault(u => u.Username == username);
        return _users?.FirstOrDefault(u => u.Username == username) ?? new User();

    }
}

public class JwtHandler
{
    private readonly byte[] _secretKey;

    public JwtHandler(byte[] secretKey)
    {
        _secretKey = secretKey;
    }

    public string GenerateToken(string username)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        try
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, username) }),
                Expires = DateTime.UtcNow.AddHours(1),
                NotBefore = DateTime.UtcNow,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_secretKey), SecurityAlgorithms.HmacSha256)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error generating token: {ex.Message}");
            throw;
        }
    }

    public ClaimsPrincipal ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(_secretKey),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        try
        {
            return tokenHandler.ValidateToken(token, validationParameters, out _);
        }
        catch
        {
            return null;
        }
    }


}

[ApiController]
[Route("api/[controller]")]
public class SecureController : ControllerBase
{
    [HttpGet]
    [Authorize]
    public IActionResult GetSecureData()
    {
        // This action can only be accessed by authenticated users
        return Ok("This is secure data!");
    }
}

[ApiController]
[Route("api/[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly UserService _userService;
    private readonly JwtHandler _jwtHandler;

    public AuthenticationController(UserService userService, JwtHandler jwtHandler)
    {
        _userService = userService;
        _jwtHandler = jwtHandler;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] User user)
{
        var authenticatedUser = _userService.GetUserByUsername(user.Username);

        if (authenticatedUser == null || authenticatedUser.Password != user.Password)
        {
            return Unauthorized();
        }

        var key = Encoding.ASCII.GetBytes("your-secret-key"); // Replace with your actual secret key

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, authenticatedUser.Username) }),
            Expires = DateTime.UtcNow.AddHours(1), // Token expiration time
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = _jwtHandler.GenerateToken(authenticatedUser.Username);

        return Ok(new { Token = token });
    }
}

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthentication();

        services.AddControllers();
        services.AddSingleton<UserService>(); 
        var secretKey = GenerateRandomKey(32); // 32 bytes for a 256-bit key
        services.AddSingleton(new JwtHandler(secretKey));
    }

    private byte[] GenerateRandomKey(int length)
    {
        var key = new byte[length];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(key);
        }
        return key;
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
        });
    }
}
