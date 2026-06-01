using Microsoft.AspNetCore.Mvc;

namespace VulnerableApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    // CWE-798: Hard-coded credentials
    private const string AdminUser = "admin";
    private const string AdminPassword = "admin123";

    // CWE-522: Plaintext credential check + CWE-798 hardcoded creds
    [HttpPost("admin-login")]
    public IActionResult AdminLogin([FromBody] AdminLoginRequest req)
    {
        if (req.Username == AdminUser && req.Password == AdminPassword)
        {
            // CWE-384 / CWE-330: predictable session token
            var token = $"session-{req.Username}-{DateTime.UtcNow.Ticks}";
            return Ok(new { Token = token });
        }
        return Unauthorized();
    }

    // CWE-639: Insecure direct object reference - no authorization on resource access
    [HttpGet("profile/{userId}")]
    public IActionResult Profile(int userId)
    {
        return Ok(new { UserId = userId, Email = $"user{userId}@example.com", Ssn = "123-45-6789" });
    }
}

public class AdminLoginRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
}
