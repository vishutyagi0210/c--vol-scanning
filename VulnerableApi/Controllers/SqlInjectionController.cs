using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace VulnerableApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SqlInjectionController : ControllerBase
{
    private readonly string _connectionString;

    public SqlInjectionController(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("Default");
    }

    // CWE-89: SQL Injection via string concatenation
    [HttpGet("user")]
    public IActionResult GetUser([FromQuery] string username)
    {
        var query = "SELECT Id, Username, Email FROM Users WHERE Username = '" + username + "'";

        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        using var cmd = new SqlCommand(query, conn);
        using var reader = cmd.ExecuteReader();

        var results = new List<object>();
        while (reader.Read())
        {
            results.Add(new { Id = reader[0], Username = reader[1], Email = reader[2] });
        }
        return Ok(results);
    }

    // CWE-89: SQL Injection via string interpolation
    [HttpGet("search")]
    public IActionResult Search([FromQuery] string term)
    {
        var query = $"SELECT * FROM Products WHERE Name LIKE '%{term}%'";

        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        using var cmd = new SqlCommand(query, conn);
        var count = cmd.ExecuteScalar();
        return Ok(new { Query = query, Count = count });
    }

    // CWE-89 + CWE-209: Returns the raw exception details to the caller
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest req)
    {
        try
        {
            var sql = "SELECT COUNT(*) FROM Users WHERE Username = '" + req.Username +
                      "' AND Password = '" + req.Password + "'";
            using var conn = new SqlConnection(_connectionString);
            conn.Open();
            using var cmd = new SqlCommand(sql, conn);
            var count = (int)cmd.ExecuteScalar();
            return Ok(new { Authenticated = count > 0, Sql = sql });
        }
        catch (Exception ex)
        {
            // CWE-209: leaks stack trace and internal details
            return StatusCode(500, new { Error = ex.ToString() });
        }
    }
}

public class LoginRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
}
