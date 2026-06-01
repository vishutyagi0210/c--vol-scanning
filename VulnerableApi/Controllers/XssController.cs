using Microsoft.AspNetCore.Mvc;

namespace VulnerableApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class XssController : ControllerBase
{
    // CWE-79: Reflected XSS - user input written into HTML response unescaped
    [HttpGet("hello")]
    [Produces("text/html")]
    public IActionResult Hello([FromQuery] string name)
    {
        var html = "<html><body><h1>Hello, " + name + "!</h1></body></html>";
        return Content(html, "text/html");
    }

    // CWE-117: Log injection - unsanitized input written to log
    [HttpGet("log")]
    public IActionResult Log([FromQuery] string message, [FromServices] ILogger<XssController> logger)
    {
        logger.LogInformation("User said: " + message);
        return Ok();
    }
}
