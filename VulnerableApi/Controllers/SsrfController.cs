using Microsoft.AspNetCore.Mvc;

namespace VulnerableApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SsrfController : ControllerBase
{
    private static readonly HttpClient Client = new HttpClient();

    // CWE-918: Server-Side Request Forgery - user URL fetched without validation
    [HttpGet("fetch")]
    public async Task<IActionResult> Fetch([FromQuery] string url)
    {
        var response = await Client.GetStringAsync(url);
        return Content(response);
    }

    // CWE-601: Open Redirect
    [HttpGet("redirect")]
    public new IActionResult Redirect([FromQuery] string next)
    {
        return base.Redirect(next);
    }
}
