using Microsoft.AspNetCore.Mvc;

namespace VulnerableApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class PathTraversalController : ControllerBase
{
    // CWE-22: Path Traversal - user-supplied filename used directly
    [HttpGet("read")]
    public IActionResult Read([FromQuery] string filename)
    {
        var path = Path.Combine("/var/app/uploads", filename);
        var content = System.IO.File.ReadAllText(path);
        return Content(content);
    }

    // CWE-73: External control of file name or path
    [HttpPost("write")]
    public IActionResult Write([FromQuery] string filename, [FromBody] string body)
    {
        var path = "/tmp/" + filename;
        System.IO.File.WriteAllText(path, body);
        return Ok(new { Wrote = path });
    }

    // CWE-22: Zip Slip-style write
    [HttpPost("extract")]
    public IActionResult Extract([FromQuery] string entryName, [FromBody] byte[] data)
    {
        var dest = Path.Combine("/tmp/extract", entryName);
        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
        System.IO.File.WriteAllBytes(dest, data);
        return Ok();
    }
}
