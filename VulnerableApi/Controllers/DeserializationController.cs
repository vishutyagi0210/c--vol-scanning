using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace VulnerableApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class DeserializationController : ControllerBase
{
    // CWE-502: BinaryFormatter is unsafe and deprecated
    [HttpPost("binary")]
    public IActionResult Binary()
    {
        using var ms = new MemoryStream();
        Request.Body.CopyToAsync(ms).GetAwaiter().GetResult();
        ms.Position = 0;

#pragma warning disable SYSLIB0011
        var formatter = new BinaryFormatter();
        var obj = formatter.Deserialize(ms);
#pragma warning restore SYSLIB0011
        return Ok(obj?.GetType().FullName);
    }

    // CWE-502: JSON.NET with TypeNameHandling.All allows gadget chains
    [HttpPost("json")]
    public IActionResult Json([FromBody] string json)
    {
        var obj = JsonConvert.DeserializeObject(json, new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All
        });
        return Ok(obj?.GetType().FullName);
    }
}
