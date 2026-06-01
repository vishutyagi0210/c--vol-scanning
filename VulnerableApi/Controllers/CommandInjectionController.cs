using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CommandInjectionController : ControllerBase
{
    // CWE-78: OS Command Injection - user input piped into shell
    [HttpGet("ping")]
    public IActionResult Ping([FromQuery] string host)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/sh",
            Arguments = "-c \"ping -c 1 " + host + "\"",
            RedirectStandardOutput = true,
            UseShellExecute = false
        };

        var proc = Process.Start(psi);
        var output = proc!.StandardOutput.ReadToEnd();
        proc.WaitForExit();
        return Ok(output);
    }

    // CWE-78: another flavor using cmd.exe / shell with concatenation
    [HttpGet("nslookup")]
    public IActionResult Nslookup([FromQuery] string domain)
    {
        var cmd = "nslookup " + domain;
        var proc = Process.Start("cmd.exe", "/c " + cmd);
        proc?.WaitForExit();
        return Ok(new { Executed = cmd });
    }
}
