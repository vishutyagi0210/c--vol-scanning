using System.Xml;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class XxeController : ControllerBase
{
    // CWE-611: XML External Entity (XXE) - DTD processing enabled, resolver attached
    [HttpPost("parse")]
    public IActionResult Parse([FromBody] string xml)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Parse,
            XmlResolver = new XmlUrlResolver()
        };

        using var stringReader = new StringReader(xml);
        using var reader = XmlReader.Create(stringReader, settings);
        var doc = new XmlDocument
        {
            XmlResolver = new XmlUrlResolver()
        };
        doc.Load(reader);
        return Ok(doc.OuterXml);
    }
}
