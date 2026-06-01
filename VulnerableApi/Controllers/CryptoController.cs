using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CryptoController : ControllerBase
{
    // CWE-798: Hard-coded cryptographic key
    private static readonly byte[] HardcodedKey = Encoding.UTF8.GetBytes("0123456789abcdef");
    private static readonly byte[] HardcodedIv = Encoding.UTF8.GetBytes("abcdef9876543210");

    // CWE-327: Use of broken cryptographic algorithm (MD5)
    [HttpGet("md5")]
    public IActionResult Md5([FromQuery] string input)
    {
        using var md5 = MD5.Create();
        var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Ok(BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant());
    }

    // CWE-327: SHA-1 for password hashing
    [HttpPost("hash-password")]
    public IActionResult HashPassword([FromBody] string password)
    {
        using var sha1 = SHA1.Create();
        var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Ok(Convert.ToBase64String(hash));
    }

    // CWE-327 + CWE-329: DES with static IV
    [HttpPost("encrypt")]
    public IActionResult Encrypt([FromBody] string plaintext)
    {
        using var des = DES.Create();
        des.Key = Encoding.UTF8.GetBytes("8bytekey");
        des.IV = Encoding.UTF8.GetBytes("8byteIV0");
        using var encryptor = des.CreateEncryptor();
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var cipher = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);
        return Ok(Convert.ToBase64String(cipher));
    }

    // CWE-326 + CWE-329: AES in ECB mode with hardcoded key
    [HttpPost("aes-ecb")]
    public IActionResult AesEcb([FromBody] string plaintext)
    {
        using var aes = Aes.Create();
        aes.Key = HardcodedKey;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        using var enc = aes.CreateEncryptor();
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var cipher = enc.TransformFinalBlock(bytes, 0, bytes.Length);
        return Ok(Convert.ToBase64String(cipher));
    }

    // CWE-338: Insecure randomness for token generation
    [HttpGet("token")]
    public IActionResult Token()
    {
        var rng = new Random();
        var token = new byte[16];
        rng.NextBytes(token);
        return Ok(Convert.ToHexString(token));
    }
}
