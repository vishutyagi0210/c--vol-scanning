// ============================================================================
// WARNING: This application is INTENTIONALLY VULNERABLE.
// It exists ONLY for practicing security scanners (SAST/DAST/SCA).
// DO NOT deploy, expose to a network, or use any code from this project
// in real software.
// ============================================================================

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// CWE-942: Permissive CORS - allow any origin, any header, any method, with credentials
builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
    p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();

// Always show developer exception page (CWE-209: information exposure through error messages)
app.UseDeveloperExceptionPage();

app.UseSwagger();
app.UseSwaggerUI();

// CWE-319: Cleartext transmission - HTTPS redirect deliberately disabled
// app.UseHttpsRedirection();

app.UseCors();
app.UseAuthorization();
app.MapControllers();

app.Run();
