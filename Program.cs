using Microsoft.EntityFrameworkCore;
using IdentityService.Entities;
using System.Text.Json.Serialization;
using IdentityService.Helpers;
using IdentityService.Authorization;
using IdentityService.Services;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

{
    var services = builder.Services;
    var environment = builder.Environment;

    services.AddDbContext<DataContext>();
    services.AddCors();
    services.AddControllers().AddJsonOptions(x =>
    {
        //serialize enums as strings.
        x.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    });
    services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());
    services.AddSwaggerGen(options => {
        options.AddSecurityDefinition("jwt", 
        new OpenApiSecurityScheme {
            Description = "Standard Authorization header",
            In = ParameterLocation.Header,
            Name = "Authorization",
            Type = SecuritySchemeType.ApiKey
        });
    });

    //configure strongly typed settings object.
    services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));

    //configure DI for application services.
    services.AddScoped<ITokenUtility, TokenUtility>();
    services.AddScoped<IUserService, UserService>();
    services.AddScoped<IEmailService, EmailService>();

}

var app = builder.Build();

//migrate database.
using (var scope = app.Services.CreateScope())
{
    var dataContext = scope.ServiceProvider.GetRequiredService<DataContext>();
    dataContext.Database.Migrate();
}

{
    // Configure the HTTP request pipeline.
    app.UseSwagger();
    app.UseSwaggerUI(x => x.SwaggerEndpoint("/swagger/v1/swagger.json", "YATT Identity Service"));

    //global cors policy
    app.UseCors(x => x.SetIsOriginAllowed(origin => true)
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials());

    //global error handler
    app.UseMiddleware<ErrorHandlerMiddleware>();

    //custom jwt auth middleware
    app.UseMiddleware<AuthMiddleware>();

    app.MapControllers();
}

app.Run("http://localhost:5000/");
