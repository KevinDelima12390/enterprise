    using Microsoft.EntityFrameworkCore;
    using Microsoft.AspNetCore.Identity;
    using MedicalClaimSystem.Data;
    using Microsoft.AspNetCore.Diagnostics;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.EntityFrameworkCore.Sqlite;
    using MedicalClaimSystem.Models;
    using Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore;


    var builder = WebApplication.CreateBuilder(args);

    // Add services to the container.
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

    builder.Services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlite(connectionString));

    builder.Services.AddDatabaseDeveloperPageExceptionFilter();

    builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = false)
       .AddRoles<IdentityRole>()
       .AddEntityFrameworkStores<ApplicationDbContext>();
    builder.Services.AddControllersWithViews();


    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
       app.UseMigrationsEndPoint();
    }
    else
    {
       app.UseExceptionHandler("/Home/Error");
       // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
       app.UseHsts();
    }

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseRouting();

    app.UseAuthorization();

    app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");
    app.MapRazorPages();

    // Seed data for Admin user and roles
    using (var scope = app.Services.CreateScope())
    {
       var services = scope.ServiceProvider;
       var context = services.GetRequiredService<ApplicationDbContext>();
       var userManager = services.GetRequiredService<UserManager<IdentityUser>>();
       var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

        context.Database.EnsureCreated();
        // Create roles
        string[] roleNames = { "Admin", "Management", "User" };
        foreach (var roleName in roleNames)
        {
           var roleExist = await roleManager.RoleExistsAsync(roleName);
           if (!roleExist)
           {
                await roleManager.CreateAsync(new IdentityRole(roleName));
           }
        }
         // Create Admin user
        var adminUser = await userManager.FindByEmailAsync("admin@test.com");
        if(adminUser == null)
        {
           adminUser = new IdentityUser
           {
              UserName = "admin@test.com",
              Email = "admin@test.com",
              EmailConfirmed = true
           };
           await userManager.CreateAsync(adminUser, "Admin123!");

           // Assign Admin role to Admin user
             await userManager.AddToRoleAsync(adminUser, "Admin");
        }
    }
    app.Run();
