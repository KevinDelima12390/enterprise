#!/bin/bash

# Project Name
PROJECT_NAME="MedicalClaimSystem"

# Create project directory
mkdir "$PROJECT_NAME"
cd "$PROJECT_NAME"

# Create ASP.NET Core MVC project (targeting .NET 8)
dotnet new mvc -o . --framework net8.0

# Install necessary NuGet packages
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.Tools
dotnet add package Microsoft.VisualStudio.Web.CodeGeneration.Design
dotnet add package Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore

# Create folder for database context
mkdir Data
mkdir Models
mkdir Controllers
mkdir ViewModels

# Create Data/ApplicationDbContext.cs
cat << EOF > Data/ApplicationDbContext.cs
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using MedicalClaimSystem.Models;

namespace MedicalClaimSystem.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

       public DbSet<Claim> Claims { get; set; }
       public new DbSet<UserClaim> UserClaims { get; set; }
    }
}
EOF

# Create Models/Claim.cs
cat << EOF > Models/Claim.cs
using System;
using System.ComponentModel.DataAnnotations;

namespace MedicalClaimSystem.Models
{
    public class Claim
    {
        public int Id { get; set; }
        [Required]
        public string? ClaimType { get; set; }
        [Required]
        public string? Description { get; set; }

        public decimal Amount { get; set; }
        public string? Status { get; set; }
        public DateTime SubmissionDate { get; set; }

    }
}
EOF

# Create Models/UserClaim.cs
cat << EOF > Models/UserClaim.cs
using System;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace MedicalClaimSystem.Models
{
    public class UserClaim
    {
         public int Id { get; set; }
         [Required]
         public string? UserId { get; set; }
         [Required]
         public int ClaimId { get; set; }

        public virtual IdentityUser? User { get; set; }
        public virtual Claim? Claim { get; set; }
    }
}
EOF

# Create Controllers/HomeController.cs
cat << EOF > Controllers/HomeController.cs
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using MedicalClaimSystem.Models;


namespace MedicalClaimSystem.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
EOF

# Create Controllers/ClaimsController.cs
cat << EOF > Controllers/ClaimsController.cs
using Microsoft.AspNetCore.Mvc;
using MedicalClaimSystem.Data;
using MedicalClaimSystem.Models;
using Microsoft.AspNetCore.Identity;
using System;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using System.Linq;
using System.Collections.Generic;

namespace MedicalClaimSystem.Controllers
{
    [Authorize]
    public class ClaimsController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<IdentityUser> _userManager;

         public ClaimsController(ApplicationDbContext context, UserManager<IdentityUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        // GET: Claims
        public async Task<IActionResult> Index()
        {
            var userId = _userManager.GetUserId(User);
            List<Claim?> claims = new List<Claim?>();
             if (userId != null)
             {
                 claims = await _context.UserClaims
                    .Where(uc => uc.UserId == userId)
                    .Include(uc => uc.Claim)
                    .Select(uc => uc.Claim)
                    .ToListAsync();
              }


            if (User.IsInRole("Admin") || User.IsInRole("Management"))
            {
                claims = await _context.Claims.ToListAsync();
            }

            return View(claims);
        }

        // GET: Claims/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Claims/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,ClaimType,Description,Amount")] Claim claim)
        {
            if (ModelState.IsValid)
            {
                claim.SubmissionDate = DateTime.Now;
                claim.Status = "Pending";
               _context.Add(claim);
               await _context.SaveChangesAsync();

               var userClaim = new UserClaim()
               {
                   UserId = _userManager.GetUserId(User),
                   ClaimId = claim.Id,

               };

               _context.Add(userClaim);
               await _context.SaveChangesAsync();



                return RedirectToAction(nameof(Index));
            }
            return View(claim);
        }


          // GET: Claims/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

             var userId = _userManager.GetUserId(User);
            var claim = await _context.UserClaims
            .Where(uc => uc.UserId == userId && uc.ClaimId == id)
            .Include(uc => uc.Claim)
            .Select(uc => uc.Claim)
            .FirstOrDefaultAsync();



            if(claim == null && !User.IsInRole("Admin")) {

                 return NotFound();
            }
             if (claim == null )
            {
               claim = await _context.Claims.FindAsync(id);

            }
            if(claim == null){
                  return NotFound();
            }

            return View(claim);
        }
        // POST: Claims/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
         public async Task<IActionResult> Edit(int id, [Bind("Id,ClaimType,Description,Amount,SubmissionDate,Status")] Claim claim)
        {
           if (id != claim.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(claim);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                     if (!ClaimExists(claim.Id))
                    {
                        return NotFound();
                    }
                }

                return RedirectToAction(nameof(Index));
            }
            return View(claim);
        }

       // GET: Claims/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }
           var userId = _userManager.GetUserId(User);
           var claim = await _context.UserClaims
           .Where(uc => uc.UserId == userId && uc.ClaimId == id)
           .Include(uc => uc.Claim)
           .Select(uc => uc.Claim)
           .FirstOrDefaultAsync();
            if(claim == null && !User.IsInRole("Admin")){
                  return NotFound();
            }

              if (claim == null )
            {
               claim = await _context.Claims.FindAsync(id);

            }
             if(claim == null){
                  return NotFound();
            }
              return View(claim);
        }
         // POST: Claims/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {

          var userId = _userManager.GetUserId(User);
           var userClaim = await _context.UserClaims
           .FirstOrDefaultAsync(uc => uc.UserId == userId && uc.ClaimId == id);


              if(userClaim != null){
                 _context.UserClaims.Remove(userClaim);
             }

             var claim = await _context.Claims.FindAsync(id);

            if(claim != null){
                  _context.Claims.Remove(claim);
            }
             await _context.SaveChangesAsync();
             return RedirectToAction(nameof(Index));
        }

          // GET: Claims/Approve/5
         [Authorize(Roles = "Admin,Management")]
        public async Task<IActionResult> Approve(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }
            var claim = await _context.Claims.FindAsync(id);
             if (claim == null )
            {
               return NotFound();

            }
            return View(claim);
        }

        // POST: Claims/Approve/5
        [HttpPost]
        [ValidateAntiForgeryToken]
         [Authorize(Roles = "Admin,Management")]
        public async Task<IActionResult> Approve(int id, [Bind("Id,ClaimType,Description,Amount,SubmissionDate,Status")] Claim claim)
        {
             if (id != claim.Id)
            {
                return NotFound();
            }
            var claimToUpdate = await _context.Claims.FindAsync(id);

             if(claimToUpdate != null)
             {
                  if (ModelState.IsValid)
                {
                   try
                    {
                        claimToUpdate.Status = "Approved";
                        _context.Claims.Update(claimToUpdate);
                        await _context.SaveChangesAsync();
                         TempData["Message"] = "Claim Approved successfully.";

                    }
                     catch (DbUpdateConcurrencyException)
                    {
                       if (!ClaimExists(claim.Id))
                          {
                             return NotFound();
                         }
                       TempData["Message"] = "Failed to approve claim, concurrency error.";
                    }
                }
            }
             else {
                    TempData["Message"] = "Claim not found.";
                }

            return RedirectToAction(nameof(Index));
         }

        // GET: Claims/Reject/5
        [Authorize(Roles = "Admin,Management")]
         public async Task<IActionResult> Reject(int? id)
        {
              if (id == null)
            {
                return NotFound();
            }
            var claim = await _context.Claims.FindAsync(id);
             if (claim == null )
            {
               return NotFound();

            }
             return View(claim);
        }
           // POST: Claims/Reject/5
         [HttpPost]
         [ValidateAntiForgeryToken]
         [Authorize(Roles = "Admin,Management")]
          public async Task<IActionResult> Reject(int id, [Bind("Id,ClaimType,Description,Amount,SubmissionDate,Status")] Claim claim)
        {
              if (id != claim.Id)
            {
                return NotFound();
            }
             var claimToUpdate = await _context.Claims.FindAsync(id);
               if(claimToUpdate != null){
                   if (ModelState.IsValid)
                    {
                        try
                        {
                            claimToUpdate.Status = "Rejected";
                            _context.Claims.Update(claimToUpdate);
                            await _context.SaveChangesAsync();
                            TempData["Message"] = "Claim rejected successfully.";
                        }
                         catch (DbUpdateConcurrencyException)
                            {
                                 if (!ClaimExists(claim.Id))
                                  {
                                       return NotFound();
                                  }
                                TempData["Message"] = "Failed to reject claim, concurrency error.";
                            }
                    }
               }else {
                   TempData["Message"] = "Claim not found.";
                }


             return RedirectToAction(nameof(Index));
        }
        private bool ClaimExists(int id)
        {
            return _context.Claims.Any(e => e.Id == id);
        }
    }
}
EOF


# Create ViewModels/ClaimsViewModel.cs
cat << EOF > ViewModels/ClaimsViewModel.cs
using System.Collections.Generic;
using MedicalClaimSystem.Models;

namespace MedicalClaimSystem.ViewModels
{
    public class ClaimsViewModel
    {
        public List<Claim>? Claims { get; set; }
        public string? CurrentUserId { get; set; }
         public bool IsAdmin { get; set; }
         public bool IsManagement { get; set; }
    }
}
EOF

# Update Program.cs
cat << EOF > Program.cs
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
EOF


# Create a default SQLite connection string
cat << EOF > appsettings.json
{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=MedicalClaimSystem.db"
  },
  "Logging": {
      "LogLevel": {
          "Default": "Information",
          "Microsoft.AspNetCore": "Warning"
      }
  },
  "AllowedHosts": "*"
}
EOF

# Create View/Claims/Index.cshtml
cat << EOF > Views/Claims/Index.cshtml
@model IEnumerable<MedicalClaimSystem.Models.Claim>

@{
    ViewData["Title"] = "Claims";
}

<h1>Claims</h1>
@if (TempData["Message"] != null)
{
  <div class="alert alert-info">@TempData["Message"]</div>
}
<p>
    <a asp-action="Create">Create New</a>
</p>
<table class="table">
    <thead>
        <tr>
            <th>
               Claim Type
            </th>
             <th>
                Description
            </th>
             <th>
              Amount
            </th>
             <th>
               Status
            </th>
             <th>
              Submission Date
            </th>
            <th></th>
        </tr>
    </thead>
    <tbody>
@foreach (var item in Model) {
        <tr>
            <td>
                @Html.DisplayFor(modelItem => item.ClaimType)
            </td>
             <td>
                @Html.DisplayFor(modelItem => item.Description)
            </td>
              <td>
                 @Html.DisplayFor(modelItem => item.Amount)
            </td>
             <td>
                  @Html.DisplayFor(modelItem => item.Status)
            </td>
              <td>
                 @Html.DisplayFor(modelItem => item.SubmissionDate)
            </td>
            <td>
                @if (User.IsInRole("Admin") || User.IsInRole("Management"))
                {
                    <a asp-action="Approve" asp-route-id="@item.Id">Approve</a>
                    <span>|</span>
                    <a asp-action="Reject" asp-route-id="@item.Id">Reject</a>
                    <span>|</span>

                }
                <a asp-action="Edit" asp-route-id="@item.Id">Edit</a>
                <span>|</span>
                <a asp-action="Delete" asp-route-id="@item.Id">Delete</a>
            </td>
        </tr>
}
    </tbody>
</table>
EOF

# Create View/Claims/Create.cshtml
cat << EOF > Views/Claims/Create.cshtml
@model MedicalClaimSystem.Models.Claim

@{
    ViewData["Title"] = "Create Claim";
}

<h1>Create Claim</h1>

<h4>Claim</h4>
<hr />
<div class="row">
    <div class="col-md-4">
        <form asp-action="Create">
            <div asp-validation-summary="ModelOnly" class="text-danger"></div>
            <div class="form-group">
                <label asp-for="ClaimType" class="control-label"></label>
                <input asp-for="ClaimType" class="form-control" />
                <span asp-validation-for="ClaimType" class="text-danger"></span>
            </div>
               <div class="form-group">
                <label asp-for="Description" class="control-label"></label>
                <input asp-for="Description" class="form-control" />
                <span asp-validation-for="Description" class="text-danger"></span>
            </div>
             <div class="form-group">
                <label asp-for="Amount" class="control-label"></label>
                <input asp-for="Amount" class="form-control" />
                <span asp-validation-for="Amount" class="text-danger"></span>
            </div>
             <div class="form-group">
                <input type="submit" value="Create" class="btn btn-primary" />
            </div>
        </form>
    </div>
</div>

<div>
    <a asp-action="Index">Back to List</a>
</div>

@section Scripts {
    @{await Html.RenderPartialAsync("_ValidationScriptsPartial");}
}
EOF


# Create View/Claims/Edit.cshtml
cat << EOF > Views/Claims/Edit.cshtml
@model MedicalClaimSystem.Models.Claim

@{
    ViewData["Title"] = "Edit Claim";
}

<h1>Edit Claim</h1>

<h4>Claim</h4>
<hr />
<div class="row">
    <div class="col-md-4">
        <form asp-action="Edit">
            <div asp-validation-summary="ModelOnly" class="text-danger"></div>
            <input type="hidden" asp-for="Id" />
            <div class="form-group">
                <label asp-for="ClaimType" class="control-label"></label>
                <input asp-for="ClaimType" class="form-control" />
                <span asp-validation-for="ClaimType" class="text-danger"></span>
            </div>
                <div class="form-group">
                <label asp-for="Description" class="control-label"></label>
                <input asp-for="Description" class="form-control" />
                <span asp-validation-for="Description" class="text-danger"></span>
            </div>
            <div class="form-group">
                <label asp-for="Amount" class="control-label"></label>
                <input asp-for="Amount" class="form-control" />
                <span asp-validation-for="Amount" class="text-danger"></span>
            </div>
              <div class="form-group">
                <label asp-for="Status" class="control-label"></label>
                 <input asp-for="Status" class="form-control" readonly/>
                 <span asp-validation-for="Status" class="text-danger"></span>
            </div>
               <div class="form-group">
                <label asp-for="SubmissionDate" class="control-label"></label>
                 <input asp-for="SubmissionDate" class="form-control" readonly/>
                 <span asp-validation-for="SubmissionDate" class="text-danger"></span>
            </div>
            <div class="form-group">
                <input type="submit" value="Save" class="btn btn-primary" />
            </div>
        </form>
    </div>
</div>

<div>
    <a asp-action="Index">Back to List</a>
</div>

@section Scripts {
    @{await Html.RenderPartialAsync("_ValidationScriptsPartial");}
}
EOF


# Create View/Claims/Delete.cshtml
cat << EOF > Views/Claims/Delete.cshtml
@model MedicalClaimSystem.Models.Claim

@{
    ViewData["Title"] = "Delete Claim";
}

<h1>Delete Claim</h1>

<h3>Are you sure you want to delete this?</h3>
<div>
    <h4>Claim</h4>
    <hr />
    <dl class="row">
          <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.ClaimType)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.ClaimType)
        </dd>
        <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.Description)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.Description)
        </dd>
        <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.Amount)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.Amount)
        </dd>
         <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.Status)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.Status)
        </dd>
         <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.SubmissionDate)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.SubmissionDate)
        </dd>

    </dl>

    <form asp-action="Delete">
        <input type="hidden" asp-for="Id" />
        <input type="submit" value="Delete" class="btn btn-danger" /> |
        <a asp-action="Index">Back to List</a>
    </form>
</div>
EOF

# Create View/Claims/Approve.cshtml
cat << EOF > Views/Claims/Approve.cshtml
@model MedicalClaimSystem.Models.Claim

@{
    ViewData["Title"] = "Approve Claim";
}

<h1>Approve Claim</h1>

<h3>Are you sure you want to approve this?</h3>
<div>
    <h4>Claim</h4>
    <hr />
    <dl class="row">
           <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.ClaimType)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.ClaimType)
        </dd>
        <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.Description)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.Description)
        </dd>
        <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.Amount)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.Amount)
        </dd>
         <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.Status)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.Status)
        </dd>
         <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.SubmissionDate)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.SubmissionDate)
        </dd>

    </dl>

    <form asp-action="Approve" method="post">
        <input type="hidden" asp-for="Id" />
        <input type="hidden" asp-for="ClaimType"/>
         <input type="hidden" asp-for="Description"/>
          <input type="hidden" asp-for="Amount"/>
           <input type="hidden" asp-for="SubmissionDate"/>
        <input type="submit" value="Approve" class="btn btn-success" /> |
         <a asp-action="Index">Back to List</a>
    </form>
</div>
EOF


# Create View/Claims/Reject.cshtml
cat << EOF > Views/Claims/Reject.cshtml
@model MedicalClaimSystem.Models.Claim

@{
    ViewData["Title"] = "Reject Claim";
}

<h1>Reject Claim</h1>

<h3>Are you sure you want to reject this?</h3>
<div>
    <h4>Claim</h4>
    <hr />
    <dl class="row">
        <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.ClaimType)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.ClaimType)
        </dd>
         <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.Description)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.Description)
        </dd>
        <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.Amount)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.Amount)
        </dd>
        <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.Status)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.Status)
        </dd>
          <dt class="col-sm-2">
            @Html.DisplayNameFor(model => model.SubmissionDate)
        </dt>
        <dd class="col-sm-10">
            @Html.DisplayFor(model => model.SubmissionDate)
        </dd>

    </dl>

    <form asp-action="Reject" method="post">
        <input type="hidden" asp-for="Id" />
         <input type="hidden" asp-for="ClaimType"/>
         <input type="hidden" asp-for="Description"/>
          <input type="hidden" asp-for="Amount"/>
           <input type="hidden" asp-for="SubmissionDate"/>
        <input type="submit" value="Reject" class="btn btn-danger" /> |
        <a asp-action="Index">Back to List</a>
    </form>
</div>
EOF


# Create Views/_Layout.cshtml
cat << EOF > Views/Shared/_Layout.cshtml
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>@ViewData["Title"] - MedicalClaimSystem</title>
    <link rel="stylesheet" href="~/lib/bootstrap/dist/css/bootstrap.min.css" />
    <link rel="stylesheet" href="~/css/site.css" asp-append-version="true" />
    <link rel="stylesheet" href="~/MedicalClaimSystem.styles.css" asp-append-version="true" />
</head>
<body>
    <header>
        <nav class="navbar navbar-expand-sm navbar-toggleable-sm navbar-light bg-white border-bottom box-shadow mb-3">
            <div class="container-fluid">
                <a class="navbar-brand" asp-area="" asp-controller="Home" asp-action="Index">MedicalClaimSystem</a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target=".navbar-collapse" aria-controls="navbarSupportedContent"
                        aria-expanded="false" aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="navbar-collapse collapse d-sm-inline-flex justify-content-between">
                    <ul class="navbar-nav flex-grow-1">
                        <li class="nav-item">
                            <a class="nav-link text-dark" asp-area="" asp-controller="Home" asp-action="Index">Home</a>
                        </li>
                         <li class="nav-item">
                            <a class="nav-link text-dark" asp-area="" asp-controller="Claims" asp-action="Index">Claims</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link text-dark" asp-area="" asp-controller="Home" asp-action="Privacy">Privacy</a>
                        </li>
                    </ul>
                     <partial name="_LoginPartial" />
                </div>
            </div>
        </nav>
    </header>
    <div class="container">
        <main role="main" class="pb-3">
            @RenderBody()
        </main>
    </div>

    <footer class="border-top footer text-muted">
        <div class="container">
            © 2024 - MedicalClaimSystem - <a asp-area="" asp-controller="Home" asp-action="Privacy">Privacy</a>
        </div>
    </footer>
    <script src="~/lib/jquery/dist/jquery.min.js"></script>
    <script src="~/lib/bootstrap/dist/js/bootstrap.bundle.min.js"></script>
    <script src="~/js/site.js" asp-append-version="true"></script>
    @await RenderSectionAsync("Scripts", required: false)
</body>
</html>
EOF


# Run migrations
dotnet ef migrations add InitialCreate -o Data/Migrations

dotnet ef database update

# Finish message
echo "MedicalClaimSystem project created successfully!"
echo "Please register as an admin user with email admin@test.com and the password Admin123!"
echo "You can run the project using 'dotnet run'"