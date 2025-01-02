 using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Collections.Generic;

namespace MedicalClaimSystem.Controllers
{
    [Authorize(Roles = "Admin")]
    public class UserManagementController : Controller
    {
          private readonly UserManager<IdentityUser> _userManager;
         private readonly RoleManager<IdentityRole> _roleManager;
         public UserManagementController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }
          public async Task<IActionResult> Index()
        {
          var users = await _userManager.Users.ToListAsync();
          List<UserViewModel> userViewModels = new List<UserViewModel>();
           foreach(var user in users){
              var userViewModel = new UserViewModel
              {
                  Id = user.Id,
                  Email = user.Email,
                  UserName = user.UserName,
                  Roles = await _userManager.GetRolesAsync(user)
              };
              userViewModels.Add(userViewModel);
          }

              return View(userViewModels);
        }
        public async Task<IActionResult> ManageRoles(string id) {
             var user = await _userManager.FindByIdAsync(id);
              if (user == null)
            {
                return NotFound();
            }
           var model = new UserRolesViewModel
            {
                UserId = user.Id,
                Email = user.Email,
                UserName = user.UserName,
                Roles = await _userManager.GetRolesAsync(user),
               AllRoles =  await _roleManager.Roles.Select(r => r.Name).ToListAsync(),
             };

            return View(model);
       }

        [HttpPost]
        [ValidateAntiForgeryToken]
         public async Task<IActionResult> ManageRoles(UserRolesViewModel model) {

             var user = await _userManager.FindByIdAsync(model.UserId);
             if (user == null)
            {
                return NotFound();
            }
           var roles =  await _userManager.GetRolesAsync(user);
           var allRoles =  await _roleManager.Roles.Select(r => r.Name).ToListAsync();

            foreach(var role in allRoles){
              if(model.SelectedRoles.Contains(role) && !roles.Contains(role)){
                 await _userManager.AddToRoleAsync(user, role);
              }
              if(!model.SelectedRoles.Contains(role) && roles.Contains(role)){
                  await _userManager.RemoveFromRoleAsync(user, role);
              }
           }


            TempData["Message"] = "User roles updated successfully.";

             return RedirectToAction(nameof(Index));
       }
    }
        public class UserViewModel {
            public string Id { get; set; }
            public string Email { get; set; }
            public string UserName { get; set; }
            public IList<string> Roles { get; set; }

        }

        public class UserRolesViewModel {
            public string UserId { get; set; }
            public string Email { get; set; }
            public string UserName { get; set; }
             public IList<string> Roles { get; set; }
             public List<string> AllRoles { get; set; }
            public List<string> SelectedRoles { get; set; } = new List<string>();
        }
}