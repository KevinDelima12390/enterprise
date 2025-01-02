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
       public async Task<IActionResult> Index(string sortOrder)
        {
            ViewData["AmountSortParm"] = sortOrder == "amount" ? "amount_desc" : "amount";
            ViewData["ClaimTypeSortParm"] = String.IsNullOrEmpty(sortOrder) ? "claimType_asc" : "";

            var userId = _userManager.GetUserId(User);
            List<Claim> claims = new List<Claim>();
            if (userId != null)
            {
               var userClaimsQuery = _context.UserClaims
                    .Where(uc => uc.UserId == userId)
                    .Include(uc => uc.Claim)
                    .Where(uc => uc.Claim != null)
                    .Select(uc => uc.Claim);

                var userClaims = await userClaimsQuery.ToListAsync() ?? new List<Claim>();

                claims = sortOrder switch
                {
                    "amount" => userClaims.OrderBy(c => c.Amount).ToList(),
                    "amount_desc" => userClaims.OrderByDescending(c => c.Amount).ToList(),
                    _ => userClaims.OrderBy(c => c.ClaimType).ToList(),
                };
            }

            if (User.IsInRole("Admin") || User.IsInRole("Management"))
            {
               var allClaimsQuery = _context.Claims.Where(c => c!= null);
               var allClaims = await allClaimsQuery.ToListAsync() ?? new List<Claim>();

                claims = sortOrder switch
                {
                    "amount" => allClaims.OrderBy(c => c.Amount).ToList(),
                    "amount_desc" => allClaims.OrderByDescending(c => c.Amount).ToList(),
                     _ => allClaims.OrderBy(c => c.ClaimType).ToList(),
                };

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

            if (claim == null && !User.IsInRole("Admin"))
            {
                return NotFound();
            }
            if (claim == null)
            {
                claim = await _context.Claims.FindAsync(id);

            }
            if (claim == null)
            {
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
            if (claim == null && !User.IsInRole("Admin"))
            {
                return NotFound();
            }

            if (claim == null)
            {
                claim = await _context.Claims.FindAsync(id);

            }
            if (claim == null)
            {
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


            if (userClaim != null)
            {
                _context.UserClaims.Remove(userClaim);
            }

            var claim = await _context.Claims.FindAsync(id);

            if (claim != null)
            {
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
            if (claim == null)
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

            if (claimToUpdate != null)
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
            else
            {
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
            if (claim == null)
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
            if (claimToUpdate != null)
            {
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
            }
            else
            {
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