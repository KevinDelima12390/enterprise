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
