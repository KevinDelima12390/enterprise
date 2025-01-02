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
