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
