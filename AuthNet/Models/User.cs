using System.ComponentModel.DataAnnotations;

namespace AuthNet.Models
{
    public class User
    {
        [Key]
        public string UserName { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
    }
}
