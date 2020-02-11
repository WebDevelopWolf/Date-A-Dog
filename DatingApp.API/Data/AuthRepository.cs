using System;
using System.Threading.Tasks;
using DatingApp.API.Models;
using Microsoft.EntityFrameworkCore;

namespace DatingApp.API.Data
{
    public class AuthRepository : IAuthRepository
    {
        private readonly DataContext _context;
        public AuthRepository(DataContext context)
        {
            this._context = context;
        }
        public async Task<User> Login(string username, string password)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x => x.Username == username);
            // If no user found...
            if (user == null)
            {
                return null;
            }
            // If incorrect password...
            if (!VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt))
            {
                return null;
            }
            // Return User
            return user;
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512(passwordSalt)) {
                // Check Hash
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                // Compare generated hash and DB hash per byte
                for (int i = 0; i < computedHash.Length; i++)
                {
                    if (computedHash[i] != passwordHash[i])
                    {
                        return false;
                    }
                }
                return true;
            }
        }

        public async Task<User> Register(User user, string password)
        {
            byte[] passwordHash, passwordSalt;
            // Create Hash & Salt
            CreatePasswordHash(password, out passwordHash, out passwordSalt);
            // Apply Hash & Salt to User
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            // Add to DB Context
            await _context.Users.AddAsync(user);
            // Save to DB
            await _context.SaveChangesAsync();
            // Return Registered User
            return user;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            // Using to dispose of hash and salt
            using (var hmac = new System.Security.Cryptography.HMACSHA512()) {
                // Generate salt
                passwordSalt = hmac.Key;
                // Generate Hash
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
            ;
        }

        public async Task<bool> UserExists(string username)
        {
            // Find User by Username
            if (await _context.Users.AnyAsync(x => x.Username == username))
            {
                return true;
            } 
            return false;
        }
    }
}