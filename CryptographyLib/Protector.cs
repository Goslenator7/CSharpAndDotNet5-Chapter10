using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Xml.Linq;
using static System.Convert;

namespace Packt.Shared
{
    public static class Protector
    {
        // salt size must be at least 8 bytes, we will use 16
        private static readonly byte[] salt = Encoding.Unicode.GetBytes("7BANANAS");

        //iterations must be at least 1000, lets use 2000
        private static readonly int iterations = 2000;

        private static Dictionary<string, User> Users = new Dictionary<string, User>();

        public static User Register(string username, string password, string[] roles = null)
        {
            // generate a random salt
            var rng = RandomNumberGenerator.Create();
            var saltBytes = new byte[16];
            rng.GetBytes(saltBytes);
            var saltText = Convert.ToBase64String(saltBytes);

            // generate the salted and hashed password 
            var saltedhashedPassword = SaltAndHashPassword(password, saltText);

            var user = new User
            {
                Name = username,
                Salt = saltText,
                SaltedHashedPassword = saltedhashedPassword,
            };
            Users.Add(user.Name, user);

            return user;
        }

        // check a user's password that is stored
        // in the private static dictionary Users
        public static bool CheckPassword(string username, string password)
        {
            if (!Users.ContainsKey(username))
            {
                return false;
            }

            var user = Users[username];

            return CheckPassword(username, password, user.Salt, user.SaltedHashedPassword);
        }

        // check a user's password using salt and hashed password
        public static bool CheckPassword(string username, string password, string salt, string hashedPassword)
        {
            // re-generate the salted and hashed password 
            var saltedhashedPassword = SaltAndHashPassword(
              password, salt);

            return (saltedhashedPassword == hashedPassword);
        }

        private static string SaltAndHashPassword(string password, string salt)
        {
            var sha = SHA256.Create();
            var saltedPassword = password + salt;
            return Convert.ToBase64String(
              sha.ComputeHash(Encoding.Unicode.GetBytes(saltedPassword)));
        }

        public static string Encrypt(string plainText, string password)
        {
            byte[] encryptedBytes;
            byte[] plainBytes = Encoding.Unicode.GetBytes(plainText);

            var aes = Aes.Create(); // abstract class factory method

            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);

            aes.Key = pbkdf2.GetBytes(32); //set a 256-bit key
            aes.IV = pbkdf2.GetBytes(16); // set a 128-bit IV

            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(plainBytes, 0, plainBytes.Length);
                }
                encryptedBytes = ms.ToArray();
            }
            return Convert.ToBase64String(encryptedBytes);
        }

        public static string Decrypt(string cryptoText, string password)
        {
            byte[] plainBytes;
            byte[] cryptoBytes = Convert.FromBase64String(cryptoText);

            var aes = Aes.Create();

            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);

            aes.Key = pbkdf2.GetBytes(32);
            aes.IV = pbkdf2.GetBytes(16);

            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(
                  ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(cryptoBytes, 0, cryptoBytes.Length);
                }
                plainBytes = ms.ToArray();
            }

            return Encoding.Unicode.GetString(plainBytes);
        }
    }
}
