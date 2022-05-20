using System;
using System.Security.Cryptography; //CryptographicException
using Packt.Shared;                 //Protector class
using static System.Console;

namespace EncryptionApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Write("Enter a message that you want to encrypt: ");
            string message = ReadLine();

            Write("Enter a password: ");
            string password = ReadLine();

            string cryptoText = Protector.Encrypt(message, password);

            WriteLine($"Encrypted text: {cryptoText}");

            Write("Enter the password: ");
            string password2 = ReadLine();

            try
            {
                string clearText = Protector.Decrypt(cryptoText, password2);
                WriteLine($"Decrypted text: {clearText}");
            }
            catch (CryptographicException ex)
            {
                WriteLine($"You entered the wrong password!\nMore Details: {ex.Message}");
            }
            catch (Exception ex)
            {
                WriteLine($"Non-cryptographic exeption: {ex.GetType().Name}, {ex.Message}");
            }
        }
    }
}
