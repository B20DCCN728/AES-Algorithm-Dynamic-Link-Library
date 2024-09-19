using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Testing
{
    class Program
    {
        private const string _dllPath = @"C:\Users\Nguyen Hoang Viet\source\repos\Testing\x64\Debug\AES.dll";

        // Import the DLL functions
        [DllImport(_dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr GenerateKey(out UIntPtr keyLen);

        [DllImport(_dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr Encrypt(byte[] keyBytes, UIntPtr keyLen, byte[] plainBytes, UIntPtr plainLen, out UIntPtr encryptedLen);

        [DllImport(_dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr Decrypt(byte[] keyBytes, UIntPtr keyLen, byte[] encryptedBytes, UIntPtr encryptedLen, out UIntPtr decryptedLen);

        // Import the FreeMemory function
        [DllImport(_dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void FreeMemory(IntPtr ptr);

        static void Main()
        {
            try
            {
                Console.WriteLine("AES Encryption/Decryption");

                // Generate Key
                UIntPtr keyLen;
                IntPtr keyPtr = GenerateKey(out keyLen);

                if (keyPtr == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to generate key.");
                    return;
                }
                Console.WriteLine("Key Length: " + keyLen.ToUInt32());

                byte[] key = new byte[keyLen.ToUInt32()];
                Marshal.Copy(keyPtr, key, 0, key.Length);
                FreeMemory(keyPtr); // Free the memory allocated by the DLL
                Console.WriteLine("Generated Key: " + BitConverter.ToString(key).Replace("-", ""));

                // Sample plain text
                string plainTextStr = "Nguyễn Hoàng Việt";
                byte[] plainText = Encoding.UTF8.GetBytes(plainTextStr);
                Console.WriteLine("Plain Text: " + plainTextStr);

                // Encrypt
                UIntPtr encryptedLen;
                IntPtr encryptedPtr = Encrypt(key, keyLen, plainText, new UIntPtr((uint)plainText.Length), out encryptedLen);

                if (encryptedPtr == IntPtr.Zero)
                {
                    Console.WriteLine("Encryption failed.");
                    return;
                }

                byte[] encryptedData = new byte[encryptedLen.ToUInt32()];
                Marshal.Copy(encryptedPtr, encryptedData, 0, encryptedData.Length);
                FreeMemory(encryptedPtr); // Free the memory allocated by the DLL

                Console.WriteLine("Encrypted Data: " + BitConverter.ToString(encryptedData).Replace("-", ""));

                // Decrypt
                UIntPtr decryptedLen;
                IntPtr decryptedPtr = Decrypt(key, keyLen, encryptedData, encryptedLen, out decryptedLen);

                if (decryptedPtr == IntPtr.Zero)
                {
                    Console.WriteLine("Decryption failed.");
                    return;
                }

                byte[] decryptedData = new byte[decryptedLen.ToUInt32()];
                Marshal.Copy(decryptedPtr, decryptedData, 0, decryptedData.Length);
                FreeMemory(decryptedPtr); // Free the memory allocated by the DLL

                string decryptedText = Encoding.UTF8.GetString(decryptedData).TrimEnd('\0'); // Remove any padding null characters
                Console.WriteLine("Decrypted Text: " + decryptedText);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }
    }
}
