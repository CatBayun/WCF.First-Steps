using Microsoft.SqlServer.Server;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Security.Permissions;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.IO;

public class SQLExtentions
{
    private static Int32 SlowRandom(Int32 min, Int32 max)
    {
        byte[] items = new byte[12];
        RNGCryptoServiceProvider.Create().GetBytes(items);

        Random rand1 = new Random((int)DateTime.Now.Ticks & 0x0000FFFF | BitConverter.ToInt32(items, 0));
        for (int i = 0; i < 100; i++)
        {
            rand1.Next();
        }

        Random rand2 = new Random((int)DateTime.Now.Ticks & 0x0000FFFF | rand1.Next() | BitConverter.ToInt32(items, 8));
        for (int i = 0; i < 100; i++)
        {
            rand1.Next();
            rand2.Next();
        }

        Random rand3 = new Random((int)DateTime.Now.Ticks & 0x0000FFFF | rand2.Next() | rand1.Next() | BitConverter.ToInt32(items, 4));
        for (int i = 0; i < 100; i++)
        {
            rand1.Next();
            rand2.Next();
            rand3.Next();
        }

        Random rnd = new Random((int)DateTime.Now.Ticks & 0x0000FFFF | rand3.Next() | rand2.Next() | rand1.Next());

        for (int i = 0; i < rand1.Next(100, 150); i++)
        {
            rnd.Next();
        }

        return rnd.Next(min, max);
    }

    private static SqlDataRecord FillRecord(Int32 pk, SqlDataRecord record)
    {
        Int32 age = SlowRandom(16, 99);
        string sourceString = "Age: " + age.ToString();
        DateTime sourceDate = DateTime.UtcNow;

        var data = /*salt + */sourceString;
                
        string key = "Top Secret Key";

        var encData = AES.EncryptBytes(data, key);
        //var encDataBytes = Encoding.Unicode.GetBytes(encData);
        var decData = AES.DecryptBytes(encData, key);

        var sha = new SHA256Managed();
        byte[] dataSHA256 = sha.ComputeHash(encData/*Bytes*/);
        sha.Dispose();

        // конвертирую хеш из byte[16] в строку шестнадцатиричного формата
        // (вида «3C842B246BC74D28E59CCD92AF46F5DA»)
        // это опциональный этап, если вам хеш нужен в строковом виде
        // string sha512hex = BitConverter.ToString(dataSHA512).Replace("-", string.Empty); 

        record.SetInt32(0, pk);
        record.SetDateTime(1, sourceDate);        
        record.SetString(2, sourceString);
        record.SetString(3, Convert.ToBase64String(dataSHA256)); // sha256
        record.SetString(4, Convert.ToBase64String(encData)); // Encrypted
        record.SetString(5, decData); // Decrypted

        return record;
    }

    [SqlProcedure]
    public static void CreateNewRecordProc()
    {
        DateTime now = DateTime.UtcNow;

        SqlDataRecord record = new SqlDataRecord(new SqlMetaData("PK", SqlDbType.Int),
            new SqlMetaData("UTC_DateTime", SqlDbType.DateTime),
            new SqlMetaData("Source", SqlDbType.NVarChar, 128),
            new SqlMetaData("Encrypted_SHA256", SqlDbType.NVarChar, 32),
            new SqlMetaData("Encrypted_AES", SqlDbType.NVarChar, 512),
            new SqlMetaData("Decrypted", SqlDbType.NVarChar, 128));

        SqlContext.Pipe.SendResultsStart(record);

        for (int i = 0; i < SlowRandom(1, 50); i++)
        {
            SqlContext.Pipe.SendResultsRow(FillRecord(i, record));
        }

        TimeSpan delta = DateTime.UtcNow - now;

        record.SetInt32(0, 0);
        record.SetDateTime(1, DateTime.UtcNow);
        record.SetString(2, "Total ms:");
        record.SetString(3, delta.Milliseconds.ToString());
        record.SetString(4, ""); 
        record.SetString(5, ""); 

        SqlContext.Pipe.SendResultsRow(record);

        SqlContext.Pipe.SendResultsEnd();
    }

    public interface IAES
    {
        string Decrypt(string ciphertext, string key);
        string Encrypt(string plainText, string key);
    }

    public static class AES
    {
        private const int _saltSize = 16;

        public static string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentNullException("plainText");
            }

            if (string.IsNullOrEmpty(key))
            {
                throw new ArgumentNullException("key");
            }

            var md5 = MD5.Create();
            byte[] salt = md5.ComputeHash(Guid.NewGuid().ToByteArray());
            md5.Dispose();

            using (var keyDerivationFunction = new Rfc2898DeriveBytes(key, salt))
            {
                byte[] saltBytes = keyDerivationFunction.Salt;
                byte[] keyBytes = keyDerivationFunction.GetBytes(32);
                byte[] ivBytes = keyDerivationFunction.GetBytes(16);

                using (var aesManaged = new AesManaged())
                {
                    aesManaged.KeySize = 256;

                    using (var encryptor = aesManaged.CreateEncryptor(keyBytes, ivBytes))
                    {
                        MemoryStream memoryStream = null;
                        CryptoStream cryptoStream = null;

                        return WriteMemoryStream(plainText, ref saltBytes, encryptor, ref memoryStream, ref cryptoStream);
                    }
                }
            }
        }

        public static byte[] EncryptBytes(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentNullException("plainText");
            }

            if (string.IsNullOrEmpty(key))
            {
                throw new ArgumentNullException("key");
            }

            var md5 = MD5.Create();
            byte[] salt = md5.ComputeHash(Guid.NewGuid().ToByteArray());
            md5.Dispose();

            using (var keyDerivationFunction = new Rfc2898DeriveBytes(key, salt))
            {
                byte[] saltBytes = keyDerivationFunction.Salt;
                byte[] keyBytes = keyDerivationFunction.GetBytes(32);
                byte[] ivBytes = keyDerivationFunction.GetBytes(16);

                using (var aesManaged = new AesManaged())
                {
                    aesManaged.KeySize = 256;

                    using (var encryptor = aesManaged.CreateEncryptor(keyBytes, ivBytes))
                    {
                        MemoryStream memoryStream = null;
                        CryptoStream cryptoStream = null;

                        return WriteMemoryStreamBytes(plainText, ref saltBytes, encryptor, ref memoryStream, ref cryptoStream);
                    }
                }
            }
        }

        public static string Decrypt(string ciphertext, string key)
        {
            if (string.IsNullOrEmpty(ciphertext))
            {
                throw new ArgumentNullException("ciphertext");
            }

            if (string.IsNullOrEmpty(key))
            {
                throw new ArgumentNullException("key");
            }

            var allTheBytes = Convert.FromBase64String(ciphertext);
            var saltBytes = allTheBytes.Take(_saltSize).ToArray();
            var ciphertextBytes = allTheBytes.Skip(_saltSize).Take(allTheBytes.Length - _saltSize).ToArray();

            using (var keyDerivationFunction = new Rfc2898DeriveBytes(key, saltBytes))
            {
                var keyBytes = keyDerivationFunction.GetBytes(32);
                var ivBytes = keyDerivationFunction.GetBytes(16);

                return DecryptWithAES(ciphertextBytes, keyBytes, ivBytes);
            }
        }

        public static string DecryptBytes(byte[] ciphertext, string key)
        {
            if (ciphertext == null || ciphertext.Length == 0)
            {
                throw new ArgumentNullException("ciphertext");
            }

            if (string.IsNullOrEmpty(key))
            {
                throw new ArgumentNullException("key");
            }

            var allTheBytes = ciphertext;
            var saltBytes = allTheBytes.Take(_saltSize).ToArray();
            var ciphertextBytes = allTheBytes.Skip(_saltSize).Take(allTheBytes.Length - _saltSize).ToArray();

            using (var keyDerivationFunction = new Rfc2898DeriveBytes(key, saltBytes))
            {
                var keyBytes = keyDerivationFunction.GetBytes(32);
                var ivBytes = keyDerivationFunction.GetBytes(16);

                return DecryptWithAES(ciphertextBytes, keyBytes, ivBytes);
            }
        }

        private static string WriteMemoryStream(string plainText, ref byte[] saltBytes, ICryptoTransform encryptor, ref MemoryStream memoryStream, ref CryptoStream cryptoStream)
        {
            try
            {
                memoryStream = new MemoryStream();

                try
                {
                    cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);

                    using (var streamWriter = new StreamWriter(cryptoStream))
                    {
                        streamWriter.Write(plainText);
                    }
                }
                finally
                {
                    if (cryptoStream != null)
                    {
                        cryptoStream.Dispose();
                    }
                }

                var cipherTextBytes = memoryStream.ToArray();
                Array.Resize(ref saltBytes, saltBytes.Length + cipherTextBytes.Length);
                Array.Copy(cipherTextBytes, 0, saltBytes, _saltSize, cipherTextBytes.Length);

                return Convert.ToBase64String(saltBytes);
            }
            finally
            {
                if (memoryStream != null)
                {
                    memoryStream.Dispose();
                }
            }
        }

        private static byte[] WriteMemoryStreamBytes(string plainText, ref byte[] saltBytes, ICryptoTransform encryptor, ref MemoryStream memoryStream, ref CryptoStream cryptoStream)
        {
            try
            {
                memoryStream = new MemoryStream();

                try
                {
                    cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);

                    using (var streamWriter = new StreamWriter(cryptoStream))
                    {
                        streamWriter.Write(plainText);
                    }
                }
                finally
                {
                    if (cryptoStream != null)
                    {
                        cryptoStream.Dispose();
                    }
                }

                var cipherTextBytes = memoryStream.ToArray();
                Array.Resize(ref saltBytes, saltBytes.Length + cipherTextBytes.Length);
                Array.Copy(cipherTextBytes, 0, saltBytes, _saltSize, cipherTextBytes.Length);

                return saltBytes;
            }
            finally
            {
                if (memoryStream != null)
                {
                    memoryStream.Dispose();
                }
            }
        }

        private static string DecryptWithAES(byte[] ciphertextBytes, byte[] keyBytes, byte[] ivBytes)
        {
            using (var aesManaged = new AesManaged())
            {
                using (var decryptor = aesManaged.CreateDecryptor(keyBytes, ivBytes))
                {
                    MemoryStream memoryStream = null;
                    CryptoStream cryptoStream = null;
                    StreamReader streamReader = null;

                    try
                    {
                        memoryStream = new MemoryStream(ciphertextBytes);
                        cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
                        streamReader = new StreamReader(cryptoStream);

                        return streamReader.ReadToEnd();
                    }
                    finally
                    {
                        if (memoryStream != null)
                        {
                            memoryStream.Dispose();
                            memoryStream = null;
                        }
                    }
                }
            }
        }
    }
}
