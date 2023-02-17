using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;


namespace SEAI_Crypt_Lib
{

    [Guid("18B40A81-B4F1-4f35-A096-3D2B81343213")]
    [InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
    public interface _Crypt_Int
    {
        [DispId(1)]
        string EncryptStr(string clearText, string Password);
        [DispId(2)]
        string DecryptStr(string cipherText, string Password);
        [DispId(3)]
        Boolean EncryptFile(string FileToEncrypt, string FileEncrypted, string Password);
        [DispId(4)]
        Boolean DecryptFile(string FileToDecrypt, string FileClear, string Password);

    }


    [Guid("514A01FD-0AB8-485e-ADEC-61C60F9A1BD2")]
    [ClassInterface(ClassInterfaceType.None)]
    [ProgId("SEAI.Security")]
    public class Crypt_Class : _Crypt_Int
    {
        

        const int nIVBytes = 16;
        const int nKeyBytes = 32;

        #region Metodos Privados

        #endregion

        #region ISPSecurity Members

        public byte[] EncryptStr( byte[] clearData, byte[] Key, byte[] IV)
        {
            MemoryStream ms = new MemoryStream();

            Rijndael algRIJ = Rijndael.Create();
            algRIJ.Key = Key;
            algRIJ.IV = IV;
            CryptoStream csRIJ = new CryptoStream(ms, algRIJ.CreateEncryptor(),
                                                  CryptoStreamMode.Write);
            csRIJ.Write(clearData, 0, clearData.Length);
            csRIJ.Close();

            byte[] encryptedData = ms.ToArray();
            return encryptedData;
        }

        public string EncryptStr(string clearText, string Password)
        {
            byte[] clearBytes = System.Text.Encoding.Unicode.GetBytes(clearText);
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password,
                                              new byte[]{0x49,0x76,0x61,0x6e,0x20,0x4d,0x65,
	                                                 0x64,0x76,0x65,0x64,0x65,0x76});

            byte[] encryptedData = EncryptStr(clearBytes,pdb.GetBytes(nKeyBytes), pdb.GetBytes(nIVBytes));
            return Convert.ToBase64String(encryptedData);
        }

        public byte[] DecryptStr( byte[] cipherData, byte[] Key, byte[] IV)
        {
            MemoryStream ms = new MemoryStream();

            Rijndael algRIJ = Rijndael.Create();
            algRIJ.Key = Key;
            algRIJ.IV = IV;
            CryptoStream csRIJ = new CryptoStream(ms, algRIJ.CreateDecryptor(), CryptoStreamMode.Write);
            csRIJ.Write(cipherData, 0, cipherData.Length);
            csRIJ.Close();

            byte[] decryptedData = ms.ToArray();
            return decryptedData;
        }

        public string DecryptStr(string cipherText, string Password)
        {
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password,
                                              new byte[]{0x49,0x76,0x61,0x6e,0x20,0x4d,0x65,
	                                                 0x64,0x76,0x65,0x64,0x65,0x76});

            byte[] decryptedData = DecryptStr(cipherBytes,pdb.GetBytes(nKeyBytes), pdb.GetBytes(nIVBytes));
            return System.Text.Encoding.Unicode.GetString(decryptedData);
        }

        public byte[] DecryptStr( byte[] cipherData, string Password)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password,
                                              new byte[]{0x49,0x76,0x61,0x6e,0x20,0x4d,0x65,
	                                                 0x64,0x76,0x65,0x64,0x65,0x76});
            return DecryptStr(cipherData, pdb.GetBytes(nKeyBytes), pdb.GetBytes(nIVBytes));
        }

        public static Byte[] ConvertStringToByteArray(String s)
        {
            return (new UnicodeEncoding()).GetBytes(s);
        }

        public Boolean EncryptFile(string FileToEncrypt, string FileEncrypted, string Password)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password,
                          new byte[]{0x49,0x76,0x61,0x6e,0x20,0x4d,0x65,
                                                     0x64,0x76,0x65,0x64,0x65,0x76});
            FileStream file1 = null;
            FileStream fsOut = null;
            Rijndael algRIJ = null;
            CryptoStream csRIJ = null;
            try
            {
                file1 = new FileStream(FileToEncrypt, FileMode.Open, FileAccess.Read);
                fsOut = new FileStream(FileEncrypted, FileMode.OpenOrCreate, FileAccess.Write);
                byte[] hashvalue1SHA1 = (new SHA1CryptoServiceProvider()).ComputeHash(file1);
                byte[] buffer = new byte[file1.Length + hashvalue1SHA1.Length];
                hashvalue1SHA1.CopyTo(buffer, 0);
                file1.Position = 0;
                file1.Read(buffer, hashvalue1SHA1.Length, (int)file1.Length);
                file1.Close();
                algRIJ = Rijndael.Create();
                algRIJ.Key = pdb.GetBytes(nKeyBytes);
                algRIJ.IV = pdb.GetBytes(nIVBytes);
                csRIJ = new CryptoStream(fsOut, algRIJ.CreateEncryptor(), CryptoStreamMode.Write);
                csRIJ.Write(buffer, 0, buffer.Length);
                csRIJ.Close();
                fsOut.Close();
                return true;

            }
            catch (Exception)
            {
                try
                {
                    file1.Close();
                    fsOut.Close();
                    algRIJ.Clear();
                    csRIJ.Close();
                    return false;
                }
                catch (Exception)
                {
                    return false;
                }
            }

        }

        public Boolean DecryptFile(string FileToDecrypt, string FileClear, string Password)
        {
            MemoryStream ms = new MemoryStream();
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password,
              new byte[]{0x49,0x76,0x61,0x6e,0x20,0x4d,0x65,
                                                     0x64,0x76,0x65,0x64,0x65,0x76});

            FileStream file1 = null;
            FileStream fsOut = null;
            Rijndael algRIJ = null;
            CryptoStream csRIJ = null;
            try
            {
                file1 = new FileStream(FileToDecrypt, FileMode.Open, FileAccess.Read);
                byte[] buffer = new byte[file1.Length];
                file1.Read(buffer, 0, (int)file1.Length);
                file1.Close();

                algRIJ = Rijndael.Create();
                algRIJ.Key = pdb.GetBytes(nKeyBytes);
                algRIJ.IV = pdb.GetBytes(nIVBytes);
                csRIJ = new CryptoStream(ms, algRIJ.CreateDecryptor(), CryptoStreamMode.Write);
                csRIJ.Write(buffer, 0, buffer.Length);

                csRIJ.Close();
                buffer = ms.ToArray();

                byte[] data1ToHashSHA1 = new byte[buffer.Length - 20];
                for (int i = 20; i < buffer.Length; i++)
                {
                    data1ToHashSHA1[i - 20] = buffer[i];
                }

                byte[] data1HashSHA1 = (new SHA1CryptoServiceProvider()).ComputeHash(data1ToHashSHA1);

                Boolean ConfHashSHA1 = true;
                for (int i = 0; i < 20; i++)
                {
                    if (data1HashSHA1[i] != buffer[i])
                    {
                        ConfHashSHA1 = false;
                    }
                }
                if (ConfHashSHA1)
                {
                    fsOut = new FileStream(FileClear, FileMode.OpenOrCreate, FileAccess.Write);
                    fsOut.Write(buffer, 20, buffer.Length - 20);
                    fsOut.Close();
                    return true;
                }
                else
                {
                    file1.Close();
                    algRIJ.Clear();
                    csRIJ.Close();
                    return false;
                }
            }
            catch (Exception)
            {
                try
                {
                    file1.Close();
                    fsOut.Close();
                    algRIJ.Clear();
                    csRIJ.Close();
                    return false;
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }

        #endregion

    }
}

