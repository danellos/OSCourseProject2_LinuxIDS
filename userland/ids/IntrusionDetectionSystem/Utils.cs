/*
 * Name: Trevor Philip
 * Student ID: NL10252
 * Date: 5/8/2018
 * CMSC 421, Spring 2018
 *
 * Purpose: Only has the function to calculate the MD5 of a string.
 *
 */

using System;
using System.Collections.Generic;
using System.Text;

namespace IntrusionDetectionSystem
{
    internal static class Utils
    {
        public static string GenerateMD5(string bytes)
        {
            // Use input string to calculate MD5 hash
            using (var md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(bytes);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Convert the byte array to hexadecimal string
                var sb = new StringBuilder();
                foreach (var t in hashBytes)
                {
                    sb.Append(t.ToString("X2"));
                }
                return sb.ToString();
            }
        }
    }
}
