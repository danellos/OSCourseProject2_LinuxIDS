/*
 * Name: Trevor Philip
 * Student ID: NL10252
 * Date: 5/8/2018
 * CMSC 421, Spring 2018
 *
 * Purpose: This is the main entry point of the program.
 *
 */

using System; 

namespace IntrusionDetectionSystem
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (Environment.GetEnvironmentVariable("HOME") != "/root")
            {
                Console.WriteLine();
                Console.Error.WriteLine("It is *HIGHLY RECOMMENDED* that you run the intrusion detection system as root!");
                Console.WriteLine("Press ENTER/RETURN to continue, or CTRL+C to exit.");
                Console.ReadLine();
            }

            Engine.Instance.Start();
        }
    }
}
