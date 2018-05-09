/*
 * Name: Trevor Philip
 * Student ID: NL10252
 * Date: 5/8/2018
 * CMSC 421, Spring 2018
 *
 * Purpose: This is the "brain" of the IDS. Here the majority of the logic is done, such
 *          as training the IDS to learn of what system calls are valid for given processes,
 *          and doing the intrusion detection itself.
 *
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net.Mime;
using System.Text;
using Newtonsoft.Json;
using static System.Console;

namespace IntrusionDetectionSystem
{
    /// <summary>
    /// The main engine of the intrusion detection system.
    /// </summary>
    internal class Engine
    {
        private const int logLen = 12;
        private const string syscallsDb = "syscalls.json";
        private const string configFile = "config.txt";

        // Default value. User will be prompted to change it if they want to.
        private string _logDirectory = "../../logger/logs";
        private readonly Dictionary<string, NormalDbEntry> _logEntries;
        private readonly Dictionary<uint, Syscall> _syscalls;
        private readonly SyscallComparer SyscallComparer = new SyscallComparer();

        /// <summary>
        /// Constructor for Engine.
        /// </summary>
        private Engine()
        {
            _logEntries = new Dictionary<string, NormalDbEntry>();
            _syscalls = new Dictionary<uint, Syscall>();
        }

        private static Engine instance;

        /// <summary>
        /// The singleton instance of the intrusion detection system engine.
        /// </summary>
        public static Engine Instance => instance ?? (instance = new Engine());

        private void LoadSyscallDatabase()
        {
            var syscallDbContent = File.ReadAllText(syscallsDb);
            var rawSyscallList = JsonConvert.DeserializeObject<List<Syscall>>(syscallDbContent);
            foreach (var item in rawSyscallList)
                _syscalls[item.Id] = item;
        }

        /// <summary>
        /// Runs the intrustion detection system. Will stop if
        /// the IDS has not been trained to understand normal
        /// system calls for the given process.
        /// 
        /// Note: an attempt is made here to implment the 20% extra credit method
        /// from Hofmeyr, et al's method.
        /// 
        /// </summary>
        private void Run()
        {
            // this is the list of intrusions we will write to log
            List<string> intrusions = new List<string>();

            // iterate over each file
            foreach (var file in Directory.GetFiles(_logDirectory, "*.log"))
            {
                var fileContent = File.ReadAllText(file);
                if (string.IsNullOrEmpty(fileContent))
                    continue;

                WriteLine("Analyzing log {0}", file);

                string[] parts = fileContent.Split(',');

                if (parts.Length != logLen)
                    throw new FileLoadException("log file is not in the correct format!");

                string id = Utils.GenerateMD5(parts[0]);
                var dbFile = $"database/{id}.json";

                // Make sure database file exists
                if (!File.Exists(dbFile))
                {
                    WriteLine($"Cannot run the IDS against {parts[0]} with PID {parts[1]} because there is no database for it. File will NOT be removed.");
                    continue;
                }

                // read database entry from file
                var dbEntry = JsonConvert.DeserializeObject<NormalDbEntry>(File.ReadAllText(dbFile));

                // iterate over log, move window by K
                for (int i = 2; i < logLen; i++)
                {
                    var part = parts[i];
                    if (part == "-1")
                        break;

                    // get the system call
                    var syscall = _syscalls[uint.Parse(part)];
                    if (syscall == null)
                        throw new ArgumentOutOfRangeException(part);

                    // [syscall], 2nd, 3rd, 4th, 5th = K - 1
                    // "To determine that a new sequence is a mismatch requires at most comparisons" -- Hoffmeyer, et al.
                    Syscall[] sub = new Syscall[NormalDbEntry.K - 1];
                    var j = i;
                    for (int k = 0; k < sub.Length; k++)
                    {
                        if (j == logLen)
                            break;
                        if (parts[j] == "-1")
                            break;

                        sub[k] = _syscalls[uint.Parse(parts[j])];

                        j++;
                    }

                    // start testing
                    if (!dbEntry.SyscallSequences.Keys.Contains(syscall.Id))
                    {
                        // If we reach this condition, it  *could* mean an attack, but as Hofmeyr, et al indicated in their paper,
                        // this may not necessarily be the case. This condition could be reached if, for example, a program
                        // runs out of disk space and abnormal system calls are made. This is not illegal behavior, but it would
                        // be classified as unknown behavior.

                        var sb = new StringBuilder();

                        // build message
                        sb.AppendFormat("{0} ", syscall.Name);
                        foreach (var sys in sub)
                            sb.AppendFormat("{0} ", sys.Name);

                        intrusions.Add($"UNKNOWN BEHAVIOR: " +
                                       $"\n ---> There are no known sequence combinations for system call '{syscall.EntryPoint}'. " +
                                       $"\n ---> The window values are: '{sb.ToString()}'");
                        continue;
                    }

                    var validSequences = dbEntry.SyscallSequences[syscall.Id];

                    if (!validSequences.Contains(sub, SyscallComparer))
                    {
                        // If we reach this condition, we may have a breach. We need to start by determining the hamming
                        // distance. The hamming distance is easy to compute, since we already implemented an equality
                        // system for the two objects.

                        // As per Hofmeyer et al, we want to get the minimum hamming distance of known sequences
                        // so we will have to iterate over all of them.

                        int distance = int.MaxValue;
                        Syscall[] closestMatch = new Syscall[NormalDbEntry.K - 1];

                        foreach (var sequence in validSequences)
                        {
                            int currDistance = 0;
                            for (j = 0; j < sub.Length; j++)
                            {
                                if (sequence[j] == null && sub[j] == null)
                                    continue;
                                if (sequence[j] == null ^ sub[j] == null)
                                {
                                    currDistance++;
                                    continue;
                                }

                                if (sequence[j].Equals(sub[j]))
                                    currDistance++;
                            }

                            if (currDistance < distance)
                            {
                                distance = currDistance;
                                closestMatch = sequence;
                            }
                        }


                        var sbWindow = new StringBuilder();
                        var sbClosest = new StringBuilder();

                        // build message
                        sbWindow.AppendFormat("{0} ", syscall.Name);
                        sbClosest.AppendFormat("{0} ", syscall.Name);
                        foreach (var sys in sub)
                            sbWindow.AppendFormat("{0} ", sys.Name);
                        foreach (var sys in closestMatch)
                            sbClosest.AppendFormat("{0} ", sys.Name);

                        intrusions.Add(
                            $"POTENTIAL INTRUSION: " +
                            $"\n ---> Potential breach from syscall '{syscall.Name}'. " +
                            $"\n ---> The window values are: '{sbWindow.ToString()}'" +
                            $"\n ---> The syscall sequence it most closely relates to is: '{sbClosest.ToString()}'" +
                            $"\n ---> The hamming distance: {distance}\n"
                            );
                    }
                }

                WriteLine();

                if (intrusions.Count > 0)
                {
                    WriteLine("WARNING! The following possible issues were found:");
                    foreach (var intrusion in intrusions)
                    {
                        WriteLine($"{intrusion}");
                    }

                    TextWriter tw = new StreamWriter($"{DateTime.Now:MM-dd-yyyy-hh-mm-ss-fffffff}.txt");
                    System.Threading.Thread.Sleep(10); // sleep for 10 milliseconds

                    foreach (var intrusion in intrusions)
                        tw.WriteLine(intrusion);

                    tw.Close();

                }
                else
                {
                    WriteLine("No Intrusions were found! Yay!");
                }
                WriteLine();

                // remove file --  we are done with it
                File.Delete(file);
            }

            WriteLine();
            WriteLine("Operation complete!");
            WriteLine();
        }

        /// <summary>
        /// Performs training on the IDS based on logs that were created by the log writer.
        /// </summary>
        private void Train()
        {
            foreach (var file in Directory.GetFiles(_logDirectory, "*.log"))
            {
                var fileContent = File.ReadAllText(file);
                if (string.IsNullOrEmpty(fileContent))
                    continue;

                WriteLine("Parsing log {0}", file);

                string[] parts = fileContent.Split(',');

                if (parts.Length != logLen)
                    throw new FileLoadException("log file is not in the correct format!");

                string id = Utils.GenerateMD5(parts[0]);
                var dbFile = $"database/{id}.json";

                // create the database file if it does not exist
                if (!File.Exists(dbFile))
                {
                    var newEntry = new NormalDbEntry { Id = id };
                    var json = JsonConvert.SerializeObject(newEntry);
                    File.WriteAllText(dbFile, json);
                }

                // read database entry from file
                var dbEntry = JsonConvert.DeserializeObject<NormalDbEntry>(File.ReadAllText(dbFile));

                for (int i = 2; i < logLen; i++)
                {
                    var part = parts[i];
                    if (part == "-1")
                        break;

                    // get the system call
                    var syscall = _syscalls[uint.Parse(part)];
                    if (syscall == null)
                        throw new ArgumentOutOfRangeException(part);

                    if (!dbEntry.SyscallSequences.Keys.Contains(syscall.Id))
                        dbEntry.SyscallSequences[syscall.Id] = new List<Syscall[]>();

                    // [syscall], 2nd, 3rd, 4th, 5th = K - 1
                    // "To determine that a new sequence is a mismatch requires at most comparisons" -- Hoffmeyer, et al.
                    Syscall[] sub = new Syscall[NormalDbEntry.K - 1];
                    var j = i;
                    for (int k = 0; k < sub.Length; k++)
                    {
                        if (j == logLen)
                            break;
                        if (parts[j] == "-1")
                            break;

                        sub[k] = _syscalls[uint.Parse(parts[j])];

                        j++;
                    }

                    if (!dbEntry.SyscallSequences[syscall.Id].Contains(sub, SyscallComparer))
                        dbEntry.SyscallSequences[syscall.Id].Add(sub);
                }

                var jsonWrite = JsonConvert.SerializeObject(dbEntry);
                File.WriteAllText(dbFile, jsonWrite);
            }

            WriteLine();
            WriteLine("Operation complete!");
            WriteLine();

        }

        /// <summary>
        /// Changes the log directory.
        /// </summary>
        private void ChangeLogDir()
        {
            while (true)
            {
                Write("Specify new directory: ");
                string newDir = ReadLine();

                if (!Directory.Exists(newDir))
                {
                    WriteLine("Directory specified is invalid, try again.");
                    continue;
                }

                File.WriteAllText(configFile, newDir);
                break;
            }

        }

        /// <summary>
        /// Starts the Engine.
        /// </summary>
        public void Start()
        {
            WriteLine();
            WriteLine("One moment please...");
            WriteLine();

            // verify that the directory for the database exists
            if (!Directory.Exists("database"))
                Directory.CreateDirectory("database");
            WriteLine("Database loaded.");

            // verify that the log directory is set
            if (!File.Exists(configFile))
                File.WriteAllText(configFile, "../../logger/logs");
            _logDirectory = File.ReadAllText(configFile);

            //_logDirectory = @"D:\OneDrive\UMBC\CMSC421\userland\logger\logs"; // temporary

            if (!Directory.Exists(_logDirectory))
            {
                Error.WriteLine("The logs directory specified {0} does not exist. Please specify a valid directory using option 3 below.", _logDirectory);
            }

            WriteLine("Log directory loaded.");


            // syscall DB must be present
            if (!File.Exists(syscallsDb))
            {
                Error.WriteLine("ERROR! Missing the {0} file. Terminating!", syscallsDb);
                return;
            }

            // load the stuff from fules
            LoadSyscallDatabase();
            WriteLine("Syscall database loaded.");

            // done!
            WriteLine();
            WriteLine("Welcome to Trevor Philip's Intrusion Detection System!");
            WriteLine("The log directory is set as: {0}", _logDirectory);
            WriteLine();

            while (true)
            {
                WriteLine("Please select a mode.");
                WriteLine("1. Train the IDS");
                WriteLine("2. Run the IDS");
                WriteLine("3. Change the log directory (current setting is '{0}')", _logDirectory);
                WriteLine("4. Exit");
                WriteLine();
                Write("   Choice: ");

                switch (ReadLine())
                {
                    case "1":
                        Train();
                        break;
                    case "2":
                        Run();
                        break;
                    case "3":
                        ChangeLogDir();
                        break;
                    case "4":
                        return;
                    default:
                        WriteLine("Unknown choice, try again!");
                        break;
                }
            }
        }
    }
}
