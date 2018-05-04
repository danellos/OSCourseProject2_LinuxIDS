using System;
using System.Collections.Generic;
using System.IO;
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
        private const string syscallsDb = "syscalls.json";

        // Default value. User will be prompted to change it if they want to.
        private string _logDirectory = "../../../../../logger/logs/";
        private readonly Dictionary<string, NormalDbEntry> _logEntries;
        private readonly Dictionary<uint, Syscall> _syscalls;


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
        /// </summary>
        private void Run()
        {
            foreach (var file in Directory.GetFiles(_logDirectory + "*.log"))
            {
                var fileContent = File.ReadAllText(file);
                if (string.IsNullOrEmpty(fileContent))
                    continue;

                string[] parts = fileContent.Split(',');

            }
        }

        private void Train()
        {
            foreach (var file in Directory.GetFiles(_logDirectory + "*.log"))
            {
                var fileContent = File.ReadAllText(file);
                if (string.IsNullOrEmpty(fileContent))
                    continue;

                string[] parts = fileContent.Split(',');

            }
        }

        private void ChangeLogDir()
        {

        }

        public void Start()
        {
            WriteLine();
            WriteLine("One moment please...");
            WriteLine();

            // verify that the directory for the database exists
            if (!Directory.Exists("database"))
                Directory.CreateDirectory("database");

            if (!File.Exists(syscallsDb))
            {
                Error.WriteLine("ERROR! Missing the {0} file. Terminating!", syscallsDb);
                return;
            }
             
            LoadSyscallDatabase();

            if (!Directory.Exists(_logDirectory))
            {
                Error.WriteLine("The logs directory specified {0} does not exist. Please specify a valid directory using option 3 below.", _logDirectory);
            }

            WriteLine("Welcome to Trevor Philip's Intrusion Detection System!");
            WriteLine();

            while (true)
            { 
                WriteLine("Please select a mode.");
                WriteLine("1. Train the IDS");
                WriteLine("2. Run the IDS");
                WriteLine("3. Change the log directory (current setting is '{0}')", _logDirectory);

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
                    default:
                        break;
                }
            }
        }
    }
}
