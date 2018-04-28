/*
 * Name: Trevor Philip
 * Date: April 11, 2018
 * Course: CMSC 421 Spring 2018, Project 2
 * Userspace program
 */

using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;

namespace IntrusionMonitor
{
    class MainClass
    {
        private static Queue<LogResult> logQueue = new Queue<LogResult>();
        
        public static void Main(string[] args)
        {
            // start watching the log directory
            WatchLogDirectory("/var/log/proj2");

            while (true)
            {
                // keep running the main thread, sleep for 50 seconds
                System.Threading.Thread.Sleep(50);
                var pop = logQueue.Dequeue();
                pop.ProcessLog();
                if (pop.HammingDistance > 0) 
                {
                    Console.WriteLine("WARNING: Hamming distance is larger than 0!: {0}" pop.HammingDistance);
                }
            }
        }

        static void Watcher_Changed(object sender, FileSystemEventArgs e)
        {
            var logReader = new LogReader(e.FullPath);
            EnqueueThreadSafe(logReader.GetLogResult());
        }


        static void EnqueueThreadSafe(LogResult result)
        {
            var obj = new Object();
            lock(obj) {
                logQueue.Enqueue(result);
            }
        }


        /// <summary>
        /// Watches the log directory.
        /// </summary>
        /// <param name="path">Path.</param>
        private static void WatchLogDirectory(string path)
        {
            FileSystemWatcher watcher = new FileSystemWatcher();
            watcher.Path = path;
            watcher.NotifyFilter = NotifyFilters.LastWrite;
            watcher.Filter = "*.log";
            watcher.Changed += Watcher_Changed;
            watcher.EnableRaisingEvents = true;
        }
    }
}
