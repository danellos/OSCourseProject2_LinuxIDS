/*
 * Name: Trevor Philip
 * Date: April 11, 2018
 * 
 */

using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;

namespace IntrusionMonitor
{
    class MainClass
    {
        private static Queue<>
        
        static void Main(string[] args)
        {
            // start watching the log directory
            WatchLogDirectory("/var/log/proj2");

            while (true)
            {
                // keep running the main thread, sleep for 50 seconds
                System.Threading.Thread.Sleep(50);
            }
        }

        static void Watcher_Changed(object sender, FileSystemEventArgs e)
        {
            
        }


        static void EnqueueThreadSafe()
        {
            var obj = new Object();
            lock(obj) {
                
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
