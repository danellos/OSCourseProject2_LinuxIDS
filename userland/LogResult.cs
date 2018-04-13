/*
 * Name: Trevor Philip
 * Date: April 11, 2018
 * Course: CMSC 421 Spring 2018, Project 2
 * Userspace program
 */

using System;
using System.Collections;
using System.Collections.Generic;

namespace IntrusionMonitor
{
    public class LogResult
    {
        const int WindowSize = 5;

        public int ProcessId { get; set; }

        public List<SystemCall> Results { get; private set; }

        public string RawLog { get; private set; }

        public int HammingDistance { get; private set; }

        public LogResult(string rawLog)
        {
            this.RawLog = rawLog;
        }

        public void ProcessLog()
        {
            // TODO: Use the Window Size
            List<SystemCall> destination = new List<SystemCall>();
            foreach (var item in Results)
                destination.Add(new SystemCall(item.Id, true));
            
            HammingDistance = DetermineHammingDistance(Results, destination);

            // TODO: interpret results
        }

        private int DetermineHammingDistance(List<SystemCall> source, List<SystemCall> destination)
        {
            int hammingDistance = 0;

            if (source.Count != destination.Count)
                throw new ArgumentOutOfRangeException();
            

            for (int i = 0; i < source.Count; i++)
            {
                if (source[i].Bit != destination[i].Bit)
                    hammingDistance++;
            }

            return hammingDistance;
        }
    }
}
