/*
 * Name: Trevor Philip
 * Date: April 11, 2018
 * Course: CMSC 421 Spring 2018, Project 2
 * Userspace program
 */

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

namespace IntrusionMonitor
{
    public class LogReader
    {
        private string filePath;

        public LogReader(string filePath)
        {
            this.filePath = filePath;
        }

        public LogResult GetLogResult()
        {
            var entireFile = File.ReadAllText(filePath);
            return new LogResult(entireFile);
        }
    }
}
