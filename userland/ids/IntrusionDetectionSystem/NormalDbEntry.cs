/*
 * Name: Trevor Philip
 * Student ID: NL10252
 * Date: 5/8/2018
 * CMSC 421, Spring 2018
 *
 * Purpose: A model for representing a database entry.
 *
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading;
using Newtonsoft.Json;

namespace IntrusionDetectionSystem
{
    /// <summary>
    /// A database entry containing a sub-database of normal system call
    /// behavior for a given program.
    /// </summary>
    internal class NormalDbEntry
    {
        /// <summary>
        /// This is the constant we have chosen for K. Hofmeyr, et al chose 3
        /// as their constant, but I will chose 5 based on the project description. 
        /// The logs are stored in windows of 10, but we sub-divide these into 
        /// windows of 5.
        /// </summary>
        public static readonly int K = 5;

        /// <summary>
        /// This is an MD5 hash of the binary executable that the process is running
        /// from. This helps us ensure we are executing our algorithm for intrusion
        /// detection against the correct thing when comparing from historical data
        /// (this is especially important if a malicious script attempts to move
        /// the binary somewhere else to evade the IDS).
        /// </summary>
        [JsonProperty("id")]
        public string Id { get; set; }

        /// <summary>
        /// This represents a K-ary tree of valid system call sequences. The key is the system
        /// call ID, and the value is a fixed k-sized array. The size is at maximum the constant
        /// chosen for K (it may be less if a given program makes less system calls than the size 
        /// of K allows).
        /// </summary>
        [JsonProperty("database")]
        public Dictionary<uint, List<Syscall[]>> SyscallSequences { get; set; } = new Dictionary<uint, List<Syscall[]>>();
    }
}
