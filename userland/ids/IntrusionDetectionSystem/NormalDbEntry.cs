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
        private const int K = 5;

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
        public Dictionary<uint, List<uint[]>> Syscalls { get; set; } = new Dictionary<uint, List<uint[]>>();


        /// <summary>
        /// This is the main algorithm of the entire IDS. Here 
        /// we attempt to determine if the program has made
        /// any system calls it should not do. An attempt was made
        /// to implemented it similarly to K. Hofmeyr, et al's method.
        /// </summary>
        /// <param name="syscallSequence">The raw sequence of system calls.</param>
        /// <param name="syscalls">The database of known statically-defined system calls in the kernel.</param>
        /// <returns></returns>
        public List<string> DetermineIntrusions(List<int> syscallSequence, Dictionary<uint, Syscall> syscalls)
        {
            // this is our vector of intrusions 
            var intrusions = new List<string>();

            for (int i = 0; i < syscallSequence.Count; i++)
            {
                // -1 means an empty space from the kernel
                if(syscallSequence[i] == -1)
                    break; 

                // build K-sized sub-list to compare
                var sub = new List<uint>();
                for (int j = i + 1; j < K && j < syscallSequence.Count; j++)
                {
                    sub.Add(Convert.ToUInt32(syscallSequence[j]));
                }

                // get the unsigned int version of the current syscall ID
                uint syscallId = Convert.ToUInt32(syscallSequence[i]);

                // get the list of sequences
                var sequenceList = Syscalls[syscallId];
                if (sequenceList == null)
                {
                    // If we reach this condition, it  *could* mean an attack, but as Hofmeyr, et al indicated in their paper,
                    // this may not necessarily be the case. This condition could be reached if, for example, a program
                    // runs out of disk space and abnormal system calls are made. This is not illegal behavior, but it would
                    // be classified as unknown behavior.

                    var entryPoint = syscalls[syscallId].EntryPoint;
                    var sb = new StringBuilder();

                    // build message
                    sb.AppendFormat("{0} ", entryPoint);
                    foreach (var id in sub) 
                        sb.AppendFormat("{0} ", syscalls[id].EntryPoint);

                    intrusions.Add($"UNKNOWN BEHAVIOR: There are no known sequence combinations for system call {entryPoint}. The window values are: {sb.ToString()}");
                    continue;
                }

                // if we end up with this remaining false, we have a potential breach
                bool equivalent = false;

                // iterate only over sequences with equivalent length
                foreach (var validSequence in sequenceList.Where(x => x.Length == sub.Count))
                {
                    // Because C# is awesome and was not designed by script kiddies, 
                    // this is actually only happening in O(n) time at worst.
                    // A join does not imply arrays/lists being merged. This is actually just
                    // creating an anonymous well-optimized IEnumerable (possibly a List) type in the background :-)
                    var q = from a in sub 
                        join b in validSequence on a equals b
                        select a;
                    equivalent = q.Count() == sub.Count;
 
                    if (equivalent)
                        break; // this means we found a match, so 
                }

                if (!equivalent)
                { 
                    var entryPoint = syscalls[syscallId].EntryPoint;
                    var sb = new StringBuilder();

                    // build message
                    sb.AppendFormat("{0} ", entryPoint);
                    foreach (var id in sub)
                        sb.AppendFormat("{0} ", syscalls[id].EntryPoint);

                    intrusions.Add($"POTENTIAL INTRUSION: Abnormal system call sequence detected: {sb.ToString()}");
                }

            }

            return intrusions;
        }
    }
}
