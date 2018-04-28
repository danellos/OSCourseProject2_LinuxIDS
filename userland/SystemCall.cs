/*
 * Name: Trevor Philip
 * Date: April 11, 2018
 * Course: CMSC 421 Spring 2018, Project 2
 * Userspace program
 */

namespace IntrusionMonitor
{
    public class SystemCall
    {
        public int Id { get; private set;  }
        public bool Bit { get; private set; }

        public SystemCall(int id, bool bit)
        {
            this.Id = id;
            this.Bit = bit;
        }
    }
}
