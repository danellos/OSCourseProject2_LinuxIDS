
using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;

namespace IntrusionDetectionSystem
{
    internal class Syscall
    {
        private string _entryPoint;

        [JsonProperty("id")]
        public uint Id { get; set; }

        [JsonProperty("abi")]
        public string Abi { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("entry_point")]
        public  string EntryPoint { get => string.IsNullOrEmpty(_entryPoint) ? Name : _entryPoint; set => _entryPoint = value; }
    }
}
