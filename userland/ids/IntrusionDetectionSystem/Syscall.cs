﻿/*
 * Name: Trevor Philip
 * Student ID: NL10252
 * Date: 5/8/2018
 * CMSC 421, Spring 2018
 *
 * Purpose: This defines a model for a system call, and also overrides some comparison methods.
 *
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Reflection;
using System.Text;
using Microsoft.VisualBasic.CompilerServices;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace IntrusionDetectionSystem
{
    /// <summary>
    /// Model for a system call. Implements IEquatable so that
    /// we can reliably store and query this in dictionaries.
    /// </summary>
    public class Syscall : IEquatable<Syscall>
    {
        private string _entryPoint;

        [JsonProperty("id")]
        public uint Id { get; set; }

        [JsonProperty("abi")]
        public string Abi { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("entry_point")]
        public string EntryPoint { get => string.IsNullOrEmpty(_entryPoint) ? Name : _entryPoint; set => _entryPoint = value; }

        public override string ToString()
        {
            if (string.IsNullOrEmpty(Name))
                return base.ToString();

            return Id.ToString();
        }

        public bool Equals(Syscall other)
        {
            // note: this code was generated by the ReSharper extension in Visual Studio
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(_entryPoint, other._entryPoint) && Id == other.Id && string.Equals(Abi, other.Abi) && string.Equals(Name, other.Name);
        }

        public override bool Equals(object obj)
        {
            // note: this code was generated by the ReSharper extension in Visual Studio
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((Syscall)obj);
        }

        public override int GetHashCode()
        {
            // note: this code was generated by the ReSharper extension in Visual Studio
            unchecked
            {
                var hashCode = (_entryPoint != null ? _entryPoint.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (int)Id;
                hashCode = (hashCode * 397) ^ (Abi != null ? Abi.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (Name != null ? Name.GetHashCode() : 0);
                return hashCode;
            }
        }
    }

    /// <inheritdoc />
    /// <summary>
    /// This is for comparison in arrays.
    /// </summary>
    internal class SyscallComparer : IEqualityComparer<Syscall[]>
    {
        public bool Equals(Syscall[] x, Syscall[] y)
        {
            if (x == null && y == null)
                return true;
            if (x == null ^ y == null)
                return false;
            if (x.Length != y.Length)
                return false;

            for (int i = 0; i < x.Length; i++)
            {
                if (x[i] == null && y[i] == null)
                    continue;
                
                if (x[i] == null ^ y[i] == null)
                    return false;

                if (!x[i].Equals(y[i]))
                    return false;
            }

            return true;
        }

        public int GetHashCode(Syscall[] obj)
        {
            if (obj != null)
            {
                unchecked
                {
                    int hash = 17;
                    foreach (var item in obj)
                        hash = hash * 23 + ((item != null) ? item.GetHashCode() : 0);
                    return hash;
                }
            }

            return 0;
        }
    }
}
