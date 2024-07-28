using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using static ConsolePlus;

//To Smash One Must:

//Set the owner of the target file or folder to Everyone.
//Remove all permission entries from the target file or folder.
//Add a new permission entry granting full control in every way to Everyone.
//For folders recursively apply the steps above to sub-folders and sub-files.
public static class NTFSPermSmash
{
    public static int Main()
    {
        //Format command line and extract target path.
        string command = Environment.CommandLine;
        //Debug testing
        command = $"\"{typeof(NTFSPermSmash).Assembly.Location}\" \"C:\\Users\\RandomiaGaming\\Desktop\\Hehe.txt\"";
        //Trim leading whitespace
        for (int i = 0; i < command.Length; i++)
        {
            if (command[i] != ' ')
            {
                command = command.Substring(i);
                break;
            }
        }
        //Trim exe path
        bool inQuotes = false;
        for (int i = 0; i < command.Length; i++)
        {
            if (command[i] == ' ')
            {
                if (!inQuotes)
                {
                    command = command.Substring(i + 1);
                    break;
                }
            }
            else if (command[i] == '"')
            {
                if (inQuotes)
                {
                    command = command.Substring(i + 1);
                    break;
                }
                else
                {
                    inQuotes = true;
                }
            }
        }
        //Trim leading whitespace again
        for (int i = 0; i < command.Length; i++)
        {
            if (command[i] != ' ')
            {
                command = command.Substring(i);
                break;
            }
        }
        //Trim trailing whitespace
        for (int i = command.Length - 1; i >= 0; i--)
        {
            if (command[i] != ' ')
            {
                command = command.Substring(0, i + 1);
                break;
            }
        }
        //Trim quotes
        if (command.Length != 0 && command[0] == '"')
        {
            if (command[command.Length - 1] == '"')
            {
                command = command.Substring(1, command.Length - 2);
            }
            else
            {
                command = command.Substring(1);
            }
        }
        //Check for empty command
        if (command.Length == 0)
        {
            WriteLine();
            WriteLine("NTFSPermSmash Version 1.0.0");
            WriteLine();
            WriteLine("Usage: Smash C:\\Path\\To\\Some\\File.txt");
            WriteLine("Usage: Smash C:\\Path\\To\\Some\\Folder");
            WriteLine();
            WriteLine("Smashing a file or folder will preform the following actions:");
            WriteLine("Set the owner to the Everyone group.");
            WriteLine("Disable permission inheritance.");
            WriteLine("Remove all permission entries.");
            WriteLine("Add a permission entry granting full control to the Everyone group.");
            WriteLine("For folders sub-folders, and sub-files will also be smashed.");
            WriteLine();
            return 1;
        }
        //Smash target file
        return Smash(command);
    }
    #region Smashing
    public static int Smash(string target)
    {
        if (File.Exists(target))
        {
            return SmashFile(new FileInfo(target).FullName);
        }
        else if (Directory.Exists(target))
        {
            return SmashFolder(new DirectoryInfo(target).FullName);
        }
        else
        {
            WriteError($"Error: Unable to find file or folder at path \"{target}\".");
            return -1;
        }
    }
    public static int SmashFile(string target)
    {
        //Validate Input
        if (target is null)
        {
            WriteError($"Error: Unable to smash file because file path is null.");
            return -1;
        }
        if (target is "")
        {
            WriteError($"Error: Unable to smash file because file path is empty.");
            return -1;
        }
        if (!File.Exists(target))
        {
            WriteError($"Error: Unable to smash file \"{target}\" because file does not exist or is not visible try smashing parent folder first.");
            return -1;
        }
        //Enable takeown permissions for process
        bool enabledRestorePermission = false;
        NoExcept(() => { enabledRestorePermission = EnablePrivilege(SE_RESTORE_NAME, true); });
        //Set owner of file to everyone
        FileInfo fileInfo = new FileInfo(target);
        FileSecurity fileSecurity = new FileSecurity();
        SecurityIdentifier everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        fileSecurity.SetOwner(everyone);
        fileInfo.SetAccessControl(fileSecurity);
        //Revoke takeown permissions to the opperating system.
        if (enabledRestorePermission)
        {
            NoExcept(() => { EnablePrivilege(SE_RESTORE_NAME, false); });
        }
        //Disable inheritance and destroy all permision entries.
        //Add a full access entry granting everyone total control over this file.
        fileSecurity = new FileSecurity();
        FileSystemAccessRule accessRule = new FileSystemAccessRule(everyone, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow);
        fileSecurity.ModifyAccessRule(AccessControlModification.Set, accessRule, out _);
        fileSecurity.SetAccessRuleProtection(true, false);
        fileInfo.SetAccessControl(fileSecurity);
        return 0;
    }
    public static int SmashFolder(string target)
    {
        //Validate Input
        if (target is null)
        {
            WriteError($"Error: Unable to smash folder because folder path is null.");
            return -1;
        }
        if (target is "")
        {
            WriteError($"Error: Unable to smash folder because folder path is empty.");
            return -1;
        }
        if (!File.Exists(target))
        {
            WriteError($"Error: Unable to smash folder \"{target}\" because folder does not exist or is not visible try smashing parent folder first.");
            return -1;
        }
        //Enable takeown permissions for process
        bool enabledRestorePermission = false;
        NoExcept(() => { enabledRestorePermission = EnablePrivilege(SE_RESTORE_NAME, true); });
        //Set owner of folder to everyone
        DirectoryInfo folderInfo = new DirectoryInfo(target);
        DirectorySecurity folderSecurity = new DirectorySecurity();
        SecurityIdentifier everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        folderSecurity.SetOwner(everyone);
        folderInfo.SetAccessControl(folderSecurity);
        //Revoke takeown permissions to the opperating system.
        if (enabledRestorePermission)
        {
            NoExcept(() => { EnablePrivilege(SE_RESTORE_NAME, false); });
        }
        //Disable inheritance and destroy all permision entries.
        //Add a full access entry granting everyone total control over this file.
        folderSecurity = new DirectorySecurity();
        FileSystemAccessRule accessRule = new FileSystemAccessRule(everyone, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow);
        folderSecurity.ModifyAccessRule(AccessControlModification.Set, accessRule, out _);
        folderSecurity.SetAccessRuleProtection(true, false);
        folderInfo.SetAccessControl(folderSecurity);
        //Recursively smash sub-files
        string[] subFiles = Directory.GetFiles(target);
        for (int i = 0; i < subFiles.Length; i++)
        {
            SmashFile(subFiles[i]);
        }
        //Recursively smash sub-folders
        string[] subFolders = Directory.GetDirectories(target);
        for (int i = 0; i < subFolders.Length; i++)
        {
            SmashFolder(subFolders[i]);
        }
        return 0;
    }
    #endregion
    #region Internal Code
    private static bool EnablePrivilege(string lpszPrivilege, bool bEnablePrivilege)
    {
        bool retval = false;
        int ltkpOld = 0;
        IntPtr hToken = IntPtr.Zero;
        TOKEN_PRIVILEGES tkp = new TOKEN_PRIVILEGES();
        tkp.Privileges = new int[3];
        TOKEN_PRIVILEGES tkpOld = new TOKEN_PRIVILEGES();
        tkpOld.Privileges = new int[3];
        LUID tLUID = new LUID();
        tkp.PrivilegeCount = 1;
        if (bEnablePrivilege)
            tkp.Privileges[2] = SE_PRIVILEGE_ENABLED;
        else
            tkp.Privileges[2] = 0;
        if (LookupPrivilegeValue(null, lpszPrivilege, out tLUID))
        {
            System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
            if (proc.Handle != IntPtr.Zero)
            {
                if (OpenProcessToken(proc.Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken) != false)
                {
                    tkp.PrivilegeCount = 1;
                    tkp.Privileges[2] = SE_PRIVILEGE_ENABLED;
                    tkp.Privileges[1] = tLUID.HighPart;
                    tkp.Privileges[0] = tLUID.LowPart;
                    const int bufLength = 256;
                    IntPtr tu = Marshal.AllocHGlobal(bufLength);
                    Marshal.StructureToPtr(tkp, tu, true);
                    if (AdjustTokenPrivileges(hToken, false, tu, bufLength, IntPtr.Zero, ref ltkpOld) != false)
                    {
                        int nErr = Marshal.GetLastWin32Error();
                        // successful AdjustTokenPrivileges doesn't mean privilege could be    changed
                        //ERROR_NOT_ALL_ASSIGNED   1300(0x514)
                        if (nErr == 0)
                        {
                            retval = true; // Token changed
                        }
                    }
                    TOKEN_PRIVILEGES tokp = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(tu, typeof(TOKEN_PRIVILEGES));
                    Marshal.FreeHGlobal(tu);
                }
            }
        }
        if (hToken != IntPtr.Zero)
        {
            CloseHandle(hToken);
        }
        return retval;
    }
    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue([In] string lpSystemName, [In] string lpName, [Out] out LUID Luid);
    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public int LowPart;
        public int HighPart;
    }
    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, IntPtr NewState, int BufferLength, IntPtr PreviousState, ref int ReturnLength);
    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public int[] Privileges;
    }
    private const int TOKEN_QUERY = 0x8;
    private const int TOKEN_ADJUST_PRIVILEGES = 0x20;
    private const string SE_BACKUP_NAME = "SeBackupPrivilege"; // Read files/folders. Traverse folders.
    private const string SE_RESTORE_NAME = "SeRestorePrivilege"; // Write files/folders. Delete files/folders. Change owner files/folders.
    private const string SE_RELABEL_NAME = "SeRelabelPrivilege"; // Change integrity files/folders.


    private const int SE_PRIVILEGE_ENABLED = (0x00000002);
    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool OpenProcessToken(IntPtr hProcess, uint desiredAccess, out IntPtr hToken);
    [DllImport("Kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
    #endregion
}