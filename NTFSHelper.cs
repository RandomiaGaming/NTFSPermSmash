using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Data.Common;
using System.Diagnostics;
using static ConsolePlus;

public static class NTFSHelper
{
    #region Public Constants
    public static readonly NTAccount CurrentNTAccount = new NTAccount(Environment.UserDomainName, Environment.UserName);
    public static readonly bool CurrentProcessIsAdministrator = GetCurrentProcessAdministratorState();
    #endregion
    #region Directory Permissions
    //Removes all permission entries for a specified NTAcount from a directory.
    public static void RevokeAccessToDirectory(string directoryPath, NTAccount ntAccount)
    {
        if (directoryPath is null)
        {
            throw new Exception("directoryPath cannot be null.");
        }
        if (directoryPath is "")
        {
            throw new Exception("directoryPath cannot be empty.");
        }
        if (!Directory.Exists(directoryPath))
        {
            throw new Exception($"Directory at \"{directoryPath}\" does not exist.");
        }
        if (ntAccount is null)
        {
            throw new Exception("ntAccount cannot be null.");
        }
        DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
        DirectorySecurity directorySecurity;
        try
        {
            directorySecurity = directoryInfo.GetAccessControl(AccessControlSections.All);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to read directory permissions for this directory. To attempt to override the original directory permissions use ForceFullAccessToDirectory.");
        }
        FileSystemAccessRule accessRule = new FileSystemAccessRule(ntAccount, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Deny);
        try
        {
            if (!directorySecurity.ModifyAccessRule(AccessControlModification.RemoveAll, accessRule, out bool result) || !result)
            {
                throw new Exception("Failed add new access rule granting full access to target NTAccount.");
            }
        }
        catch (IdentityNotMappedException)
        {
            throw new Exception($"NTAccount \"{ntAccount.Value}\" does not exist or could not be found.");
        }
        try
        {
            directoryInfo.SetAccessControl(directorySecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change directory permissions for this directory.");
        }
    }
    //Removes all permission entries from a given directory except for a newly added entry granting full access to the specified NTAccount and enables or disables inheritance.
    public static void OverwriteFullAccessToDirectory(string directoryPath, NTAccount ntAccount, bool allowInheritance)
    {
        if (directoryPath is null)
        {
            throw new Exception("directoryPath cannot be null.");
        }
        if (directoryPath is "")
        {
            throw new Exception("directoryPath cannot be empty.");
        }
        if (!Directory.Exists(directoryPath))
        {
            throw new Exception($"Directory at \"{directoryPath}\" does not exist.");
        }
        if (ntAccount is null)
        {
            throw new Exception("ntAccount cannot be null.");
        }
        DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
        DirectorySecurity directorySecurity = new DirectorySecurity();
        FileSystemAccessRule accessRule = new FileSystemAccessRule(ntAccount, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow);
        try
        {
            if (!directorySecurity.ModifyAccessRule(AccessControlModification.Set, accessRule, out bool result) || !result)
            {
                throw new Exception("Failed add new access rule granting full access to target NTAccount.");
            }
        }
        catch (IdentityNotMappedException)
        {
            throw new Exception($"NTAccount \"{ntAccount.Value}\" does not exist or could not be found.");
        }
        directorySecurity.SetAccessRuleProtection(!allowInheritance, false);
        try
        {
            directoryInfo.SetAccessControl(directorySecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change directory permissions for this directory.");
        }
    }
    //Adds a new permission entry granting full access to the specified NTAccount to a directory and deletes all other entries for the specified NTAccount.
    public static void GrantFullAccessToDirectory(string directoryPath, NTAccount ntAccount)
    {
        if (directoryPath is null)
        {
            throw new Exception("directoryPath cannot be null.");
        }
        if (directoryPath is "")
        {
            throw new Exception("directoryPath cannot be empty.");
        }
        if (!Directory.Exists(directoryPath))
        {
            throw new Exception($"Directory at \"{directoryPath}\" does not exist.");
        }
        if (ntAccount is null)
        {
            throw new Exception("ntAccount cannot be null.");
        }
        DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
        DirectorySecurity directorySecurity;
        try
        {
            directorySecurity = directoryInfo.GetAccessControl(AccessControlSections.All);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to read directory permissions for this directory. To attempt to override the original directory permissions use ForceFullAccessToDirectory.");
        }
        FileSystemAccessRule accessRule = new FileSystemAccessRule(ntAccount, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow);
        try
        {
            if (!directorySecurity.ModifyAccessRule(AccessControlModification.Add, accessRule, out bool result) || !result)
            {
                throw new Exception("Failed add new access rule granting full access to target NTAccount.");
            }
        }
        catch (IdentityNotMappedException)
        {
            throw new Exception($"NTAccount \"{ntAccount.Value}\" does not exist or could not be found.");
        }
        try
        {
            directoryInfo.SetAccessControl(directorySecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change directory permissions for this directory.");
        }
    }
    //Removes all permission entries from a given directory and enables or disables inheritance.
    public static void RevokeAllAccessToDirectory(string directoryPath, bool allowInheritance)
    {
        if (directoryPath is null)
        {
            throw new Exception("directoryPath cannot be null.");
        }
        if (directoryPath is "")
        {
            throw new Exception("directoryPath cannot be empty.");
        }
        if (!Directory.Exists(directoryPath))
        {
            throw new Exception($"Directory at \"{directoryPath}\" does not exist.");
        }
        DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
        DirectorySecurity directorySecurity = new DirectorySecurity();
        directorySecurity.SetAccessRuleProtection(!allowInheritance, false);
        try
        {
            directoryInfo.SetAccessControl(directorySecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change directory permissions for this directory.");
        }
    }
    #endregion
    #region Directory Inheritance
    //Returns true if inheritance is enbabled otherwise false.
    public static bool GetInheritanceStateForDirectory(string directoryPath)
    {
        if (directoryPath is null)
        {
            throw new Exception("directoryPath cannot be null.");
        }
        if (directoryPath is "")
        {
            throw new Exception("directoryPath cannot be empty.");
        }
        if (!Directory.Exists(directoryPath))
        {
            throw new Exception($"Directory at \"{directoryPath}\" does not exist.");
        }
        DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
        DirectorySecurity directorySecurity;
        try
        {
            directorySecurity = directoryInfo.GetAccessControl(AccessControlSections.Access);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to read directory permissions for this directory.");
        }
        return !directorySecurity.AreAccessRulesProtected;
    }
    //Disables inheritance for directory and removes all permission entries.
    public static void ForceDisableInheritanceForDirectory(string directoryPath)
    {
        if (directoryPath is null)
        {
            throw new Exception("directoryPath cannot be null.");
        }
        if (directoryPath is "")
        {
            throw new Exception("directoryPath cannot be empty.");
        }
        if (!Directory.Exists(directoryPath))
        {
            throw new Exception($"Directory at \"{directoryPath}\" does not exist.");
        }
        DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
        DirectorySecurity directorySecurity = new DirectorySecurity();
        directorySecurity.SetAccessRuleProtection(false, false);
        try
        {
            directoryInfo.SetAccessControl(directorySecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change directory permissions for this directory.");
        }
    }
    //Diables inheritance for a directory and optionally converts inherited permissions to local permissions
    public static void DisableInheritanceForDirectory(string directoryPath, bool convertInheritedToLocal)
    {
        if (directoryPath is null)
        {
            throw new Exception("directoryPath cannot be null.");
        }
        if (directoryPath is "")
        {
            throw new Exception("directoryPath cannot be empty.");
        }
        if (!Directory.Exists(directoryPath))
        {
            throw new Exception($"Directory at \"{directoryPath}\" does not exist.");
        }
        DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
        DirectorySecurity directorySecurity;
        try
        {
            directorySecurity = directoryInfo.GetAccessControl(AccessControlSections.All);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to read directory permissions for this directory. To attempt to override the original directory permissions use ForceDisableInheritanceForDirectory.");
        }
        directorySecurity.SetAccessRuleProtection(false, convertInheritedToLocal);
        try
        {
            directoryInfo.SetAccessControl(directorySecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change directory permissions for this directory.");
        }
    }
    //Enables inheritance for directory and removes all permission entries.
    public static void ForceEnableInheritanceForDirectory(string directoryPath)
    {
        if (directoryPath is null)
        {
            throw new Exception("directoryPath cannot be null.");
        }
        if (directoryPath is "")
        {
            throw new Exception("directoryPath cannot be empty.");
        }
        if (!Directory.Exists(directoryPath))
        {
            throw new Exception($"Directory at \"{directoryPath}\" does not exist.");
        }
        DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
        DirectorySecurity directorySecurity = new DirectorySecurity();
        directorySecurity.SetAccessRuleProtection(true, false);
        try
        {
            directoryInfo.SetAccessControl(directorySecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change directory permissions for this directory.");
        }
    }
    //Enables inheritance for a directory.
    public static void EnableInheritanceForDirectory(string directoryPath)
    {
        if (directoryPath is null)
        {
            throw new Exception("directoryPath cannot be null.");
        }
        if (directoryPath is "")
        {
            throw new Exception("directoryPath cannot be empty.");
        }
        if (!Directory.Exists(directoryPath))
        {
            throw new Exception($"Directory at \"{directoryPath}\" does not exist.");
        }
        DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
        DirectorySecurity directorySecurity;
        try
        {
            directorySecurity = directoryInfo.GetAccessControl(AccessControlSections.All);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to read directory permissions for this directory. To attempt to override the original directory permissions use ForceEnableInheritanceForDirectory.");
        }
        directorySecurity.SetAccessRuleProtection(true, false);
        try
        {
            directoryInfo.SetAccessControl(directorySecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change directory permissions for this directory.");
        }
    }
    #endregion
    #region Directory Owners
    //Sets the owner of a directory to a specified NTAcount. Will use administrator permissions to force the opperation if availible.
    public static void SetOwnerOfDirectory(string directoryPath, NTAccount ntAccount)
    {
        if (directoryPath is null)
        {
            throw new Exception("directoryPath cannot be null.");
        }
        if (directoryPath is "")
        {
            throw new Exception("directoryPath cannot be empty.");
        }
        if (!Directory.Exists(directoryPath))
        {
            throw new Exception($"Directory at \"{directoryPath}\" does not exist.");
        }
        if (ntAccount is null)
        {
            throw new Exception("ntAccount cannot be null.");
        }
        bool enabledTakeOwnershipPermission = false;
        try
        {
            enabledTakeOwnershipPermission = EnablePrivilege(SE_TAKE_OWNERSHIP_NAME, true);
        }
        catch
        {

        }
        bool enabledRestorePermission = false;
        try
        {
            enabledTakeOwnershipPermission = EnablePrivilege(SE_RESTORE_NAME, true);
        }
        catch
        {

        }
        DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
        DirectorySecurity directorySecurity = new DirectorySecurity();
        try
        {
            directorySecurity.SetOwner(ntAccount);
        }
        catch (IdentityNotMappedException)
        {
            throw new Exception($"NTAccount \"{ntAccount.Value}\" does not exist or could not be found.");
        }
        try
        {
            directoryInfo.SetAccessControl(directorySecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change directory permissions for this directory.");
        }
        if (enabledRestorePermission)
        {
            try
            {
                EnablePrivilege(SE_RESTORE_NAME, false);
            }
            catch
            {

            }
        }
        if (enabledTakeOwnershipPermission)
        {
            try
            {
                EnablePrivilege(SE_TAKE_OWNERSHIP_NAME, false);
            }
            catch
            {

            }
        }
    }
    //Returns the current owner of a directory.
    public static NTAccount GetOwnerOfDirectory(string directoryPath)
    {
        if (directoryPath is null)
        {
            throw new Exception("directoryPath cannot be null.");
        }
        if (directoryPath is "")
        {
            throw new Exception("directoryPath cannot be empty.");
        }
        if (!Directory.Exists(directoryPath))
        {
            throw new Exception($"Directory at \"{directoryPath}\" does not exist.");
        }
        DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
        DirectorySecurity directorySecurity;
        try
        {
            directorySecurity = directoryInfo.GetAccessControl(AccessControlSections.Owner);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current directory owner cannot be displayed because current user does not have access to read directory permissions for this directory, however, administrators can always overwrite the directory owner.");
        }
        try
        {
            return (NTAccount)directorySecurity.GetOwner(typeof(NTAccount));
        }
        catch (IdentityNotMappedException)
        {
            throw new Exception("Directory is owned by a corrupted user which cannot be displayed, however, the current user may be able to overwrite the directory owner.");
        }
    }
    #endregion
    #region File Permissions
    //Removes all permission entries for a specified NTAcount from a file.
    public static void RevokeAccessToFile(string filePath, NTAccount ntAccount)
    {
        if (filePath is null)
        {
            throw new Exception("filePath cannot be null.");
        }
        if (filePath is "")
        {
            throw new Exception("filePath cannot be empty.");
        }
        if (!File.Exists(filePath))
        {
            throw new Exception($"File at \"{filePath}\" does not exist.");
        }
        if (ntAccount is null)
        {
            throw new Exception("ntAccount cannot be null.");
        }
        FileInfo fileInfo = new FileInfo(filePath);
        FileSecurity fileSecurity;
        try
        {
            fileSecurity = fileInfo.GetAccessControl(AccessControlSections.All);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to read file permissions for this file. To attempt to override the original file permissions use ForceFullAccessToFile.");
        }
        FileSystemAccessRule accessRule = new FileSystemAccessRule(ntAccount, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Deny);
        try
        {
            if (!fileSecurity.ModifyAccessRule(AccessControlModification.RemoveAll, accessRule, out bool result) || !result)
            {
                throw new Exception("Failed add new access rule granting full access to target NTAccount.");
            }
        }
        catch (IdentityNotMappedException)
        {
            throw new Exception($"NTAccount \"{ntAccount.Value}\" does not exist or could not be found.");
        }
        try
        {
            fileInfo.SetAccessControl(fileSecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change file permissions for this file.");
        }
    }
    //Removes all permission entries from a given file except for a newly added entry granting full access to the specified NTAccount and enables or disables inheritance.
    public static void OverwriteFullAccessToFile(string filePath, NTAccount ntAccount, bool allowInheritance)
    {
        if (filePath is null)
        {
            throw new Exception("filePath cannot be null.");
        }
        if (filePath is "")
        {
            throw new Exception("filePath cannot be empty.");
        }
        if (!File.Exists(filePath))
        {
            throw new Exception($"File at \"{filePath}\" does not exist.");
        }
        if (ntAccount is null)
        {
            throw new Exception("ntAccount cannot be null.");
        }
        FileInfo fileInfo = new FileInfo(filePath);
        FileSecurity fileSecurity = new FileSecurity();
        FileSystemAccessRule accessRule = new FileSystemAccessRule(ntAccount, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow);
        try
        {
            if (!fileSecurity.ModifyAccessRule(AccessControlModification.Set, accessRule, out bool result) || !result)
            {
                throw new Exception("Failed add new access rule granting full access to target NTAccount.");
            }
        }
        catch (IdentityNotMappedException)
        {
            throw new Exception($"NTAccount \"{ntAccount.Value}\" does not exist or could not be found.");
        }
        fileSecurity.SetAccessRuleProtection(!allowInheritance, false);
        try
        {
            fileInfo.SetAccessControl(fileSecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change file permissions for this file.");
        }
    }
    //Adds a new permission entry granting full access to the specified NTAccount to a file and deletes all other entries for the specified NTAccount.
    public static void GrantFullAccessToFile(string filePath, NTAccount ntAccount)
    {
        if (filePath is null)
        {
            throw new Exception("filePath cannot be null.");
        }
        if (filePath is "")
        {
            throw new Exception("filePath cannot be empty.");
        }
        if (!File.Exists(filePath))
        {
            throw new Exception($"File at \"{filePath}\" does not exist.");
        }
        if (ntAccount is null)
        {
            throw new Exception("ntAccount cannot be null.");
        }
        FileInfo fileInfo = new FileInfo(filePath);
        FileSecurity fileSecurity;
        try
        {
            fileSecurity = fileInfo.GetAccessControl(AccessControlSections.All);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to read file permissions for this file. To attempt to override the original file permissions use ForceFullAccessToFile.");
        }
        FileSystemAccessRule accessRule = new FileSystemAccessRule(ntAccount, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow);
        try
        {
            if (!fileSecurity.ModifyAccessRule(AccessControlModification.Add, accessRule, out bool result) || !result)
            {
                throw new Exception("Failed add new access rule granting full access to target NTAccount.");
            }
        }
        catch (IdentityNotMappedException)
        {
            throw new Exception($"NTAccount \"{ntAccount.Value}\" does not exist or could not be found.");
        }
        try
        {
            fileInfo.SetAccessControl(fileSecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change file permissions for this file.");
        }
    }
    //Removes all permission entries from a given file and enables or disables inheritance.
    public static void RevokeAllAccessToFile(string filePath, bool allowInheritance)
    {
        if (filePath is null)
        {
            throw new Exception("filePath cannot be null.");
        }
        if (filePath is "")
        {
            throw new Exception("filePath cannot be empty.");
        }
        if (!File.Exists(filePath))
        {
            throw new Exception($"File at \"{filePath}\" does not exist.");
        }
        FileInfo fileInfo = new FileInfo(filePath);
        FileSecurity fileSecurity = new FileSecurity();
        fileSecurity.SetAccessRuleProtection(!allowInheritance, false);
        try
        {
            fileInfo.SetAccessControl(fileSecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change file permissions for this file.");
        }
    }
    #endregion
    #region File Inheritance
    //Returns true if inheritance is enbabled otherwise false.
    public static bool GetInheritanceStateForFile(string filePath)
    {
        if (filePath is null)
        {
            throw new Exception("filePath cannot be null.");
        }
        if (filePath is "")
        {
            throw new Exception("filePath cannot be empty.");
        }
        if (!File.Exists(filePath))
        {
            throw new Exception($"File at \"{filePath}\" does not exist.");
        }
        FileInfo fileInfo = new FileInfo(filePath);
        FileSecurity fileSecurity;
        try
        {
            fileSecurity = fileInfo.GetAccessControl(AccessControlSections.Access);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to read file permissions for this file.");
        }
        return !fileSecurity.AreAccessRulesProtected;
    }
    //Disables inheritance for file and removes all permission entries.
    public static void ForceDisableInheritanceForFile(string filePath)
    {
        if (filePath is null)
        {
            throw new Exception("filePath cannot be null.");
        }
        if (filePath is "")
        {
            throw new Exception("filePath cannot be empty.");
        }
        if (!File.Exists(filePath))
        {
            throw new Exception($"File at \"{filePath}\" does not exist.");
        }
        FileInfo fileInfo = new FileInfo(filePath);
        FileSecurity fileSecurity = new FileSecurity();
        fileSecurity.SetAccessRuleProtection(false, false);
        try
        {
            fileInfo.SetAccessControl(fileSecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change file permissions for this file.");
        }
    }
    //Diables inheritance for a file and optionally converts inherited permissions to local permissions
    public static void DisableInheritanceForFile(string filePath, bool convertInheritedToLocal)
    {
        if (filePath is null)
        {
            throw new Exception("filePath cannot be null.");
        }
        if (filePath is "")
        {
            throw new Exception("filePath cannot be empty.");
        }
        if (!File.Exists(filePath))
        {
            throw new Exception($"File at \"{filePath}\" does not exist.");
        }
        FileInfo fileInfo = new FileInfo(filePath);
        FileSecurity fileSecurity;
        try
        {
            fileSecurity = fileInfo.GetAccessControl(AccessControlSections.All);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to read file permissions for this file. To attempt to override the original file permissions use ForceDisableInheritanceForFile.");
        }
        fileSecurity.SetAccessRuleProtection(false, convertInheritedToLocal);
        try
        {
            fileInfo.SetAccessControl(fileSecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change file permissions for this file.");
        }
    }
    //Enables inheritance for file and removes all permission entries.
    public static void ForceEnableInheritanceForFile(string filePath)
    {
        if (filePath is null)
        {
            throw new Exception("filePath cannot be null.");
        }
        if (filePath is "")
        {
            throw new Exception("filePath cannot be empty.");
        }
        if (!File.Exists(filePath))
        {
            throw new Exception($"File at \"{filePath}\" does not exist.");
        }
        FileInfo fileInfo = new FileInfo(filePath);
        FileSecurity fileSecurity = new FileSecurity();
        fileSecurity.SetAccessRuleProtection(true, false);
        try
        {
            fileInfo.SetAccessControl(fileSecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change file permissions for this file.");
        }
    }
    //Enables inheritance for a file.
    public static void EnableInheritanceForFile(string filePath)
    {
        if (filePath is null)
        {
            throw new Exception("filePath cannot be null.");
        }
        if (filePath is "")
        {
            throw new Exception("filePath cannot be empty.");
        }
        if (!File.Exists(filePath))
        {
            throw new Exception($"File at \"{filePath}\" does not exist.");
        }
        FileInfo fileInfo = new FileInfo(filePath);
        FileSecurity fileSecurity;
        try
        {
            fileSecurity = fileInfo.GetAccessControl(AccessControlSections.All);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to read file permissions for this file. To attempt to override the original file permissions use ForceEnableInheritanceForFile.");
        }
        fileSecurity.SetAccessRuleProtection(true, false);
        try
        {
            fileInfo.SetAccessControl(fileSecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change file permissions for this file.");
        }
    }
    #endregion
    #region File Owners
    //Sets the owner of a file to a specified NTAcount. Will use administrator permissions to force the opperation if availible.
    public static void SetOwnerOfFile(string filePath, NTAccount ntAccount)
    {
        if (filePath is null)
        {
            throw new Exception($"Unable to set owner of file because file path is null.");
        }
        if (filePath is "")
        {
            throw new Exception($"Unable to set owner of file because file path is empty.");
        }
        if (!File.Exists(filePath))
        {
            throw new Exception($"Unable to set owner of file at \"{filePath}\" because file does not exist.");
        }
        if (ntAccount is null)
        {
            throw new Exception($"Unable to set owner of file at \"{filePath}\" because NTAcount is null.");
        }
        bool enabledTakeOwnershipPermission = false;
        try
        {
            enabledTakeOwnershipPermission = EnablePrivilege(SE_TAKE_OWNERSHIP_NAME, true);
        }
        catch
        {

        }
        bool enabledRestorePermission = false;
        try
        {
            enabledTakeOwnershipPermission = EnablePrivilege(SE_RESTORE_NAME, true);
        }
        catch
        {

        }
        FileInfo fileInfo = new FileInfo(filePath);
        FileSecurity fileSecurity = new FileSecurity();
        try
        {
            fileSecurity.SetOwner(ntAccount);
        }
        catch (IdentityNotMappedException)
        {
            throw new Exception($"NTAccount \"{ntAccount.Value}\" does not exist or could not be found.");
        }
        try
        {
            fileInfo.SetAccessControl(fileSecurity);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception("Current user does not have access to change file permissions for this file.");
        }
        if (enabledRestorePermission)
        {
            try
            {
                EnablePrivilege(SE_RESTORE_NAME, false);
            }
            catch
            {

            }
        }
        if (enabledTakeOwnershipPermission)
        {
            try
            {
                EnablePrivilege(SE_TAKE_OWNERSHIP_NAME, false);
            }
            catch
            {

            }
        }
    }
    //Returns the current owner of a file.
    public static NTAccount GetOwnerOfFile(string filePath)
    {
        if (filePath is null)
        {
            throw new Exception($"Unable to get owner of file because file path is null.");
        }
        if (filePath is "")
        {
            throw new Exception($"Unable to get owner of file because file path is empty.");
        }
        if (!File.Exists(filePath))
        {
            throw new Exception($"Unable to get owner of file at \"{filePath}\" because file does not exist.");
        }
        FileInfo fileInfo;
        try
        {
            fileInfo = new FileInfo(filePath);
        }
        catch (Exception exception)
        {
            throw new Exception($"Unable to get owner of file at \"{filePath}\" because creation of file info encountered error: \"{exception.Message}\".");
        }
        FileSecurity fileSecurity;
        try
        {
            fileSecurity = fileInfo.GetAccessControl(AccessControlSections.Owner);
        }
        catch (UnauthorizedAccessException)
        {
            throw new Exception($"Unable to get owner of file at \"{filePath}\" because current user does not have access to read file permissions for this file, however, the current user may be able to overwrite the file owner.");
        }
        try
        {
            return (NTAccount)fileSecurity.GetOwner(typeof(NTAccount));
        }
        catch (IdentityNotMappedException)
        {
            throw new Exception($"Unable to get owner of file at \"{filePath}\" because file is owned by a corrupted user which cannot be displayed, however, the current user may be able to overwrite the file owner.");
        }
    }
    #endregion
    #region Symbolic Links
    //Returns true if the directory is a symbolic link otherwise false.
    public static bool DirectoryIsSymbolicLink(string directoryPath)
    {
        try
        {
            if (directoryPath is null)
            {
                throw new Exception($"Unable to determine if directory is symbolic link because directory path is null.");
            }
            if (directoryPath is "")
            {
                throw new Exception($"Unable to determine if directory is symbolic link because directory path is empty.");
            }
            if (!Directory.Exists(directoryPath))
            {
                throw new Exception($"Unable to determine if directory at \"{directoryPath}\" is symbolic link because directory does not exist.");
            }
            DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
            return directoryInfo.Attributes.HasFlag(FileAttributes.ReparsePoint);
        }
        catch (Exception exception)
        {
            throw new Exception($"Unable to determine if directory at \"{directoryPath}\" is symbolic link due to exception: \"{exception.Message}\".");
        }
    }
    //Returns true if the file is a symbolic link otherwise false.
    public static bool FileIsSymbolicLink(string filePath)
    {
        try
        {
            if (filePath is null)
            {
                throw new Exception($"Unable to determine if file is symbolic link because file path is null.");
            }
            if (filePath is "")
            {
                throw new Exception($"Unable to determine if file is symbolic link because file path is empty.");
            }
            if (!File.Exists(filePath))
            {
                throw new Exception($"Unable to determine if file at \"{filePath}\" is symbolic link because file does not exist.");
            }
            FileInfo fileInfo = new FileInfo(filePath);
            return fileInfo.Attributes.HasFlag(FileAttributes.ReparsePoint);
        }
        catch (Exception exception)
        {
            throw new Exception($"Unable to determine if file at \"{filePath}\" is symbolic link due to exception: \"{exception.Message}\".");
        }
    }
    #endregion
    #region Administration
    //Returns true if the current process is running as administrator otherwise returns false.
    public static bool GetCurrentProcessAdministratorState()
    {
        bool output = false;
        try
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            try
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                output = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            finally
            {
                try
                {
                    identity.Dispose();
                }
                catch
                {

                }
            }
        }
        catch (Exception exception)
        {
            throw new Exception($"Unable to determine if current process is administrator due to exception: \"{exception.Message}\".");
        }
        return output;
    }
    #endregion
    #region Internal Code
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string lpFileName, int dwDesiredAccess, int dwShareMode, IntPtr securityAttributes, int dwCreationDisposition, int dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetFinalPathNameByHandle([In] SafeFileHandle hFile, [Out] StringBuilder lpszFilePath, [In] int cchFilePath, [In] int dwFlags);
    private const int CREATION_DISPOSITION_OPEN_EXISTING = 3;
    private const int FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    public static string GetSymbolicLinkTarget(string symbolicLinkPath)
    {
        if (!Directory.Exists(symbolicLinkPath) && !File.Exists(symbolicLinkPath))
        {
            throw new IOException("Path not found");
        }

        SafeFileHandle directoryHandle = CreateFile(symbolicLinkPath, 0, 2, IntPtr.Zero, CREATION_DISPOSITION_OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero); //Handle file / folder

        if (directoryHandle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        StringBuilder result = new StringBuilder(512);
        int mResult = GetFinalPathNameByHandle(directoryHandle, result, result.Capacity, 0);

        if (mResult < 0)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        if (result.Length >= 4 && result[0] == '\\' && result[1] == '\\' && result[2] == '?' && result[3] == '\\')
        {
            return result.ToString().Substring(4);
        }
        return result.ToString();
    }
    public static bool EnablePrivilege(string lpszPrivilege, bool bEnablePrivilege)
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
    public static extern uint RegOpenKeyEx(IntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, ref IntPtr phkResult);
    public const int HKEY_CURRENT_USER = unchecked((int)0x80000001);
    public const int HKEY_CLASSES_ROOT = unchecked((int)0x80000000);
    public const int KEY_WOW64_64KEY = 0x0100;
    public const int WRITE_OWNER = 0x00080000;
    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint RegCloseKey(IntPtr hKey);
    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue([In] string lpSystemName, [In] string lpName, [Out] out LUID Luid);
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public int LowPart;
        public int HighPart;
    }
    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, IntPtr NewState, int BufferLength, IntPtr PreviousState, ref int ReturnLength);
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public int Attributes;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
    {
        internal int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        internal int[] Privileges;
    }
    public const int TOKEN_ASSIGN_PRIMARY = 0x1;
    public const int TOKEN_DUPLICATE = 0x2;
    public const int TOKEN_IMPERSONATE = 0x4;
    public const int TOKEN_QUERY = 0x8;
    public const int TOKEN_QUERY_SOURCE = 0x10;
    public const int TOKEN_ADJUST_PRIVILEGES = 0x20;
    public const int TOKEN_ADJUST_GROUPS = 0x40;
    public const int TOKEN_ADJUST_DEFAULT = 0x80;
    public const int TOKEN_ALL_ACCESS = TOKEN_ASSIGN_PRIMARY + TOKEN_DUPLICATE + TOKEN_IMPERSONATE + TOKEN_QUERY + TOKEN_QUERY_SOURCE + TOKEN_ADJUST_PRIVILEGES + TOKEN_ADJUST_GROUPS + TOKEN_ADJUST_DEFAULT;
    public const string SE_RESTORE_NAME = "SeRestorePrivilege";
    public const string SE_DEBUG_NAME = "SeDebugPrivilege";
    public const string SE_TCB_NAME = "SeTcbPrivilege";
    public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
    public const int SE_PRIVILEGE_ENABLED_BY_DEFAULT = (0x00000001);
    public const int SE_PRIVILEGE_ENABLED = (0x00000002);
    public const int SE_PRIVILEGE_REMOVED = (0X00000004);
    public const int SE_PRIVILEGE_USED_FOR_ACCESS = unchecked((int)0x80000000);
    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool OpenProcessToken(IntPtr hProcess, uint desiredAccess, out IntPtr hToken);
    [DllImport("Kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    public const int OWNER_SECURITY_INFORMATION = 0x00000001;
    #endregion
}